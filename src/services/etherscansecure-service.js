const { Interface, getAddress, isAddress, keccak256, formatEther, MaxUint256 } = require('ethers');

const COMMON_ABI = [
  'function approve(address spender,uint256 amount)', 'function increaseAllowance(address spender,uint256 addedValue)',
  'function setApprovalForAll(address operator,bool approved)', 'function transfer(address to,uint256 amount)',
  'function transferFrom(address from,address to,uint256 amount)', 'function safeTransferFrom(address from,address to,uint256 tokenId)',
  'function permit(address owner,address spender,uint256 value,uint256 deadline,uint8 v,bytes32 r,bytes32 s)'
];
const iface = new Interface(COMMON_ABI);
const IMPLEMENTATION_SLOT = '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc';
const ADMIN_SLOT = '0xb53127684a568b3173ae13b9f8a6016e0199248a875d6e0a610243e63b6e8ee';

class ScanError extends Error { constructor(message, code = 'SCAN_ERROR', status = 500) { super(message); this.name = 'ScanError'; this.code = code; this.status = status; } }

function finding(severity, code, message, details = {}) { return { severity, code, message, ...details }; }
function riskFrom(findings) {
  const points = findings.reduce((sum, item) => sum + ({ info: 0, low: 10, medium: 25, high: 50, critical: 80 }[item.severity] || 0), 0);
  const score = Math.min(100, points); return { score, level: score >= 80 ? 'critical' : score >= 50 ? 'high' : score >= 25 ? 'medium' : score >= 10 ? 'low' : 'informational' };
}

class EtherScanSecureService {
  constructor({ rpcUrls = {}, fetchImpl = globalThis.fetch, timeout = 12000 } = {}) { this.rpcUrls = rpcUrls; this.fetch = fetchImpl; this.timeout = timeout; this.requestId = 0; }
  listChains() { return Object.keys(this.rpcUrls); }

  scanTransaction(tx = {}) {
    if (!isAddress(tx.to || '')) throw new ScanError('Transaction destination is invalid', 'INVALID_ADDRESS', 400);
    if (tx.from && !isAddress(tx.from)) throw new ScanError('Transaction sender is invalid', 'INVALID_ADDRESS', 400);
    const data = tx.data || '0x'; if (!/^0x(?:[a-fA-F0-9]{2})*$/.test(data)) throw new ScanError('Transaction data must be even-length hex', 'INVALID_DATA', 400);
    let value; try { value = BigInt(tx.value || 0); } catch { throw new ScanError('Transaction value must be an integer', 'INVALID_VALUE', 400); }
    if (value < 0n) throw new ScanError('Transaction value cannot be negative', 'INVALID_VALUE', 400);
    const findings = []; let decoded = null;
    if (data === '0x' && value > 0n) findings.push(finding('info', 'NATIVE_TRANSFER', `Transfers ${formatEther(value)} native currency`, { value: value.toString() }));
    if (data !== '0x') {
      try {
        const parsed = iface.parseTransaction({ data, value }); decoded = { function: parsed.signature, name: parsed.name, args: serialize(parsed.args) };
        if (parsed.name === 'approve' || parsed.name === 'increaseAllowance' || parsed.name === 'permit') {
          const amount = BigInt(parsed.name === 'increaseAllowance' ? parsed.args.addedValue : parsed.name === 'permit' ? parsed.args.value : parsed.args.amount);
          const spender = parsed.name === 'permit' ? parsed.args.spender : parsed.args.spender;
          findings.push(finding(amount > MaxUint256 / 2n ? 'high' : amount === 0n ? 'info' : 'medium', amount > MaxUint256 / 2n ? 'UNLIMITED_ALLOWANCE' : 'TOKEN_ALLOWANCE', amount > MaxUint256 / 2n ? 'Grants a near-unlimited token allowance' : amount === 0n ? 'Revokes a token allowance' : 'Grants a token allowance', { spender, amount: amount.toString() }));
        } else if (parsed.name === 'setApprovalForAll') {
          findings.push(finding(parsed.args.approved ? 'high' : 'info', parsed.args.approved ? 'NFT_OPERATOR_APPROVAL' : 'NFT_OPERATOR_REVOKE', parsed.args.approved ? 'Allows this operator to transfer every token in the collection' : 'Revokes collection-wide operator access', { operator: parsed.args.operator }));
        } else findings.push(finding('info', 'TOKEN_TRANSFER', `Calls ${parsed.signature}`));
      } catch { findings.push(finding('low', 'UNKNOWN_CALLDATA', `Unknown function selector ${data.slice(0, 10)}; verify it against trusted contract documentation`)); }
    }
    if (value > 0n && data !== '0x') findings.push(finding('medium', 'VALUE_WITH_CALLDATA', 'Sends native value while calling a contract', { value: value.toString() }));
    if (tx.chainId == null) findings.push(finding('low', 'MISSING_CHAIN_ID', 'No chainId was supplied; verify the wallet network before signing'));
    return { transaction: { ...tx, to: getAddress(tx.to), ...(tx.from ? { from: getAddress(tx.from) } : {}), data, value: value.toString() }, decoded, findings, risk: riskFrom(findings), scannedAt: new Date().toISOString(), disclaimer: 'Heuristic analysis cannot prove a transaction is safe.' };
  }

  async scanAddress(chain, address) {
    const url = this.rpcUrls[chain]; if (!url) throw new ScanError(`Chain '${chain}' is not configured`, 'CHAIN_NOT_CONFIGURED', 404);
    if (!isAddress(address)) throw new ScanError('Address is invalid', 'INVALID_ADDRESS', 400); const checksum = getAddress(address);
    const [code, balance, nonce, implementationRaw, adminRaw] = await Promise.all([
      this.rpc(url, 'eth_getCode', [checksum, 'latest']), this.rpc(url, 'eth_getBalance', [checksum, 'latest']), this.rpc(url, 'eth_getTransactionCount', [checksum, 'latest']),
      this.rpc(url, 'eth_getStorageAt', [checksum, IMPLEMENTATION_SLOT, 'latest']), this.rpc(url, 'eth_getStorageAt', [checksum, ADMIN_SLOT, 'latest'])
    ]);
    const isContract = Boolean(code && code !== '0x'); const implementation = storageAddress(implementationRaw); const admin = storageAddress(adminRaw); const findings = [];
    if (!isContract) findings.push(finding('info', 'EOA', 'No contract bytecode is currently deployed at this address'));
    if (implementation) findings.push(finding('medium', 'UPGRADEABLE_PROXY', 'EIP-1967 implementation slot is populated; contract behavior can depend on another address', { implementation }));
    if (admin) findings.push(finding('medium', 'PROXY_ADMIN', 'EIP-1967 admin slot is populated; an administrator may be able to upgrade the implementation', { admin }));
    return { chain, address: checksum, type: isContract ? 'contract' : 'externally-owned-or-empty', balanceWei: BigInt(balance).toString(), balance: formatEther(BigInt(balance)), nonce: Number(BigInt(nonce)), ...(isContract ? { bytecode: { bytes: (code.length - 2) / 2, keccak256: keccak256(code) } } : {}), proxy: { implementation, admin }, findings, risk: riskFrom(findings), scannedAt: new Date().toISOString() };
  }

  async rpc(url, method, params) {
    const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), this.timeout);
    try { const response = await this.fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: ++this.requestId, method, params }), signal: controller.signal }); if (!response.ok) throw new ScanError(`RPC returned HTTP ${response.status}`, 'RPC_HTTP', 502); const body = await response.json(); if (body.error) throw new ScanError(`RPC ${body.error.code}: ${body.error.message}`, 'RPC_ERROR', 502); return body.result; }
    catch (error) { if (error.name === 'AbortError') throw new ScanError(`RPC timed out after ${this.timeout}ms`, 'RPC_TIMEOUT', 504); throw error; } finally { clearTimeout(timer); }
  }
}

function storageAddress(value) { if (!value || /^0x0*$/.test(value)) return null; const candidate = `0x${value.slice(-40)}`; return isAddress(candidate) ? getAddress(candidate) : null; }
function serialize(value) { return Array.from(value, item => typeof item === 'bigint' ? item.toString() : item); }
module.exports = { EtherScanSecureService, ScanError, riskFrom, storageAddress, IMPLEMENTATION_SLOT, ADMIN_SLOT, COMMON_ABI };
