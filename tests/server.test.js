const test = require('node:test'); const assert = require('node:assert/strict'); const request = require('supertest'); const { Interface, MaxUint256 } = require('ethers');
const { EtherScanSecureService, COMMON_ABI, IMPLEMENTATION_SLOT } = require('../src/services/etherscansecure-service'); const { Server } = require('../src/server');
const iface = new Interface(COMMON_ABI); const target = '0x0000000000000000000000000000000000001000'; const spender = '0x0000000000000000000000000000000000002000';
test('detects unlimited approvals and preserves decoded intent', () => {
  const service = new EtherScanSecureService(); const result = service.scanTransaction({ to: target, chainId: 1, data: iface.encodeFunctionData('approve', [spender, MaxUint256]), value: '0' });
  assert.equal(result.decoded.name, 'approve'); assert.equal(result.findings[0].code, 'UNLIMITED_ALLOWANCE'); assert.equal(result.risk.level, 'high');
});
test('recognizes revocations, NFT operators, unknown calldata, and value calls', () => {
  const service = new EtherScanSecureService();
  assert.equal(service.scanTransaction({ to: target, chainId: 1, data: iface.encodeFunctionData('approve', [spender, 0]) }).findings[0].severity, 'info');
  assert.equal(service.scanTransaction({ to: target, chainId: 1, data: iface.encodeFunctionData('setApprovalForAll', [spender, true]) }).findings[0].code, 'NFT_OPERATOR_APPROVAL');
  const unknown = service.scanTransaction({ to: target, data: '0x12345678', value: '10' }); assert.ok(unknown.findings.some(item => item.code === 'UNKNOWN_CALLDATA')); assert.ok(unknown.findings.some(item => item.code === 'VALUE_WITH_CALLDATA'));
});
test('inspects live address fields and EIP-1967 slots through RPC', async () => {
  const implementation = '0000000000000000000000000000000000000000000000000000000000003000';
  const fetchImpl = async (_url, options) => { const body = JSON.parse(options.body); const result = body.method === 'eth_getCode' ? '0x60006000' : body.method === 'eth_getBalance' ? '0xde0b6b3a7640000' : body.method === 'eth_getTransactionCount' ? '0x2' : body.params[1] === IMPLEMENTATION_SLOT ? `0x${implementation}` : `0x${'0'.repeat(64)}`; return { ok: true, json: async () => ({ result }) }; };
  const service = new EtherScanSecureService({ rpcUrls: { ethereum: 'https://rpc.test' }, fetchImpl }); const result = await service.scanAddress('ethereum', target);
  assert.equal(result.type, 'contract'); assert.equal(result.balance, '1.0'); assert.equal(result.nonce, 2); assert.equal(result.proxy.implementation.toLowerCase(), '0x0000000000000000000000000000000000003000'); assert.equal(result.findings[0].code, 'UPGRADEABLE_PROXY');
});
test('serves transaction scans and structured validation errors', async () => {
  const app = new Server({ service: new EtherScanSecureService() }).app;
  const scan = await request(app).post('/api/v1/scan/transaction').send({ to: target, data: iface.encodeFunctionData('approve', [spender, MaxUint256]), chainId: 1 }); assert.equal(scan.status, 200); assert.equal(scan.body.risk.level, 'high');
  const bad = await request(app).post('/api/v1/scan/transaction').send({ to: 'bad' }); assert.equal(bad.status, 400); assert.equal(bad.body.code, 'INVALID_ADDRESS');
});
