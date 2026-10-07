# EtherScanSecure

[![CI](https://github.com/centxyz/EtherScanSecure/actions/workflows/ci.yml/badge.svg)](https://github.com/centxyz/EtherScanSecure/actions/workflows/ci.yml)

EtherScanSecure is a pre-signing Ethereum safety scanner API. It decodes common ERC-20, ERC-721, and permit calls, highlights risky approvals and value-bearing contract calls, and inspects addresses through configured EVM RPC endpoints for bytecode, balance, nonce, and EIP-1967 upgradeability slots.

It is independent of Etherscan, does not require an explorer API key, and never signs or broadcasts transactions.

## Configure and run

```bash
git clone https://github.com/centxyz/EtherScanSecure.git
cd EtherScanSecure
npm install

export RPC_URLS='{"ethereum":"https://your-ethereum-rpc.example"}'
npm start
```

## Scan before signing

```bash
curl -X POST http://localhost:3000/api/v1/scan/transaction \
  -H 'content-type: application/json' \
  -d '{"chainId":1,"to":"0x...","data":"0x...","value":"0"}'
```

The response contains normalized transaction fields, decoded intent when recognized, explainable findings, and a deterministic risk level. Detectors cover token allowances (including near-unlimited approvals), collection-wide NFT operators, transfers, permits, unknown selectors, missing chain IDs, and native value attached to calldata.

Inspect an address:

```bash
curl http://localhost:3000/api/v1/scan/address/ethereum/0xADDRESS
```

Address results include the checksummed address, native balance, nonce, bytecode size/hash, and populated EIP-1967 implementation/admin slots.

## Security boundary

The scanner is heuristic. A low score is not proof of safety; malicious behavior can hide behind proxies, fallback functions, delegate calls, or legitimate-looking selectors. Verify the chain, destination, decoded arguments, and trusted project documentation before signing. RPC URLs are operator-configured and never supplied by API callers.

## Verify

```bash
npm test
```

## License

MIT © cent

## Current limitations

- Findings are heuristics and cannot prove that a transaction or contract is safe.
- RPC responses and proxy-slot inspection depend on the configured node and supported contract patterns.
- The service does not simulate every execution path, sign transactions, or replace an audit.
