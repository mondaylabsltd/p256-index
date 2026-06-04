# WebAuthnP256PublicKeyIndex

On-chain registry for WebAuthn P256 passkey public keys. Append-only, first come first served.

Built by [Vela Wallet](https://getvela.app).

## Quick start

```shell
forge build   # compile
forge test    # run tests
```

## How it works

Two-step commit-reveal to prevent front-running:

1. `commit(keccak256(abi.encode(rpId, credentialId, walletRef, publicKey, name, initialCredentialId, metadata)))`
2. Wait 1 block
3. `createRecord(rpId, credentialId, walletRef, publicKey, name, initialCredentialId, metadata)`

No signature verification — pure storage index. The contract validates that `publicKey` is an uncompressed P-256 curve point. Pass normalized `rpId` (lowercase, punycode) to avoid duplicates.

`walletRef` is a globally unique cross-chain wallet identifier. For EVM addresses, use `bytes32(uint256(uint160(addr)))`. For 32-byte addresses, use the value directly. For longer address formats, use `keccak256`.

## Key rotation

- **Initial key**: `initialCredentialId = credentialId`
- **Rotated key**: `initialCredentialId` = an existing root credential under the same `rpId`

Every key traces directly back to the origin credential.

## Contract interface

### Write

| Function | Description |
|---|---|
| `commit(bytes32)` | Submit commitment hash |
| `createRecord(rpId, credentialId, walletRef, publicKey, name, initialCredentialId, metadata)` | Register a passkey (requires prior commit) |

### Batch helper (WebAuthnP256BatchHelper)

A separate stateless contract for batching multiple operations into a single transaction:

| Function | Description |
|---|---|
| `batchCommit(index, bytes32[])` | Batch commit N commitments in one tx |
| `batchCreateRecord(index, CreateParams[])` | Batch create N records in one tx |

Batch operations are atomic — if any record fails, the entire batch reverts.

### Read — single record

| Function | Description |
|---|---|
| `getRecord(rpId, credentialId)` → `PublicKeyRecord` | Get a record (reverts if not found) |
| `getRecordByWalletRef(walletRef)` → `PublicKeyRecord` | Get a record by wallet reference (reverts if not found) |
| `hasRecord(rpId, credentialId)` → `bool` | Check existence |
| `getCommitBlock(bytes32)` → `uint256` | Return the commit block, or 0 if not committed |

### Read — enumeration (paginated, sortable)

| Function | Description |
|---|---|
| `getTotalRpIds()` → `uint256` | Total distinct sites |
| `getTotalCredentials()` → `uint256` | Total credentials across all rpIds |
| `getTotalCredentialsByRpId(rpId)` → `uint256` | Credential count under an rpId |
| `getRpIds(offset, limit, desc)` → `(total, rpIds[], counts[], createdAts[])` | List all sites with pagination |
| `getKeysByRpId(rpId, offset, limit, desc)` → `(total, PublicKeyRecord[])` | List all keys under a site |

Pagination: `offset` = items to skip, `limit` = max items. `desc = true` for newest first.

> All read functions are `view` — free to call (no gas cost).

## PublicKeyRecord

| Field | Type | Description |
|---|---|---|
| `rpId` | `string` | Relying Party domain |
| `credentialId` | `string` | WebAuthn credential ID |
| `walletRef` | `bytes32` | Globally unique cross-chain wallet identifier |
| `publicKey` | `bytes` | Uncompressed P256 key (65 bytes: `04 \|\| x \|\| y`) |
| `name` | `string` | Human-readable label (max 256 bytes) |
| `initialCredentialId` | `string` | Root credential this key traces to |
| `metadata` | `bytes` | Caller-defined data (max 1024 bytes) |
| `createdAt` | `uint256` | `block.timestamp` (seconds) |

## Deployment

| Version | Address | Networks |
|---|---|---|
| v2 | `0xdd93420BD49baaBdFF4A363DdD300622Ae87E9c3` | Gnosis (CREATE2, salt=0) |
| v1 (legacy) | `0xc1f7Ef155a0ee1B48edbbB5195608e336ae6542b` | Gnosis |

Deployed via CREATE2 ([Deterministic Deployment Proxy](https://github.com/Arachnid/deterministic-deployment-proxy)) for consistent address across chains.

The easiest way to deploy is via [biubiu.tools Contract Deployer](https://biubiu.tools/apps/contract-deployer) — paste the bytecode, pick a chain, and deploy with your browser wallet. No CLI or private key export needed.

Or deploy via Foundry:

```shell
forge script script/Deploy.s.sol --rpc-url <RPC_URL> --broadcast --private-key <KEY>
```

## v2 vs v1

Current source is `VERSION = 2`. v1 is deployed on Gnosis at [`0xc1f7Ef155a0ee1B48edbbB5195608e336ae6542b`](https://gnosisscan.io/address/0xc1f7Ef155a0ee1B48edbbB5195608e336ae6542b).

### What changed in v2

| Area | v1 | v2 |
|---|---|---|
| Public key validation | Length + `0x04` prefix only | Full P-256 curve point verification (`y² = x³ - 3x + b mod p`) |
| `walletRef` | Not supported | Required globally unique `bytes32` cross-chain wallet reference |
| Record existence check | `createdAt != 0` | `rpId.length != 0` — correct even when `block.timestamp == 0` |
| Commit storage | `block.number` | Internal `block.number + 1` sentinel; `getCommitBlock()` returns the real commit block, and repeated commits do not overwrite the first commit block |
| `getTotalCredentials()` | Not available | Global credential counter |
| `getTotalCredentialsByRpId()` | Named `getRpCount()` | Renamed for clarity |
| `getRecordByWalletRef()` | Not available | Query record by wallet address |
| `getCommitBlock()` | Not available | Check if a commitment exists before submitting |
| Event `RecordCreated` | 2 indexed fields (`key`, `rpIdHash`) | 3 indexed fields (`key`, `rpIdHash`, `walletRef`) |
| Solidity version | `^0.8.20` | `0.8.28` pinned, `paris` EVM target |

### Migrating data from v1

Use the migration script to replay all v1 records into the v2 contract:

```shell
# Phase 1: commit all records
PRIVATE_KEY=0x... CONTRACT_ADDRESS=0x... PHASE=commit bun run script/migrate.ts

# Wait 1 block

# Phase 2: reveal all records
PRIVATE_KEY=0x... CONTRACT_ADDRESS=0x... PHASE=reveal bun run script/migrate.ts
```

The script fetches all existing records from the v1 API, adds `walletRef` and `metadata`, and writes them to the new contract via commit-reveal. Records that already exist on-chain are automatically skipped (idempotent).

## API service

A companion open-source backend is available at [webauthnp256-publickey-index.biubiu.tools](https://webauthnp256-publickey-index.biubiu.tools/). It indexes on-chain events and exposes a REST API for querying records without direct RPC calls:

| Endpoint | Description |
|---|---|
| `GET /api/query?rpId=...&credentialId=...` | Query a single record |
| `GET /api/stats/sites?page=1&pageSize=20&order=desc` | List all sites (paginated) |
| `GET /api/stats/keys?rpId=...&page=1&pageSize=20&order=desc` | List all keys under a site (paginated) |

The API mirrors the on-chain view functions but returns JSON with millisecond timestamps for web compatibility. Source code: [atshelchin/webauthnp256-publickey-index.biubiu.tools](https://github.com/atshelchin/webauthnp256-publickey-index.biubiu.tools).

## License

MIT
