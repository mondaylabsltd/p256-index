# WebAuthn P256 Public Key Index Service

A public key index service for WebAuthn P256 credentials. Data is stored on-chain via a smart contract (V2) on Gnosis Chain. This service acts as a read/write proxy, providing a REST API.

Contract source: [`contracts/`](contracts/) (Foundry; merged into this monorepo)

| Contract | Address (Gnosis Chain) |
|----------|----------------------|
| WebAuthnP256PublicKeyIndex | `0xdd93420BD49baaBdFF4A363DdD300622Ae87E9c3` |
| WebAuthnP256BatchHelper | `0xc7B0db5d4974abA3EA25780f40Bf369CC013a16E` |

Public endpoint: `https://webauthnp256-publickey-index.biubiu.tools`

- Runtime: Deno (self-hosted) or Cloudflare Workers (edge), two independent deployments
- Data source: On-chain contract on Gnosis (via viem, RPC round-robin + auto failover)
- Write path: Async queue (Deno: SQLite / CF: D1), background batch commit-reveal on-chain
- Batch on-chain: Via BatchHelper contract, single tx for multiple commit/createRecord calls
- Dual wallet: commit and createRecord use separate EOAs, independent nonce management
- Default port: 11256 (Deno) / N/A (CF Workers)
- CORS: Allow all origins

## API Reference

Base URL: `https://webauthnp256-publickey-index.biubiu.tools` (or your self-hosted address)

---

### GET /api/challenge

Get a random challenge. **Compatibility endpoint**: the service does not
require or verify possession of the P256 private key on create — the challenge
is not consumed anywhere server-side.

**Response** (200):
```json
{
  "challenge": "a1b2c3d4..."
}
```

---

### POST /api/create

Create a public key record. Returns 202 immediately; the on-chain commit-reveal process runs asynchronously in the background.

**Request body** (JSON):
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| rpId | string | Yes | Site domain (e.g. `example.com`) |
| credentialId | string | Yes | Credential ID |
| publicKey | string | Yes | P256 public key (hex, uncompressed with 04 prefix, 65 bytes) |
| name | string | Yes | Passkey display name |
| walletRef | string | No | Deterministic Safe address derived from publicKey (bytes32 hex). If provided it MUST equal the derived value — arbitrary values are rejected (identity-forgery guard) |
| initialCredentialId | string | No | Initial credential ID, defaults to credentialId (points to root credential during key rotation) |
| metadata | string | No | Additional metadata (hex), defaults to `abi.encode("VelaWalletV1", publicKey)` |

**Request example**:
```json
{
  "rpId": "example.com",
  "credentialId": "abc123",
  "publicKey": "04a1b2c3...",
  "name": "My MacBook"
}
```

**Response** (202 - Queued):
```json
{
  "id": "uuid",
  "status": "pending"
}
```

**Response** (201 - Already exists, idempotent):
```json
{
  "rpId": "example.com",
  "credentialId": "abc123",
  "walletRef": "0x000...abc",
  "publicKey": "04a1b2c3...",
  "name": "My MacBook",
  "status": "done"
}
```

**Response** (409 - walletRef conflict):
```json
{
  "error": "this publicKey is already registered under a different credential (walletRef conflict)",
  "walletRef": "0x000...abc"
}
```
The walletRef is derived from the publicKey alone (independent of rpId), so the
same P256 key can only ever be registered once. Registering the same passkey
under a second credential/site is rejected up-front — the on-chain write would
deterministically revert (`WalletRefAlreadyExists`). Resolve by creating a new
passkey, or look up the existing record with `GET /api/query?walletRef=...`.

**Error responses**:
- `400` - Missing/invalid parameters (incl. a publicKey that is not a real point on the P-256 curve, or a walletRef that does not match the derived one)
- `409` - The publicKey's walletRef is already registered (or actively being registered) under a different credential
- `413` - Body larger than 32KB
- `429` - Rate limit exceeded (5 creates per IP per minute)
- `503` - Backpressure (queue too deep) or global create cap reached — retry with backoff (`Retry-After` provided)

---

### GET /api/create/:id

Query the status of an async create task.

**Response - Complete** (200, status=done):
```json
{
  "id": "uuid",
  "status": "done",
  "rpId": "example.com",
  "credentialId": "abc123",
  "walletRef": "0x000...abc",
  "publicKey": "04a1b2c3...",
  "name": "My MacBook",
  "txHash": "0x...",
  "createdAt": 1711000000000
}
```

**Response - In progress** (200, status != done):
```json
{
  "id": "uuid",
  "status": "pending | committed",
  "rpId": "example.com",
  "publicKey": "04a1b2c3...",
  "name": "My MacBook",
  "createdAt": 1711000000000
}
```

> In-progress responses omit `credentialId` and `walletRef` to prevent front-running during the commit-reveal phase. Failed tasks include an `error` field.

Status machine: `pending → committed → done`. Failed tasks auto-retry up to 10 times with exponential backoff.

---

### GET /api/query

Query a public key record. Supports two query modes:

**Mode 1: By rpId + credentialId**

`GET /api/query?rpId=example.com&credentialId=abc123`

**Mode 2: By walletRef**

`GET /api/query?walletRef=0x000...abc`

**Success response** (200):
```json
{
  "rpId": "example.com",
  "credentialId": "abc123",
  "walletRef": "0x000...abc",
  "publicKey": "04a1b2c3...",
  "name": "My MacBook",
  "initialCredentialId": "abc123",
  "metadata": "0000...00",
  "createdAt": 1711000000000
}
```

If not found on-chain but in the queue (being submitted), partial data is returned with a `_queue` field (sensitive fields redacted to prevent front-running):
```json
{
  "rpId": "example.com",
  "publicKey": "04a1b2c3...",
  "name": "My MacBook",
  "metadata": "0000...00",
  "createdAt": 1711000000000,
  "_queue": { "id": "uuid", "status": "committed" }
}
```

**Error responses**:
- `400` - Missing parameters (need rpId+credentialId or walletRef)
- `404` - Not found

---

### GET /api/stats/total

Get total credential count across all sites.

**Response** (200):
```json
{
  "totalCredentials": 1234
}
```

---

### GET /api/stats/sites

Paginated list of all sites.

**Query parameters**:
| Param | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| page | number | No | 1 | Page number |
| pageSize | number | No | 20 | Items per page (max 100) |
| order | string | No | desc | Sort direction: `asc` or `desc` |

**Response** (200):
```json
{
  "total": 42,
  "page": 1,
  "pageSize": 20,
  "items": [
    { "rpId": "example.com", "publicKeyCount": 5, "createdAt": 1711000000000 }
  ]
}
```

---

### GET /api/stats/keys

Paginated list of public keys for a specific site.

**Query parameters**:
| Param | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| rpId | string | Yes | - | Site domain |
| page | number | No | 1 | Page number |
| pageSize | number | No | 20 | Items per page (max 100) |
| order | string | No | desc | Sort direction: `asc` or `desc` |

**Response** (200):
```json
{
  "total": 5,
  "page": 1,
  "pageSize": 20,
  "items": [
    {
      "rpId": "example.com",
      "credentialId": "abc123",
      "walletRef": "0x000...abc",
      "publicKey": "04a1b2c3...",
      "name": "My MacBook",
      "initialCredentialId": "abc123",
      "metadata": "0000...00",
      "createdAt": 1711000000000
    }
  ]
}
```

**Error response**: `400` - rpId missing

---

### GET /api/health

Health check.

**Response** (200):
```json
{
  "service": "webauthn-p256-publickey-index",
  "version": "1.0.0",
  "chainId": 100,
  "contract": "0xdd93420BD49baaBdFF4A363DdD300622Ae87E9c3",
  "rpcCircuit": "closed",
  "status": "ok",
  "queue": { "depth": 0, "dlq": 0, "oldestJobAgeMs": 0 }
}
```

`status` becomes `degraded` (with a `reasons` array: `queue-depth` / `dlq` /
`oldest-job` / `stats-unavailable`) when queue thresholds trip — the service is
still serving; route monitoring accordingly.

---

### GET /

Returns an HTML-rendered version of this documentation (GitHub style).

---

## Example Flow

```
1. POST /api/create                           → 202 { id, status: "pending" }
   Body: { rpId, credentialId, publicKey, name }
2. GET  /api/create/:id                       → { status: "done", txHash: "0x..." }
3. GET  /api/query?rpId=...&credentialId=...  → { publicKey, walletRef, ... }
   or GET /api/query?walletRef=0x...          → same
```

## Privacy & Compliance

- IP addresses are SHA-256 hashed before storage, cannot be reversed, GDPR compliant
- No user identity data collected, only public keys and site domains (public data)
- All data is immutable once on-chain (blockchain property), users should be aware

## Caching Strategy

Two-layer cache:
- Server-side in-memory cache: 5-minute TTL, 100MB limit, evicts oldest entries when full
- CDN cache: `Cache-Control: public, max-age=3600` (1 hour)

Rules:
- Only 200 responses are cached, 404s are not

## Project Structure

```
shared/                      Platform-agnostic shared code (imported by both runtimes)
  contract.ts                ABI, contract address, formatRecord, buildCommitment
  contract-read.ts           On-chain read operations (getPublicKey, listRpIds, etc.)
  queue.ts                   Types, constants, DDL, hashIp, wallet helpers, sendTelegram
  rpc.ts                     RPC round-robin + auto failover
  cache.ts                   In-memory cache (TTL + memory limit + eviction)
  validation.ts              Input length validation
  wallet-ref.ts              walletRef computation (P256 pubkey → Safe address → bytes32)
  routes/
    challenge.ts             GET /api/challenge
    stats.ts                 GET /api/stats/*

deno/                        Deno runtime specific
  index.ts                   Entry point (Deno.serve)
  config.ts                  Config (Deno.env + node:crypto)
  queue.ts                   SQLite queue + setInterval background worker
  nonce.ts                   Nonce management
  routes/
    query.ts                 GET /api/query
    create.ts                POST /api/create
  tests/                     Deno tests

worker/                      Cloudflare Worker runtime specific
  index.ts                   Entry point (fetch + scheduled)
  config.ts                  Config (crypto.subtle + env bindings)
  queue.ts                   D1 queue (async)
  nonce.ts                   Nonce management (config param injection)
  queue-processor.ts         Durable Object + alarm (replaces setInterval)
  types.ts                   CF environment type definitions
  routes/
    query.ts                 GET /api/query (async D1)
    create.ts                POST /api/create (async D1)
  tests/                     CF Worker tests

scripts/                     Deployment scripts
build.ts                     Build script (README → HTML + compile binary)
```

## Local Development

```bash
# Deno
deno task dev          # Hot-reload dev (auto-loads .env)
deno task test         # Offline suite (live-chain tests gated behind RUN_LIVE_TESTS / PRIVATE_KEY / RUN_PERF)

# Cloudflare Worker
npm install            # Install dependencies
npm test               # Run tests (vitest + miniflare)
npm run dev            # Local wrangler dev
```

## Deploy (Deno - Self-hosted Server)

Deploy to your server via `deno task deploy`, interactive target selection.

```bash
deno task deploy              # Deploy: select target → upload → health check
deno task deploy status       # Check remote service status
deno task deploy rollback     # Rollback to previous version
```

First deploy auto-provisions: install Deno → create user/directories → prompt .env config → install systemd service.

### Server Environment Variables

```env
PORT=11256
QUEUE_DB_PATH=/opt/webauthnp256-publickey-index/data/queue.db
PRIVATE_KEY=0x...            # 0x + 64 hex; startup fails fast otherwise
ALCHEMY_API_KEY=             # optional priority write RPC
TELEGRAM_BOT_TOKEN=          # strongly recommended: all operator alerts
TELEGRAM_CHAT_ID=
CACHE_MAX_MB=32              # optional
GLOBAL_WRITE_LIMIT=40        # optional: global creates/min cap
LOG_LEVEL=info               # optional: debug|info|warn|error
# QUEUE_WORKER=0             # dev only: disable on-chain processing
```

## Deploy (Cloudflare Workers)

```bash
npm install                                    # Install dependencies
npm run setup                                  # Auto-create D1 database, generate wrangler.json (idempotent)
npx wrangler secret put PRIVATE_KEY            # Set secrets
npx wrangler secret put TELEGRAM_BOT_TOKEN
npx wrangler secret put TELEGRAM_CHAT_ID
npx wrangler secret put ALCHEMY_API_KEY        # Optional: priority write RPC
npm run deploy                                 # Deploy
```

Queue processing uses Durable Object + Alarm (~10s interval), with a Cron Trigger (every minute) as backup to ensure the DO alarm is running.
