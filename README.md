# WebAuthn P256 Public Key Registry Service

A neutral, permissionless registry of P-256 passkey public keys: anyone may
store data about keys they hold, on Gnosis chain and in this service's
database. What a key is for — deriving a wallet, assembling an identity,
anything else — is entirely the storer's business, carried in an opaque
per-unit `metadata` payload. Built by Vela Wallet; Vela is the registry's
first client, not its owner.

## The trust model

- **The public key is the primary key, and possession is the only thing
  verified — on-chain.** Every stored entry requires a WebAuthn-formatted
  P-256 assertion by its own key over a storage-authorization challenge
  (`keccak256(abi.encode(chainid, registry, rpId, publicKey, unitNonce))`),
  verified by the contract via the EIP-7951/RIP-7212 precompile. Nobody can
  attach data to a key they do not hold.
- **Nothing else is exclusive or interpreted.** A key may appear in any
  number of registration units; queries return lists and readers filter by
  their own metadata schema. Credential ids, display names, wallet
  derivation preimages all live inside `metadata` (≤1024 bytes, opaque).
- **A registration unit** is 1..7 members sharing one rpId, one metadata
  payload and one single-use `unitNonce`, appended atomically in one
  `register` transaction. The nonce is consumed on-chain: every proof dies
  with its registration, and identical content registers only once.
- **Reads are list-shaped and id-stable.** Entry ids are sequential and
  immutable — clients that remember their entry ids read in O(1) forever.
  Discovery without local state: recover the two candidate keys from any
  live assertion signature and query both — only a held key can have
  entries, so at most one bucket is non-empty.

## Client flow

1. At flow start, pick a random 32-byte `unitNonce`
   (`POST /api/challenge` with an empty body suggests one).
2. For each passkey: `navigator.credentials.create()` (collect the public
   key), then one `navigator.credentials.get()` whose challenge is the
   member's storage-authorization challenge (`POST /api/challenge` with
   `{rpId, publicKey, unitNonce}` computes it, or compute it locally).
   Two prompts per key, any order, any device, independently.
3. `POST /api/register` with the unit. The service verifies every proof
   (pure Rust mirror of the contract check — invalid proofs never reach the
   chain), durably queues the unit (Redis + Iggy, two-phase), and the worker
   lands it in one `register` transaction. Poll `GET /api/task/{id}`.
4. Before the transaction lands, `GET /api/query?publicKey=` already answers
   with a `_queue` marker: data handed to this service is never invisible.

## Architecture

- The Cargo workspace has two crates: `p256-registrar` owns the business
  vocabulary and decision rules (task lifecycle, proof verification,
  admission, lookup/cache policy, submission state machine, gas policy,
  chain-error classification) and is deliberately I/O-free;
  `p256-index-server` is the shell that wires those rules to Axum, Redis,
  Iggy, Gnosis RPC and Telegram.
- Redis holds the response cache, rate limits, task status, the
  nonce-idempotency and per-key placeholders, queue-depth and DLQ
  projections, and the broadcast ledger.
- Iggy provides the durable registration stream (at-least-once, ordered);
  Redis admission and Iggy append are two-phase so a lost acknowledgement
  is safely re-enqueued and the consumer stays idempotent.
- The worker submits ONE unit per transaction (no batching, no
  commit-reveal, a single funded wallet): failures attribute to exactly one
  task; a reverted receipt reconciles by content hash and resends once to
  surface the revert reason for classification.
- Contract reads use a bounded Gnosis RPC failover pool; fresh cache hits
  never touch RPC; stale responses are served marked `_stale` during RPC
  outages.

## API

| Method | Route | Purpose |
| --- | --- | --- |
| POST | /api/register | Verify proofs and durably enqueue one unit (1..7 members) |
| GET | /api/task/{id} | Task status (full disclosure; no proofs echoed) |
| POST | /api/challenge | Compute a member's storage challenge; empty body suggests a unitNonce |
| GET | /api/query?publicKey= | Paginated entries for a key (`_queue` marker pre-chain) |
| GET | /api/query?entryId= | One entry by its immutable id |
| GET | /api/stats/total | {totalEntries, totalUnits, totalRpIds} |
| GET | /api/stats/sites | Paginated rpId list |
| GET | /api/stats/keys?rpId= | Paginated entries under an rpId |
| GET | /api/health | Health, RPC circuit, queue/DLQ metrics, registry address |

Register body shape:

~~~json
{
  "rpId": "example.com",
  "metadata": "0x…",
  "unitNonce": "0x…32 bytes…",
  "members": [{
    "publicKey": "04…65 bytes…",
    "attestation": "0x…20 bytes, optional…",
    "proof": {
      "authenticatorData": "…", "clientDataJSON": "…",
      "challengeIndex": 23, "typeIndex": 1, "r": "0x…", "s": "0x…"
    }
  }]
}
~~~

`attestation` is 20 versioned bytes of registration-time WebAuthn signals
(version, AAGUID, authData flags, attachment, transports) — shape-checked,
truthfulness is the storer's claim; display mapping is a client concern.

Conflicts: 409 only for unitNonce problems (a different unit on an in-flight
nonce, or a nonce already consumed on-chain — the proofs are void, re-enroll
with a fresh nonce). Identical content already on-chain answers 200 "done".

## Configuration

Copy .env.example to .env. Redis and Iggy are mandatory; the service fails
fast if it cannot reach either one. `P256_INDEX_CONTRACT_ADDRESS` (the
deployed registry) is always required.

~~~dotenv
P256_INDEX_IGGY_URL=iggy+tcp://user:password@iggy.example:5100?reconnection_retries=5&reconnection_interval=1s&reestablish_after=5s&heartbeat_interval=3s&nodelay=true
P256_INDEX_REDIS_URL=redis://redis.example:6379/0
P256_INDEX_CONTRACT_ADDRESS=0x…
PRIVATE_KEY=0x…
~~~

PRIVATE_KEY is optional only for read-only operation: without it the HTTP
API serves reads but the Iggy consumer is disabled and new tasks stay
pending. The service pays gas for all registrations; the per-IP (5/min) and
global create budgets are the cost gate.

## Contract

`contracts/src/WebAuthnP256PublicKeyRegistry.sol` — deployment requires a
chain with the P256VERIFY precompile (EIP-7951/RIP-7212) at 0x100 (live on
Gnosis; verify with the cast one-liner in
`contracts/script/DeployRegistry.s.sol` before deploying).

~~~sh
cd contracts && forge test
forge script script/DeployRegistry.s.sol --rpc-url $RPC --broadcast
~~~

Gas: a 1-member unit is ~0.7M gas, 7 members ~3.1M (linear per member).

## Run and verify

~~~sh
# From the repository root, so the p256-registrar crate is checked too.
cargo fmt --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo run --release -p p256-index-server
~~~

Gated integration tests (kept out of CI, which has no infrastructure):

~~~sh
# HTTP contract over real Redis:
P256_INDEX_TEST_REDIS_URL='redis://127.0.0.1:6379/0' \
  cargo test -p p256-index-server --lib -- --ignored http_contract

# HTTP + queue contract over real Redis and Iggy:
P256_INDEX_TEST_REDIS_URL='redis://127.0.0.1:6379/0' \
P256_INDEX_TEST_IGGY_URL='iggy+tcp://user:pass@127.0.0.1:5100' \
  cargo test --test e2e -- --ignored

# Full register -> chain -> confirmed (real Gnosis write, spends gas):
P256_INDEX_E2E_CHAIN=1 cargo test --lib -- --ignored \
  e2e_chain_tests::register_persists_on_chain_end_to_end
~~~

## Reliability and alerting

- Daily Telegram heartbeat (queue depth, DLQ, wallet balance, funding
  runway, uptime): a silent channel becomes a signal.
- Operator alerts for low funding runway, an open RPC read circuit, DLQ
  growth, and a nonce the unstick sweep cannot clear.
- Stuck-nonce unstick sweep with a Redis broadcast ledger and monotonic
  same-nonce replacement pricing.
- Exponential backoff on transient chain/RPC failures (5s → 15s → 45s …,
  clamped to 60s).
- Per-task poison quarantine: one unit per transaction means a
  deterministic revert isolates exactly one task into the DLQ.

Only one writer may use a given PRIVATE_KEY at a time. Set
TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID to enable alert delivery; RELEASE
adds a build tag to the heartbeat.
