# WebAuthn P256 Public Key Index Service

The WebAuthn P256 Public Key Index is a REST service for the Gnosis-chain V2
contract. It is now a single Rust service; the Deno runtime and Cloudflare
Worker implementation have been removed.

| Contract | Gnosis address |
| --- | --- |
| WebAuthnP256PublicKeyIndex | 0xdd93420BD49baaBdFF4A363DdD300622Ae87E9c3 |
| WebAuthnP256BatchHelper | 0xc7B0db5d4974abA3EA25780f40Bf369CC013a16E |

## Architecture

- Rust/Axum provides the public API on port 11256 by default.
- Redis holds the shared response cache, rate limits, task status, duplicate
  indexes, queue-depth projection, and DLQ projection.
- Iggy provides the durable p256-index / create stream. A shared consumer
  group supplies ordered, at-least-once processing.
- The consumer first persists the task in Redis, then processes batch
  commit-reveal calls through WebAuthnP256BatchHelper.
- Redis admission and Iggy append are intentionally two-phase: if an Iggy
  acknowledgement is lost, the same task ID can safely be re-enqueued and the
  consumer remains idempotent.
- Contract reads use a bounded Gnosis RPC failover pool; fresh Redis cache hits
  do not contact RPC providers.

POST /api/create retains the public contract: it returns 202 with
{ id, status: "pending" }, status reads redact pre-reveal sensitive fields,
and an existing on-chain record returns 201 with status "done".

## Configuration

Copy .env.example to .env. Redis and Iggy are mandatory; the service fails fast
if it cannot reach either one.

~~~dotenv
P256_INDEX_IGGY_URL=iggy+tcp://user:password@iggy.example:5100?reconnection_retries=5&reconnection_interval=1s&reestablish_after=5s&heartbeat_interval=3s&nodelay=true
P256_INDEX_REDIS_URL=redis://redis.example:6379/0
PRIVATE_KEY=0x...
~~~

PRIVATE_KEY is optional only for read-only operation. When it is absent, the
HTTP API starts but the Iggy consumer is disabled, so newly created tasks remain
pending. The commit wallet is deterministically derived as
SHA-256(PRIVATE_KEY bytes) to keep the established on-chain behavior.

Iggy creates this topology on first startup (the provisioner identity needs
permission to create it):

| Resource | Name |
| --- | --- |
| stream | p256-index |
| topic | create |
| partitions | 1 |
| consumer group | p256-index-server-v1 |

Use a separate, least-privilege consumer/provisioner Iggy identity in
production through P256_INDEX_IGGY_CONSUMER_URL and
P256_INDEX_IGGY_PROVISIONER_URL.

## Run and verify

~~~sh
cd p256-index-server
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo run --release
~~~

The Rust binary loads a local .env for development and uses regular process
environment variables in systemd/container deployments.

## API compatibility

The following routes and JSON field names are retained:

| Method | Route | Purpose |
| --- | --- | --- |
| GET | /api/challenge | Base64url random challenge |
| POST | /api/create | Validate and durably enqueue a public-key registration |
| GET | /api/create/:id | Registration status; redacts unrevealed fields |
| GET | /api/query?rpId=&credentialId= | Query a record by credential |
| GET | /api/query?walletRef= | Query a record by deterministic wallet reference |
| GET | /api/stats/total | Total credential count |
| GET | /api/stats/sites | Paginated site list |
| GET | /api/stats/keys?rpId= | Paginated key list for a site |
| GET | /api/health | Health, RPC circuit, and queue/DLQ metrics |

The service preserves CORS support (GET, POST, OPTIONS), request-body and
P-256 validation, walletRef binding, 5/minute per-IP creates, global create
budgeting, read limiting for cache misses, stale cache responses during RPC
outages, and the pending → committed → done | failed status machine.

## Reliability and alerting

The queue worker runs alongside a maintenance loop that ports the operational
safety net of the retired Deno/CF-Worker service:

- Daily heartbeat to Telegram (queue depth, DLQ, create/commit wallet balances,
  funding runway, uptime): a silent channel becomes a signal.
- Operator alerts for the failure modes that otherwise fail silently — low
  create-wallet funding runway, an open RPC read circuit, DLQ growth, and a
  nonce the unstick sweep cannot clear.
- Stuck-nonce unstick sweep: a broadcast whose receipt never arrives jams the
  wallet nonce and stalls every later send. The sweep records each in-flight tx
  in a Redis broadcast ledger and replaces a genuinely stuck one with a
  same-nonce, zero-value self-transfer at 150% gas.
- Exponential backoff on transient chain/RPC failures (5s → 15s → 45s …, clamped
  to 60s) instead of hammering a failing dependency.
- Commit-batch poison isolation: a deterministically-reverting commitment is
  quarantined individually so innocent items still make progress.

Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID to enable delivery; without them the
alerts are logged instead. Set RELEASE to include a build tag in the heartbeat.
The daily heartbeat doubles as a liveness signal: if it stops arriving, the
process, its chain reads, or the Telegram path is broken.

## End-to-end tests

Contract- and chain-level parity with the retired implementations is covered by
gated integration tests (kept out of CI, which has no infrastructure):

~~~sh
# HTTP + queue contract against real Redis and Iggy:
P256_INDEX_TEST_REDIS_URL='redis://127.0.0.1:6379/0' \
P256_INDEX_TEST_IGGY_URL='iggy+tcp://user:pass@127.0.0.1:5100' \
  cargo test --test e2e -- --ignored

# Full create -> chain -> confirmed path (real Gnosis write, spends gas):
P256_INDEX_E2E_CHAIN=1 cargo test --lib -- --ignored \
  e2e_chain_tests::create_persists_on_chain_end_to_end
~~~

## Cutover

This change deliberately has no SQLite, D1, Deno, or Cloudflare Worker
compatibility layer. Before production cutover, stop every legacy writer using
the existing PRIVATE_KEY to avoid nonce contention; preserve its old queue file
only as an audit artifact. Start the Rust service with Redis and Iggy, then
confirm /api/health and a read-only query before enabling writes.

## Deployment

Build a release binary for the target architecture and install it as
/opt/webauthnp256-publickey-index/current/p256-index-server. The supplied
systemd unit reads /opt/webauthnp256-publickey-index/data/.env; it does not
install or invoke Deno, Node, npm, Wrangler, SQLite, or Cloudflare services.

Tagged releases (push a v* tag) also publish per-platform binary archives and a
multi-arch Docker image via .github/workflows/release.yml. The Docker jobs need
the repository variable DOCKERHUB_USERNAME and secret DOCKERHUB_TOKEN.

## Docker / Compose

The service alone runs in a container (Redis and Iggy stay external, as with the
prior deployments). compose.yaml builds p256-index-server/Dockerfile and reads
p256-index-server/.env:

~~~sh
docker compose up --build
~~~

When Redis and Iggy run on the Docker host, point P256_INDEX_REDIS_URL and
P256_INDEX_IGGY_URL at host.docker.internal (see the note in compose.yaml).
