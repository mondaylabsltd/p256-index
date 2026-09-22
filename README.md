# WebAuthn P256 Public Key Registry Service

A neutral, permissionless registry of P-256 passkey public keys: anyone may
store data about keys they hold, on Gnosis chain and in this service's
database. What a key is for — deriving a wallet, assembling an identity,
anything else — is entirely the storer's business, carried in an opaque
per-unit `metadata` payload. Built by Vela Wallet; Vela is the registry's
first client, not its owner.

## The trust model

- **Three plain tables, two writes.** ENTRY is the global file of one
  passkey (one row per key, ever; attestation fixed at first sight, signed
  by the key itself). UNIT is one group (one row per single-use group key;
  rpId, metadata and the member set frozen at creation — a group's members
  can never change, and there is deliberately no operation that could
  change them). REFERENCE is one passkey pointing at one existing group —
  its own table, its own counters, never mixed with groups.
- **Possession and content are what is verified — on-chain.** Every signer
  produces a WebAuthn-formatted P-256 assertion over
  `keccak256(abi.encode(chainid, registry, rpId, publicKey, binding))`,
  verified via the EIP-7951/RIP-7212 precompile. The binding depends on the
  role: the GROUP KEY signs the group's contentHash; a MEMBER passkey signs
  `memberBindingFor(groupKey, ownAttestation)`; a REFERRING passkey signs
  `referenceBindingFor(groupKey, ownAttestation, referenceMetadata)`.
  Every byte is signature-covered: nobody can attach data to a key they do
  not hold, and nobody can alter any field — front-running, replay and
  content substitution do not exist at the protocol level.
- **Nothing else is exclusive or interpreted.** A key may appear in any
  number of registration units; queries return lists and readers filter by
  their own metadata schema. Credential ids, display names, wallet
  derivation preimages all live inside `metadata` (≤2048 bytes, opaque).
- **`register`** lands one group atomically (7 passkeys = 8 signatures in
  one transaction). The group key is a client-held one-time software key —
  it closes the group silently, no ceremony, and is discarded after.
  Member passkeys sign the moment they are created: any order, any device,
  no waiting. **`refer`** points one passkey at an existing group — the
  later-added-device flow: pure discovery data, one reference per (group,
  key) pair, the group's frozen record untouched. References are claims,
  not authority: what a referenced key may do is decided by the reader's
  schema against the wallet layer. There is no nonce and nothing
  consumable; every write is idempotent by construction.
- **Statistics are structural.** Entries are globally unique and group
  keys single-use, so `getTotalEntries()` IS the passkey count,
  `getTotalUnits()` IS the group count, and `getTotalReferences()` counts
  references apart — no dedup logic anywhere.
- **Reads are list-shaped and id-stable.** Entry ids are sequential and
  immutable — clients that remember their entry ids read in O(1) forever.
  Discovery without local state: recover the two candidate keys from any
  live assertion signature and query both — only a held key can have
  entries, so at most one bucket is non-empty.

## Client flow

1. At enrollment start the client generates a one-time software P-256
   group key. For each passkey: `navigator.credentials.create()` (collect
   the public key), then one `navigator.credentials.get()` whose challenge
   is the member-binding challenge (`POST /api/challenge` member mode:
   `{rpId, groupPublicKey, publicKey, attestation?}`) — it depends only on
   the group key and the member's own fields, so any order, any device, no
   waiting. Two prompts per key.
2. Once every key exists, the group key silently signs the closing
   challenge (`POST /api/challenge` group mode returns the contentHash and
   the group challenge) and the client submits `POST /api/register` in one
   shot. The group key is then discarded forever.
3. Adding a device later: the new passkey does create + one get() over the
   reference-binding challenge (`POST /api/challenge` with `"refer": true`)
   and the client submits `POST /api/refer` — the group is never touched.
   Discovery at login: recover the candidate keys from the signature,
   `GET /api/query?publicKey=` returns the key's file plus its group and
   reference ids.
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
  content-hash idempotency and per-key placeholders, queue-depth and DLQ
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
| POST | /api/register | Verify proofs and durably enqueue one group (1..7 members) |
| POST | /api/refer | Verify the proof and durably enqueue one reference |
| GET | /api/task/{id} | Task status (full disclosure; no proofs echoed) |
| POST | /api/challenge | Member / reference / group modes: the binding challenge for each signing role |
| GET | /api/query?publicKey= | The key's file + its group/reference ids (`_queue` marker pre-chain) |
| GET | /api/query?entryId= | One passkey file by its immutable id |
| GET | /api/query?groupPublicKey= | Group detail: frozen record + member files + reference inbox (`_queue` marker pre-chain) |
| GET | /api/query?unitId= | The same group detail by its immutable id |
| GET | /api/stats/total | {totalEntries, totalUnits, totalReferences, totalRpIds} |
| GET | /api/stats/sites | Paginated rpId list |
| GET | /api/stats/keys?rpId= | Paginated groups under an rpId |
| GET | /api/health | Health, RPC circuit, queue/DLQ metrics, registry address |

Register body shape:

~~~json
{
  "rpId": "example.com",
  "metadata": "0x…",
  "groupPublicKey": "04…65 bytes…",
  "groupProof": { "authenticatorData": "…", "clientDataJSON": "…",
                  "challengeIndex": 23, "typeIndex": 1, "r": "0x…", "s": "0x…" },
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

There is no 409: the content hash is the unit's identity, resubmitting the
same unit is idempotent, and different units never collide. Identical
content already on-chain answers 200 "done".

## Configuration

Copy .env.example to .env. Redis and Iggy are mandatory; the service fails
fast if it cannot reach either one. `P256_INDEX_CONTRACT_ADDRESS` (the
deployed registry) is always required — there is no compiled-in default, so
the server exits at boot without it.

~~~dotenv
P256_INDEX_IGGY_URL=iggy+tcp://user:password@iggy.example:5100?reconnection_retries=5&reconnection_interval=1s&reestablish_after=5s&heartbeat_interval=3s&nodelay=true
P256_INDEX_REDIS_URL=redis://redis.example:6379/0
P256_INDEX_CONTRACT_ADDRESS=0x…
P256_INDEX_DOMAIN_REGISTRY=0x…
PRIVATE_KEY=0x…
~~~

`P256_INDEX_DOMAIN_REGISTRY` is the frozen signature domain, and it is not
the same thing as the contract address. From registry VERSION 12 the
challenge domain is baked in at deployment: a migration deployment is read
and written at `P256_INDEX_CONTRACT_ADDRESS`, while every challenge keeps
binding the **original** registry's address, so this value must equal the
deployed contract's `DOMAIN_REGISTRY`. It defaults to
`P256_INDEX_CONTRACT_ADDRESS`, which is correct only for a registry that has
never been migrated. Vela's Gnosis deployment is past the V13 cutover, so
both are set explicitly (`.env.example` carries the live pair, and
`/api/health` reports `registry` and `domainRegistry` so a mismatch is
visible before it costs a registration).

PRIVATE_KEY is optional only for read-only operation: without it the HTTP
API serves reads but the Iggy consumer is disabled and new tasks stay
pending. The service pays gas for all registrations; the per-IP (5/min) and
global create budgets are the cost gate.

## Docker

Compose starts only this service; Redis and Iggy stay external. The build
context is the repository root, because the server is one member of a
three-member Cargo workspace.

~~~sh
cp .env.example p256-index-server/.env   # then fill it in
docker compose up --build -d
curl --fail --silent http://127.0.0.1:11256/api/health
~~~

That `.env` path is what `docker-compose.yaml` reads, and it is gitignored.
The compose file marks it optional so a fresh clone can still build and
`docker compose config`, but the server will exit at boot without the
required values above. When Redis or Iggy runs on the Docker host, use
`host.docker.internal` in their URLs instead of `127.0.0.1`.

## Contract

`contracts/src/WebAuthnP256PublicKeyRegistry.sol` — deployment requires a
chain with the P256VERIFY precompile (EIP-7951/RIP-7212) at 0x100 (live on
Gnosis; verify with the cast one-liner in
`contracts/script/DeployRegistry.s.sol` before deploying).

~~~sh
cd contracts && forge test
forge script script/DeployRegistry.s.sol --rpc-url $RPC --broadcast
~~~

Gas: a group + 1 member is ~1.1M gas, group + 7 members ~3.6M (linear per member).

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

## License

MIT — see [LICENSE](LICENSE). The contracts in `contracts/src` carry the same
SPDX identifier. The submodules under `contracts/lib` (forge-std, p256-verifier)
keep their own licences.
