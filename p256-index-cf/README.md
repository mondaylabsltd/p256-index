# Cloudflare Workers shell

The same registry service as `p256-index-server`, deployed on Cloudflare
instead of docker compose. Every decision rule comes from the shared
`p256-registrar` crate (compiled to wasm unchanged); only the
infrastructure wiring differs:

| Docker shell | This shell |
| --- | --- |
| Axum HTTP server | stateless Worker at the edge (300+ locations) |
| Redis: tasks, idempotency, placeholders, counters, ledger | Durable Object SQLite (strongly consistent, single writer) |
| Redis: response cache | platform Cache API (per-datacenter, zero-provisioning) |
| Iggy: durable registration stream | Durable Object SQLite queue table |
| tokio consumer loop (`worker.rs`) | Durable Object alarm loop |
| tokio maintenance loop (`maintenance.rs`) | cron trigger (every minute) → the object's `/maintain` |
| reqwest RPC pool / Telegram | `fetch` RPC pool (same registrar `Roster`) / `fetch` Telegram |

## Where the guarantees live

- **No accepted write is ever lost.** A 202 is only returned after the
  task row and its queue envelope are durably in the Durable Object's
  SQLite (output gates). The alarm loop consumes envelopes only on
  `BatchVerdict::Advance` — the Iggy offset rule — and every failure path
  keeps the envelope for redelivery; reconciliation by content hash
  absorbs duplicates ("见链即完成"). Poison tasks quarantine to the DLQ
  table, never deleted.
- **The docker shell's two-phase admission collapses.** Redis admit →
  Iggy append → mark admitted becomes sequential synchronous SQLite
  statements inside one single-threaded object; the repair path for a
  half-admitted task is preserved unchanged in the registrar program.
- **One wallet, one writer.** The Durable Object is the only nonce user,
  which is the "only one writer may use a given PRIVATE_KEY" invariant by
  construction. Scaling writes later = more wallets = more objects.
- **Reads scale at the edge.** Proof verification and challenges run in
  the stateless Worker; cache hits are served from the datacenter's Cache
  API without touching the object or the RPC pool. Only pending-task
  lookups (the `_queue` marker) and cache-miss rate checks reach the
  object. The cache is per-datacenter by design (nothing to provision, so
  the repo deploys without editing tracked files); the cached envelope
  carries its own timestamps, so locality only lowers the hit rate on a
  cold datacenter — freshness, staleness and `_queue` semantics are
  identical everywhere, and the chain stays the source of truth.

## Deploy

`wrangler.toml` is deployment-neutral: no resource ids, no addresses.
Everything a deployment needs is injected once as secrets (the config
loader reads vars and secrets interchangeably, and `keep_vars = true`
keeps dashboard-set vars across deploys):

```sh
# Required:
npx wrangler secret put P256_INDEX_CONTRACT_ADDRESS   # the deployed registry

# Optional:
npx wrangler secret put PRIVATE_KEY                   # unset = read-only mode
npx wrangler secret put P256_INDEX_DOMAIN_REGISTRY    # only differs after a migration
npx wrangler secret put ALCHEMY_API_KEY               # write-lane RPC
npx wrangler secret put TELEGRAM_BOT_TOKEN            # operator alerts
npx wrangler secret put TELEGRAM_CHAT_ID

npx wrangler deploy
```

Non-sensitive tuning (`GLOBAL_WRITE_LIMIT`, `P256_INDEX_MAX_GAS_PRICE_WEI`,
`P256_INDEX_READ_RPCS`, `P256_INDEX_WRITE_RPCS`, `RELEASE`) can be set the
same way, or as plain vars in the dashboard.

Local development (`miniflare`: real SQLite-backed object + local cache):

```sh
cp .dev.vars.example .dev.vars   # or write the two addresses by hand
npx wrangler dev
```

## Verify

```sh
cargo check  --target wasm32-unknown-unknown
cargo clippy --target wasm32-unknown-unknown -- -D warnings
```

The crate is excluded from the root workspace on purpose: it only builds
for wasm32, and the native `cargo clippy/test --workspace` gates must not
acquire wasm dependencies. Behavioral coverage comes from the registrar's
own test suite (the programs driven here are identical) plus the smoke
flow: `/api/health`, `/api/challenge` (pinned vectors), `/api/query`,
`/api/stats/*`, and a full proven `/api/register` → 202 → idempotent
resubmit → `_queue` marker → `/api/task/{id}`.

## Maintenance

The docker shell's 60-second maintenance tick is a cron trigger: every
minute the scheduled handler calls the object's `/maintain`, which runs
the stuck-nonce unstick sweep (`rescue::plan_role_sweep` over the SQLite
ledger, same-nonce cancels priced by `gas::plan_replacement` against the
stuck row's own fee), the operator alerts (open RPC circuit, DLQ growth,
low funding runway — throttled via a SQLite `alerts` table, because the
object is evicted between ticks and an in-memory throttle would re-page
on every wake), and the daily Telegram heartbeat. Without a PRIVATE_KEY
the whole pass is a no-op, exactly like the docker shell.

## Not yet done

- The real on-chain write e2e (alarm → register tx → receipt → Done) has
  not been run: it needs the funded PRIVATE_KEY and spends gas — gated
  exactly like the docker repo's `P256_INDEX_E2E_CHAIN=1` test. Run one
  proven register against `wrangler dev` with the secret set in
  `.dev.vars` before pointing production traffic here.
