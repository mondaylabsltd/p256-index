/**
 * Versioned, shared schema migrations — ONE numbered list for both runtimes
 * (SQLite on Deno, D1 on CF). Replaces the previous ad-hoc scheme (inline DDL
 * + PRAGMA-gated ALTERs on Deno only) that (a) could silently diverge between
 * runtimes and (b) re-ran the full-table dedupe UPDATE on every CF isolate
 * cold start in the request path.
 *
 * Rules:
 * - Migrations are append-only and IDEMPOTENT (they may run against a legacy
 *   database that already has the shape — e.g. a pre-versioning production DB
 *   starts at version 0 and must survive re-applying the baseline).
 * - A runtime applies every migration with version > its recorded version,
 *   in order, recording each. When the recorded version is current, apply()
 *   is two cheap statements (CREATE IF NOT EXISTS + one SELECT).
 */

import {
  CREATE_QUEUE_DDL,
  CREATE_ACTIVE_UNIQUE_INDEX,
  DEDUPE_ACTIVE_DUPLICATES_SQL,
} from "./queue.ts";

/** Minimal SQL surface both node:sqlite and D1 can provide. */
export interface SqlRunner {
  run(sql: string, params?: unknown[]): Promise<void>;
  /** Single-row scalar SELECT; undefined when no row. */
  scalar(sql: string): Promise<number | undefined>;
}

export interface Migration {
  version: number;
  name: string;
  apply(db: SqlRunner, now: number): Promise<void>;
}

/** ALTER TABLE ADD COLUMN, tolerating "duplicate column" on legacy DBs. */
async function addColumnIfMissing(db: SqlRunner, table: string, columnDdl: string): Promise<void> {
  try {
    await db.run(`ALTER TABLE ${table} ADD COLUMN ${columnDdl}`);
  } catch (err) {
    const msg = (err instanceof Error ? err.message : String(err)).toLowerCase();
    if (!msg.includes("duplicate column")) throw err;
  }
}

export const MIGRATIONS: Migration[] = [
  {
    version: 1,
    name: "baseline: create_queue + indexes + walletRef/retryAfter + active-unique dedupe + rate_limits",
    async apply(db, now) {
      await db.run(CREATE_QUEUE_DDL);
      await db.run("CREATE INDEX IF NOT EXISTS idx_queue_status ON create_queue(status)");
      await db.run("CREATE INDEX IF NOT EXISTS idx_queue_status_created ON create_queue(status, createdAt)");
      await db.run("CREATE INDEX IF NOT EXISTS idx_queue_rpid_credid ON create_queue(rpId, credentialId)");
      await db.run("CREATE INDEX IF NOT EXISTS idx_queue_created ON create_queue(createdAt)"); // global write-rate cap
      await addColumnIfMissing(db, "create_queue", "walletRef TEXT NOT NULL DEFAULT ''");
      await addColumnIfMissing(db, "create_queue", "retryAfter INTEGER NOT NULL DEFAULT 0");
      // Dedupe must run BEFORE the unique index can build on a DB that already
      // contains duplicate active rows (pre-fix behaviour).
      await db.run(DEDUPE_ACTIVE_DUPLICATES_SQL, [now]);
      await db.run(CREATE_ACTIVE_UNIQUE_INDEX);
      // Durable per-IP rate-limit hits (used by the CF runtime; the Deno
      // runtime keeps its in-memory limiter and simply never writes here —
      // one schema everywhere beats runtime-conditional DDL).
      await db.run(`
        CREATE TABLE IF NOT EXISTS rate_limits (
          ip_hash TEXT NOT NULL,
          timestamp INTEGER NOT NULL
        )
      `);
      await db.run("CREATE INDEX IF NOT EXISTS idx_rate_ip ON rate_limits(ip_hash, timestamp)");
    },
  },
  {
    version: 2,
    name: "pending_txs: broadcast ledger for the stuck-nonce unstick sweep",
    async apply(db) {
      // One row per in-flight broadcast (role, nonce). A row that outlives its
      // receipt wait marks a potentially STUCK tx: everything behind that nonce
      // is jammed and no create can complete — the engine's unstick sweep
      // checks the receipt and, if the tx is still absent, replaces it with a
      // same-nonce self-transfer at a bumped gas price (auto-unjam, no
      // developer intervention).
      await db.run(`
        CREATE TABLE IF NOT EXISTS pending_txs (
          role TEXT NOT NULL,
          nonce INTEGER NOT NULL,
          hash TEXT NOT NULL,
          sentAt INTEGER NOT NULL,
          attempts INTEGER NOT NULL DEFAULT 0,
          PRIMARY KEY (role, nonce)
        )
      `);
    },
  },
  {
    version: 3,
    name: "idx_queue_walletref: index for the query-by-walletRef queue fallback",
    async apply(db) {
      await db.run("CREATE INDEX IF NOT EXISTS idx_queue_walletref ON create_queue(walletRef)");
    },
  },
  {
    version: 4,
    name: "watchdog_state: cross-isolate state for the CF external-liveness watchdog",
    async apply(db) {
      // Tiny key/value store for the worker's every-minute VPS health probe
      // (consecutive failures, page/summary timestamps, down/up state).
      // Lives in D1 because scheduled() runs in ephemeral isolates. The Deno
      // runtime shares the schema but never writes here (one schema everywhere
      // beats runtime-conditional DDL — same rule as rate_limits).
      await db.run(`
        CREATE TABLE IF NOT EXISTS watchdog_state (
          k TEXT PRIMARY KEY,
          v TEXT NOT NULL
        )
      `);
    },
  },
];

export const LATEST_SCHEMA_VERSION = MIGRATIONS[MIGRATIONS.length - 1].version;

/**
 * Bring the database to the latest version. Cheap when already current:
 * one CREATE IF NOT EXISTS + one SELECT (important for CF isolate cold starts,
 * which run this in the request path).
 */
export async function runMigrations(db: SqlRunner, now: number): Promise<number> {
  await db.run("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, appliedAt INTEGER NOT NULL)");
  const current = (await db.scalar("SELECT MAX(version) FROM schema_migrations")) ?? 0;
  let applied = current;
  for (const m of MIGRATIONS) {
    if (m.version <= current) continue;
    // Every apply() is idempotent (CREATE IF NOT EXISTS / tolerated
    // duplicate-column / re-runnable dedupe), so two cold-start isolates racing
    // the SAME migration is safe — INSERT OR IGNORE lets the loser record a
    // no-op instead of throwing a PRIMARY KEY conflict out of initQueue (which
    // would 500 a create request). A concurrent isolate that already advanced
    // MAX(version) is fine too: re-applying is a no-op.
    await m.apply(db, now);
    await db.run("INSERT OR IGNORE INTO schema_migrations (version, appliedAt) VALUES (?, ?)", [m.version, now]);
    applied = m.version;
    console.log(`[migrations] applied v${m.version}: ${m.name}`);
  }
  return applied;
}
