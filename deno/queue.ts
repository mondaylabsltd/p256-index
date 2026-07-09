import { DatabaseSync as Database } from "node:sqlite";
import { getConfig } from "./config.ts";
import { acquireNonce } from "./nonce.ts";
import {
  type QueueStatus,
  type QueueItem,
  type AppConfig,
  RATE_WINDOW,
  DEFAULT_RATE_LIMIT,
  WORKER_INTERVAL,
  MAX_GAS_PRICE_GWEI,
  GAS_BALANCE_THRESHOLD,
  FUND_THRESHOLD,
  FUND_AMOUNT,
  CREATE_QUEUE_DDL,
  CREATE_ACTIVE_UNIQUE_INDEX,
  DEDUPE_ACTIVE_DUPLICATES_SQL,
  GLOBAL_WRITE_WINDOW,
  DEFAULT_GLOBAL_WRITE_LIMIT,
  isUniqueConstraintError,
  hashIp,
  getCreateWallet,
  getCommitWallet,
  sendTelegram,
} from "../shared/queue.ts";
import { runQueueCycle, type QueueStore } from "../shared/queue-engine.ts";
import { createViemChainOps } from "../shared/chain-viem.ts";
import { log, redactSecrets } from "../shared/log.ts";
import type { QueueStats } from "../shared/routes/health.ts";

export type { QueueStatus, QueueItem };

// --- Rate Limiting ---

let RATE_LIMIT = DEFAULT_RATE_LIMIT;

/** Override rate limit (for testing only). */
export function _setRateLimitForTest(limit: number): void {
  RATE_LIMIT = limit;
}
const ipRequests = new Map<string, number[]>();

export async function checkRateLimit(ip: string): Promise<boolean> {
  const hashed = await hashIp(ip);
  const now = Date.now();
  const timestamps = ipRequests.get(hashed) ?? [];
  const recent = timestamps.filter((t) => now - t < RATE_WINDOW);
  if (recent.length >= RATE_LIMIT) return false;
  recent.push(now);
  ipRequests.set(hashed, recent);
  return true;
}

// Cleanup stale IP entries every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [ip, timestamps] of ipRequests) {
    const recent = timestamps.filter((t) => now - t < RATE_WINDOW);
    if (recent.length === 0) ipRequests.delete(ip);
    else ipRequests.set(ip, recent);
  }
}, 5 * 60_000);

// --- SQLite Queue ---

let db: Database;

export function initQueue(dbPath = "queue.db") {
  db = new Database(dbPath);
  db.exec("PRAGMA journal_mode = WAL");
  db.exec(CREATE_QUEUE_DDL);
  db.exec("CREATE INDEX IF NOT EXISTS idx_queue_status ON create_queue(status)");
  db.exec("CREATE INDEX IF NOT EXISTS idx_queue_status_created ON create_queue(status, createdAt)");
  db.exec("CREATE INDEX IF NOT EXISTS idx_queue_rpid_credid ON create_queue(rpId, credentialId)");
  db.exec("CREATE INDEX IF NOT EXISTS idx_queue_created ON create_queue(createdAt)"); // global write-rate cap

  // Migrations for existing databases
  const columns = db.prepare("PRAGMA table_info(create_queue)").all() as unknown as { name: string }[];
  if (!columns.some((c) => c.name === "walletRef")) {
    db.exec("ALTER TABLE create_queue ADD COLUMN walletRef TEXT NOT NULL DEFAULT ''");
  }
  if (!columns.some((c) => c.name === "retryAfter")) {
    db.exec("ALTER TABLE create_queue ADD COLUMN retryAfter INTEGER NOT NULL DEFAULT 0");
  }

  // Idempotency: resolve any pre-existing active duplicates, then enforce
  // at-most-one-active-row per (rpId, credentialId). Order matters — dedupe must
  // run before the unique index can build on a DB that already has duplicates.
  db.prepare(DEDUPE_ACTIVE_DUPLICATES_SQL).run(Date.now());
  db.exec(CREATE_ACTIVE_UNIQUE_INDEX);
}

export function getQueueDb(): Database {
  return db;
}

export async function enqueue(params: {
  rpId: string;
  credentialId: string;
  walletRef: string;
  publicKey: string;
  name: string;
  initialCredentialId: string;
  metadata: string;
  ip: string;
}): Promise<string> {
  const id = crypto.randomUUID();
  const now = Date.now();
  const ipHash = await hashIp(params.ip);
  try {
    db.prepare(`
      INSERT INTO create_queue (id, status, rpId, credentialId, walletRef, publicKey, name, initialCredentialId, metadata, ip, createdAt, updatedAt)
      VALUES (?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, params.rpId, params.credentialId, params.walletRef, params.publicKey, params.name, params.initialCredentialId, params.metadata, ipHash, now, now);
    return id;
  } catch (err) {
    // Lost the race to a concurrent identical create — return the existing
    // active row's id so the request is idempotent (same job, not a duplicate).
    if (isUniqueConstraintError(err)) {
      const existing = findDuplicate(params.rpId, params.credentialId);
      if (existing && existing.status !== "failed") {
        log.info("enqueue deduplicated to existing active job", { job_id: existing.id, operation: "enqueue" });
        return existing.id;
      }
    }
    throw err;
  }
}

export function getQueueItem(id: string): QueueItem | null {
  return (db.prepare("SELECT * FROM create_queue WHERE id = ?").get(id) as unknown as QueueItem | undefined) ?? null;
}

/** Cheap single indexed COUNT of active items — for the create backpressure gate. */
export function getActiveQueueDepth(): number {
  return (db.prepare("SELECT COUNT(*) as c FROM create_queue WHERE status IN ('pending','committed','creating')").get() as unknown as { c: number }).c;
}

let GLOBAL_WRITE_LIMIT = DEFAULT_GLOBAL_WRITE_LIMIT;
/** Override the global write cap (for testing only). */
export function _setGlobalWriteLimitForTest(limit: number): void {
  GLOBAL_WRITE_LIMIT = limit;
}

/** True when the GLOBAL create rate (across all clients) is at the cap — bounds gas burn. */
export function globalWriteLimitExceeded(): boolean {
  const since = Date.now() - GLOBAL_WRITE_WINDOW;
  const n = (db.prepare("SELECT COUNT(*) as c FROM create_queue WHERE createdAt > ?").get(since) as unknown as { c: number }).c;
  return n >= GLOBAL_WRITE_LIMIT;
}

/** Queue health snapshot for /api/health (3 fields). */
export function getQueueStats(): QueueStats {
  const depth = (db.prepare("SELECT COUNT(*) as c FROM create_queue WHERE status IN ('pending','committed','creating')").get() as unknown as { c: number }).c;
  const dlq = (db.prepare("SELECT COUNT(*) as c FROM create_queue WHERE status = 'failed'").get() as unknown as { c: number }).c;
  const oldest = (db.prepare("SELECT MIN(createdAt) as m FROM create_queue WHERE status IN ('pending','committed','creating')").get() as unknown as { m: number | null }).m;
  return { queueDepth: depth, dlqCount: dlq, oldestActiveAgeMs: oldest ? Date.now() - oldest : 0 };
}

export function findDuplicate(rpId: string, credentialId: string): QueueItem | null {
  // Prefer the ACTIVE row over a 'failed' (DLQ) one for the same key — a stale
  // failed attempt must never shadow a live in-progress job. Deterministic ties.
  return (db.prepare(
    "SELECT * FROM create_queue WHERE rpId = ? AND credentialId = ? ORDER BY (status = 'failed') ASC, createdAt DESC, id DESC LIMIT 1"
  ).get(rpId, credentialId) as unknown as QueueItem | undefined) ?? null;
}

// --- Engine wiring: SQLite QueueStore + viem ChainOps ---

// Sync node:sqlite calls wrapped behind the async QueueStore interface the
// shared engine consumes. All SQL is transcribed from the pre-refactor
// implementation — semantics must not drift (see shared/queue-engine.ts).
const sqliteStore: QueueStore = {
  // deno-lint-ignore require-await
  async countActive(): Promise<number> {
    return (db.prepare(
      "SELECT COUNT(*) as count FROM create_queue WHERE status IN ('pending', 'committed', 'creating')"
    ).get() as unknown as { count: number }).count;
  },
  // deno-lint-ignore require-await
  async listCreating(limit: number): Promise<QueueItem[]> {
    return db.prepare(
      "SELECT * FROM create_queue WHERE status = 'creating' ORDER BY createdAt ASC LIMIT ?"
    ).all(limit) as unknown as QueueItem[];
  },
  // deno-lint-ignore require-await
  async listCommittedReady(now: number, limit: number): Promise<QueueItem[]> {
    return db.prepare(
      "SELECT * FROM create_queue WHERE status = 'committed' AND retryAfter <= ? ORDER BY createdAt ASC LIMIT ?"
    ).all(now, limit) as unknown as QueueItem[];
  },
  // deno-lint-ignore require-await
  async listPendingReady(now: number, limit: number): Promise<QueueItem[]> {
    return db.prepare(
      "SELECT * FROM create_queue WHERE status = 'pending' AND retryAfter <= ? ORDER BY createdAt ASC LIMIT ?"
    ).all(now, limit) as unknown as QueueItem[];
  },
  // deno-lint-ignore require-await
  async markManyDone(ids: string[], now: number, txHash?: string): Promise<void> {
    if (txHash !== undefined) {
      const stmt = db.prepare("UPDATE create_queue SET status = 'done', txHash = ?, error = '', updatedAt = ? WHERE id = ?");
      for (const id of ids) stmt.run(txHash, now, id);
    } else {
      const stmt = db.prepare("UPDATE create_queue SET status = 'done', error = '', updatedAt = ? WHERE id = ?");
      for (const id of ids) stmt.run(now, id);
    }
  },
  // deno-lint-ignore require-await
  async markManyCommitted(ids: string[], now: number): Promise<void> {
    const stmt = db.prepare("UPDATE create_queue SET status = 'committed', updatedAt = ? WHERE id = ?");
    for (const id of ids) stmt.run(now, id);
  },
  // deno-lint-ignore require-await
  async applyFailure(id, fields): Promise<void> {
    if (fields.retryAfter !== undefined) {
      db.prepare("UPDATE create_queue SET status = ?, error = ?, retries = ?, retryAfter = ?, updatedAt = ? WHERE id = ?")
        .run(fields.status, fields.error, fields.retries, fields.retryAfter, fields.updatedAt, id);
    } else {
      db.prepare("UPDATE create_queue SET status = ?, error = ?, retries = ?, updatedAt = ? WHERE id = ?")
        .run(fields.status, fields.error, fields.retries, fields.updatedAt, id);
    }
  },
  // deno-lint-ignore require-await
  async cleanupExpired(doneBefore: number, failedBefore: number): Promise<{ doneDeleted: number }> {
    const result = db.prepare("DELETE FROM create_queue WHERE status = 'done' AND updatedAt < ?").run(doneBefore);
    // Bound the DLQ: drop 'failed' rows past the retention window.
    db.prepare("DELETE FROM create_queue WHERE status = 'failed' AND updatedAt < ?").run(failedBefore);
    return { doneDeleted: (result as unknown as { changes: number }).changes };
  },
};

const chainOps = createViemChainOps(cfg);

// --- Telegram Notifications ---

const ALERT_INTERVAL = 5 * 60_000;
const QUEUE_BACKLOG_THRESHOLD = 100;
let lastAlertAt = 0;
let lastFailedCount = 0;

function cfg(): AppConfig {
  const c = getConfig();
  return { privateKey: c.privateKey, commitPrivateKey: c.commitPrivateKey, telegramBotToken: c.telegramBotToken, telegramChatId: c.telegramChatId };
}

async function checkAlerts(): Promise<void> {
  const now = Date.now();
  if (now - lastAlertAt < ALERT_INTERVAL) return;
  lastAlertAt = now;

  const alerts: string[] = [];

  // 1. Queue backlog
  const pending = (db.prepare("SELECT COUNT(*) as count FROM create_queue WHERE status IN ('pending', 'committed', 'creating')").get() as unknown as { count: number }).count;
  if (pending >= QUEUE_BACKLOG_THRESHOLD) {
    alerts.push(`⚠️ Queue backlog: ${pending} items pending`);
  }

  // 2. Failed items needing manual intervention (only alert on change)
  const failed = (db.prepare("SELECT COUNT(*) as count FROM create_queue WHERE status = 'failed'").get() as unknown as { count: number }).count;
  if (failed > 0 && failed !== lastFailedCount) {
    alerts.push(`🔴 ${failed} items permanently failed, need manual intervention`);
  }
  lastFailedCount = failed;

  // 3. Gas balance + gas price check
  try {
    const { wallet: createWallet, client } = getCreateWallet(cfg());
    const balance = await client.getBalance({ address: createWallet.account.address });
    const balanceXdai = Number(balance) / 1e18;
    if (balanceXdai < GAS_BALANCE_THRESHOLD) {
      alerts.push(`🪫 Create wallet balance low: ${balanceXdai.toFixed(6)} xDAI (${createWallet.account.address})`);
    }
    const gasPrice = await client.getGasPrice();
    const gasPriceGwei = Number(gasPrice) / 1e9;
    if (gasPriceGwei > MAX_GAS_PRICE_GWEI) {
      alerts.push(`⛽ Gas price too high: ${gasPriceGwei.toFixed(4)} Gwei (max: ${MAX_GAS_PRICE_GWEI}), queue paused`);
    }

    // Auto-fund commit wallet if balance is low
    const { wallet: commitWallet } = getCommitWallet(cfg());
    if (commitWallet.account.address !== createWallet.account.address) {
      const commitBalance = await client.getBalance({ address: commitWallet.account.address });
      const commitBalanceXdai = Number(commitBalance) / 1e18;
      if (commitBalanceXdai < FUND_THRESHOLD) {
        await ensureCommitWalletFunded();
      }
    }
  } catch (err) { console.warn(`[queue] checkAlerts gas/balance check failed:`, shortMsg(err)); }

  if (alerts.length > 0) {
    await sendTelegram(cfg(), `[webauthnp256-publickey-index] [Deno] [Gnosis]\n${alerts.join("\n")}`);
  }
}

const FAILURE_ALERT_BATCH = 10;
let failuresSinceLastAlert = 0;

/**
 * Engine hook: batched operator alert for item failures. Mirrors the
 * pre-refactor handleFailure side-effect — the DB bookkeeping itself now
 * lives in shared/queue-engine.ts.
 */
function onItemFailure(error: string): void {
  failuresSinceLastAlert++;
  if (failuresSinceLastAlert >= FAILURE_ALERT_BATCH) {
    const failed = (db.prepare("SELECT COUNT(*) as count FROM create_queue WHERE status = 'failed'").get() as unknown as { count: number }).count;
    sendTelegram(cfg(), `🔴 [webauthnp256-publickey-index] [Deno] [Gnosis]\n${failuresSinceLastAlert} tx failures since last alert\nTotal in DLQ (failed): ${failed}\nLatest error: ${error}`);
    failuresSinceLastAlert = 0;
  }
}

// --- Worker ---

let workerRunning = false;
let cycleStartedAt = 0;
let lastStuckWarnAt = 0;
const STUCK_CYCLE_MS = 3 * 60_000;

export function startQueueWorker() {
  console.log("[queue] Worker started, interval: 60s");
  ensureCommitWalletFunded().catch(() => {});
  setInterval(() => {
    if (workerRunning) {
      // Single-flight: a tick is skipped while a cycle runs. Every individual
      // await is timeout-bounded so a cycle cannot hang forever, but a pathologically
      // slow one is worth surfacing (rate-limited) so operators can spot a stall.
      const age = Date.now() - cycleStartedAt;
      if (age > STUCK_CYCLE_MS && Date.now() - lastStuckWarnAt > STUCK_CYCLE_MS) {
        lastStuckWarnAt = Date.now();
        log.warn("queue cycle still running — possible stall", { operation: "processQueue", outcome: "stuck", cycle_age_ms: age });
      }
      return;
    }
    cycleStartedAt = Date.now();
    processQueue().catch((err) => log.error("queue worker cycle error", { operation: "processQueue", error: String(err) }));
  }, WORKER_INTERVAL);
}

async function ensureCommitWalletFunded(): Promise<void> {
  try {
    const { wallet: createWallet, client } = getCreateWallet(cfg());
    const { wallet: commitWallet } = getCommitWallet(cfg());
    if (commitWallet.account.address === createWallet.account.address) return;

    const commitBalance = await client.getBalance({ address: commitWallet.account.address });
    const commitBalanceXdai = Number(commitBalance) / 1e18;
    if (commitBalanceXdai >= FUND_THRESHOLD) {
      console.log(`[queue] Commit wallet ${commitWallet.account.address} balance: ${commitBalanceXdai.toFixed(6)} xDAI (ok)`);
      return;
    }

    const mainBalance = await client.getBalance({ address: createWallet.account.address });
    const mainBalanceXdai = Number(mainBalance) / 1e18;
    if (mainBalanceXdai < FUND_AMOUNT + GAS_BALANCE_THRESHOLD) {
      console.warn(`[queue] Cannot fund commit wallet: main balance too low (${mainBalanceXdai.toFixed(6)} xDAI)`);
      return;
    }

    console.log(`[queue] Funding commit wallet ${commitWallet.account.address}: ${commitBalanceXdai.toFixed(6)} → +${FUND_AMOUNT} xDAI`);
    const hash = await createWallet.sendTransaction({
      to: commitWallet.account.address,
      value: BigInt(Math.floor(FUND_AMOUNT * 1e18)),
    });
    const fundReceipt = await client.waitForTransactionReceipt({ hash, timeout: 30_000 });
    if (fundReceipt.status === "reverted") {
      throw new Error(`Fund tx reverted: ${hash}`);
    }
    console.log(`[queue] Commit wallet funded: ${hash}`);
  } catch (err) {
    console.warn(`[queue] Auto-fund failed:`, shortMsg(err));
  }
}

async function processQueue() {
  workerRunning = true;
  const start = performance.now();
  try {
    await runQueueCycle({
      store: sqliteStore,
      chain: chainOps,
      nonces: { acquire: (role) => acquireNonce(role) },
      hooks: {
        onItemFailure,
        checkAlerts: (_gasPriceGwei?: number) => checkAlerts(),
      },
      label: "[queue]",
    });
  } finally {
    const ms = (performance.now() - start).toFixed(0);
    console.log(`[queue] Worker cycle done — ${ms}ms`);
    workerRunning = false;
  }
}

function shortMsg(err: unknown): string {
  // Redact any embedded RPC credentials before logging.
  return redactSecrets(err instanceof Error ? err.message : String(err)).slice(0, 200);
}
