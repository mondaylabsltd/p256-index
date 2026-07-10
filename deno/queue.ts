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
  GLOBAL_WRITE_WINDOW,
  DEFAULT_GLOBAL_WRITE_LIMIT,
  isUniqueConstraintError,
  hashIp,
  getCreateWallet,
  getCommitWallet,
  sendTelegram,
  HEARTBEAT_INTERVAL,
  buildHeartbeatMessage,
} from "../shared/queue.ts";
import { runQueueCycle, type QueueStore, type AlertReason, type ItemFailureInfo } from "../shared/queue-engine.ts";
import { runMigrations, type SqlRunner } from "../shared/migrations.ts";
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

export async function initQueue(dbPath = "queue.db"): Promise<void> {
  db = new Database(dbPath);
  db.exec("PRAGMA journal_mode = WAL");
  // Versioned, shared migrations (shared/migrations.ts) — one numbered list
  // for both runtimes; idempotent against legacy pre-versioning databases.
  const runner: SqlRunner = {
    // deno-lint-ignore require-await
    async run(sql, params) {
      if (params && params.length > 0) db.prepare(sql).run(...(params as (string | number)[]));
      else db.exec(sql);
    },
    // deno-lint-ignore require-await
    async scalar(sql) {
      const row = db.prepare(sql).get() as Record<string, unknown> | undefined;
      if (!row) return undefined;
      const v = Object.values(row)[0];
      return v == null ? undefined : Number(v);
    },
  };
  await runMigrations(runner, Date.now());
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
/** Set the global write cap (env-driven at startup; also used by tests). */
export function setGlobalWriteLimit(limit: number): void {
  if (Number.isFinite(limit) && limit > 0) GLOBAL_WRITE_LIMIT = limit;
}
/** Test alias. */
export const _setGlobalWriteLimitForTest = setGlobalWriteLimit;

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

/** Queue lookup by walletRef — the query-by-walletRef path's local fallback. */
export function findDuplicateByWalletRef(walletRef: string): QueueItem | null {
  return (db.prepare(
    "SELECT * FROM create_queue WHERE walletRef = ? ORDER BY (status = 'failed') ASC, createdAt DESC, id DESC LIMIT 1"
  ).get(walletRef) as unknown as QueueItem | undefined) ?? null;
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
  // deno-lint-ignore require-await
  async recordPendingTx(role, nonce, hash, sentAt, attempts = 0): Promise<void> {
    db.prepare("INSERT OR REPLACE INTO pending_txs (role, nonce, hash, sentAt, attempts) VALUES (?, ?, ?, ?, ?)")
      .run(role, nonce, hash, sentAt, attempts);
  },
  // deno-lint-ignore require-await
  async deletePendingTx(role, nonce): Promise<void> {
    db.prepare("DELETE FROM pending_txs WHERE role = ? AND nonce = ?").run(role, nonce);
  },
  // deno-lint-ignore require-await
  async listPendingTxs(sentBefore) {
    return db.prepare("SELECT role, nonce, hash, sentAt, attempts FROM pending_txs WHERE sentAt < ? ORDER BY nonce ASC")
      .all(sentBefore) as unknown as { role: "create" | "commit"; nonce: number; hash: `0x${string}`; sentAt: number; attempts: number }[];
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

  // 2. Failed items needing manual intervention (only alert on change).
  // CONFLICT: rows are user-input conflicts — terminal but NOT dev-actionable,
  // so they are excluded from this page (still visible in DLQ/status/heartbeat).
  const failed = (db.prepare("SELECT COUNT(*) as count FROM create_queue WHERE status = 'failed' AND error NOT LIKE 'CONFLICT:%'").get() as unknown as { count: number }).count;
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
        const fundingIssue = await ensureCommitWalletFunded();
        if (fundingIssue) alerts.push(fundingIssue);
      }
    }
  } catch (err) { console.warn(`[queue] checkAlerts gas/balance check failed:`, shortMsg(err)); }

  if (alerts.length > 0) {
    await sendTelegram(cfg(), `[webauthnp256-publickey-index] [Deno] [Gnosis]\n${alerts.join("\n")}`);
  }
}

const FAILURE_ALERT_BATCH = 10;
let failuresSinceLastAlert = 0;

// Terminal (DLQ) quarantines mean a user's create WILL NOT complete without a
// developer: POISON = code/data bug, EXHAUSTED = outage outlived all retries.
// Per the operator's standing requirement these page IMMEDIATELY via Telegram
// (throttled to one aggregate message per minute so a poison batch doesn't spam).
const TERMINAL_ALERT_THROTTLE = 60_000;
let lastTerminalAlertAt = 0;
let terminalSinceLastAlert = 0;
let lastTerminalError = "";

function onItemFailure(error: string, info: ItemFailureInfo): void {
  if (info.conflict) {
    // USER-INPUT conflict (e.g. the same passkey already registered under a
    // different credential). Terminal + DLQ-visible + surfaced to the client
    // via the status endpoint, but per the operator's alerting contract a page
    // means "code bug or funding" — this is neither. Log only.
    console.warn(`[queue] user-conflict quarantine (no page): job ${info.jobId}: ${error}`);
    return;
  }
  if (info.terminal) {
    terminalSinceLastAlert++;
    lastTerminalError = `${info.poison ? "POISON" : "EXHAUSTED"} (job ${info.jobId}): ${error}`;
    const now = Date.now();
    if (now - lastTerminalAlertAt >= TERMINAL_ALERT_THROTTLE) {
      lastTerminalAlertAt = now;
      const n = terminalSinceLastAlert;
      terminalSinceLastAlert = 0;
      const kind = info.poison ? "code/data bug" : "outage exhausted retries";
      sendTelegram(cfg(), `🚨 [webauthnp256-publickey-index] [Deno] [Gnosis]\n${n} create request(s) QUARANTINED to DLQ — developer intervention required (${kind}).\nLatest: ${lastTerminalError}\nReplay after fixing: see 06-operations-runbook.md`);
    }
    return;
  }
  failuresSinceLastAlert++;
  if (failuresSinceLastAlert >= FAILURE_ALERT_BATCH) {
    const failed = (db.prepare("SELECT COUNT(*) as count FROM create_queue WHERE status = 'failed'").get() as unknown as { count: number }).count;
    sendTelegram(cfg(), `🔴 [webauthnp256-publickey-index] [Deno] [Gnosis]\n${failuresSinceLastAlert} tx failures since last alert\nTotal in DLQ (failed): ${failed}\nLatest error: ${error}`);
    failuresSinceLastAlert = 0;
  }
}

// Consecutive gas-check failures = the write RPC face is unreachable and NO
// creates are progressing. checkAlerts() covers backlog/balance, but the root
// cause deserves its own explicit page after a few cycles (~3 min).
const RPC_UNREACHABLE_THRESHOLD = 3;
const RPC_UNREACHABLE_THROTTLE = 5 * 60_000;
let consecutiveGasFails = 0;
let lastRpcUnreachableAlertAt = 0;

async function flushTerminalAlerts(): Promise<void> {
  // A single throttled terminal quarantine (a lone POISON within the 60s
  // window right after a prior page) would otherwise never be reported. Flush
  // any accumulated count on the periodic alert sweep so nothing is lost.
  if (terminalSinceLastAlert > 0 && Date.now() - lastTerminalAlertAt >= TERMINAL_ALERT_THROTTLE) {
    lastTerminalAlertAt = Date.now();
    const n = terminalSinceLastAlert;
    terminalSinceLastAlert = 0;
    await sendTelegram(cfg(), `🚨 [webauthnp256-publickey-index] [Deno] [Gnosis]\n${n} create request(s) QUARANTINED to DLQ — developer intervention required.\nLatest: ${lastTerminalError}\nReplay after fixing: see 06-operations-runbook.md`);
  }
}

async function onCheckAlerts(gasPriceGwei: number | undefined, reason: AlertReason): Promise<void> {
  await flushTerminalAlerts();
  if (reason === "gas-fail") {
    consecutiveGasFails++;
    if (consecutiveGasFails >= RPC_UNREACHABLE_THRESHOLD && Date.now() - lastRpcUnreachableAlertAt >= RPC_UNREACHABLE_THROTTLE) {
      lastRpcUnreachableAlertAt = Date.now();
      const depth = getActiveQueueDepth();
      await sendTelegram(cfg(), `🔌 [webauthnp256-publickey-index] [Deno] [Gnosis]\nWrite RPC unreachable for ${consecutiveGasFails} consecutive cycles — creates are NOT being processed (${depth} queued). Endpoints are rotating automatically; if this persists, check RPC providers / ALCHEMY_API_KEY.`);
    }
  } else {
    consecutiveGasFails = 0;
  }
  void gasPriceGwei; // Deno's checkAlerts measures gas itself
  await checkAlerts();
  await maybeHeartbeat();
}

// --- Daily heartbeat ---
// A silent alert channel is indistinguishable from a broken one; the daily
// heartbeat makes "no news is good news" verifiable and carries the PROACTIVE
// funding signal (balance + runway) so top-ups happen before the 🪫 page.
// First heartbeat fires on the first cycle after boot — which doubles as the
// "deployed and alerting path works" confirmation.
const processStartedAt = Date.now();
let lastHeartbeatAt = 0;

async function maybeHeartbeat(): Promise<void> {
  const now = Date.now();
  if (now - lastHeartbeatAt < HEARTBEAT_INTERVAL) return;
  lastHeartbeatAt = now;
  try {
    const { wallet: createWallet, client } = getCreateWallet(cfg());
    const { wallet: commitWallet } = getCommitWallet(cfg());
    const [createBal, commitBal, gasPrice] = await Promise.all([
      client.getBalance({ address: createWallet.account.address }),
      client.getBalance({ address: commitWallet.account.address }),
      client.getGasPrice(),
    ]);
    const stats = getQueueStats();
    let release: string | undefined;
    try { release = Deno.realPathSync(Deno.cwd()).split("/").pop(); } catch { /* optional */ }
    await sendTelegram(cfg(), buildHeartbeatMessage({
      runtime: "Deno",
      queueDepth: stats.queueDepth,
      dlqCount: stats.dlqCount,
      createAddress: createWallet.account.address,
      createBalanceXdai: Number(createBal) / 1e18,
      commitAddress: commitWallet.account.address,
      commitBalanceXdai: Number(commitBal) / 1e18,
      gasPriceGwei: Number(gasPrice) / 1e9,
      uptimeMs: now - processStartedAt,
      release,
    }));
  } catch (err) {
    // Never let the heartbeat break a cycle; a failed heartbeat is itself a
    // signal (the daily message stops arriving).
    console.warn(`[queue] heartbeat failed:`, shortMsg(err));
  }
}

// --- Worker ---

let workerRunning = false;
let consecutiveCycleErrors = 0;
let lastCycleErrorAlertAt = 0;
let cycleStartedAt = 0;
let lastStuckWarnAt = 0;
const STUCK_CYCLE_MS = 3 * 60_000;

export function startQueueWorker() {
  console.log("[queue] Worker started, interval: 60s");
  ensureCommitWalletFunded()
    .then((issue) => {
      if (issue) return sendTelegram(cfg(), `[webauthnp256-publickey-index] [Deno] [Gnosis]\n${issue}`);
    })
    .catch(() => {});
  setInterval(() => {
    if (workerRunning) {
      // Single-flight: a tick is skipped while a cycle runs. Every individual
      // await is timeout-bounded so a cycle cannot hang forever, but a pathologically
      // slow one is worth surfacing (rate-limited) so operators can spot a stall.
      const age = Date.now() - cycleStartedAt;
      if (age > STUCK_CYCLE_MS && Date.now() - lastStuckWarnAt > STUCK_CYCLE_MS) {
        lastStuckWarnAt = Date.now();
        log.warn("queue cycle still running — possible stall", { operation: "processQueue", outcome: "stuck", cycle_age_ms: age });
        // A stalled worker means user creates silently stop progressing —
        // that's a dev-intervention condition, so it must reach Telegram.
        sendTelegram(cfg(), `[webauthnp256-publickey-index] [Deno] [Gnosis]\n🛑 Queue cycle stuck for ${Math.round(age / 60_000)}min — creates are NOT being processed. Restart / investigate.`);
      }
      return;
    }
    cycleStartedAt = Date.now();
    processQueue().then(() => { consecutiveCycleErrors = 0; }).catch((err) => {
      log.error("queue worker cycle error", { operation: "processQueue", error: shortMsg(err) });
      // A cycle that THROWS never reaches checkAlerts — so persistent cycle
      // failures (a bug, a broken migration, D1 down) would go dark. Page after
      // a few consecutive ones so a stalled pipeline always reaches Telegram.
      consecutiveCycleErrors++;
      if (consecutiveCycleErrors >= 3 && Date.now() - lastCycleErrorAlertAt >= 5 * 60_000) {
        lastCycleErrorAlertAt = Date.now();
        sendTelegram(cfg(), `🛑 [webauthnp256-publickey-index] [Deno] [Gnosis]\nQueue cycle FAILING (${consecutiveCycleErrors} consecutive errors) — creates are NOT being processed.\nLatest: ${shortMsg(err)}`);
      }
    });
  }, WORKER_INTERVAL);
}

/**
 * Top up the commit wallet from the create wallet when low. Returns an
 * operator-actionable alert string when developer intervention is required
 * (top-up needed / funding failing) so callers can push it to Telegram —
 * "needs money" must never be console-only.
 */
async function ensureCommitWalletFunded(): Promise<string | null> {
  try {
    const { wallet: createWallet, client } = getCreateWallet(cfg());
    const { wallet: commitWallet } = getCommitWallet(cfg());
    if (commitWallet.account.address === createWallet.account.address) return null;

    const commitBalance = await client.getBalance({ address: commitWallet.account.address });
    const commitBalanceXdai = Number(commitBalance) / 1e18;
    if (commitBalanceXdai >= FUND_THRESHOLD) {
      console.log(`[queue] Commit wallet ${commitWallet.account.address} balance: ${commitBalanceXdai.toFixed(6)} xDAI (ok)`);
      return null;
    }

    const mainBalance = await client.getBalance({ address: createWallet.account.address });
    const mainBalanceXdai = Number(mainBalance) / 1e18;
    if (mainBalanceXdai < FUND_AMOUNT + GAS_BALANCE_THRESHOLD) {
      console.warn(`[queue] Cannot fund commit wallet: main balance too low (${mainBalanceXdai.toFixed(6)} xDAI)`);
      return `🪫 TOP-UP REQUIRED: cannot auto-fund commit wallet — create wallet ${createWallet.account.address} has only ${mainBalanceXdai.toFixed(6)} xDAI (needs ≥ ${(FUND_AMOUNT + GAS_BALANCE_THRESHOLD).toFixed(3)}). Creates will stall when it runs out.`;
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
    return null;
  } catch (err) {
    console.warn(`[queue] Auto-fund failed:`, shortMsg(err));
    return `⚠️ Commit wallet auto-fund FAILED: ${shortMsg(err)} — check wallet balances / RPC.`;
  }
}

/**
 * Resolve once the current queue cycle (if any) finishes, or after timeoutMs.
 * Used by graceful shutdown so a mid-broadcast batch isn't killed.
 */
export async function waitForQueueIdle(timeoutMs: number): Promise<boolean> {
  const start = Date.now();
  while (workerRunning) {
    if (Date.now() - start > timeoutMs) return false;
    await new Promise((r) => setTimeout(r, 250));
  }
  return true;
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
        checkAlerts: onCheckAlerts,
        onStuckTx: (role, nonce, attempts, ageMs) =>
          sendTelegram(cfg(), `🧵 [webauthnp256-publickey-index] [Deno] [Gnosis]\nWallet nonce STUCK: role=${role} nonce=${nonce} not clearing after ${attempts} replacement attempts (${Math.round(ageMs / 60_000)}min). Every create behind it is blocked — check RPC acceptance / raise MAX_GAS_PRICE_GWEI.`),
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
