/**
 * Queue module (CF Worker version using D1).
 * Shares types, constants, and pure helpers from queue-shared.ts.
 * Only D1-specific DB operations are here.
 */
import {
  type QueueItem,
  type QueueStatus,
  RATE_WINDOW,
  DEFAULT_RATE_LIMIT,
  CREATE_QUEUE_DDL,
  hashIp,
} from "../shared/queue.ts";

export type { QueueStatus, QueueItem };

// --- D1 transient-error retry ---
//
// D1 (single-writer SQLite) intermittently fails under contention or cold start
// with "D1_ERROR: ... storage operation exceeded timeout which caused object to
// be reset". The exact same operation succeeds on a quick retry. Without this,
// such a hiccup surfaces as a 500 to the client (the symptom that made wallet
// creation "almost always fail on the first try, then succeed on retry").
const D1_TRANSIENT_PATTERNS = [
  "exceeded timeout",
  "object to be reset",
  "network connection lost",
  "d1_error",
  "storage operation",
];

function isTransientD1Error(err: unknown): boolean {
  const msg = (err instanceof Error ? err.message : String(err)).toLowerCase();
  return D1_TRANSIENT_PATTERNS.some((p) => msg.includes(p));
}

async function withD1Retry<T>(op: () => Promise<T>, attempts = 3): Promise<T> {
  let lastErr: unknown;
  for (let i = 0; i < attempts; i++) {
    try {
      return await op();
    } catch (err) {
      lastErr = err;
      if (!isTransientD1Error(err) || i === attempts - 1) throw err;
      console.warn(`[queue] transient D1 error, retry ${i + 1}/${attempts - 1}:`, err instanceof Error ? err.message : err);
      await new Promise((r) => setTimeout(r, 50 * Math.pow(3, i))); // 50ms, 150ms
    }
  }
  throw lastErr;
}

export async function initQueue(db: D1Database): Promise<void> {
  await withD1Retry(() => db.batch([
    db.prepare(CREATE_QUEUE_DDL),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_queue_status ON create_queue(status)"),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_queue_status_created ON create_queue(status, createdAt)"),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_queue_rpid_credid ON create_queue(rpId, credentialId)"),
    db.prepare(`
      CREATE TABLE IF NOT EXISTS rate_limits (
        ip_hash TEXT NOT NULL,
        timestamp INTEGER NOT NULL
      )
    `),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_rate_ip ON rate_limits(ip_hash, timestamp)"),
  ]));
}

export async function checkRateLimit(db: D1Database, ip: string): Promise<boolean> {
  const hashed = await hashIp(ip);
  const now = Date.now();
  const cutoff = now - RATE_WINDOW;

  try {
    // Prune stale rows only occasionally — a DELETE on every request is pure
    // write contention on the hot path. The SELECT below already ignores stale
    // rows (timestamp >= cutoff), so skipping cleanup never affects correctness.
    if (Math.random() < 0.1) {
      await withD1Retry(() => db.prepare("DELETE FROM rate_limits WHERE timestamp < ?").bind(cutoff).run());
    }
    const result = await withD1Retry<{ count: number } | null>(() =>
      db.prepare("SELECT COUNT(*) as count FROM rate_limits WHERE ip_hash = ? AND timestamp >= ?")
        .bind(hashed, cutoff).first<{ count: number }>()
    );

    if (result && result.count >= DEFAULT_RATE_LIMIT) return false;

    await withD1Retry(() =>
      db.prepare("INSERT INTO rate_limits (ip_hash, timestamp) VALUES (?, ?)").bind(hashed, now).run()
    );
    return true;
  } catch (err) {
    // Fail open: a D1 hiccup in rate limiting must never block a legitimate
    // wallet creation. Abuse is bounded by the on-chain commit-reveal cost.
    console.warn("[queue] checkRateLimit D1 error, allowing request:", err instanceof Error ? err.message : err);
    return true;
  }
}

export async function enqueue(db: D1Database, params: {
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
  await withD1Retry(() => db.prepare(`
    INSERT INTO create_queue (id, status, rpId, credentialId, walletRef, publicKey, name, initialCredentialId, metadata, ip, createdAt, updatedAt)
    VALUES (?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(id, params.rpId, params.credentialId, params.walletRef, params.publicKey, params.name, params.initialCredentialId, params.metadata, ipHash, now, now).run());
  return id;
}

export async function getQueueItem(db: D1Database, id: string): Promise<QueueItem | null> {
  return await withD1Retry(() =>
    db.prepare("SELECT * FROM create_queue WHERE id = ?").bind(id).first<QueueItem>()
  ) ?? null;
}

export async function findDuplicate(db: D1Database, rpId: string, credentialId: string): Promise<QueueItem | null> {
  return await withD1Retry(() =>
    db.prepare(
      "SELECT * FROM create_queue WHERE rpId = ? AND credentialId = ? ORDER BY createdAt DESC LIMIT 1"
    ).bind(rpId, credentialId).first<QueueItem>()
  ) ?? null;
}
