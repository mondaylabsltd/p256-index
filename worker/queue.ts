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

export async function initQueue(db: D1Database): Promise<void> {
  await db.batch([
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
  ]);
}

export async function checkRateLimit(db: D1Database, ip: string): Promise<boolean> {
  const hashed = await hashIp(ip);
  const now = Date.now();
  const cutoff = now - RATE_WINDOW;

  await db.prepare("DELETE FROM rate_limits WHERE timestamp < ?").bind(cutoff).run();
  const result = await db.prepare("SELECT COUNT(*) as count FROM rate_limits WHERE ip_hash = ? AND timestamp >= ?")
    .bind(hashed, cutoff).first<{ count: number }>();

  if (result && result.count >= DEFAULT_RATE_LIMIT) return false;

  await db.prepare("INSERT INTO rate_limits (ip_hash, timestamp) VALUES (?, ?)").bind(hashed, now).run();
  return true;
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
  await db.prepare(`
    INSERT INTO create_queue (id, status, rpId, credentialId, walletRef, publicKey, name, initialCredentialId, metadata, ip, createdAt, updatedAt)
    VALUES (?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(id, params.rpId, params.credentialId, params.walletRef, params.publicKey, params.name, params.initialCredentialId, params.metadata, ipHash, now, now).run();
  return id;
}

export async function getQueueItem(db: D1Database, id: string): Promise<QueueItem | null> {
  return await db.prepare("SELECT * FROM create_queue WHERE id = ?").bind(id).first<QueueItem>() ?? null;
}

export async function findDuplicate(db: D1Database, rpId: string, credentialId: string): Promise<QueueItem | null> {
  return await db.prepare(
    "SELECT * FROM create_queue WHERE rpId = ? AND credentialId = ? ORDER BY createdAt DESC LIMIT 1"
  ).bind(rpId, credentialId).first<QueueItem>() ?? null;
}
