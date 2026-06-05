import { DatabaseSync as Database } from "node:sqlite";
import { createPublicClient, http } from "viem";
import { gnosis } from "viem/chains";
import { getWriteRpc } from "../shared/rpc.ts";
import { getConfig } from "./config.ts";
import { CONTRACT_ADDRESS, CONTRACT_ABI, BATCH_HELPER_ADDRESS, BATCH_ABI } from "../shared/contract.ts";
import { acquireNonce } from "./nonce.ts";
import {
  type QueueStatus,
  type QueueItem,
  type AppConfig,
  MAX_RETRIES,
  WORKER_INTERVAL,
  QUERY_BATCH_SIZE,
  TX_BATCH_SIZE,
  RATE_WINDOW,
  DEFAULT_RATE_LIMIT,
  MAX_GAS_PRICE_GWEI,
  GAS_BALANCE_THRESHOLD,
  FUND_THRESHOLD,
  FUND_AMOUNT,
  DONE_RETENTION,
  CREATE_SUB_BATCH,
  CREATE_QUEUE_DDL,
  hashIp,
  buildCommitment,
  getCreateWallet,
  getCommitWallet,
  sendTelegram,
} from "../shared/queue.ts";

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

  // Migrations for existing databases
  const columns = db.prepare("PRAGMA table_info(create_queue)").all() as unknown as { name: string }[];
  if (!columns.some((c) => c.name === "walletRef")) {
    db.exec("ALTER TABLE create_queue ADD COLUMN walletRef TEXT NOT NULL DEFAULT ''");
  }
  if (!columns.some((c) => c.name === "retryAfter")) {
    db.exec("ALTER TABLE create_queue ADD COLUMN retryAfter INTEGER NOT NULL DEFAULT 0");
  }
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
  db.prepare(`
    INSERT INTO create_queue (id, status, rpId, credentialId, walletRef, publicKey, name, initialCredentialId, metadata, ip, createdAt, updatedAt)
    VALUES (?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, params.rpId, params.credentialId, params.walletRef, params.publicKey, params.name, params.initialCredentialId, params.metadata, ipHash, now, now);
  return id;
}

export function getQueueItem(id: string): QueueItem | null {
  return (db.prepare("SELECT * FROM create_queue WHERE id = ?").get(id) as unknown as QueueItem | undefined) ?? null;
}

export function findDuplicate(rpId: string, credentialId: string): QueueItem | null {
  return (db.prepare(
    "SELECT * FROM create_queue WHERE rpId = ? AND credentialId = ? ORDER BY createdAt DESC LIMIT 1"
  ).get(rpId, credentialId) as unknown as QueueItem | undefined) ?? null;
}

// --- Telegram Notifications ---

const ALERT_INTERVAL = 5 * 60_000;
const QUEUE_BACKLOG_THRESHOLD = 100;
let lastAlertAt = 0;
let lastFailedCount = 0;

function cleanupDoneRecords(): void {
  const cutoff = Date.now() - DONE_RETENTION;
  const result = db.prepare("DELETE FROM create_queue WHERE status = 'done' AND updatedAt < ?").run(cutoff);
  const deleted = (result as unknown as { changes: number }).changes;
  if (deleted > 0) console.log(`[queue] Cleaned up ${deleted} done records older than 7 days`);
}

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
  } catch (err) { console.warn(`[queue] checkAlerts gas/balance check failed:`, err instanceof Error ? err.message : err); }

  if (alerts.length > 0) {
    await sendTelegram(cfg(), `[webauthnp256-publickey-index] [Deno] [Gnosis]\n${alerts.join("\n")}`);
  }
}

// --- Worker ---

let workerRunning = false;

export function startQueueWorker() {
  console.log("[queue] Worker started, interval: 2s");
  ensureCommitWalletFunded().catch(() => {});
  setInterval(() => {
    if (workerRunning) return;
    processQueue().catch((err) => console.error("[queue] Worker error:", err));
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
    console.warn(`[queue] Auto-fund failed:`, err instanceof Error ? err.message : err);
  }
}

async function processQueue() {
  workerRunning = true;
  const start = performance.now();
  try {
    try {
      const writeClient = createPublicClient({ chain: gnosis, transport: http(getWriteRpc(), { timeout: 10_000 }) });
      const gasPrice = await writeClient.getGasPrice();
      const gasPriceGwei = Number(gasPrice) / 1e9;
      if (gasPriceGwei > MAX_GAS_PRICE_GWEI) {
        console.warn(`[queue] Gas price too high: ${gasPriceGwei.toFixed(4)} Gwei (max: ${MAX_GAS_PRICE_GWEI}), pausing`);
        await checkAlerts();
        return;
      }
    } catch (err) {
      console.warn(`[queue] Gas price check failed, skipping cycle:`, err instanceof Error ? err.message : err);
      return;
    }

    await processCreating();
    await processCommitted();
    await processPending();
    cleanupDoneRecords();
    await checkAlerts();
  } finally {
    const ms = (performance.now() - start).toFixed(0);
    console.log(`[queue] Worker cycle done — ${ms}ms`);
    workerRunning = false;
  }
}

// Phase 1: Verify items in 'creating' status
async function processCreating() {
  const items = db.prepare(
    "SELECT * FROM create_queue WHERE status = 'creating' ORDER BY createdAt ASC LIMIT ?"
  ).all(QUERY_BATCH_SIZE) as unknown as QueueItem[];

  if (items.length === 0) return;

  const client = createPublicClient({ chain: gnosis, transport: http(getWriteRpc(), { timeout: 10_000 }) });

  const calls = items.map((item) => ({
    address: CONTRACT_ADDRESS as `0x${string}`,
    abi: CONTRACT_ABI,
    functionName: "hasRecord" as const,
    args: [item.rpId, item.credentialId] as const,
  }));

  try {
    const results = await client.multicall({ contracts: calls });
    let doneCount = 0;
    for (let i = 0; i < items.length; i++) {
      const result = results[i];
      if (result.status === "success" && result.result) {
        db.prepare("UPDATE create_queue SET status = 'done', error = '', updatedAt = ? WHERE id = ?").run(Date.now(), items[i].id);
        doneCount++;
      } else if (result.status === "success" && !result.result) {
        const CREATING_TIMEOUT = 2 * 60_000;
        if (Date.now() - items[i].updatedAt > CREATING_TIMEOUT) {
          handleFailure(items[i], "createRecord tx not confirmed after 2min", "committed");
        }
      }
    }
    if (doneCount > 0) console.log(`[queue] ${doneCount} items confirmed on-chain, done`);
  } catch (err) {
    console.warn(`[queue] processCreating multicall failed, retry next cycle:`, err instanceof Error ? err.message : err);
  }
}

// Phase 2: Advance committed items
async function processCommitted() {
  const items = db.prepare(
    "SELECT * FROM create_queue WHERE status = 'committed' AND retryAfter <= ? ORDER BY createdAt ASC LIMIT ?"
  ).all(Date.now(), TX_BATCH_SIZE) as unknown as QueueItem[];

  if (items.length === 0) return;

  const client = createPublicClient({ chain: gnosis, transport: http(getWriteRpc(), { timeout: 10_000 }) });
  const currentBlock = await client.getBlockNumber();

  const commitments = items.map((item) => buildCommitment(item).commitment);
  const calls = commitments.map((commitment) => ({
    address: CONTRACT_ADDRESS as `0x${string}`,
    abi: CONTRACT_ABI,
    functionName: "getCommitBlock" as const,
    args: [commitment] as const,
  }));

  let results: { status: "success" | "failure"; result?: unknown; error?: unknown }[];
  try {
    results = await client.multicall({ contracts: calls }) as typeof results;
  } catch (err) {
    console.warn(`[queue] processCommitted multicall failed:`, err instanceof Error ? err.message : err);
    return;
  }

  const ready: QueueItem[] = [];
  const needsHasRecordCheck: QueueItem[] = [];

  for (let i = 0; i < items.length; i++) {
    const result = results[i];
    if (result.status !== "success") continue;
    const commitBlock = result.result as bigint;
    if (commitBlock > 0n && currentBlock >= commitBlock + 1n) {
      ready.push(items[i]);
    } else if (commitBlock === 0n) {
      needsHasRecordCheck.push(items[i]);
    }
  }

  if (needsHasRecordCheck.length > 0) {
    const hasRecordCalls = needsHasRecordCheck.map((item) => ({
      address: CONTRACT_ADDRESS as `0x${string}`,
      abi: CONTRACT_ABI,
      functionName: "hasRecord" as const,
      args: [item.rpId, item.credentialId] as const,
    }));
    try {
      const hasRecordResults = await client.multicall({ contracts: hasRecordCalls });
      for (let i = 0; i < needsHasRecordCheck.length; i++) {
        const item = needsHasRecordCheck[i];
        const r = hasRecordResults[i];
        if (r.status === "success" && r.result) {
          db.prepare("UPDATE create_queue SET status = 'done', error = '', updatedAt = ? WHERE id = ?").run(Date.now(), item.id);
        } else {
          const COMMIT_COOLDOWN = 2 * 60_000;
          if (Date.now() - item.updatedAt >= COMMIT_COOLDOWN) {
            db.prepare("UPDATE create_queue SET status = 'pending', updatedAt = ? WHERE id = ?").run(Date.now(), item.id);
            console.warn(`[queue] Item ${item.id} commitment missing after ${COMMIT_COOLDOWN / 1000}s, resetting to pending`);
          }
        }
      }
    } catch (err) { console.warn(`[queue] hasRecord multicall failed:`, err instanceof Error ? err.message : err); }
  }

  if (ready.length === 0) return;

  const { wallet, client: walletClient } = getCreateWallet(cfg());

  for (let offset = 0; offset < ready.length; offset += CREATE_SUB_BATCH) {
    const batch = ready.slice(offset, offset + CREATE_SUB_BATCH);
    const params = batch.map((item) => {
      const { walletRefHex, publicKeyHex, metadataHex } = buildCommitment(item);
      return {
        rpId: item.rpId,
        credentialId: item.credentialId,
        walletRef: walletRefHex,
        publicKey: publicKeyHex,
        name: item.name,
        initialCredentialId: item.initialCredentialId,
        metadata: metadataHex,
      };
    });

    const handle = await acquireNonce("create");
    try {
      const gasEstimate = await walletClient.estimateContractGas({
        address: BATCH_HELPER_ADDRESS,
        abi: BATCH_ABI,
        functionName: "batchCreateRecord",
        args: [CONTRACT_ADDRESS, params],
        account: wallet.account,
      });
      console.log(`[queue] batchCreateRecord: ${batch.length} items, estimated gas: ${gasEstimate}`);

      const hash = await wallet.writeContract({
        address: BATCH_HELPER_ADDRESS,
        abi: BATCH_ABI,
        functionName: "batchCreateRecord",
        args: [CONTRACT_ADDRESS, params],
        nonce: handle.nonce,
        gas: gasEstimate * 120n / 100n,
      });
      // Wait for receipt and verify success
      const createReceipt = await walletClient.waitForTransactionReceipt({ hash, timeout: 60_000 });
      if (createReceipt.status === "reverted") {
        throw new Error(`batchCreateRecord tx reverted: ${hash}`);
      }
      const now = Date.now();
      for (const item of batch) {
        db.prepare("UPDATE create_queue SET status = 'done', txHash = ?, error = '', updatedAt = ? WHERE id = ?")
          .run(hash, now, item.id);
      }
      console.log(`[queue] batchCreateRecord: ${batch.length} items confirmed, done`);
    } catch (err) {
      handle.release();
      const msg = err instanceof Error ? err.message : String(err);
      console.warn(`[queue] batchCreateRecord failed (${batch.length} items): ${msg.slice(0, 200)}`);
      break;
    }
  }
}

// Phase 3: Send commit txs for pending items
async function processPending() {
  const items = db.prepare(
    "SELECT * FROM create_queue WHERE status = 'pending' AND retryAfter <= ? ORDER BY createdAt ASC LIMIT ?"
  ).all(Date.now(), TX_BATCH_SIZE) as unknown as QueueItem[];

  if (items.length === 0) return;

  const commitments = items.map((item) => buildCommitment(item).commitment);

  const { wallet, client: commitClient } = getCommitWallet(cfg());
  const handle = await acquireNonce("commit");
  try {
    const gasEstimate = await commitClient.estimateContractGas({
      address: BATCH_HELPER_ADDRESS,
      abi: BATCH_ABI,
      functionName: "batchCommit",
      args: [CONTRACT_ADDRESS, commitments],
      account: wallet.account,
    });
    const hash = await wallet.writeContract({
      address: BATCH_HELPER_ADDRESS,
      abi: BATCH_ABI,
      functionName: "batchCommit",
      args: [CONTRACT_ADDRESS, commitments],
      nonce: handle.nonce,
      gas: gasEstimate * 120n / 100n,
    });
    // Wait for receipt and verify success
    const commitReceipt = await commitClient.waitForTransactionReceipt({ hash, timeout: 60_000 });
    if (commitReceipt.status === "reverted") {
      throw new Error(`batchCommit tx reverted: ${hash}`);
    }
    const now = Date.now();
    for (const item of items) {
      db.prepare("UPDATE create_queue SET status = 'committed', updatedAt = ? WHERE id = ?").run(now, item.id);
    }
    console.log(`[queue] batchCommit: ${items.length} items confirmed`);
  } catch (err) {
    handle.release();
    console.warn(`[queue] batchCommit failed: ${err instanceof Error ? err.message : err}`);
  }
}

const FAILURE_ALERT_BATCH = 10;
let failuresSinceLastAlert = 0;

function handleFailure(item: QueueItem, error: string, retryStatus: "pending" | "committed" = "pending") {
  const retries = item.retries + 1;
  if (retries >= MAX_RETRIES) {
    db.prepare("UPDATE create_queue SET status = 'failed', error = ?, retries = ?, updatedAt = ? WHERE id = ?")
      .run(error, retries, Date.now(), item.id);
    console.error(`[queue] Item ${item.id} permanently failed after ${retries} attempts: ${error}`);
  } else {
    const delay = Math.min(5000 * Math.pow(3, retries - 1), 12 * 60 * 60_000);
    const retryAfter = Date.now() + delay;
    db.prepare("UPDATE create_queue SET status = ?, error = ?, retries = ?, retryAfter = ?, updatedAt = ? WHERE id = ?")
      .run(retryStatus, error, retries, retryAfter, Date.now(), item.id);
    console.warn(`[queue] Item ${item.id} failed (retry ${retries}/${MAX_RETRIES}, next in ${delay / 1000}s, reset to ${retryStatus}): ${error}`);
  }

  failuresSinceLastAlert++;
  if (failuresSinceLastAlert >= FAILURE_ALERT_BATCH) {
    const failed = (db.prepare("SELECT COUNT(*) as count FROM create_queue WHERE status = 'failed'").get() as unknown as { count: number }).count;
    sendTelegram(cfg(), `🔴 [webauthnp256-publickey-index] [Deno] [Gnosis]\n${failuresSinceLastAlert} tx failures since last alert\nTotal permanently failed: ${failed}\nLatest error: ${error}`);
    failuresSinceLastAlert = 0;
  }
}
