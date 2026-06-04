import { DatabaseSync as Database } from "node:sqlite";

// --- Types ---

export type QueueStatus = "pending" | "committing" | "committed" | "creating" | "done" | "failed";

export interface QueueItem {
  id: string;
  status: QueueStatus;
  rpId: string;
  credentialId: string;
  walletRef: string;
  publicKey: string;
  name: string;
  initialCredentialId: string;
  metadata: string;
  txHash: string;
  error: string;
  retries: number;
  retryAfter: number;
  ip: string;
  createdAt: number;
  updatedAt: number;
}

// --- Config ---

const MAX_RETRIES = 10;
const WORKER_INTERVAL = 2000; // 2s
const QUERY_BATCH_SIZE = 100;  // multicall queries — can be large
const TX_BATCH_SIZE = 50;      // items per batch tx (batchCommit/batchCreateRecord handles all in 1 tx)

// --- Rate Limiting ---

const RATE_WINDOW = 60_000; // 1 minute
let RATE_LIMIT = 5; // max requests per IP per window

/** Override rate limit (for testing only). */
export function _setRateLimitForTest(limit: number): void {
  RATE_LIMIT = limit;
}
const ipRequests = new Map<string, number[]>(); // ip -> timestamps

async function hashIp(ip: string): Promise<string> {
  const data = new TextEncoder().encode(ip);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("").slice(0, 16);
}

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
  db.exec(`
    CREATE TABLE IF NOT EXISTS create_queue (
      id TEXT PRIMARY KEY,
      status TEXT NOT NULL DEFAULT 'pending',
      rpId TEXT NOT NULL,
      credentialId TEXT NOT NULL,
      walletRef TEXT NOT NULL,
      publicKey TEXT NOT NULL,
      name TEXT NOT NULL,
      initialCredentialId TEXT NOT NULL,
      metadata TEXT NOT NULL,
      txHash TEXT NOT NULL DEFAULT '',
      error TEXT NOT NULL DEFAULT '',
      retries INTEGER NOT NULL DEFAULT 0,
      retryAfter INTEGER NOT NULL DEFAULT 0,
      ip TEXT NOT NULL DEFAULT '',
      createdAt INTEGER NOT NULL,
      updatedAt INTEGER NOT NULL
    )
  `);
  db.exec("CREATE INDEX IF NOT EXISTS idx_queue_status ON create_queue(status)");

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

function generateId(): string {
  return crypto.randomUUID();
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
  const id = generateId();
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

const ALERT_INTERVAL = 5 * 60_000; // check every 5 minutes
const QUEUE_BACKLOG_THRESHOLD = 100;
const GAS_BALANCE_THRESHOLD = 0.01; // xDAI
const MAX_GAS_PRICE_GWEI = 0.1;
let lastAlertAt = 0;
let lastFailedCount = 0; // only alert when failed count changes

async function sendTelegram(message: string): Promise<void> {
  const { telegramBotToken: botToken, telegramChatId: chatId } = getConfig();
  if (!botToken || !chatId) return;
  try {
    await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: chatId, text: message }),
    });
  } catch { /* ignore send failures */ }
}

const DONE_RETENTION = 7 * 24 * 60 * 60_000; // 7 days

function cleanupDoneRecords(): void {
  const cutoff = Date.now() - DONE_RETENTION;
  const result = db.prepare("DELETE FROM create_queue WHERE status = 'done' AND updatedAt < ?").run(cutoff);
  const deleted = (result as unknown as { changes: number }).changes;
  if (deleted > 0) console.log(`[queue] Cleaned up ${deleted} done records older than 7 days`);
}

async function checkAlerts(): Promise<void> {
  const now = Date.now();
  if (now - lastAlertAt < ALERT_INTERVAL) return;
  lastAlertAt = now;

  const alerts: string[] = [];

  // 1. Queue backlog
  const pending = (db.prepare("SELECT COUNT(*) as count FROM create_queue WHERE status IN ('pending', 'committing', 'committed', 'creating')").get() as unknown as { count: number }).count;
  if (pending >= QUEUE_BACKLOG_THRESHOLD) {
    alerts.push(`⚠️ Queue backlog: ${pending} items pending`);
  }

  // 2. Failed items needing manual intervention (only alert on change)
  const failed = (db.prepare("SELECT COUNT(*) as count FROM create_queue WHERE status = 'failed'").get() as unknown as { count: number }).count;
  if (failed > 0 && failed !== lastFailedCount) {
    alerts.push(`🔴 ${failed} items permanently failed, need manual intervention`);
  }
  lastFailedCount = failed;

  // 3. Gas balance + gas price check (use write RPC for reliability)
  try {
    const { wallet: createWallet, client } = getCreateWallet();
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

    // Auto-fund commit wallet if balance is low (transfer from create wallet)
    const { wallet: commitWallet } = getCommitWallet();
    if (commitWallet.account.address !== createWallet.account.address) {
      const commitBalance = await client.getBalance({ address: commitWallet.account.address });
      const commitBalanceXdai = Number(commitBalance) / 1e18;
      if (commitBalanceXdai < FUND_THRESHOLD) {
        await ensureCommitWalletFunded();
      }
    }
  } catch { /* ignore check failures */ }

  if (alerts.length > 0) {
    await sendTelegram(`[webauthnp256-publickey-index]\n${alerts.join("\n")}`);
  }
}

// --- Worker ---

let workerRunning = false;

export function startQueueWorker() {
  console.log("[queue] Worker started, interval: 2s");
  // Ensure commit wallet is funded before first cycle
  ensureCommitWalletFunded().catch(() => {});
  setInterval(() => {
    if (workerRunning) return;
    processQueue().catch((err) => console.error("[queue] Worker error:", err));
  }, WORKER_INTERVAL);
}

const FUND_THRESHOLD = 0.005; // xDAI
const FUND_AMOUNT = 0.05;     // xDAI

async function ensureCommitWalletFunded(): Promise<void> {
  try {
    const { wallet: createWallet, client } = getCreateWallet();
    const { wallet: commitWallet } = getCommitWallet();
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
    // Wait for fund tx to be confirmed
    await client.waitForTransactionReceipt({ hash, timeout: 30_000 });
    console.log(`[queue] Commit wallet funded: ${hash}`);
  } catch (err) {
    console.warn(`[queue] Auto-fund failed:`, err instanceof Error ? err.message : err);
  }
}

async function processQueue() {
  workerRunning = true;
  try {
    // Check gas price using write RPC (known-good, not the rotating public list)
    try {
      const writeClient = createPublicClient({ chain: gnosis, transport: http(getWriteRpc()) });
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

    // Priority order: verify creating → advance committed → send pending commits
    // Items closest to done get processed first; nonces prioritize createRecord over commit.
    await processCreating();
    await processCommitted();
    await processPending();
    cleanupDoneRecords();
    await checkAlerts();
  } finally {
    workerRunning = false;
  }
}

// Phase 1: Verify items in 'creating' status — batch hasRecord via multicall
async function processCreating() {
  const items = db.prepare(
    "SELECT * FROM create_queue WHERE status = 'creating' ORDER BY createdAt ASC LIMIT ?"
  ).all(QUERY_BATCH_SIZE) as unknown as QueueItem[];

  if (items.length === 0) return;

  const client = createPublicClient({ chain: gnosis, transport: http(getWriteRpc()) });

  // Single multicall: check hasRecord for all items at once
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
      // result.status === "failure" → RPC error for this call, skip
    }
    if (doneCount > 0) console.log(`[queue] ${doneCount} items confirmed on-chain, done`);
  } catch {
    // Entire multicall failed (RPC error), retry next cycle
  }
}

// Phase 2: Advance committed items — batch getCommitBlock via multicall, fire createRecord
async function processCommitted() {
  const items = db.prepare(
    "SELECT * FROM create_queue WHERE status = 'committed' AND retryAfter <= ? ORDER BY createdAt ASC LIMIT ?"
  ).all(Date.now(), TX_BATCH_SIZE) as unknown as QueueItem[];

  if (items.length === 0) return;

  const client = createPublicClient({ chain: gnosis, transport: http(getWriteRpc()) });
  const currentBlock = await client.getBlockNumber();

  // Single multicall: check getCommitBlock for all items at once
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
  } catch {
    return; // multicall failed, retry next cycle
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
    // commitBlock > 0 but not enough delay → just wait
  }

  // Batch check hasRecord for items with commitBlock === 0 (maybe already on-chain or never committed)
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
    } catch { /* multicall failed, retry next cycle */ }
  }

  if (ready.length === 0) return;

  // Build params for batchCreateRecord
  const params = ready.map((item) => {
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

  // Single batchCreateRecord tx for all items — 1 nonce, no gaps
  const { wallet } = getCreateWallet();
  const handle = await acquireNonce("create");
  try {
    const hash = await wallet.writeContract({
      address: BATCH_HELPER_ADDRESS,
      abi: batchAbi,
      functionName: "batchCreateRecord",
      args: [CONTRACT_ADDRESS, params],
      nonce: handle.nonce,
    });
    // Mark all as creating
    const now = Date.now();
    for (const item of ready) {
      db.prepare("UPDATE create_queue SET status = 'creating', txHash = ?, updatedAt = ? WHERE id = ?")
        .run(hash, now, item.id);
    }
    console.log(`[queue] batchCreateRecord: ${ready.length} items in 1 tx`);
  } catch (err) {
    handle.release();
    console.warn(`[queue] batchCreateRecord failed: ${err instanceof Error ? err.message : err}`);
    // Items stay committed, will retry next cycle
  }
}

// Phase 3: Send commit txs for pending items (no waiting for receipt)
async function processPending() {
  const items = db.prepare(
    "SELECT * FROM create_queue WHERE status = 'pending' AND retryAfter <= ? ORDER BY createdAt ASC LIMIT ?"
  ).all(Date.now(), TX_BATCH_SIZE) as unknown as QueueItem[];

  if (items.length === 0) return;

  // Build all commitments
  const commitments = items.map((item) => buildCommitment(item).commitment);

  // Single batchCommit tx for all items — 1 nonce, no gaps
  const { wallet } = getCommitWallet();
  const handle = await acquireNonce("commit");
  try {
    await wallet.writeContract({
      address: BATCH_HELPER_ADDRESS,
      abi: batchAbi,
      functionName: "batchCommit",
      args: [CONTRACT_ADDRESS, commitments],
      nonce: handle.nonce,
    });
    // Mark all as committed
    const now = Date.now();
    for (const item of items) {
      db.prepare("UPDATE create_queue SET status = 'committed', updatedAt = ? WHERE id = ?").run(now, item.id);
    }
    console.log(`[queue] batchCommit: ${items.length} items in 1 tx`);
  } catch (err) {
    handle.release();
    console.warn(`[queue] batchCommit failed: ${err instanceof Error ? err.message : err}`);
    // Individual items will retry next cycle (still pending)
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
    // Exponential backoff: 5s, 15s, 45s, 2m, 6m, 20m, 1h, 3h, 9h, 12h
    const delay = Math.min(5000 * Math.pow(3, retries - 1), 12 * 60 * 60_000);
    const retryAfter = Date.now() + delay;
    db.prepare("UPDATE create_queue SET status = ?, error = ?, retries = ?, retryAfter = ?, updatedAt = ? WHERE id = ?")
      .run(retryStatus, error, retries, retryAfter, Date.now(), item.id);
    console.warn(`[queue] Item ${item.id} failed (retry ${retries}/${MAX_RETRIES}, next in ${delay / 1000}s, reset to ${retryStatus}): ${error}`);
  }

  failuresSinceLastAlert++;
  if (failuresSinceLastAlert >= FAILURE_ALERT_BATCH) {
    const failed = (db.prepare("SELECT COUNT(*) as count FROM create_queue WHERE status = 'failed'").get() as unknown as { count: number }).count;
    sendTelegram(`🔴 [webauthnp256-publickey-index] ${failuresSinceLastAlert} tx failures since last alert\nTotal permanently failed: ${failed}\nLatest error: ${error}`);
    failuresSinceLastAlert = 0;
  }
}

// --- On-chain operations ---

import { createWalletClient, createPublicClient, http, keccak256, encodeAbiParameters } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { gnosis } from "viem/chains";
import { getWriteRpc } from "./rpc.ts";
import { getConfig } from "./config.ts";
import { CONTRACT_ADDRESS, CONTRACT_ABI } from "./contract.ts";
import { acquireNonce } from "./nonce.ts";

const BATCH_HELPER_ADDRESS = "0xc7b0db5d4974aba3ea25780f40bf369cc013a16e" as const;

const batchAbi = [
  {
    type: "function",
    name: "batchCommit",
    inputs: [
      { name: "index", type: "address" },
      { name: "commitments", type: "bytes32[]" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "batchCreateRecord",
    inputs: [
      { name: "index", type: "address" },
      {
        name: "params",
        type: "tuple[]",
        components: [
          { name: "rpId", type: "string" },
          { name: "credentialId", type: "string" },
          { name: "walletRef", type: "bytes32" },
          { name: "publicKey", type: "bytes" },
          { name: "name", type: "string" },
          { name: "initialCredentialId", type: "string" },
          { name: "metadata", type: "bytes" },
        ],
      },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
] as const;

function getCreateWallet() {
  const pk = getConfig().privateKey;
  if (!pk) throw new Error("Missing env: PRIVATE_KEY");
  const rpcUrl = getWriteRpc();
  return {
    wallet: createWalletClient({
      account: privateKeyToAccount(pk as `0x${string}`),
      chain: gnosis,
      transport: http(rpcUrl),
    }),
    client: createPublicClient({ chain: gnosis, transport: http(rpcUrl) }),
  };
}

function getCommitWallet() {
  const pk = getConfig().commitPrivateKey;
  if (!pk) throw new Error("Missing env: COMMIT_PRIVATE_KEY or PRIVATE_KEY");
  const rpcUrl = getWriteRpc();
  return {
    wallet: createWalletClient({
      account: privateKeyToAccount(pk as `0x${string}`),
      chain: gnosis,
      transport: http(rpcUrl),
    }),
    client: createPublicClient({ chain: gnosis, transport: http(rpcUrl) }),
  };
}

function buildCommitment(item: QueueItem) {
  const walletRefHex = item.walletRef as `0x${string}`;
  const publicKeyHex = (item.publicKey.startsWith("0x") ? item.publicKey : `0x${item.publicKey}`) as `0x${string}`;
  const metadataHex = (item.metadata.startsWith("0x") ? item.metadata : `0x${item.metadata}`) as `0x${string}`;

  return {
    commitment: keccak256(
      encodeAbiParameters(
        [{ type: "string" }, { type: "string" }, { type: "bytes32" }, { type: "bytes" }, { type: "string" }, { type: "string" }, { type: "bytes" }],
        [item.rpId, item.credentialId, walletRefHex, publicKeyHex, item.name, item.initialCredentialId, metadataHex],
      ),
    ),
    walletRefHex,
    publicKeyHex,
    metadataHex,
  };
}

