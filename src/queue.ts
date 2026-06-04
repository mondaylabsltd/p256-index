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
const BATCH_SIZE = 100;

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
const MAX_GAS_PRICE_GWEI = 0.01;
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
      const FUND_THRESHOLD = 0.005; // xDAI
      const FUND_AMOUNT = 0.02;     // xDAI
      if (commitBalanceXdai < FUND_THRESHOLD && balanceXdai > FUND_AMOUNT + GAS_BALANCE_THRESHOLD) {
        console.log(`[queue] Auto-funding commit wallet: ${commitBalanceXdai.toFixed(6)} xDAI < ${FUND_THRESHOLD}, sending ${FUND_AMOUNT} xDAI`);
        try {
          const hash = await createWallet.sendTransaction({
            to: commitWallet.account.address,
            value: BigInt(Math.floor(FUND_AMOUNT * 1e18)),
          });
          console.log(`[queue] Funded commit wallet: ${hash}`);
        } catch (err) {
          console.warn(`[queue] Auto-fund failed:`, err instanceof Error ? err.message : err);
        }
      } else if (commitBalanceXdai < FUND_THRESHOLD) {
        alerts.push(`🪫 Commit wallet balance low: ${commitBalanceXdai.toFixed(6)} xDAI (${commitWallet.account.address}), main wallet too low to auto-fund`);
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
  setInterval(() => {
    if (workerRunning) return;
    processQueue().catch((err) => console.error("[queue] Worker error:", err));
  }, WORKER_INTERVAL);
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
    await checkAlerts();
  } finally {
    workerRunning = false;
  }
}

// Phase 1: Verify items in 'creating' status — check hasRecord on-chain
async function processCreating() {
  const items = db.prepare(
    "SELECT * FROM create_queue WHERE status = 'creating' ORDER BY createdAt ASC LIMIT ?"
  ).all(BATCH_SIZE) as unknown as QueueItem[];

  if (items.length === 0) return;

  const client = createPublicClient({ chain: gnosis, transport: http(getWriteRpc()) });
  for (const item of items) {
    try {
      const exists = await client.readContract({
        address: CONTRACT_ADDRESS,
        abi: CONTRACT_ABI,
        functionName: "hasRecord",
        args: [item.rpId, item.credentialId],
      });
      if (exists) {
        db.prepare("UPDATE create_queue SET status = 'done', error = '', updatedAt = ? WHERE id = ?").run(Date.now(), item.id);
        console.log(`[queue] Item ${item.id} confirmed on-chain, done`);
      } else {
        // Tx may still be pending; if stuck too long, retry
        const CREATING_TIMEOUT = 2 * 60_000; // 2 minutes
        if (Date.now() - item.updatedAt > CREATING_TIMEOUT) {
          // Reset to committed to re-send createRecord
          handleFailure(item, "createRecord tx not confirmed after 2min", "committed");
        }
      }
    } catch {
      // RPC error, skip — will retry next cycle
    }
  }
}

// Phase 2: Advance committed items — check reveal delay, fire createRecord (no wait)
async function processCommitted() {
  const items = db.prepare(
    "SELECT * FROM create_queue WHERE status = 'committed' AND retryAfter <= ? ORDER BY createdAt ASC LIMIT ?"
  ).all(Date.now(), BATCH_SIZE) as unknown as QueueItem[];

  if (items.length === 0) return;

  const client = createPublicClient({ chain: gnosis, transport: http(getWriteRpc()) });
  const currentBlock = await client.getBlockNumber();
  const ready: QueueItem[] = [];
  for (const item of items) {
    const { commitment } = buildCommitment(item);
    try {
      const commitBlock = await client.readContract({
        address: CONTRACT_ADDRESS,
        abi: CONTRACT_ABI,
        functionName: "getCommitBlock",
        args: [commitment],
      });
      if (commitBlock > 0n && currentBlock >= commitBlock + 1n) {
        ready.push(item);
      } else if (commitBlock === 0n) {
        // Check if record already exists on-chain
        const exists = await client.readContract({
          address: CONTRACT_ADDRESS,
          abi: CONTRACT_ABI,
          functionName: "hasRecord",
          args: [item.rpId, item.credentialId],
        });
        if (exists) {
          db.prepare("UPDATE create_queue SET status = 'done', error = '', updatedAt = ? WHERE id = ?").run(Date.now(), item.id);
          console.log(`[queue] Item ${item.id} already on-chain, marking done`);
        } else {
          const COMMIT_COOLDOWN = 2 * 60_000;
          if (Date.now() - item.updatedAt < COMMIT_COOLDOWN) {
            // Commit tx may still be pending, wait
          } else {
            db.prepare("UPDATE create_queue SET status = 'pending', updatedAt = ? WHERE id = ?").run(Date.now(), item.id);
            console.warn(`[queue] Item ${item.id} commitment missing after ${COMMIT_COOLDOWN / 1000}s, resetting to pending`);
          }
        }
      }
    } catch {
      // RPC error, skip — will retry next cycle
    }
  }

  if (ready.length === 0) return;
  console.log(`[queue] Sending ${ready.length} createRecord txs...`);

  // Fire all createRecord txs — no waiting for receipt (verified in processCreating)
  const results = await Promise.allSettled(
    ready.map((item) => fireCreateRecord(item))
  );

  for (let i = 0; i < ready.length; i++) {
    const result = results[i];
    if (result.status === "fulfilled") {
      db.prepare("UPDATE create_queue SET status = 'creating', txHash = ?, updatedAt = ? WHERE id = ?")
        .run(result.value, Date.now(), ready[i].id);
    } else {
      handleFailure(ready[i], result.reason?.message ?? "createRecord send failed", "committed");
    }
  }
}

// Phase 3: Send commit txs for pending items (no waiting for receipt)
async function processPending() {
  const items = db.prepare(
    "SELECT * FROM create_queue WHERE status = 'pending' AND retryAfter <= ? ORDER BY createdAt ASC LIMIT ?"
  ).all(Date.now(), BATCH_SIZE) as unknown as QueueItem[];

  if (items.length === 0) return;
  console.log(`[queue] Sending ${items.length} commit txs...`);

  // Fire all commit txs — no waiting for receipt (verified by getCommitBlock in processCommitted)
  const results = await Promise.allSettled(
    items.map((item) => fireCommit(item))
  );

  for (let i = 0; i < items.length; i++) {
    const result = results[i];
    if (result.status === "fulfilled") {
      // fulfilled = tx sent (or already committed). Mark 'committed', processCommitted will verify.
      db.prepare("UPDATE create_queue SET status = 'committed', updatedAt = ? WHERE id = ?").run(Date.now(), items[i].id);
    } else {
      handleFailure(items[i], result.reason?.message ?? "commit send failed");
    }
  }
}

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
}

// --- On-chain operations ---

import { createWalletClient, createPublicClient, http, keccak256, encodeAbiParameters } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { gnosis } from "viem/chains";
import { getWriteRpc } from "./rpc.ts";
import { getConfig } from "./config.ts";
import { CONTRACT_ADDRESS, CONTRACT_ABI } from "./contract.ts";
import { acquireNonce, resetNonce } from "./nonce.ts";

const writeAbi = [
  {
    type: "function",
    name: "commit",
    inputs: [{ name: "commitment", type: "bytes32" }],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "createRecord",
    inputs: [
      { name: "rpId", type: "string" },
      { name: "credentialId", type: "string" },
      { name: "walletRef", type: "bytes32" },
      { name: "publicKey", type: "bytes" },
      { name: "name", type: "string" },
      { name: "initialCredentialId", type: "string" },
      { name: "metadata", type: "bytes" },
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

/** Send commit tx (commit wallet), return immediately (no receipt wait). */
async function fireCommit(item: QueueItem): Promise<void> {
  const { wallet, client } = getCommitWallet();
  const { commitment } = buildCommitment(item);

  // Skip if already committed on-chain
  const commitBlock = await client.readContract({
    address: CONTRACT_ADDRESS,
    abi: CONTRACT_ABI,
    functionName: "getCommitBlock",
    args: [commitment],
  });
  if (commitBlock > 0n) {
    console.log(`[queue] Item ${item.id} already committed at block ${commitBlock}, skipping`);
    return;
  }

  const nonce = await acquireNonce("commit");
  try {
    await wallet.writeContract({
      address: CONTRACT_ADDRESS,
      abi: writeAbi,
      functionName: "commit",
      args: [commitment],
      nonce,
    });
  } catch (err) {
    resetNonce("commit");
    throw err;
  }
}

/** Send createRecord tx (create wallet), return txHash immediately (no receipt wait). */
async function fireCreateRecord(item: QueueItem): Promise<string> {
  const { wallet } = getCreateWallet();
  const { walletRefHex, publicKeyHex, metadataHex } = buildCommitment(item);

  const nonce = await acquireNonce("create");
  try {
    const hash = await wallet.writeContract({
      address: CONTRACT_ADDRESS,
      abi: writeAbi,
      functionName: "createRecord",
      args: [item.rpId, item.credentialId, walletRefHex, publicKeyHex, item.name, item.initialCredentialId, metadataHex],
      nonce,
    });
    return hash;
  } catch (err) {
    resetNonce("create");
    throw err;
  }
}
