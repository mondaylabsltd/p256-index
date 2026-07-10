/**
 * Shared queue types, constants, and pure logic.
 * Used by both Deno (node:sqlite) and CF Worker (D1) queue implementations.
 */
import { createWalletClient, createPublicClient, http, keccak256, encodeAbiParameters } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { gnosis } from "viem/chains";
import { getWriteRpc } from "./rpc.ts";
import { classifyError } from "./reliability.ts";
import { log } from "./log.ts";

// --- Types ---

// NOTE: 'creating' is legacy (rolling-upgrade safety net — see queue-engine
// processCreating); no new rows enter it. A former 'committing' member had no
// readers or writers anywhere and was removed.
export type QueueStatus = "pending" | "committed" | "creating" | "done" | "failed";

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

// --- Constants ---

export const MAX_RETRIES = 10;
export const WORKER_INTERVAL = 60_000;
export const QUERY_BATCH_SIZE = 100;
export const TX_BATCH_SIZE = 50;
export const RATE_WINDOW = 60_000;
export const DEFAULT_RATE_LIMIT = 5;
// GLOBAL write cap across ALL clients in a 60s window. The per-IP limit can be
// evaded (IP spoofing / botnets), and every create costs the server real gas
// (xDAI). This caps the TOTAL create rate so the worst-case gas burn is bounded
// and operator-tunable, instead of unbounded. Counted via the shared queue
// table so it holds across instances/isolates.
export const GLOBAL_WRITE_WINDOW = 60_000;
// Default 40/min (was 120): the pipeline's measured drain is ~40-60 items/min
// (sub-batch receipt waits serialize); admitting 120/min let a sustained flood
// legally build an hours-long backlog until the 10k shed. Tunable via the
// GLOBAL_WRITE_LIMIT env (Deno) / binding (CF) — raise it together with
// TX_BATCH_SIZE/interval if real traffic ever approaches it.
export const DEFAULT_GLOBAL_WRITE_LIMIT = 40;
export const MAX_GAS_PRICE_GWEI = 0.1;
export const GAS_BALANCE_THRESHOLD = 0.01;
export const FUND_THRESHOLD = 0.005;
export const FUND_AMOUNT = 0.05;
export const DONE_RETENTION = 7 * 24 * 60 * 60_000;
// DLQ ('failed') rows are kept for inspection/replay but bounded so they can't
// grow forever. 30 days is ample for an operator to triage a poison/exhausted item.
export const FAILED_RETENTION = 30 * 24 * 60 * 60_000;
export const CREATE_SUB_BATCH = 10;

// --- Table DDL ---

export const CREATE_QUEUE_DDL = `
  CREATE TABLE IF NOT EXISTS create_queue (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'pending',
    rpId TEXT NOT NULL,
    credentialId TEXT NOT NULL,
    walletRef TEXT NOT NULL DEFAULT '',
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
`;

// Idempotency: at most one ACTIVE (non-failed) row per (rpId, credentialId).
// This closes the race between findDuplicate's SELECT and enqueue's INSERT that
// previously let two concurrent identical POSTs create duplicate queue rows
// (which then poisoned the whole on-chain batch with RecordAlreadyExists).
// Partial index so a NEW attempt is still allowed after a row goes 'failed'.
export const CREATE_ACTIVE_UNIQUE_INDEX =
  "CREATE UNIQUE INDEX IF NOT EXISTS idx_queue_active_unique ON create_queue(rpId, credentialId) WHERE status != 'failed'";

// Migration safety: existing DBs may already contain duplicate active rows (from
// the pre-fix behaviour). Keep the BEST active row per (rpId, credentialId) and
// demote the rest to 'failed' so the unique index can be built. "Best" =
// already-on-chain ('done') beats anything (never lose a recorded success),
// then newest createdAt, then id as a deterministic tiebreak. Idempotent: a
// no-op once no active duplicates remain. Bind param: now (updatedAt).
export const DEDUPE_ACTIVE_DUPLICATES_SQL = `
  UPDATE create_queue SET status = 'failed', error = 'superseded-duplicate', updatedAt = ?
  WHERE status != 'failed' AND EXISTS (
    SELECT 1 FROM create_queue n
    WHERE n.rpId = create_queue.rpId AND n.credentialId = create_queue.credentialId
      AND n.status != 'failed' AND n.id != create_queue.id
      AND (
        (n.status = 'done') > (create_queue.status = 'done')
        OR ((n.status = 'done') = (create_queue.status = 'done')
            AND (n.createdAt > create_queue.createdAt
              OR (n.createdAt = create_queue.createdAt AND n.id > create_queue.id)))
      )
  )
`;

/** True when an error is a unique-constraint violation (duplicate active row). */
export function isUniqueConstraintError(err: unknown): boolean {
  const msg = (err instanceof Error ? err.message : String(err)).toLowerCase();
  return msg.includes("unique constraint") || msg.includes("constraint failed");
}

// --- Queue worker pure decision helpers (testable without a chain) ---

/** A multicall-style result row (viem returns { status, result } per call). */
export interface CallResult { status: "success" | "failure"; result?: unknown; error?: unknown }

/**
 * Split items by an aligned `hasRecord` multicall result into those already
 * present on-chain (→ mark done) and those genuinely missing (→ must submit).
 * Used for reconciliation BEFORE re-sending createRecord so a record that
 * already landed (duplicate / receipt-timeout-but-succeeded) does not revert
 * the whole batch.
 */
export function splitByHasRecord<T>(items: T[], results: CallResult[]): { present: T[]; missing: T[] } {
  const present: T[] = [];
  const missing: T[] = [];
  for (let i = 0; i < items.length; i++) {
    const r = results[i];
    if (r && r.status === "success" && r.result) present.push(items[i]);
    else missing.push(items[i]);
  }
  return { present, missing };
}

/**
 * Decide how to handle a failed batch WRITE (commit / createRecord):
 * - "retry-transient": an RPC/timeout/gas hiccup — the whole batch is fine,
 *   apply backoff and retry later.
 * - "isolate-poison": a deterministic revert — at least one item is poison;
 *   re-check items individually, quarantine the culprit(s), let the rest pass.
 */
export function batchFailureAction(err: unknown): "retry-transient" | "isolate-poison" {
  return classifyError(err, "rpc-write").category === "transient" ? "retry-transient" : "isolate-poison";
}

/** Exponential backoff for a failed queue item (full of jitter-free determinism for tx scheduling). */
export function retryDelayMs(retries: number): number {
  return Math.min(5000 * Math.pow(3, retries - 1), 12 * 60 * 60_000);
}

// --- User-conflict classification (deterministic reverts that are NOT bugs) ---

// Contract reverts caused by the USER's input conflicting with on-chain state.
// These are deterministic (poison-class) but need NO developer: the fix is on
// the client side (the passkey/credential is already registered). Matched both
// by decoded error name (ABI knows the error) and by raw 4-byte selector (an
// RPC/ABI that can't decode it — the exact failure shape seen in production).
const RECORD_EXISTS_SIGNATURES = ["RecordAlreadyExists", "0x46a08bc5"];
const WALLET_REF_EXISTS_SIGNATURES = ["WalletRefAlreadyExists", "0xc9af4506"];

/**
 * RecordAlreadyExists: the EXACT (rpId, credentialId) is already on-chain —
 * the revert itself proves the user's create succeeded. Treat as done.
 */
export function isRecordExistsError(err: unknown): boolean {
  const text = err instanceof Error ? err.message : String(err);
  return RECORD_EXISTS_SIGNATURES.some((s) => text.includes(s));
}

/**
 * WalletRefAlreadyExists: the same P256 public key is already registered under
 * a DIFFERENT credential. Deterministic, but a client-side conflict — not a
 * code bug, not a funding problem. Quarantined as "CONFLICT:" (visible in the
 * DLQ + status endpoint) WITHOUT paging the developer.
 */
export function isWalletRefConflictError(err: unknown): boolean {
  const text = err instanceof Error ? err.message : String(err);
  return WALLET_REF_EXISTS_SIGNATURES.some((s) => text.includes(s));
}

// --- Daily heartbeat (alert-channel observability) ---

// A silent Telegram channel is indistinguishable from a broken one. A daily
// heartbeat makes "no news" verifiable: if the daily message stops arriving,
// something is wrong (process, chain reads, or the Telegram path itself) —
// discovered within a day instead of at the next incident. It also carries the
// PROACTIVE funding signal (runway) so top-ups happen before the 🪫 threshold.
export const HEARTBEAT_INTERVAL = 24 * 60 * 60_000;

// Rough all-in gas per create (commit share + createRecord share). Only used
// for the runway ESTIMATE in the heartbeat — never for real gas decisions.
export const EST_GAS_PER_CREATE = 300_000n;

export interface HeartbeatInput {
  runtime: string;              // "Deno" | "CF Worker"
  queueDepth: number;
  dlqCount: number;
  createAddress: string;
  createBalanceXdai: number;
  commitAddress: string;
  commitBalanceXdai: number;
  gasPriceGwei: number;
  uptimeMs: number;
  release?: string;
}

/** Estimated number of creates the balance can still pay for at a gas price. */
export function estimateCreateRunway(balanceXdai: number, gasPriceGwei: number): number {
  if (gasPriceGwei <= 0) return Infinity;
  // Multiply before dividing: balance(gwei) / per-create(gwei) keeps clean
  // ratios exact (0.3 xDAI @ 1 gwei → 1000, not 999 via float 3e-4).
  return Math.floor((balanceXdai * 1e9) / (Number(EST_GAS_PER_CREATE) * gasPriceGwei));
}

export function buildHeartbeatMessage(h: HeartbeatInput): string {
  const runway = estimateCreateRunway(h.createBalanceXdai, h.gasPriceGwei);
  const runwayText = runway === Infinity ? "∞" : `~${runway}`;
  const upHours = Math.floor(h.uptimeMs / 3_600_000);
  const upText = upHours >= 48 ? `${Math.floor(upHours / 24)}d` : `${upHours}h`;
  const attention = h.dlqCount > 0 ? `⚠️ DLQ has ${h.dlqCount} item(s) — inspect when convenient\n` : "";
  return (
    `💓 [webauthnp256-publickey-index] [${h.runtime}] [Gnosis] daily heartbeat\n` +
    attention +
    `queue: ${h.queueDepth} active, ${h.dlqCount} DLQ\n` +
    `create wallet ${h.createAddress}: ${h.createBalanceXdai.toFixed(6)} xDAI (${runwayText} creates @ ${h.gasPriceGwei.toFixed(3)} gwei)\n` +
    `commit wallet ${h.commitAddress}: ${h.commitBalanceXdai.toFixed(6)} xDAI\n` +
    `up ${upText}${h.release ? `, release ${h.release}` : ""}`
  );
}

// --- Pure helpers ---

// IP hashes are stored for rate-limiting. SHA-256(ip) truncated to 64 bits is
// trivially reversible — IPv4 is only 2^32, so a DB leak lets an attacker
// brute-force every address back to the raw IP. A server-secret salt makes the
// hash unrecoverable without the secret (true GDPR pseudonymisation).
let ipHashSalt = "";
/** Set the per-deployment IP-hash salt (a server secret, e.g. derived from PRIVATE_KEY). */
export function setIpHashSalt(salt: string): void {
  ipHashSalt = salt;
}

/**
 * Derive the IP-hash salt from the deployment secret instead of using the raw
 * funds-controlling PRIVATE_KEY as salt material (key-hygiene: the signing key
 * should never feed unrelated hash paths).
 */
export async function deriveIpSalt(secret: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`ip-salt\0${secret}`));
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function hashIp(ip: string): Promise<string> {
  const data = new TextEncoder().encode(`${ipHashSalt}\0${ip}`);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("").slice(0, 16);
}

export function buildCommitment(item: QueueItem) {
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

// --- Wallet helpers ---

export interface AppConfig {
  privateKey: string;
  commitPrivateKey: string;
  telegramBotToken: string;
  telegramChatId: string;
}

// Explicit transport budget for write-path clients. Without this they fell back
// to viem's defaults (10s × retryCount 3 ≈ 40s), and balance/gas calls in the
// best-effort alerting path could dominate the single-flight worker's wall time.
const WRITE_TRANSPORT = { timeout: 8_000, retryCount: 1 } as const;

export function getCreateWallet(config: AppConfig) {
  const pk = config.privateKey;
  if (!pk) throw new Error("Missing env: PRIVATE_KEY");
  const rpcUrl = getWriteRpc();
  return {
    wallet: createWalletClient({
      account: privateKeyToAccount(pk as `0x${string}`),
      chain: gnosis,
      transport: http(rpcUrl, WRITE_TRANSPORT),
    }),
    client: createPublicClient({ chain: gnosis, transport: http(rpcUrl, WRITE_TRANSPORT) }),
  };
}

export function getCommitWallet(config: AppConfig) {
  const pk = config.commitPrivateKey;
  if (!pk) throw new Error("Missing env: COMMIT_PRIVATE_KEY or PRIVATE_KEY");
  const rpcUrl = getWriteRpc();
  return {
    wallet: createWalletClient({
      account: privateKeyToAccount(pk as `0x${string}`),
      chain: gnosis,
      transport: http(rpcUrl, WRITE_TRANSPORT),
    }),
    client: createPublicClient({ chain: gnosis, transport: http(rpcUrl, WRITE_TRANSPORT) }),
  };
}

// --- Telegram ---

const TELEGRAM_TIMEOUT = 5_000;

let warnedNoTelegram = false;
export async function sendTelegram(config: AppConfig, message: string): Promise<void> {
  const { telegramBotToken: botToken, telegramChatId: chatId } = config;
  if (!botToken || !chatId) {
    // Alerting is the operator's only eyes on this unattended fund-spending
    // queue. A missing channel is itself worth one loud log (once) so a
    // deploy without TELEGRAM_* doesn't run blind and silent.
    if (!warnedNoTelegram) {
      warnedNoTelegram = true;
      log.warn("Telegram NOT configured — operator alerts will not be delivered", { dependency: "telegram", operation: "config", outcome: "unconfigured" });
    }
    return;
  }
  try {
    // Bounded: a hung Telegram API must never stall the single-flight queue
    // worker / Durable Object alarm (which awaits this during checkAlerts).
    const res = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: chatId, text: message }),
      signal: AbortSignal.timeout(TELEGRAM_TIMEOUT),
    });
    // A 4xx (bad token / wrong chat id) does NOT throw — surface it so a
    // silently-misconfigured alert channel is discoverable instead of every
    // alert vanishing without a trace. redactSecrets (in log.emit) strips the
    // bot token before this line is written.
    if (!res.ok) {
      log.warn("telegram alert delivery failed", { dependency: "telegram", operation: "sendMessage", outcome: "failed", http_status: res.status });
    }
  } catch (err) {
    // Delivery error (timeout / network) — best-effort, never affects the caller,
    // but no longer completely silent.
    log.warn("telegram alert delivery error", { dependency: "telegram", operation: "sendMessage", outcome: "error", error: err instanceof Error ? err.message : String(err) });
  }
}
