/**
 * Unified queue state machine — SHARED by both runtimes.
 *
 * Previously this logic existed as two hand-synced ~600-line forks
 * (deno/queue.ts processQueue/... and worker/queue-processor.ts). Every
 * money-path production bug (receipt waits, batch poisoning, commit
 * oscillation) had to be fixed twice and could silently drift. This module is
 * the single implementation; the runtimes provide only storage (SQLite / D1),
 * chain access (viem), nonces, and alerting via the injected deps — which also
 * makes the whole state machine deterministically testable with a fake chain
 * (deno/tests/queue-engine.test.ts).
 *
 * DISCIPLINE: this is a behavior-preserving transcription of the prior
 * implementations. Invariants that MUST hold (see docs/project-takeover/03):
 * - Phase order: creating → committed → pending, then cleanup + alerts.
 * - Gas gate first; on gas-check failure alert BEFORE returning (P1-A fix).
 * - Nonces: acquired OUTSIDE the send try-block; consumed on successful send,
 *   release()d on any failure after acquisition (forces a chain resync).
 * - State advances ONLY after a successful receipt.
 * - reconcile (hasRecord) runs BEFORE re-sending createRecord.
 * - transient → backed-off retry via handleFailure; poison → per-item
 *   isolation; a failed multicall row is skipped (no state change).
 * - Error strings keep the "POISON:" / "EXHAUSTED:" operator interface.
 */

import {
  type QueueItem,
  type CallResult,
  MAX_RETRIES,
  QUERY_BATCH_SIZE,
  TX_BATCH_SIZE,
  MAX_GAS_PRICE_GWEI,
  DONE_RETENTION,
  FAILED_RETENTION,
  CREATE_SUB_BATCH,
  buildCommitment,
  splitByHasRecord,
  batchFailureAction,
  retryDelayMs,
  isRecordExistsError,
  isWalletRefConflictError,
} from "./queue.ts";
import type { NonceHandle, NonceRole } from "./nonce.ts";
import { log, redactSecrets } from "./log.ts";

const CREATING_TIMEOUT = 2 * 60_000;
const COMMIT_COOLDOWN = 2 * 60_000;
const RECEIPT_TIMEOUT = 60_000;
// Stuck-tx unstick sweep: a broadcast whose receipt never arrived within this
// age is checked and — if still absent from the chain — REPLACED with a
// same-nonce zero-value self-transfer at a bumped gas price. Without this, one
// underpriced/stuck tx jams the wallet's nonce sequence and every later send
// stacks behind it: creates stall for hours until a human intervenes.
const STUCK_TX_AGE_MS = 2 * 60_000;
const MAX_UNSTICK_PER_CYCLE = 5;
const UNSTICK_ALERT_ATTEMPTS = 5; // page after this many failed replacements of one nonce
const UNSTICK_ALERT_AGE_MS = 10 * 60_000; // ...or after a nonce has been stuck this long (cancel persistently rejected)
const CANCEL_GAS_NUM = 150n; // 150% of current network gas price
const CANCEL_GAS_DEN = 100n;

// ── Injected dependency interfaces ────────────────────────────────────────────

/** Persistence operations the engine needs. Implemented over SQLite (Deno) and D1 (CF). */
export interface QueueStore {
  /** COUNT of rows with status IN ('pending','committed','creating'). */
  countActive(): Promise<number>;
  /** status='creating' ORDER BY createdAt ASC LIMIT n. */
  listCreating(limit: number): Promise<QueueItem[]>;
  /** status='committed' AND retryAfter <= now ORDER BY createdAt ASC LIMIT n. */
  listCommittedReady(now: number, limit: number): Promise<QueueItem[]>;
  /** status='pending' AND retryAfter <= now ORDER BY createdAt ASC LIMIT n. */
  listPendingReady(now: number, limit: number): Promise<QueueItem[]>;
  /**
   * SET status='done', error='', updatedAt=now for every id; when txHash is
   * given also SET txHash (otherwise the column is left untouched).
   */
  markManyDone(ids: string[], now: number, txHash?: string): Promise<void>;
  /** SET status='committed', updatedAt=now for every id. */
  markManyCommitted(ids: string[], now: number): Promise<void>;
  /** Single-row failure/retry bookkeeping write. */
  applyFailure(id: string, fields: {
    status: string;       // 'failed' | retryStatus
    error: string;
    retries: number;
    retryAfter?: number;  // only on the retry path
    updatedAt: number;
  }): Promise<void>;
  /** DELETE done rows older than DONE_RETENTION and failed rows older than FAILED_RETENTION. */
  cleanupExpired(doneBefore: number, failedBefore: number): Promise<{ doneDeleted: number }>;
  /** Broadcast ledger for the unstick sweep: upsert an in-flight (role, nonce) → hash, with replacement attempt count. */
  recordPendingTx(role: NonceRole, nonce: number, hash: string, sentAt: number, attempts?: number): Promise<void>;
  /** Remove a ledger row once its tx is known to be mined (success OR reverted). */
  deletePendingTx(role: NonceRole, nonce: number): Promise<void>;
  /** Ledger rows older than the given sentAt timestamp (potentially stuck). */
  listPendingTxs(sentBefore: number): Promise<{ role: NonceRole; nonce: number; hash: `0x${string}`; sentAt: number; attempts: number }[]>;
}

/** Parameter tuple for batchCreateRecord, as consumed by the BatchHelper ABI. */
export interface BatchCreateParam {
  rpId: string;
  credentialId: string;
  walletRef: `0x${string}`;
  publicKey: `0x${string}`;
  name: string;
  initialCredentialId: string;
  metadata: `0x${string}`;
}

/**
 * Chain operations the engine needs. The real implementation
 * (shared/chain-viem.ts) owns RPC endpoint selection, timeouts, and — for
 * getGasPrice — write-endpoint cooldown marking. Fakes drive the tests.
 */
export interface ChainOps {
  /**
   * Called at the start of every phase. Adapters use it to pin ENDPOINT
   * AFFINITY for the phase: the pre-refactor code resolved the RPC endpoint
   * once per phase and reused it for estimate/send/receipt (and reads), so a
   * tx was never broadcast on endpoint A while its receipt was polled on
   * endpoint B (spurious timeouts → duplicate sends). Optional so fakes can
   * ignore it.
   */
  beginPhase?(): void;
  getGasPrice(): Promise<bigint>;
  getBlockNumber(): Promise<bigint>;
  /**
   * `via` restores the pre-refactor client mapping: "read" (default) = the
   * phase's read client (creating-phase + commit-block checks); "wallet" = the
   * create-wallet's client (reconcileReady ran on the SAME endpoint that the
   * subsequent send used, with the tighter WRITE_TRANSPORT budget).
   */
  hasRecordMulticall(items: Pick<QueueItem, "rpId" | "credentialId">[], via?: "read" | "wallet"): Promise<CallResult[]>;
  getCommitBlockMulticall(commitments: `0x${string}`[]): Promise<CallResult[]>;
  hasRecord(rpId: string, credentialId: string): Promise<boolean>;
  estimateBatchCreate(params: BatchCreateParam[]): Promise<bigint>;
  sendBatchCreate(params: BatchCreateParam[], nonce: number, gas: bigint): Promise<`0x${string}`>;
  estimateBatchCommit(commitments: `0x${string}`[]): Promise<bigint>;
  sendBatchCommit(commitments: `0x${string}`[], nonce: number, gas: bigint): Promise<`0x${string}`>;
  waitReceipt(hash: `0x${string}`, timeoutMs: number, role: NonceRole): Promise<{ status: "success" | "reverted" }>;
  /** Same-nonce zero-value self-transfer at an explicit gas price (stuck-tx replacement). */
  sendCancel(role: NonceRole, nonce: number, gasPrice: bigint): Promise<`0x${string}`>;
  /** On-chain confirmed ("latest") nonce count for the role's EOA — sweep ground truth. */
  getConfirmedNonce(role: NonceRole): Promise<number>;
}

/** Why the engine is invoking the runtime's alert check this time. */
export type AlertReason = "cycle-end" | "gas-high" | "gas-fail" | "idle";

export interface ItemFailureInfo {
  jobId: string;
  /** true when the item was quarantined to the DLQ (POISON, CONFLICT or EXHAUSTED). */
  terminal: boolean;
  /** true for deterministic POISON quarantines (code/data bug — dev must act). */
  poison: boolean;
  /**
   * true for USER-INPUT conflicts (e.g. the same P256 key already registered
   * under another credential → WalletRefAlreadyExists). Terminal and visible
   * in the DLQ/status endpoint, but NOT a developer page: there is no code or
   * funding fix — the resolution is on the client side.
   */
  conflict: boolean;
}

export interface EngineHooks {
  /**
   * Called after every persisted item failure (retry or DLQ). Runtimes use it
   * to drive Telegram alerts. `info.terminal` failures mean a user's create
   * request will NOT complete without developer intervention (POISON = code or
   * data bug; EXHAUSTED = an outage outlived every retry) — runtimes must
   * surface those IMMEDIATELY, not just via the batched counter.
   */
  onItemFailure?(errorText: string, info: ItemFailureInfo): void | Promise<void>;
  /**
   * Runtime alerting (backlog / DLQ change / balances / auto-funding).
   * Runs on EVERY cycle — including idle ones (reason "idle"), so a drained
   * wallet or growing DLQ is discovered while the queue is quiet instead of
   * hours later when the next user create arrives. Runtimes throttle
   * internally. `gasPriceGwei` is passed only on the gas-too-high branch;
   * `reason` "gas-fail" marks cycles skipped because the write RPC is
   * unreachable (runtimes alert after several consecutive ones).
   */
  checkAlerts?(gasPriceGwei: number | undefined, reason: AlertReason): Promise<void>;
  /**
   * A wallet nonce the unstick sweep has repeatedly failed to clear — genuine
   * dev-intervention condition (RPC rejecting replacements / gas cap too low).
   * Runtimes page Telegram (throttled).
   */
  onStuckTx?(role: NonceRole, nonce: number, attempts: number, ageMs: number): Promise<void>;
}

export interface QueueEngineDeps {
  store: QueueStore;
  chain: ChainOps;
  nonces: { acquire(role: NonceRole): Promise<NonceHandle> };
  hooks?: EngineHooks;
  /** Injectable clock for deterministic tests. Defaults to Date.now. */
  now?: () => number;
  /** Console log prefix ("[queue]" for Deno, "[queue-processor]" for CF). */
  label?: string;
}

function shortMsg(err: unknown): string {
  // Redact any embedded RPC credentials before this string is stored in the
  // queue 'error' column (surfaced to operators / the status endpoint) or logged.
  return redactSecrets(err instanceof Error ? err.message : String(err)).slice(0, 200);
}

// The broadcast-ledger writes must NEVER reroute a successful send/receipt into
// the batch-failure path: a store hiccup after a good broadcast would otherwise
// release a CONSUMED nonce and back off items whose tx is actually in flight.
// A swallowed RECORD failure leaves a jammed nonce with no row — the sweep's
// GAP FILL (nonces below an aged row) recovers it, and if even that can't
// (all rows for the role lost, which implies a broader store outage that the
// per-cycle error escalation already pages on), onItemFailure(terminal) still
// pages once queued items EXHAUST. A swallowed DELETE failure is harmless: the
// next sweep sees the nonce is consumed (< confirmed) and removes the row.
async function safeRecordPending(deps: QueueEngineDeps, role: NonceRole, nonce: number, hash: `0x${string}`, sentAt: number): Promise<void> {
  try { await deps.store.recordPendingTx(role, nonce, hash, sentAt); }
  catch (err) { log.warn("pending-tx ledger record failed (sweep will reconcile via confirmed nonce)", { operation: "ledger", role, nonce, error: shortMsg(err) }); }
}
async function safeDeletePending(deps: QueueEngineDeps, role: NonceRole, nonce: number): Promise<void> {
  try { await deps.store.deletePendingTx(role, nonce); }
  catch (err) { log.warn("pending-tx ledger delete failed (sweep will reconcile)", { operation: "ledger", role, nonce, error: shortMsg(err) }); }
}

// ── The cycle ─────────────────────────────────────────────────────────────────

/**
 * Run one full queue cycle. Mirrors the prior processQueue bodies exactly:
 * an unexpected throw from a phase propagates to the caller (which logs a
 * cycle error) and skips the remaining phases for this cycle — the next cycle
 * retries. The caller owns single-flight/alarm scheduling and cycle timing.
 */
export async function runQueueCycle(deps: QueueEngineDeps): Promise<void> {
  const now = deps.now ?? Date.now;
  const label = deps.label ?? "[queue]";

  // Skip gas price check and phases if nothing to process — but STILL run the
  // alert check: a drained wallet / growing DLQ / dead alert channel must be
  // discovered while the queue is quiet, not hours later when the next user
  // create arrives and silently stalls. (Runtimes throttle to one real check
  // per ALERT_INTERVAL, so idle cycles are near-free.)
  // Unstick FIRST — even on an otherwise-idle cycle a jammed nonce left by a
  // now-drained queue must be cleared (it self-guards, is a no-op with an empty
  // ledger, and never throws). Uses on-chain confirmed nonce as ground truth.
  await unstickPendingTxs(deps, now);

  const pending = await deps.store.countActive();
  if (pending === 0) {
    await cleanup(deps);
    await deps.hooks?.checkAlerts?.(undefined, "idle");
    return;
  }

  let gasPriceGwei: number;
  try {
    const gasPrice = await deps.chain.getGasPrice();
    gasPriceGwei = Number(gasPrice) / 1e9;
  } catch (err) {
    // The chain adapter has already cooled down the failing endpoint so the
    // next cycle rotates away from it. Surface the stall: run alerting BEFORE
    // returning so operators hear about backlog/balances/DLQ during the outage
    // instead of going completely dark for its whole duration.
    log.warn("write RPC gas-price check failed, skipping cycle", {
      dependency: "rpc", operation: "getGasPrice", error_category: "transient",
      error: shortMsg(err), queue_depth: pending,
    });
    await deps.hooks?.checkAlerts?.(undefined, "gas-fail");
    return;
  }

  if (gasPriceGwei > MAX_GAS_PRICE_GWEI) {
    console.warn(`${label} Gas price too high: ${gasPriceGwei.toFixed(4)} Gwei (max: ${MAX_GAS_PRICE_GWEI}), ${pending} items waiting`);
    await deps.hooks?.checkAlerts?.(gasPriceGwei, "gas-high");
    return;
  }

  await processCreating(deps, now, label);
  await processCommitted(deps, now, label);
  await processPending(deps, now, label);
  await cleanup(deps);
  await deps.hooks?.checkAlerts?.(undefined, "cycle-end");
}

/**
 * Reconcile the broadcast ledger and unjam genuinely-stuck nonces.
 *
 * GROUND TRUTH is the on-chain confirmed nonce count, NOT the recorded tx hash.
 * A nonce below the confirmed count is consumed — whatever tx won (the original,
 * a cancel, or an out-of-band tx) — so its ledger row is deleted unconditionally.
 * This is what makes the sweep zombie-proof: the earlier "did THIS hash mine?"
 * check left a row immortal if the original landed after a cancel was broadcast
 * (the cancel could then never mine → row never cleared → sweep budget starved).
 *
 * A nonce at/above the confirmed count that is still aged is genuinely pending:
 * replace it with a same-nonce zero-value self-transfer at an escalating gas
 * price (rises with attempts so a persistent jam eventually clears), and PAGE
 * the operator once attempts pass a threshold — a nonce that won't clear is a
 * dev-intervention condition. Runs every cycle incl. idle; never throws.
 */
async function unstickPendingTxs(deps: QueueEngineDeps, now: () => number): Promise<void> {
  let rows: { role: NonceRole; nonce: number; hash: `0x${string}`; sentAt: number; attempts: number }[];
  try {
    rows = await deps.store.listPendingTxs(now() - STUCK_TX_AGE_MS);
  } catch (err) {
    log.warn("unstick sweep: ledger read failed", { operation: "unstick", error: shortMsg(err) });
    return;
  }
  if (rows.length === 0) return; // idle / nothing aged → free

  // Confirmed on-chain nonce per role (one call per role present in the ledger).
  const confirmed: Partial<Record<NonceRole, number>> = {};
  for (const role of new Set(rows.map((r) => r.role))) {
    try {
      confirmed[role] = await deps.chain.getConfirmedNonce(role);
    } catch (err) {
      log.warn("unstick sweep: confirmed-nonce read failed for role", { operation: "unstick", role, error: shortMsg(err) });
      // Leave undefined → this role's rows are skipped safely this cycle.
    }
  }

  const stuck: typeof rows = [];
  for (const tx of rows) {
    const c = confirmed[tx.role];
    if (c === undefined) continue; // couldn't read — skip, retry next cycle
    if (tx.nonce < c) {
      // Nonce consumed — nothing is stuck here regardless of which hash won.
      try { await deps.store.deletePendingTx(tx.role, tx.nonce); } catch { /* retry next cycle */ }
    } else {
      stuck.push(tx); // nonce >= confirmed AND aged → genuinely jammed
    }
  }

  // GAP FILL: a broadcast whose ledger row was lost (a store write that
  // safeRecordPending swallowed) leaves a jammed nonce with NO row. If aged
  // rows sit ABOVE the confirmed nonce, the nonces between confirmed and the
  // lowest such row are — by mempool sequencing — occupied by unmined txs; any
  // that lack a row are exactly those lost jams. Synthesize entries so the
  // sweep replaces them too. (Bounded to below an aged row, so we never cancel
  // a nonce the pool is about to legitimately use.)
  for (const role of new Set(stuck.map((r) => r.role))) {
    const c = confirmed[role];
    if (c === undefined) continue;
    const known = new Set(rows.filter((r) => r.role === role).map((r) => r.nonce));
    const lowestStuck = Math.min(...stuck.filter((r) => r.role === role).map((r) => r.nonce));
    for (let n = c; n < lowestStuck; n++) {
      if (!known.has(n)) {
        stuck.push({ role, nonce: n, hash: "0x" as `0x${string}`, sentAt: now() - STUCK_TX_AGE_MS, attempts: 0 });
      }
    }
  }
  if (stuck.length === 0) return;

  // Lowest nonce first — a jam is cleared from the bottom (a higher nonce can't
  // mine until the one below it does).
  stuck.sort((a, b) => a.nonce - b.nonce);

  // Price the replacement off the CURRENT network gas, escalating with attempts.
  let networkGwei: number;
  try {
    networkGwei = Number(await deps.chain.getGasPrice()) / 1e9;
  } catch {
    return; // can't price a cancel now — next cycle
  }

  // The cancel must respect the operator's willingness-to-pay ceiling: never
  // spend more per-gas than the queue itself would (MAX_GAS_PRICE_GWEI). During
  // a spike above the cap the replacement may not clear until the spike passes —
  // that's the correct trade-off (onStuckTx pages by age below).
  const gasCapWei = BigInt(Math.round(MAX_GAS_PRICE_GWEI * 1e9));

  for (const tx of stuck.slice(0, MAX_UNSTICK_PER_CYCLE)) {
    const attempts = tx.attempts + 1;
    // 1.5x, 2.0x, 2.5x, … of current network price so a persistent jam clears.
    const factorNum = CANCEL_GAS_NUM + BigInt(attempts - 1) * 50n; // 150,200,250…
    let cancelGas = BigInt(Math.round(networkGwei * 1e9)) * factorNum / CANCEL_GAS_DEN;
    if (cancelGas > gasCapWei) cancelGas = gasCapWei;
    const ageMs = now() - tx.sentAt;
    try {
      const cancelHash = await deps.chain.sendCancel(tx.role, tx.nonce, cancelGas);
      // Success → track the cancel (new hash, reset age, bumped attempts).
      await deps.store.recordPendingTx(tx.role, tx.nonce, cancelHash, now(), attempts);
      log.warn("stuck tx replaced with same-nonce cancel", {
        operation: "unstick", outcome: "cancelled",
        role: tx.role, nonce: tx.nonce, stuck_hash: tx.hash, cancel_hash: cancelHash,
        attempts, stuck_age_ms: ageMs,
      });
    } catch (err) {
      // Cancel rejected (e.g. "replacement underpriced" when the stuck tx paid
      // above our gas cap). PERSIST the bumped attempt count while KEEPING the
      // original hash/sentAt so (a) the counter still climbs → escalation fires
      // even when cancels never land, and (b) age keeps growing.
      try { await deps.store.recordPendingTx(tx.role, tx.nonce, tx.hash, tx.sentAt, attempts); } catch { /* retry next cycle */ }
      log.warn("unstick attempt failed, will retry next cycle", {
        operation: "unstick", role: tx.role, nonce: tx.nonce, attempts, error: shortMsg(err),
      });
    }
    // Escalation: a nonce we've failed to clear for many attempts OR that has
    // been stuck a long time needs a human (RPC won't accept our replacement,
    // or the stuck tx out-prices our gas cap). Age-based too, so a cancel that
    // is persistently REJECTED (attempts stuck low) still eventually pages.
    if (attempts >= UNSTICK_ALERT_ATTEMPTS || ageMs >= UNSTICK_ALERT_AGE_MS) {
      await deps.hooks?.onStuckTx?.(tx.role, tx.nonce, attempts, ageMs);
    }
  }
}

async function cleanup(deps: QueueEngineDeps): Promise<void> {
  const now = (deps.now ?? Date.now)();
  const { doneDeleted } = await deps.store.cleanupExpired(now - DONE_RETENTION, now - FAILED_RETENTION);
  if (doneDeleted > 0) {
    console.log(`${deps.label ?? "[queue]"} Cleaned up ${doneDeleted} done records older than 7 days`);
  }
}

// ── Phase 1: legacy 'creating' reconciliation ────────────────────────────────
// No NEW item enters 'creating' (the flow goes committed→done directly);
// retained as a rolling-upgrade safety net so a row written 'creating' by an
// older build is confirmed on-chain (→ done) or failed out rather than stranded.
async function processCreating(deps: QueueEngineDeps, now: () => number, label: string): Promise<void> {
  deps.chain.beginPhase?.();
  const items = await deps.store.listCreating(QUERY_BATCH_SIZE);
  if (items.length === 0) return;

  try {
    const results = await deps.chain.hasRecordMulticall(items);
    const doneIds: string[] = [];
    for (let i = 0; i < items.length; i++) {
      const r = results[i];
      if (r.status === "success" && r.result) {
        doneIds.push(items[i].id);
      } else if (r.status === "success" && !r.result) {
        if (now() - items[i].updatedAt > CREATING_TIMEOUT) {
          await handleFailure(deps, now, items[i], "createRecord tx not confirmed after 2min", "committed");
        }
      }
    }
    if (doneIds.length > 0) {
      await deps.store.markManyDone(doneIds, now());
      console.log(`${label} ${doneIds.length} items confirmed on-chain, done`);
    }
  } catch (err) {
    console.warn(`${label} processCreating multicall failed, retry next cycle:`, shortMsg(err));
  }
}

// ── Phase 2: advance committed items ─────────────────────────────────────────
async function processCommitted(deps: QueueEngineDeps, now: () => number, label: string): Promise<void> {
  deps.chain.beginPhase?.();
  const items = await deps.store.listCommittedReady(now(), TX_BATCH_SIZE);
  if (items.length === 0) return;

  // Deliberately outside a try: a getBlockNumber failure aborts the remaining
  // phases for this cycle (matching the prior implementations) and surfaces as
  // a cycle error at the caller.
  const currentBlock = await deps.chain.getBlockNumber();

  // Guard commitment building per item — a poison row is quarantined, not
  // allowed to crash the cycle (was a queue-wide DoS).
  const { valid, commitments } = await buildCommitmentsSafe(deps, now, items, "committed");
  if (commitments.length === 0) return;

  let results: CallResult[];
  try {
    results = await deps.chain.getCommitBlockMulticall(commitments);
  } catch (err) {
    console.warn(`${label} processCommitted multicall failed:`, shortMsg(err));
    return;
  }

  const ready: QueueItem[] = [];
  const needsHasRecordCheck: QueueItem[] = [];

  for (let i = 0; i < valid.length; i++) {
    const result = results[i];
    if (result.status !== "success") continue;
    const commitBlock = result.result as bigint;
    if (commitBlock > 0n && currentBlock >= commitBlock + 1n) {
      ready.push(valid[i]);
    } else if (commitBlock === 0n) {
      needsHasRecordCheck.push(valid[i]);
    }
  }

  if (needsHasRecordCheck.length > 0) {
    try {
      const hasRecordResults = await deps.chain.hasRecordMulticall(needsHasRecordCheck);
      for (let i = 0; i < needsHasRecordCheck.length; i++) {
        const item = needsHasRecordCheck[i];
        const r = hasRecordResults[i];
        if (r.status === "success" && r.result) {
          await deps.store.markManyDone([item.id], now());
        } else if (now() - item.updatedAt >= COMMIT_COOLDOWN) {
          // Commitment never landed — re-commit, but THROUGH handleFailure so
          // retries/retryAfter advance. Otherwise an item whose commit never
          // confirms oscillates committed↔pending forever with no progress.
          await handleFailure(deps, now, item, "commitment missing after cooldown, re-committing", "pending");
        }
      }
    } catch (err) {
      console.warn(`${label} hasRecord multicall failed:`, shortMsg(err));
    }
  }

  if (ready.length === 0) return;

  // Reconciliation: some 'ready' items may already be on-chain — a prior
  // createRecord landed but our receipt wait timed out, or the record was
  // created out of band. Re-sending those would revert the WHOLE batch
  // (RecordAlreadyExists). Mark already-present ones done and submit only the
  // genuinely-missing ones.
  const missing = await reconcileReady(deps, now, ready);
  if (missing.length === 0) return;

  for (let offset = 0; offset < missing.length; offset += CREATE_SUB_BATCH) {
    const batch = missing.slice(offset, offset + CREATE_SUB_BATCH);
    const params = batch.map(toCreateParam);

    const handle = await deps.nonces.acquire("create");
    try {
      const gasEstimate = await deps.chain.estimateBatchCreate(params);
      const hash = await deps.chain.sendBatchCreate(params, handle.nonce, gasEstimate * 120n / 100n);
      await safeRecordPending(deps, "create", handle.nonce, hash, now());
      // Wait for receipt and verify success before marking done
      const receipt = await deps.chain.waitReceipt(hash, RECEIPT_TIMEOUT, "create");
      // A receipt — success OR reverted — means the tx is MINED and the nonce
      // consumed: clear the unstick ledger before acting on the outcome.
      await safeDeletePending(deps, "create", handle.nonce);
      if (receipt.status === "reverted") {
        throw new Error(`batchCreateRecord tx reverted: ${hash}`);
      }
      await deps.store.markManyDone(batch.map((i) => i.id), now(), hash);
      log.info("batchCreateRecord confirmed", { operation: "batchCreateRecord", count: batch.length, outcome: "success" });
    } catch (err) {
      handle.release();
      const msg = shortMsg(err);
      if (batchFailureAction(err) === "retry-transient") {
        // The whole batch is fine — an RPC/gas hiccup. Back each item off and
        // stop this cycle; they retry (with backoff) on a later cycle.
        for (const item of batch) await handleFailure(deps, now, item, `batchCreateRecord: ${msg}`, "committed");
        log.warn("batchCreateRecord transient failure, backing off", { operation: "batchCreateRecord", count: batch.length, error_category: "transient" });
        break;
      }
      // Deterministic revert → at least one poison item. Isolate it so it can
      // never again block the innocent items in this (or any) batch.
      log.warn("batchCreateRecord poison batch, isolating", { operation: "batchCreateRecord", count: batch.length, error_category: "poison" });
      await isolatePoisonCreate(deps, now, batch);
      // Do NOT break — let subsequent sub-batches proceed.
    }
  }
}

function toCreateParam(item: QueueItem): BatchCreateParam {
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
}

/**
 * For each 'ready' item, mark those already on-chain as done; return the rest.
 * If the reconciliation read itself fails, fall back to the full set (the next
 * cycle re-reconciles) — never lose items.
 */
async function reconcileReady(deps: QueueEngineDeps, now: () => number, items: QueueItem[]): Promise<QueueItem[]> {
  let results: CallResult[];
  try {
    // "wallet": run on the create-wallet's endpoint — the SAME one the
    // subsequent send uses (pre-refactor parity; avoids a cross-endpoint
    // read saying "missing" for a record the send endpoint already has).
    results = await deps.chain.hasRecordMulticall(items, "wallet");
  } catch (err) {
    log.warn("reconcileReady multicall failed, retrying full set next cycle", { operation: "hasRecord", error_category: "transient", error: shortMsg(err) });
    return items;
  }
  const { present, missing } = splitByHasRecord(items, results);
  if (present.length > 0) {
    await deps.store.markManyDone(present.map((i) => i.id), now());
    log.info("reconciled already-on-chain items to done", { operation: "reconcile", count: present.length, outcome: "success" });
  }
  return missing;
}

/**
 * Poison isolation for createRecord: process each item INDIVIDUALLY so the
 * batch always makes forward progress, even when items conflict with EACH
 * OTHER (e.g. two credentials sharing a walletRef — only one can win).
 * Per item: already on-chain → done; else fresh estimate + single-item send +
 * receipt. Sequential, so once one lands the next conflicting one reverts and
 * is quarantined. Every item ends done / quarantined / transient-backoff.
 */
async function isolatePoisonCreate(deps: QueueEngineDeps, now: () => number, items: QueueItem[]): Promise<void> {
  for (const item of items) {
    try {
      const has = await deps.chain.hasRecord(item.rpId, item.credentialId);
      if (has) {
        await deps.store.markManyDone([item.id], now());
        continue;
      }
    } catch { /* fall through to per-item submit */ }

    const param = toCreateParam(item);

    // 1. Fresh estimate (reflects any sibling we just sent this pass).
    let gasEstimate: bigint;
    try {
      gasEstimate = await deps.chain.estimateBatchCreate([param]);
    } catch (err) {
      if (isRecordExistsError(err)) {
        // The revert itself proves this exact (rpId, credentialId) is already
        // on-chain (an endpoint-lag miss in the earlier hasRecord read). The
        // user's create SUCCEEDED — mark done, never quarantine.
        await deps.store.markManyDone([item.id], now());
        log.info("item already on-chain (RecordAlreadyExists revert), marked done", { job_id: item.id, operation: "batchCreateRecord", outcome: "reconciled" });
      } else if (isWalletRefConflictError(err)) {
        await handleFailure(deps, now, item, `walletRef already registered under another credential: ${shortMsg(err)}`, "committed", { conflict: true });
      } else if (batchFailureAction(err) === "isolate-poison") {
        await handleFailure(deps, now, item, `batchCreateRecord poison: ${shortMsg(err)}`, "committed", { poison: true });
      } else {
        await handleFailure(deps, now, item, `batchCreateRecord transient during isolation: ${shortMsg(err)}`, "committed");
      }
      continue;
    }

    // 2. Submit this item alone, wait the receipt, verify it didn't revert.
    const handle = await deps.nonces.acquire("create");
    try {
      const hash = await deps.chain.sendBatchCreate([param], handle.nonce, gasEstimate * 120n / 100n);
      await safeRecordPending(deps, "create", handle.nonce, hash, now());
      const receipt = await deps.chain.waitReceipt(hash, RECEIPT_TIMEOUT, "create");
      await safeDeletePending(deps, "create", handle.nonce);
      if (receipt.status === "reverted") throw new Error(`reverted: ${hash}`);
      await deps.store.markManyDone([item.id], now(), hash);
      log.info("isolated item created individually", { job_id: item.id, operation: "batchCreateRecord", outcome: "success" });
    } catch (err) {
      handle.release();
      if (isRecordExistsError(err)) {
        await deps.store.markManyDone([item.id], now());
        log.info("item already on-chain (RecordAlreadyExists revert on send), marked done", { job_id: item.id, operation: "batchCreateRecord", outcome: "reconciled" });
      } else if (isWalletRefConflictError(err)) {
        await handleFailure(deps, now, item, `walletRef already registered under another credential: ${shortMsg(err)}`, "committed", { conflict: true });
      } else if (batchFailureAction(err) === "isolate-poison") {
        await handleFailure(deps, now, item, `batchCreateRecord poison (individual send): ${shortMsg(err)}`, "committed", { poison: true });
      } else {
        await handleFailure(deps, now, item, `batchCreateRecord transient (individual send): ${shortMsg(err)}`, "committed");
      }
    }
  }
}

// ── Phase 3: send commit txs for pending items ────────────────────────────────
async function processPending(deps: QueueEngineDeps, now: () => number, _label: string): Promise<void> {
  deps.chain.beginPhase?.();
  const items = await deps.store.listPendingReady(now(), TX_BATCH_SIZE);
  if (items.length === 0) return;

  // Guard commitment building per item — quarantine poison rows, never crash.
  const { valid: items2, commitments } = await buildCommitmentsSafe(deps, now, items, "pending");
  if (commitments.length === 0) return;

  const handle = await deps.nonces.acquire("commit");
  try {
    const gasEstimate = await deps.chain.estimateBatchCommit(commitments);
    const hash = await deps.chain.sendBatchCommit(commitments, handle.nonce, gasEstimate * 120n / 100n);
    await safeRecordPending(deps, "commit", handle.nonce, hash, now());
    // Wait for receipt and verify success
    const receipt = await deps.chain.waitReceipt(hash, RECEIPT_TIMEOUT, "commit");
    await safeDeletePending(deps, "commit", handle.nonce);
    if (receipt.status === "reverted") {
      throw new Error(`batchCommit tx reverted: ${hash}`);
    }
    await deps.store.markManyCommitted(items2.map((i) => i.id), now());
    log.info("batchCommit confirmed", { operation: "batchCommit", count: items2.length, outcome: "success" });
  } catch (err) {
    handle.release();
    const msg = shortMsg(err);
    if (batchFailureAction(err) === "retry-transient") {
      for (const item of items2) await handleFailure(deps, now, item, `batchCommit: ${msg}`, "pending");
      log.warn("batchCommit transient failure, backing off", { operation: "batchCommit", count: items2.length, error_category: "transient" });
    } else {
      log.warn("batchCommit poison batch, isolating", { operation: "batchCommit", count: items2.length, error_category: "poison" });
      await isolatePoisonCommit(deps, now, items2);
    }
  }
}

/**
 * Poison isolation for batchCommit: re-estimate each commitment individually;
 * quarantine the item(s) that deterministically revert, leave the rest 'pending'
 * to be re-batched cleanly next cycle.
 */
async function isolatePoisonCommit(deps: QueueEngineDeps, now: () => number, items: QueueItem[]): Promise<void> {
  for (const item of items) {
    const { commitment } = buildCommitment(item);
    try {
      await deps.chain.estimateBatchCommit([commitment]);
      // Estimable individually → innocent; leave 'pending' for next cycle.
    } catch (err) {
      if (batchFailureAction(err) === "isolate-poison") {
        await handleFailure(deps, now, item, `batchCommit poison: ${shortMsg(err)}`, "pending", { poison: true });
      } else {
        await handleFailure(deps, now, item, `batchCommit transient during isolation: ${shortMsg(err)}`, "pending");
      }
    }
  }
}

// ── Failure bookkeeping ───────────────────────────────────────────────────────

/**
 * Record a queue item failure.
 * - poison (deterministic): quarantine immediately to 'failed' (the DLQ) — no
 *   retry, prefixed "POISON:" so operators know it needs a code/data fix.
 * - conflict (deterministic, user-input): quarantine prefixed "CONFLICT:" —
 *   terminal and DLQ-visible, but hooks are told it needs NO developer page.
 * - transient: schedule a backed-off retry; after MAX_RETRIES give up with
 *   "EXHAUSTED:". Either way the item never blocks the rest of the queue.
 */
async function handleFailure(
  deps: QueueEngineDeps,
  now: () => number,
  item: QueueItem,
  error: string,
  retryStatus: "pending" | "committed" = "pending",
  opts?: { poison?: boolean; conflict?: boolean },
): Promise<void> {
  const retries = item.retries + 1;
  const terminal = opts?.poison || opts?.conflict || retries >= MAX_RETRIES;
  if (terminal) {
    const prefix = opts?.conflict ? "CONFLICT" : opts?.poison ? "POISON" : "EXHAUSTED";
    const outcome = opts?.conflict ? "conflict" : opts?.poison ? "poison" : "exhausted";
    await deps.store.applyFailure(item.id, { status: "failed", error: `${prefix}: ${error}`, retries, updatedAt: now() });
    log.error("queue item quarantined to DLQ", {
      job_id: item.id, operation: "tx", outcome,
      error_category: opts?.conflict ? "conflict" : opts?.poison ? "poison" : "transient", retries,
    });
  } else {
    const delay = retryDelayMs(retries);
    const retryAfter = now() + delay;
    await deps.store.applyFailure(item.id, { status: retryStatus, error, retries, retryAfter, updatedAt: now() });
    log.warn("queue item retry scheduled", {
      job_id: item.id, operation: "tx", outcome: "retry", attempt: retries,
      error_category: "transient", next_retry_in_s: Math.round(delay / 1000),
    });
  }
  await deps.hooks?.onItemFailure?.(error, {
    jobId: item.id,
    terminal,
    poison: opts?.poison ?? false,
    conflict: opts?.conflict ?? false,
  });
}

/**
 * Build commitments for a batch, quarantining any row whose stored fields
 * can't be ABI-encoded (e.g. a malformed walletRef/publicKey/metadata that
 * slipped in before validation was tightened). MUST be used instead of
 * items.map(build...) so one poison row goes to the DLQ rather than throwing
 * and aborting the whole worker cycle (which was a queue-wide DoS).
 */
async function buildCommitmentsSafe(
  deps: QueueEngineDeps,
  now: () => number,
  items: QueueItem[],
  retryStatus: "pending" | "committed",
): Promise<{ valid: QueueItem[]; commitments: `0x${string}`[] }> {
  const valid: QueueItem[] = [];
  const commitments: `0x${string}`[] = [];
  for (const item of items) {
    try {
      commitments.push(buildCommitment(item).commitment);
      valid.push(item);
    } catch (err) {
      await handleFailure(deps, now, item, `uncommittable (bad encoding): ${shortMsg(err)}`, retryStatus, { poison: true });
    }
  }
  return { valid, commitments };
}
