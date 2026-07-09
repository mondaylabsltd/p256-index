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
} from "./queue.ts";
import type { NonceHandle, NonceRole } from "./nonce.ts";
import { log, redactSecrets } from "./log.ts";

const CREATING_TIMEOUT = 2 * 60_000;
const COMMIT_COOLDOWN = 2 * 60_000;
const RECEIPT_TIMEOUT = 60_000;

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
}

export interface EngineHooks {
  /**
   * Called after every persisted item failure (retry or DLQ). Runtimes use it
   * to drive their batched Telegram failure alerts.
   */
  onItemFailure?(errorText: string): void | Promise<void>;
  /**
   * Runtime alerting (backlog / DLQ change / balances / auto-funding).
   * `gasPriceGwei` is passed only on the gas-too-high branch.
   */
  checkAlerts?(gasPriceGwei?: number): Promise<void>;
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

  // Skip gas price check and RPC calls if nothing to process
  const pending = await deps.store.countActive();
  if (pending === 0) {
    await cleanup(deps);
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
    await deps.hooks?.checkAlerts?.();
    return;
  }

  if (gasPriceGwei > MAX_GAS_PRICE_GWEI) {
    console.warn(`${label} Gas price too high: ${gasPriceGwei.toFixed(4)} Gwei (max: ${MAX_GAS_PRICE_GWEI}), ${pending} items waiting`);
    await deps.hooks?.checkAlerts?.(gasPriceGwei);
    return;
  }

  await processCreating(deps, now, label);
  await processCommitted(deps, now, label);
  await processPending(deps, now, label);
  await cleanup(deps);
  await deps.hooks?.checkAlerts?.();
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
      // Wait for receipt and verify success before marking done
      const receipt = await deps.chain.waitReceipt(hash, RECEIPT_TIMEOUT, "create");
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
      if (batchFailureAction(err) === "isolate-poison") {
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
      const receipt = await deps.chain.waitReceipt(hash, RECEIPT_TIMEOUT, "create");
      if (receipt.status === "reverted") throw new Error(`reverted: ${hash}`);
      await deps.store.markManyDone([item.id], now(), hash);
      log.info("isolated item created individually", { job_id: item.id, operation: "batchCreateRecord", outcome: "success" });
    } catch (err) {
      handle.release();
      if (batchFailureAction(err) === "isolate-poison") {
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
    // Wait for receipt and verify success
    const receipt = await deps.chain.waitReceipt(hash, RECEIPT_TIMEOUT, "commit");
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
 * - transient: schedule a backed-off retry; after MAX_RETRIES give up with
 *   "EXHAUSTED:". Either way the item never blocks the rest of the queue.
 */
async function handleFailure(
  deps: QueueEngineDeps,
  now: () => number,
  item: QueueItem,
  error: string,
  retryStatus: "pending" | "committed" = "pending",
  opts?: { poison?: boolean },
): Promise<void> {
  const retries = item.retries + 1;
  const terminal = opts?.poison || retries >= MAX_RETRIES;
  if (terminal) {
    const prefix = opts?.poison ? "POISON" : "EXHAUSTED";
    await deps.store.applyFailure(item.id, { status: "failed", error: `${prefix}: ${error}`, retries, updatedAt: now() });
    log.error("queue item quarantined to DLQ", {
      job_id: item.id, operation: "tx", outcome: opts?.poison ? "poison" : "exhausted",
      error_category: opts?.poison ? "poison" : "transient", retries,
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
  await deps.hooks?.onItemFailure?.(error);
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
