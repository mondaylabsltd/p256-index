/**
 * Deterministic fake-chain tests for the unified queue state machine
 * (shared/queue-engine.ts) — the money path, previously testable only via
 * PRIVATE_KEY-gated real-chain e2e.
 *
 * No network, no wall clock: chain responses are scripted FIFO queues, the
 * clock is injected, and the store is an in-memory transcription of the SQL
 * semantics. Every invariant listed in queue-engine.ts's header is pinned here.
 */
import { assertEquals, assert } from "@std/assert/";
import {
  runQueueCycle,
  type QueueStore,
  type ChainOps,
  type BatchCreateParam,
  type QueueEngineDeps,
} from "../../shared/queue-engine.ts";
import type { QueueItem, CallResult } from "../../shared/queue.ts";
import type { NonceHandle, NonceRole } from "../../shared/nonce.ts";

// ── Fixtures ──────────────────────────────────────────────────────────────────

const T0 = 1_000_000_000;

let seq = 0;
function mkItem(over: Partial<QueueItem> = {}): QueueItem {
  seq++;
  return {
    id: `item-${seq}`,
    status: "pending",
    rpId: "example.com",
    credentialId: `cred-${seq}`,
    walletRef: "0x" + "11".repeat(32),
    publicKey: "04" + "ab".repeat(64),
    name: "test",
    initialCredentialId: `cred-${seq}`,
    metadata: "0x00",
    txHash: "",
    error: "",
    retries: 0,
    retryAfter: 0,
    ip: "",
    createdAt: T0,
    updatedAt: T0,
    ...over,
  };
}

/** In-memory QueueStore with the same semantics as the SQLite/D1 SQL. */
class FakeStore implements QueueStore {
  rows: QueueItem[];
  constructor(rows: QueueItem[] = []) {
    this.rows = rows;
  }
  row(id: string): QueueItem {
    const r = this.rows.find((r) => r.id === id);
    if (!r) throw new Error(`no row ${id}`);
    return r;
  }
  // deno-lint-ignore require-await
  async countActive(): Promise<number> {
    return this.rows.filter((r) => ["pending", "committed", "creating"].includes(r.status)).length;
  }
  private list(status: string, limit: number, retryReadyBefore?: number): QueueItem[] {
    return this.rows
      .filter((r) => r.status === status && (retryReadyBefore === undefined || r.retryAfter <= retryReadyBefore))
      .sort((a, b) => a.createdAt - b.createdAt)
      .slice(0, limit)
      .map((r) => ({ ...r })); // snapshots, like SQL row reads
  }
  // deno-lint-ignore require-await
  async listCreating(limit: number): Promise<QueueItem[]> {
    return this.list("creating", limit);
  }
  // deno-lint-ignore require-await
  async listCommittedReady(now: number, limit: number): Promise<QueueItem[]> {
    return this.list("committed", limit, now);
  }
  // deno-lint-ignore require-await
  async listPendingReady(now: number, limit: number): Promise<QueueItem[]> {
    return this.list("pending", limit, now);
  }
  // deno-lint-ignore require-await
  async markManyDone(ids: string[], now: number, txHash?: string): Promise<void> {
    for (const id of ids) {
      const r = this.row(id);
      r.status = "done";
      r.error = "";
      r.updatedAt = now;
      if (txHash !== undefined) r.txHash = txHash;
    }
  }
  // deno-lint-ignore require-await
  async markManyCommitted(ids: string[], now: number): Promise<void> {
    for (const id of ids) {
      const r = this.row(id);
      r.status = "committed";
      r.updatedAt = now;
    }
  }
  // deno-lint-ignore require-await
  async applyFailure(id: string, f: { status: string; error: string; retries: number; retryAfter?: number; updatedAt: number }): Promise<void> {
    const r = this.row(id);
    r.status = f.status as QueueItem["status"];
    r.error = f.error;
    r.retries = f.retries;
    if (f.retryAfter !== undefined) r.retryAfter = f.retryAfter;
    r.updatedAt = f.updatedAt;
  }
  // deno-lint-ignore require-await
  async cleanupExpired(doneBefore: number, failedBefore: number): Promise<{ doneDeleted: number }> {
    const before = this.rows.length;
    this.rows = this.rows.filter((r) => !(r.status === "done" && r.updatedAt < doneBefore));
    const doneDeleted = before - this.rows.length;
    this.rows = this.rows.filter((r) => !(r.status === "failed" && r.updatedAt < failedBefore));
    return { doneDeleted };
  }
}

type Resp<T> = { ok: T } | { err: unknown };

/** Scripted ChainOps: per-method FIFO response queues with sensible defaults. */
class FakeChain implements ChainOps {
  calls: { method: string; args: unknown }[] = [];
  beginPhaseCalls = 0;
  private q = new Map<string, Resp<unknown>[]>();
  private hashSeq = 0;

  beginPhase(): void {
    this.beginPhaseCalls++;
  }

  /** Script the NEXT response for a method (FIFO; falls back to defaults when empty). */
  push(method: string, r: Resp<unknown>): void {
    const arr = this.q.get(method) ?? [];
    arr.push(r);
    this.q.set(method, arr);
  }
  private take<T>(method: string, args: unknown, dflt: () => T): T {
    this.calls.push({ method, args });
    const arr = this.q.get(method);
    if (arr && arr.length > 0) {
      const r = arr.shift()!;
      if ("err" in r) throw r.err;
      return r.ok as T;
    }
    return dflt();
  }
  called(method: string): number {
    return this.calls.filter((c) => c.method === method).length;
  }

  // deno-lint-ignore require-await
  async getGasPrice(): Promise<bigint> {
    return this.take("getGasPrice", [], () => 10_000_000n); // 0.01 gwei — under the 0.1 cap
  }
  // deno-lint-ignore require-await
  async getBlockNumber(): Promise<bigint> {
    return this.take("getBlockNumber", [], () => 100n);
  }
  // deno-lint-ignore require-await
  async hasRecordMulticall(items: Pick<QueueItem, "rpId" | "credentialId">[], via: "read" | "wallet" = "read"): Promise<CallResult[]> {
    return this.take("hasRecordMulticall", { items, via }, () => items.map(() => ({ status: "success" as const, result: false })));
  }
  // deno-lint-ignore require-await
  async getCommitBlockMulticall(commitments: `0x${string}`[]): Promise<CallResult[]> {
    // Default: commitment landed at block 50 (ready, since default head is 100).
    return this.take("getCommitBlockMulticall", commitments, () => commitments.map(() => ({ status: "success" as const, result: 50n })));
  }
  // deno-lint-ignore require-await
  async hasRecord(rpId: string, credentialId: string): Promise<boolean> {
    return this.take("hasRecord", [rpId, credentialId], () => false);
  }
  // deno-lint-ignore require-await
  async estimateBatchCreate(params: BatchCreateParam[]): Promise<bigint> {
    return this.take("estimateBatchCreate", params, () => 100_000n);
  }
  // deno-lint-ignore require-await
  async sendBatchCreate(params: BatchCreateParam[], nonce: number, gas: bigint): Promise<`0x${string}`> {
    return this.take("sendBatchCreate", { params, nonce, gas }, () => `0xc${(++this.hashSeq).toString(16).padStart(3, "0")}` as `0x${string}`);
  }
  // deno-lint-ignore require-await
  async estimateBatchCommit(commitments: `0x${string}`[]): Promise<bigint> {
    return this.take("estimateBatchCommit", commitments, () => 80_000n);
  }
  // deno-lint-ignore require-await
  async sendBatchCommit(commitments: `0x${string}`[], nonce: number, gas: bigint): Promise<`0x${string}`> {
    return this.take("sendBatchCommit", { commitments, nonce, gas }, () => `0xd${(++this.hashSeq).toString(16).padStart(3, "0")}` as `0x${string}`);
  }
  // deno-lint-ignore require-await
  async waitReceipt(hash: `0x${string}`, _timeoutMs: number, _role: NonceRole): Promise<{ status: "success" | "reverted" }> {
    return this.take("waitReceipt", hash, () => ({ status: "success" as const }));
  }
}

class FakeNonces {
  next = 100;
  acquired: { role: NonceRole; nonce: number }[] = [];
  released: number[] = [];
  // deno-lint-ignore require-await
  async acquire(role: NonceRole): Promise<NonceHandle> {
    const nonce = this.next++;
    this.acquired.push({ role, nonce });
    return { nonce, release: () => this.released.push(nonce) };
  }
}

function harness(rows: QueueItem[]) {
  const store = new FakeStore(rows);
  const chain = new FakeChain();
  const nonces = new FakeNonces();
  const failures: string[] = [];
  const alerts: (number | undefined)[] = [];
  let t = T0 + 10_000;
  const deps: QueueEngineDeps = {
    store,
    chain,
    nonces,
    hooks: {
      onItemFailure: (e) => { failures.push(e); },
      // deno-lint-ignore require-await
      checkAlerts: async (g) => { alerts.push(g); },
    },
    now: () => t,
    label: "[test]",
  };
  return { store, chain, nonces, failures, alerts, deps, setNow: (v: number) => { t = v; }, getNow: () => t };
}

// TRANSIENT vs POISON errors, classified by shared/reliability.ts on rpc-write:
const transientErr = () => new Error("fetch failed");                       // network → transient
const revertErr = () => new Error("execution reverted: RecordAlreadyExists"); // revert → poison on write

// ── Cycle gating ──────────────────────────────────────────────────────────────

Deno.test("engine: empty queue → cleanup only, zero chain calls", async () => {
  const h = harness([mkItem({ status: "done", updatedAt: 0 })]); // expired done row
  await runQueueCycle(h.deps);
  assertEquals(h.chain.calls.length, 0, "no chain calls on an idle queue");
  assertEquals(h.store.rows.length, 0, "expired done row cleaned up");
  assertEquals(h.alerts.length, 0, "no alert hook on the idle path");
});

Deno.test("engine: gas price above cap → pause cycle, alert with the measured price, no phases", async () => {
  const h = harness([mkItem({ status: "pending" })]);
  h.chain.push("getGasPrice", { ok: 200_000_000n }); // 0.2 gwei > 0.1 cap
  await runQueueCycle(h.deps);
  assertEquals(h.alerts, [0.2], "checkAlerts receives the measured gwei");
  assertEquals(h.chain.called("getBlockNumber"), 0);
  assertEquals(h.chain.called("sendBatchCommit"), 0);
  assertEquals(h.store.row("item-" + seq).status, "pending", "item untouched");
});

Deno.test("engine: gas-price check FAILURE alerts before returning and skips phases (P1-A)", async () => {
  const h = harness([mkItem({ status: "pending" })]);
  h.chain.push("getGasPrice", { err: transientErr() });
  await runQueueCycle(h.deps);
  assertEquals(h.alerts.length, 1, "checkAlerts MUST run during the outage — this was the silent-stall bug");
  assertEquals(h.alerts[0], undefined, "no gas price measured on the failure branch");
  assertEquals(h.chain.called("sendBatchCommit"), 0, "no phase ran");
});

// ── processPending (batchCommit) ─────────────────────────────────────────────

Deno.test("engine: pending → batchCommit success → committed; nonce consumed, not released", async () => {
  const a = mkItem({ status: "pending" });
  const b = mkItem({ status: "pending" });
  const h = harness([a, b]);
  // No committed/creating rows → the only send is the commit.
  await runQueueCycle(h.deps);
  assertEquals(h.store.row(a.id).status, "committed");
  assertEquals(h.store.row(b.id).status, "committed");
  assertEquals(h.nonces.acquired.map((x) => x.role), ["commit"]);
  assertEquals(h.nonces.released, [], "successful send consumes the nonce");
  assertEquals(h.failures, []);
  assertEquals(h.alerts.length, 1, "end-of-cycle alerting ran");
});

Deno.test("engine: transient batchCommit failure → all items backed off as pending, nonce released", async () => {
  const a = mkItem({ status: "pending" });
  const b = mkItem({ status: "pending" });
  const h = harness([a, b]);
  h.chain.push("sendBatchCommit", { err: transientErr() });
  await runQueueCycle(h.deps);
  for (const id of [a.id, b.id]) {
    const r = h.store.row(id);
    assertEquals(r.status, "pending", "transient keeps retry status");
    assertEquals(r.retries, 1);
    assertEquals(r.retryAfter, h.getNow() + 5000, "retryDelayMs(1) = 5000");
    assert(r.error.startsWith("batchCommit: "), r.error);
  }
  assertEquals(h.nonces.released.length, 1, "failed send releases the nonce");
  assertEquals(h.failures.length, 2, "onItemFailure fired per item");
});

Deno.test("engine: poison batchCommit → per-item isolation: innocent stays pending untouched, culprit → POISON DLQ", async () => {
  const innocent = mkItem({ status: "pending" });
  const culprit = mkItem({ status: "pending" });
  const h = harness([innocent, culprit]);
  h.chain.push("estimateBatchCommit", { ok: 80_000n });        // batch estimate passes
  h.chain.push("sendBatchCommit", { err: revertErr() });       // batch send reverts deterministically
  h.chain.push("estimateBatchCommit", { ok: 80_000n });        // isolation: innocent estimates fine
  h.chain.push("estimateBatchCommit", { err: revertErr() });   // isolation: culprit reverts
  await runQueueCycle(h.deps);
  const i = h.store.row(innocent.id);
  assertEquals(i.status, "pending", "innocent left pending for clean re-batch");
  assertEquals(i.retries, 0, "innocent untouched");
  const c = h.store.row(culprit.id);
  assertEquals(c.status, "failed");
  assert(c.error.startsWith("POISON: batchCommit poison: "), c.error);
  assertEquals(h.failures.length, 1, "only the culprit counted as a failure");
});

Deno.test("engine: transient failure at retries=9 → EXHAUSTED to the DLQ", async () => {
  const item = mkItem({ status: "pending", retries: 9 });
  const h = harness([item]);
  h.chain.push("sendBatchCommit", { err: transientErr() });
  await runQueueCycle(h.deps);
  const r = h.store.row(item.id);
  assertEquals(r.status, "failed");
  assert(r.error.startsWith("EXHAUSTED: batchCommit: "), r.error);
  assertEquals(r.retries, 10);
});

Deno.test("engine: pending row that can't be ABI-encoded is quarantined POISON; valid sibling still commits", async () => {
  const bad = mkItem({ status: "pending", walletRef: "0xdead" }); // not bytes32 → encode throws
  const good = mkItem({ status: "pending" });
  const h = harness([bad, good]);
  await runQueueCycle(h.deps);
  const b = h.store.row(bad.id);
  assertEquals(b.status, "failed");
  assert(b.error.startsWith("POISON: uncommittable (bad encoding): "), b.error);
  assertEquals(h.store.row(good.id).status, "committed", "valid sibling proceeded");
});

// ── processCommitted (reveal path) ────────────────────────────────────────────

Deno.test("engine: committed → landed commit → reconcile(miss) → batchCreateRecord → done with txHash", async () => {
  const item = mkItem({ status: "committed" });
  const h = harness([item]);
  // defaults: commitBlock=50, head=100 → ready; reconcile hasRecord=false; send ok
  await runQueueCycle(h.deps);
  const r = h.store.row(item.id);
  assertEquals(r.status, "done");
  assert(r.txHash.startsWith("0xc"), "txHash recorded from the create send");
  assertEquals(r.error, "");
  assertEquals(h.nonces.acquired.map((x) => x.role), ["create"]);
  assertEquals(h.nonces.released, []);
});

Deno.test("engine: reconcile marks already-on-chain item done WITHOUT sending; only the missing one is sent", async () => {
  const onChain = mkItem({ status: "committed" });
  const missing = mkItem({ status: "committed" });
  const h = harness([onChain, missing]);
  // First hasRecordMulticall in this flow is the reconcile over `ready`.
  h.chain.push("hasRecordMulticall", {
    ok: [{ status: "success", result: true }, { status: "success", result: false }],
  });
  await runQueueCycle(h.deps);
  assertEquals(h.store.row(onChain.id).status, "done");
  assertEquals(h.store.row(onChain.id).txHash, "", "reconciled item keeps its (empty) txHash — no send happened");
  assertEquals(h.store.row(missing.id).status, "done");
  assert(h.store.row(missing.id).txHash.startsWith("0xc"), "missing item was actually sent");
  const sent = h.chain.calls.filter((c) => c.method === "sendBatchCreate");
  assertEquals(sent.length, 1, "exactly one send");
  assertEquals((sent[0].args as { params: BatchCreateParam[] }).params.length, 1, "batch contained only the missing item");
});

Deno.test("engine: commitBlock=0 + hasRecord=true → done (out-of-band landed record)", async () => {
  const item = mkItem({ status: "committed" });
  const h = harness([item]);
  h.chain.push("getCommitBlockMulticall", { ok: [{ status: "success", result: 0n }] });
  h.chain.push("hasRecordMulticall", { ok: [{ status: "success", result: true }] });
  await runQueueCycle(h.deps);
  assertEquals(h.store.row(item.id).status, "done");
  assertEquals(h.chain.called("sendBatchCreate"), 0);
});

Deno.test("engine: commitBlock=0 + hasRecord=false + past cooldown → re-commit THROUGH handleFailure (anti-oscillation)", async () => {
  const item = mkItem({ status: "committed", updatedAt: T0 });
  const h = harness([item]);
  h.setNow(T0 + 3 * 60_000); // past the 2min COMMIT_COOLDOWN
  h.chain.push("getCommitBlockMulticall", { ok: [{ status: "success", result: 0n }] });
  h.chain.push("hasRecordMulticall", { ok: [{ status: "success", result: false }] });
  await runQueueCycle(h.deps);
  const r = h.store.row(item.id);
  assertEquals(r.status, "pending", "re-queued for a fresh commit");
  assertEquals(r.retries, 1, "retries MUST advance — this pins the fixed oscillation bug");
  assertEquals(r.error, "commitment missing after cooldown, re-committing");
});

Deno.test("engine: commitBlock=0 + fresh (within cooldown) → untouched this cycle", async () => {
  const item = mkItem({ status: "committed", updatedAt: T0 });
  const h = harness([item]);
  h.setNow(T0 + 30_000); // 30s < 2min cooldown
  h.chain.push("getCommitBlockMulticall", { ok: [{ status: "success", result: 0n }] });
  h.chain.push("hasRecordMulticall", { ok: [{ status: "success", result: false }] });
  await runQueueCycle(h.deps);
  const r = h.store.row(item.id);
  assertEquals(r.status, "committed");
  assertEquals(r.retries, 0);
});

// NOTE — pins the ACTUAL (pre-refactor) semantics: when the reconcile multicall
// fails entirely, reconcileReady returns the FULL set and the caller proceeds to
// send it un-reconciled. Worst case an already-on-chain item reverts the batch,
// which poison isolation then converges (per-item hasRecord probe → done). This
// is a documented residual (08-open-issues P3: failed reads count as "missing");
// the refactor deliberately preserves it rather than silently changing behavior.
Deno.test("engine: reconcile multicall failure → full set sent un-reconciled (converges via isolation)", async () => {
  const item = mkItem({ status: "committed" });
  const h = harness([item]);
  h.chain.push("hasRecordMulticall", { err: transientErr() }); // reconcile read fails
  await runQueueCycle(h.deps);
  assertEquals(h.chain.called("sendBatchCreate"), 1, "full set is sent without reconciliation");
  assertEquals(h.store.row(item.id).status, "done", "default receipt success → done");
});

Deno.test("engine: create receipt REVERTED → poison isolation; item already-on-chain probe false → individual send succeeds → done", async () => {
  const item = mkItem({ status: "committed" });
  const h = harness([item]);
  h.chain.push("waitReceipt", { ok: { status: "reverted" } }); // batch reverted
  // isolation: hasRecord(single) default false → estimate default ok → individual send default ok → receipt default success
  await runQueueCycle(h.deps);
  const r = h.store.row(item.id);
  assertEquals(r.status, "done", "isolation converged the item individually");
  assertEquals(h.nonces.acquired.length, 2, "batch nonce + individual-send nonce");
  assertEquals(h.nonces.released.length, 1, "the reverted batch send's nonce was released");
});

Deno.test("engine: create receipt timeout (transient) → whole batch backed off on committed", async () => {
  const item = mkItem({ status: "committed" });
  const h = harness([item]);
  h.chain.push("waitReceipt", { err: new Error("Timed out while waiting for transaction") });
  await runQueueCycle(h.deps);
  const r = h.store.row(item.id);
  assertEquals(r.status, "committed", "receipt timeout is transient — retry from committed");
  assertEquals(r.retries, 1);
  assert(r.error.startsWith("batchCreateRecord: "), r.error);
  assertEquals(h.nonces.released.length, 1);
});

Deno.test("engine: poison batch create with mixed batch → culprit quarantined, innocent lands individually", async () => {
  const innocent = mkItem({ status: "committed" });
  const culprit = mkItem({ status: "committed" });
  const h = harness([innocent, culprit]);
  h.chain.push("sendBatchCreate", { err: revertErr() });        // batch send reverts
  // isolation item 1 (innocent): hasRecord false (default) → estimate ok (default) → send ok → done
  // isolation item 2 (culprit): hasRecord false → estimate reverts → POISON
  h.chain.push("hasRecord", { ok: false });
  h.chain.push("hasRecord", { ok: false });
  h.chain.push("estimateBatchCreate", { ok: 100_000n });        // batch estimate (before send)
  // NOTE: order of estimate calls: batch first, then per-item. Script per-item:
  h.chain.push("estimateBatchCreate", { ok: 100_000n });        // innocent individual estimate
  h.chain.push("estimateBatchCreate", { err: revertErr() });    // culprit individual estimate
  await runQueueCycle(h.deps);
  assertEquals(h.store.row(innocent.id).status, "done");
  const c = h.store.row(culprit.id);
  assertEquals(c.status, "failed");
  assert(c.error.startsWith("POISON: batchCreateRecord poison: "), c.error);
});

// ── processCreating (rolling-upgrade safety net) ─────────────────────────────

Deno.test("engine: 'creating' rows reconcile — on-chain → done; stale unconfirmed → failed back to committed", async () => {
  const landed = mkItem({ status: "creating", updatedAt: T0 });
  const stale = mkItem({ status: "creating", updatedAt: T0 });
  const h = harness([landed, stale]);
  h.setNow(T0 + 3 * 60_000); // past 2min CREATING_TIMEOUT
  h.chain.push("hasRecordMulticall", {
    ok: [{ status: "success", result: true }, { status: "success", result: false }],
  });
  // NOTE: the re-queued stale item gets retryAfter = now + retryDelayMs(1), so
  // the committed phase in this same cycle does NOT list it (retryAfter gating)
  // — no further chain responses are needed.
  await runQueueCycle(h.deps);
  assertEquals(h.store.row(landed.id).status, "done");
  const s = h.store.row(stale.id);
  assertEquals(s.status, "committed", "stale creating row re-queued for confirmation via committed");
  assertEquals(s.retries, 1);
  assertEquals(s.error, "createRecord tx not confirmed after 2min");
  assert(s.retryAfter > h.getNow(), "backoff gate set — committed phase skips it this cycle");
  assertEquals(h.chain.called("getCommitBlockMulticall"), 0, "not listed by the committed phase this cycle");
});

// ── Multicall row failures are skipped, not crashed ───────────────────────────

Deno.test("engine: a failed getCommitBlock multicall ROW is skipped without state change", async () => {
  const item = mkItem({ status: "committed" });
  const h = harness([item]);
  h.chain.push("getCommitBlockMulticall", { ok: [{ status: "failure", error: new Error("decode") }] });
  await runQueueCycle(h.deps);
  const r = h.store.row(item.id);
  assertEquals(r.status, "committed");
  assertEquals(r.retries, 0, "row-level failure → wait for next cycle, no penalty");
  assertEquals(h.chain.called("sendBatchCreate"), 0);
});

// ── Sub-batch semantics (CREATE_SUB_BATCH = 10) ──────────────────────────────

Deno.test("engine: 12 ready items split into 10+2 sub-batches with distinct sequential nonces and per-batch txHashes", async () => {
  const items = Array.from({ length: 12 }, () => mkItem({ status: "committed" }));
  const h = harness(items);
  await runQueueCycle(h.deps);
  const sends = h.chain.calls.filter((c) => c.method === "sendBatchCreate")
    .map((c) => c.args as { params: BatchCreateParam[]; nonce: number });
  assertEquals(sends.map((s) => s.params.length), [10, 2], "sliced at CREATE_SUB_BATCH");
  assertEquals(h.nonces.acquired.map((x) => x.role), ["create", "create"], "one nonce per sub-batch");
  assertEquals(sends[1].nonce, sends[0].nonce + 1, "sequential distinct nonces");
  const hashes = new Set(items.map((i) => h.store.row(i.id).txHash));
  assertEquals(hashes.size, 2, "each row carries its own sub-batch's txHash");
  for (const i of items) assertEquals(h.store.row(i.id).status, "done");
});

Deno.test("engine: transient failure on sub-batch 1 BREAKS — later sub-batches untouched this cycle", async () => {
  const items = Array.from({ length: 12 }, () => mkItem({ status: "committed" }));
  const h = harness(items);
  h.chain.push("sendBatchCreate", { err: transientErr() });
  await runQueueCycle(h.deps);
  assertEquals(h.chain.called("sendBatchCreate"), 1, "no further sends after a transient batch failure");
  const rows = items.map((i) => h.store.row(i.id));
  assertEquals(rows.slice(0, 10).every((r) => r.status === "committed" && r.retries === 1), true, "first 10 backed off");
  assertEquals(rows.slice(10).every((r) => r.retries === 0 && r.error === ""), true, "last 2 untouched — retry next cycle");
});

Deno.test("engine: poison failure on sub-batch 1 CONTINUES — sub-batch 2 still sent after isolation", async () => {
  const items = Array.from({ length: 12 }, () => mkItem({ status: "committed" }));
  const h = harness(items);
  h.chain.push("sendBatchCreate", { err: revertErr() }); // batch 1 reverts; isolation + batch 2 use defaults (ok)
  await runQueueCycle(h.deps);
  // 1 failed batch send + 10 individual isolation sends + 1 second sub-batch send
  assertEquals(h.chain.called("sendBatchCreate"), 12, "isolation sends per item, then sub-batch 2 proceeds");
  for (const i of items) assertEquals(h.store.row(i.id).status, "done", "everything converged");
});

// ── Index alignment through quarantine (guards a P0-class mixup) ─────────────

Deno.test("engine: valid[i]/results[i] stay aligned after a bad-encoding row is quarantined mid-list", async () => {
  const bad = mkItem({ status: "committed", walletRef: "0xdead" }); // quarantined by buildCommitmentsSafe
  const landed = mkItem({ status: "committed" });                    // commitBlock=50 → ready → reconcile says on-chain
  const missing = mkItem({ status: "committed", updatedAt: T0 });    // commitBlock=0, fresh → untouched
  const h = harness([bad, landed, missing]);
  h.setNow(T0 + 30_000); // within COMMIT_COOLDOWN for `missing`
  // Multicall rows must align with the 2 VALID items (landed, missing) — not the original 3.
  h.chain.push("getCommitBlockMulticall", { ok: [{ status: "success", result: 50n }, { status: "success", result: 0n }] });
  h.chain.push("hasRecordMulticall", { ok: [{ status: "success", result: false }] }); // needsHasRecordCheck: [missing]
  h.chain.push("hasRecordMulticall", { ok: [{ status: "success", result: true }] });  // reconcile: [landed] already on-chain
  await runQueueCycle(h.deps);
  assert(h.store.row(bad.id).error.startsWith("POISON: uncommittable"), "bad row quarantined");
  assertEquals(h.store.row(landed.id).status, "done", "the RIGHT item was reconciled done");
  assertEquals(h.store.row(landed.id).txHash, "", "reconciled — never sent");
  const m = h.store.row(missing.id);
  assertEquals(m.status, "committed", "fresh missing-commit item untouched");
  assertEquals(m.retries, 0);
  assertEquals(h.chain.called("sendBatchCreate"), 0, "nothing needed sending");
});

// ── Cross-phase invariants ────────────────────────────────────────────────────

Deno.test("engine: nonce roles across one cycle — committed uses 'create', pending uses 'commit', in that phase order", async () => {
  const c = mkItem({ status: "committed" });
  const p = mkItem({ status: "pending" });
  const h = harness([c, p]);
  await runQueueCycle(h.deps);
  assertEquals(h.nonces.acquired.map((x) => x.role), ["create", "commit"], "reveal phase precedes commit phase, roles never swap");
  assertEquals(h.store.row(c.id).status, "done");
  assertEquals(h.store.row(p.id).status, "committed");
  assertEquals(h.chain.beginPhaseCalls, 3, "endpoint affinity pinned per phase (creating/committed/pending)");
});

Deno.test("engine: reconcile runs via the WALLET endpoint (same endpoint as the subsequent send)", async () => {
  const item = mkItem({ status: "committed" });
  const h = harness([item]);
  await runQueueCycle(h.deps);
  const reconcile = h.chain.calls.filter((c) => c.method === "hasRecordMulticall");
  assertEquals(reconcile.length, 1);
  assertEquals((reconcile[0].args as { via: string }).via, "wallet", "pre-refactor endpoint affinity for reconcile-before-send");
});

Deno.test("engine: getBlockNumber failure aborts the cycle — no sends, later phases skipped, rows untouched", async () => {
  const c = mkItem({ status: "committed" });
  const p = mkItem({ status: "pending" });
  const h = harness([c, p]);
  h.chain.push("getBlockNumber", { err: transientErr() });
  let threw = false;
  try {
    await runQueueCycle(h.deps);
  } catch {
    threw = true;
  }
  assertEquals(threw, true, "cycle error propagates to the caller (which logs it)");
  assertEquals(h.chain.called("sendBatchCreate"), 0);
  assertEquals(h.chain.called("sendBatchCommit"), 0, "pending phase never ran");
  assertEquals(h.store.row(c.id).retries, 0);
  assertEquals(h.store.row(p.id).retries, 0);
});

Deno.test("engine: retryAfter gates work — backed-off item is skipped, then processed once the clock passes", async () => {
  const item = mkItem({ status: "pending", retryAfter: T0 + 60_000 });
  const h = harness([item]);
  h.setNow(T0 + 30_000); // before retryAfter
  await runQueueCycle(h.deps);
  assertEquals(h.chain.called("sendBatchCommit"), 0, "inside the backoff window — not listed");
  assertEquals(h.store.row(item.id).status, "pending");
  h.setNow(T0 + 61_000); // past retryAfter
  await runQueueCycle(h.deps);
  assertEquals(h.chain.called("sendBatchCommit"), 1);
  assertEquals(h.store.row(item.id).status, "committed");
});

Deno.test("engine: commit receipt REVERTED with all-innocent isolation → both stay pending, nonce released", async () => {
  // Pins that a mined-but-reverted batchCommit routes to isolation (poison
  // classification of the synthesized 'batchCommit tx reverted' message), and
  // that isolation with all-passing individual estimates leaves items pending
  // and untouched for a clean re-batch next cycle.
  const a = mkItem({ status: "pending" });
  const b = mkItem({ status: "pending" });
  const h = harness([a, b]);
  h.chain.push("waitReceipt", { ok: { status: "reverted" } }); // per-method FIFO: first (only) receipt is the commit's
  await runQueueCycle(h.deps);
  assertEquals(h.nonces.released.length, 1, "reverted commit send's nonce released");
  for (const id of [a.id, b.id]) {
    const r = h.store.row(id);
    assertEquals(r.status, "pending");
    assertEquals(r.retries, 0, "individually-estimable items are innocent — untouched");
  }
  // batch estimate + 2 isolation estimates all happened:
  assertEquals(h.chain.called("estimateBatchCommit"), 3);
});

Deno.test("engine: commit receipt REVERTED with a real culprit → culprit POISON, innocent pending untouched", async () => {
  const innocent = mkItem({ status: "pending" });
  const culprit = mkItem({ status: "pending" });
  const h = harness([innocent, culprit]);
  h.chain.push("estimateBatchCommit", { ok: 80_000n });        // batch estimate ok
  h.chain.push("waitReceipt", { ok: { status: "reverted" } }); // batch mined-but-reverted
  h.chain.push("estimateBatchCommit", { ok: 80_000n });        // isolation: innocent ok
  h.chain.push("estimateBatchCommit", { err: revertErr() });   // isolation: culprit reverts
  await runQueueCycle(h.deps);
  const i = h.store.row(innocent.id);
  assertEquals(i.status, "pending");
  assertEquals(i.retries, 0, "innocent untouched for clean re-batch");
  const c = h.store.row(culprit.id);
  assertEquals(c.status, "failed");
  assert(c.error.startsWith("POISON: batchCommit poison: "), c.error);
});

Deno.test("engine: fresh (within CREATING_TIMEOUT) unconfirmed 'creating' row is left untouched", async () => {
  const item = mkItem({ status: "creating", updatedAt: T0 });
  const h = harness([item]);
  h.setNow(T0 + 60_000); // 1min < 2min CREATING_TIMEOUT
  h.chain.push("hasRecordMulticall", { ok: [{ status: "success", result: false }] });
  await runQueueCycle(h.deps);
  const r = h.store.row(item.id);
  assertEquals(r.status, "creating", "tx may still be in flight — do not re-queue yet");
  assertEquals(r.retries, 0);
  assertEquals(r.error, "");
});

// ── Cleanup retention boundaries (7d done / 30d failed) ──────────────────────

Deno.test("engine: cleanup deletes done>7d and failed>30d, keeps boundary rows and young DLQ rows", async () => {
  const now = T0 + 100 * 24 * 60 * 60_000;
  const doneBoundary = mkItem({ status: "done", updatedAt: now - 7 * 24 * 60 * 60_000 });      // exactly 7d — survives (strict <)
  const doneOld = mkItem({ status: "done", updatedAt: now - 7 * 24 * 60 * 60_000 - 1 });        // deleted
  const failedYoung = mkItem({ status: "failed", updatedAt: now - 8 * 24 * 60 * 60_000 });      // 8d — must SURVIVE (30d retention)
  const failedOld = mkItem({ status: "failed", updatedAt: now - 30 * 24 * 60 * 60_000 - 1 });   // deleted
  const h = harness([doneBoundary, doneOld, failedYoung, failedOld]);
  h.setNow(now);
  await runQueueCycle(h.deps); // idle queue → cleanup-only path
  const ids = h.store.rows.map((r) => r.id).sort();
  assertEquals(ids, [doneBoundary.id, failedYoung.id].sort(), "8-day-old DLQ row kept — swapped retention windows would destroy poison triage");
});
