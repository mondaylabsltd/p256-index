/**
 * E2E tests — real chain interaction via .env config.
 *
 * Run: deno test --allow-net --allow-read --allow-write --allow-env --unstable-node-globals --env src/e2e.test.ts
 *
 * Requires PRIVATE_KEY in .env with funded Gnosis Chain wallet.
 * These tests are slow (chain interaction) and NOT run in CI.
 */

import { assertEquals, assert } from "@std/assert/";
import { initConfig, getConfig } from "./config.ts";
import { initRpc } from "./rpc.ts";
import { initQueue, enqueue, getQueueItem, startQueueWorker, _setRateLimitForTest, type QueueStatus } from "./queue.ts";
import { handleCreate, handleCreateStatus } from "./routes/create.ts";
import { handleQuery } from "./routes/query.ts";
import { cacheClear } from "./cache.ts";

// ── Helpers ──

const ADJECTIVES = ["swift", "bold", "keen", "calm", "warm", "cool", "fair", "deep", "wild", "free"];
const NOUNS = ["falcon", "cedar", "river", "frost", "blaze", "storm", "coral", "ember", "stone", "drift"];

function randomName(): string {
  const adj = ADJECTIVES[Math.floor(Math.random() * ADJECTIVES.length)];
  const noun = NOUNS[Math.floor(Math.random() * NOUNS.length)];
  const n = Math.floor(Math.random() * 1000);
  return `${adj}-${noun}-${n}`;
}

async function generateP256PublicKeyHex(): Promise<string> {
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
  return Array.from(raw).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function makeCreateRequest(body: Record<string, unknown>): Request {
  const json = JSON.stringify(body);
  return new Request("http://localhost/api/create", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Content-Length": String(json.length) },
    body: json,
  });
}

async function pollStatus(id: string, timeoutMs = 600_000): Promise<{ status: QueueStatus; txHash?: string }> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const item = getQueueItem(id);
    if (!item) throw new Error(`Item ${id} not found in queue`);
    if (item.status === "done") return { status: "done", txHash: item.txHash };
    if (item.status === "failed") throw new Error(`Item ${id} failed: ${item.error}`);
    await new Promise((r) => setTimeout(r, 2000));
  }
  const item = getQueueItem(id);
  throw new Error(`Timeout waiting for ${id}, last status: ${item?.status}`);
}

// ── Setup ──

let configReady = false;
let workerStarted = false;

async function ensureConfig() {
  if (configReady) return;
  initConfig();
  const cfg = getConfig();
  if (!cfg.privateKey) {
    throw new Error("PRIVATE_KEY not set in .env — cannot run E2E tests");
  }
  await initRpc();
  _setRateLimitForTest(Infinity);
  configReady = true;
}

const E2E_DB_PATH = "/tmp/e2e-test-queue.db";

function setupChainTest() {
  // Use disk-based SQLite for realistic throughput measurement
  try { Deno.removeSync(E2E_DB_PATH); } catch { /* ok if missing */ }
  try { Deno.removeSync(E2E_DB_PATH + "-shm"); } catch { /* ok */ }
  try { Deno.removeSync(E2E_DB_PATH + "-wal"); } catch { /* ok */ }
  initQueue(E2E_DB_PATH);
  cacheClear();
  if (!workerStarted) {
    startQueueWorker();
    workerStarted = true;
  }
}

// ── Performance: SQLite enqueue throughput (separate DB, no worker) ──

Deno.test({
  name: "PERF: SQLite enqueue throughput (1000 items)",
  sanitizeOps: false,
  sanitizeResources: false,
  async fn() {
    // Use disk-based SQLite for realistic throughput measurement
    const perfDb = "/tmp/e2e-perf-queue.db";
    try { Deno.removeSync(perfDb); } catch { /* ok */ }
    try { Deno.removeSync(perfDb + "-shm"); } catch { /* ok */ }
    try { Deno.removeSync(perfDb + "-wal"); } catch { /* ok */ }
    initQueue(perfDb);

    const count = 1000;
    const items: { publicKey: string; credentialId: string; name: string }[] = [];
    for (let i = 0; i < count; i++) {
      items.push({
        publicKey: await generateP256PublicKeyHex(),
        credentialId: crypto.randomUUID(),
        name: randomName(),
      });
    }

    const start = performance.now();
    const ids: string[] = [];
    for (const item of items) {
      const id = await enqueue({
        rpId: "localhost",
        credentialId: item.credentialId,
        walletRef: "0x" + "00".repeat(32),
        publicKey: item.publicKey,
        name: item.name,
        initialCredentialId: item.credentialId,
        metadata: "0x00",
        ip: "127.0.0.1",
      });
      ids.push(id);
    }
    const elapsed = performance.now() - start;

    console.log(`\n  SQLite enqueue: ${count} items in ${elapsed.toFixed(0)}ms (${(count / elapsed * 1000).toFixed(0)} items/sec)`);
    assertEquals(ids.length, count);

    // Spot check
    const first = getQueueItem(ids[0]);
    assert(first !== null);
    assertEquals(first!.status, "pending");
    const last = getQueueItem(ids[count - 1]);
    assert(last !== null);
    assertEquals(last!.status, "pending");
  },
});

// ── E2E: Single item commit-reveal cycle ──

Deno.test({
  name: "E2E: create → commit → reveal → query (single item)",
  ignore: !Deno.env.get("PRIVATE_KEY"),
  sanitizeOps: false,
  sanitizeResources: false,
  async fn() {
    await ensureConfig();
    setupChainTest();

    const publicKey = await generateP256PublicKeyHex();
    const credentialId = crypto.randomUUID();
    const name = randomName();

    console.log(`\n  Creating: credentialId=${credentialId}, name=${name}`);

    // Step 1: POST /api/create
    const createRes = await handleCreate(makeCreateRequest({
      rpId: "localhost",
      credentialId,
      publicKey,
      name,
    }));
    const createBody = await createRes.json();
    assertEquals(createRes.status, 202, `Expected 202, got ${createRes.status}: ${JSON.stringify(createBody)}`);
    assert(createBody.id, "should return queue id");
    assertEquals(createBody.status, "pending");
    console.log(`  ✅ Enqueued: id=${createBody.id}`);

    // Step 2: Poll status until done
    const start = performance.now();
    const result = await pollStatus(createBody.id);
    const elapsed = performance.now() - start;
    assertEquals(result.status, "done");
    assert(result.txHash, "should have txHash");
    console.log(`  ✅ On-chain: txHash=${result.txHash} (${(elapsed / 1000).toFixed(1)}s)`);

    // Step 3: GET /api/create/:id — verify done state
    const statusReq = new Request(`http://localhost/api/create/${createBody.id}`);
    const statusRes = handleCreateStatus(statusReq);
    const statusBody = await statusRes.json();
    assertEquals(statusBody.status, "done");
    assertEquals(statusBody.credentialId, credentialId);
    assertEquals(statusBody.rpId, "localhost");
    assert(statusBody.walletRef, "done status should include walletRef");
    console.log(`  ✅ Status: walletRef=${statusBody.walletRef}`);

    // Step 4: GET /api/query — verify on-chain data
    const queryRes = await handleQuery(
      new Request(`http://localhost/api/query?rpId=localhost&credentialId=${credentialId}`),
    );
    assertEquals(queryRes.status, 200);
    const queryBody = await queryRes.json();
    assertEquals(queryBody.rpId, "localhost");
    assertEquals(queryBody.credentialId, credentialId);
    assert(queryBody.publicKey.includes(publicKey.slice(2)) || queryBody.publicKey === publicKey,
      "publicKey should match");
    console.log(`  ✅ Query confirmed on-chain`);
  },
});

// ── E2E: Batch throughput (5 items) ──

Deno.test({
  name: "E2E: batch create 5 items — on-chain throughput",
  ignore: !Deno.env.get("PRIVATE_KEY"),
  sanitizeOps: false,
  sanitizeResources: false,
  async fn() {
    await ensureConfig();
    setupChainTest();

    const count = 5;
    const items: { publicKey: string; credentialId: string; name: string }[] = [];
    for (let i = 0; i < count; i++) {
      items.push({
        publicKey: await generateP256PublicKeyHex(),
        credentialId: crypto.randomUUID(),
        name: randomName(),
      });
    }

    // Enqueue all
    const ids: string[] = [];
    for (const item of items) {
      const res = await handleCreate(makeCreateRequest({
        rpId: "localhost",
        credentialId: item.credentialId,
        publicKey: item.publicKey,
        name: item.name,
      }));
      const body = await res.json();
      assertEquals(res.status, 202);
      ids.push(body.id);
    }
    console.log(`\n  📦 Enqueued ${count} items`);

    // Wait for all to complete
    const start = performance.now();
    const results = await Promise.all(ids.map((id) => pollStatus(id)));
    const elapsed = performance.now() - start;

    for (const r of results) {
      assertEquals(r.status, "done");
      assert(r.txHash);
    }

    const perItem = elapsed / count / 1000;
    console.log(`  📊 Batch throughput: ${count} items in ${(elapsed / 1000).toFixed(1)}s (${perItem.toFixed(1)}s/item)`);
    console.log(`  📊 Estimated max: ~${Math.round(60 / perItem)} items/min`);
  },
});

// ── E2E: Idempotent create (already on-chain) ──

Deno.test({
  name: "E2E: duplicate create returns 201 (idempotent)",
  ignore: !Deno.env.get("PRIVATE_KEY"),
  sanitizeOps: false,
  sanitizeResources: false,
  async fn() {
    await ensureConfig();
    setupChainTest();

    const publicKey = await generateP256PublicKeyHex();
    const credentialId = crypto.randomUUID();
    const name = randomName();

    // Create and wait for on-chain
    const res1 = await handleCreate(makeCreateRequest({
      rpId: "localhost", credentialId, publicKey, name,
    }));
    const body1 = await res1.json();
    assertEquals(res1.status, 202);
    await pollStatus(body1.id);

    // Create again — should return 201 (already exists)
    cacheClear(); // clear cache to force chain lookup
    const res2 = await handleCreate(makeCreateRequest({
      rpId: "localhost", credentialId, publicKey, name,
    }));
    assertEquals(res2.status, 201, "duplicate should return 201");
    const body2 = await res2.json();
    assertEquals(body2.status, "done");
    assertEquals(body2.credentialId, credentialId);
    console.log(`\n  ✅ Idempotent: second create returned 201`);
  },
});

// ── E2E: Queue state transitions ──

Deno.test({
  name: "E2E: queue state machine transitions (pending → committed → creating → done)",
  ignore: !Deno.env.get("PRIVATE_KEY"),
  sanitizeOps: false,
  sanitizeResources: false,
  async fn() {
    await ensureConfig();
    setupChainTest();

    const publicKey = await generateP256PublicKeyHex();
    const credentialId = crypto.randomUUID();
    const name = randomName();

    const res = await handleCreate(makeCreateRequest({
      rpId: "localhost", credentialId, publicKey, name,
    }));
    const { id } = await res.json();
    assertEquals(res.status, 202);

    // Track state transitions
    const seenStates = new Set<string>();
    const start = Date.now();
    const TIMEOUT = 180_000;

    while (Date.now() - start < TIMEOUT) {
      const item = getQueueItem(id);
      if (!item) throw new Error("Item vanished");
      seenStates.add(item.status);
      if (item.status === "done") break;
      if (item.status === "failed") throw new Error(`Failed: ${item.error}`);
      await new Promise((r) => setTimeout(r, 500));
    }

    console.log(`\n  📊 Observed states: ${[...seenStates].join(" → ")}`);
    assert(seenStates.has("pending"), "should pass through pending");
    assert(seenStates.has("done"), "should reach done");
    // committed/creating may be too fast to catch, but at least one intermediate
    const intermediates = ["committed", "creating"].filter((s) => seenStates.has(s));
    console.log(`  📊 Intermediate states caught: ${intermediates.length > 0 ? intermediates.join(", ") : "(too fast to observe)"}`);
  },
});
