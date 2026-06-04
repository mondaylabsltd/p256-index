/**
 * Stress test — measures real on-chain throughput with fire-and-forget + dual wallet.
 *
 * Run: deno test --allow-net --allow-read --allow-write --allow-env --unstable-node-globals --env src/stress.test.ts
 *
 * Requires PRIVATE_KEY in .env with funded Gnosis Chain wallet.
 */

import { assertEquals, assert } from "@std/assert/";
import { initConfig, getConfig } from "./config.ts";
import { initRpc } from "./rpc.ts";
import { initQueue, getQueueItem, startQueueWorker, _setRateLimitForTest, type QueueStatus } from "./queue.ts";
import { handleCreate } from "./routes/create.ts";
import { cacheClear } from "./cache.ts";

// ── Helpers ──

const NAMES = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india", "juliet",
  "kilo", "lima", "mike", "november", "oscar", "papa", "quebec", "romeo", "sierra", "tango"];

async function generateP256PublicKeyHex(): Promise<string> {
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
  return Array.from(raw).map((b) => b.toString(16).padStart(2, "0")).join("");
}

import { getQueueDb } from "./queue.ts";

function getQueueStats(): Record<string, number> {
  const db = getQueueDb();
  const rows = db.prepare(
    "SELECT status, COUNT(*) as count FROM create_queue GROUP BY status"
  ).all() as unknown as { status: string; count: number }[];
  const stats: Record<string, number> = {};
  for (const row of rows) stats[row.status] = row.count;
  return stats;
}

// ── Setup ──

let ready = false;
let workerStarted = false;

async function setup() {
  if (ready) return;
  initConfig();
  const cfg = getConfig();
  if (!cfg.privateKey) throw new Error("PRIVATE_KEY not set");
  await initRpc();

  const dbPath = "/tmp/stress-test-queue.db";
  try { Deno.removeSync(dbPath); } catch { /* ok */ }
  try { Deno.removeSync(dbPath + "-shm"); } catch { /* ok */ }
  try { Deno.removeSync(dbPath + "-wal"); } catch { /* ok */ }
  initQueue(dbPath);
  _setRateLimitForTest(Infinity);
  cacheClear();

  if (!workerStarted) {
    startQueueWorker();
    workerStarted = true;
  }
  ready = true;

  // Log wallet addresses
  console.log(`\n  Create wallet: ${cfg.privateKey.slice(0, 10)}...`);
  console.log(`  Commit wallet: ${cfg.commitPrivateKey.slice(0, 10)}...`);
  console.log(`  Same wallet: ${cfg.privateKey === cfg.commitPrivateKey}`);
}

// ── Stress test: 20 items ──

Deno.test({
  name: "STRESS: 200 items fire-and-forget throughput",
  ignore: !Deno.env.get("PRIVATE_KEY"),
  sanitizeOps: false,
  sanitizeResources: false,
  async fn() {
    await setup();

    const COUNT = 200;

    // Pre-generate all keys
    console.log(`\n  Generating ${COUNT} P256 keys...`);
    const items: { publicKey: string; credentialId: string; name: string }[] = [];
    for (let i = 0; i < COUNT; i++) {
      items.push({
        publicKey: await generateP256PublicKeyHex(),
        credentialId: crypto.randomUUID(),
        name: `${NAMES[i % NAMES.length]}-${i}`,
      });
    }

    // Enqueue all via handleCreate (computes walletRef + metadata correctly)
    console.log(`  Enqueueing ${COUNT} items...`);
    const enqueueStart = performance.now();
    const ids: string[] = [];
    for (const item of items) {
      const body = JSON.stringify({
        rpId: "localhost",
        credentialId: item.credentialId,
        publicKey: item.publicKey,
        name: item.name,
      });
      const res = await handleCreate(new Request("http://localhost/api/create", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Content-Length": String(body.length) },
        body,
      }));
      const data = await res.json();
      if (res.status !== 202) throw new Error(`Enqueue failed: ${JSON.stringify(data)}`);
      ids.push(data.id);
    }
    const enqueueMs = performance.now() - enqueueStart;
    console.log(`  ✅ Enqueued ${COUNT} in ${enqueueMs.toFixed(0)}ms`);

    // Poll until all done, with progress logging
    const start = performance.now();
    const doneAt = new Map<string, number>(); // id -> timestamp
    const TIMEOUT = 10 * 60_000; // 10 minutes
    let lastLog = 0;

    while (doneAt.size < COUNT && (performance.now() - start) < TIMEOUT) {
      for (const id of ids) {
        if (doneAt.has(id)) continue;
        const item = getQueueItem(id);
        if (item?.status === "done") {
          doneAt.set(id, performance.now() - start);
        } else if (item?.status === "failed" && item.retries >= 10) {
          throw new Error(`Item ${id} permanently failed: ${item.error}`);
        }
      }

      // Progress log every 10s
      const now = performance.now();
      if (now - lastLog > 10_000) {
        lastLog = now;
        const elapsed = (now - start) / 1000;
        const stats = getQueueStats();
        const statsStr = Object.entries(stats).map(([k, v]) => `${k}:${v}`).join(" ");
        console.log(`  [${elapsed.toFixed(0)}s] done: ${doneAt.size}/${COUNT}  ${statsStr}`);
      }

      await new Promise((r) => setTimeout(r, 2000));
    }

    const totalMs = performance.now() - start;
    const totalS = totalMs / 1000;
    const completed = doneAt.size;

    // Completion times
    const times = [...doneAt.values()].sort((a, b) => a - b);
    const firstDone = times[0] ? (times[0] / 1000).toFixed(1) : "N/A";
    const lastDone = times[times.length - 1] ? (times[times.length - 1] / 1000).toFixed(1) : "N/A";
    const medianDone = times[Math.floor(times.length / 2)] ? (times[Math.floor(times.length / 2)] / 1000).toFixed(1) : "N/A";

    console.log(`\n  ════════════════════════════════════════`);
    console.log(`  STRESS TEST RESULTS (${COUNT} items)`);
    console.log(`  ════════════════════════════════════════`);
    console.log(`  Completed:    ${completed}/${COUNT}`);
    console.log(`  Total time:   ${totalS.toFixed(1)}s`);
    console.log(`  Throughput:   ${(completed / totalS * 60).toFixed(1)} items/min`);
    console.log(`  Per item:     ${(totalS / completed).toFixed(1)}s avg`);
    console.log(`  First done:   ${firstDone}s`);
    console.log(`  Median done:  ${medianDone}s`);
    console.log(`  Last done:    ${lastDone}s`);
    console.log(`  ════════════════════════════════════════\n`);

    assertEquals(completed, COUNT, `Only ${completed}/${COUNT} completed in ${totalS.toFixed(0)}s`);
  },
});
