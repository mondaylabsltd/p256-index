/**
 * Daily heartbeat message builder + runway estimate (shared/queue.ts).
 * The Deno wiring (deno/queue.ts maybeHeartbeat) is a thin, fail-soft shell
 * around these pure helpers.
 */
import { assert, assertEquals } from "@std/assert/";
import {
  buildHeartbeatMessage,
  estimateCreateRunway,
  EST_GAS_PER_CREATE,
  HEARTBEAT_INTERVAL,
} from "../../shared/queue.ts";

Deno.test("heartbeat: runway estimate — balance / (gas × per-create gas)", () => {
  // 0.3 xDAI at 1 gwei with 300k gas per create → 0.0003 xDAI per create → 1000 creates
  assertEquals(EST_GAS_PER_CREATE, 300_000n);
  assertEquals(estimateCreateRunway(0.3, 1), 1000);
  // ten times the gas price → a tenth of the runway
  assertEquals(estimateCreateRunway(0.3, 10), 100);
  // zero/negative gas price (mock chains) → Infinity, never a division blowup
  assertEquals(estimateCreateRunway(0.3, 0), Infinity);
});

Deno.test("heartbeat: interval is daily", () => {
  assertEquals(HEARTBEAT_INTERVAL, 24 * 60 * 60_000);
});

Deno.test("heartbeat: message carries balances, runway, queue, uptime, release", () => {
  const msg = buildHeartbeatMessage({
    runtime: "Deno",
    queueDepth: 2,
    dlqCount: 0,
    createAddress: "0xAAA",
    createBalanceXdai: 0.3,
    commitAddress: "0xBBB",
    commitBalanceXdai: 0.019,
    gasPriceGwei: 1,
    uptimeMs: 3 * 3_600_000,
    release: "20260710-004026",
  });
  assert(msg.includes("daily heartbeat"));
  assert(msg.includes("2 active, 0 DLQ"));
  assert(msg.includes("0xAAA: 0.300000 xDAI (~1000 creates @ 1.000 gwei)"), msg);
  assert(msg.includes("0xBBB: 0.019000 xDAI"));
  assert(msg.includes("up 3h"));
  assert(msg.includes("release 20260710-004026"));
  assert(!msg.includes("⚠️"), "no attention line when DLQ is empty");
});

Deno.test("heartbeat: non-empty DLQ adds the attention line; multi-day uptime shown in days", () => {
  const msg = buildHeartbeatMessage({
    runtime: "Deno",
    queueDepth: 0,
    dlqCount: 3,
    createAddress: "0xAAA",
    createBalanceXdai: 0.1,
    commitAddress: "0xBBB",
    commitBalanceXdai: 0.01,
    gasPriceGwei: 1.5,
    uptimeMs: 73 * 3_600_000, // >48h → days
  });
  assert(msg.includes("⚠️ DLQ has 3 item(s)"));
  assert(msg.includes("up 3d"));
  assert(!msg.includes("release"), "release line omitted when unknown");
});
