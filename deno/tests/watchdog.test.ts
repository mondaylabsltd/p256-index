/**
 * External-liveness watchdog decision logic (shared/watchdog.ts) — pure state
 * machine, deterministic clock. The CF wiring (worker/watchdog.ts) is covered
 * by the worker vitest suite.
 */
import { assert, assertEquals } from "@std/assert/";
import {
  buildDownMessage,
  buildRecoveryMessage,
  buildSummaryMessage,
  INITIAL_WATCHDOG_STATE,
  isSummaryDue,
  WATCHDOG_FAIL_THRESHOLD,
  WATCHDOG_REPAGE_MS,
  WATCHDOG_SUMMARY_INTERVAL,
  watchdogDecide,
  type WatchdogState,
} from "../../shared/watchdog.ts";

const T0 = 1_000_000_000;
const UP = { ok: true, status: "ok" };
const DOWN = { ok: false, error: "probe timeout (10000ms)" };

Deno.test("watchdog: one or two failures never page (blip tolerance)", () => {
  let s: WatchdogState = INITIAL_WATCHDOG_STATE;
  for (let i = 1; i < WATCHDOG_FAIL_THRESHOLD; i++) {
    const d = watchdogDecide(s, DOWN, T0 + i * 60_000);
    assertEquals(d.action, undefined, `failure #${i} must not page`);
    s = d.next;
    assertEquals(s.consecutiveFails, i);
  }
});

Deno.test("watchdog: third consecutive failure pages DOWN exactly once", () => {
  let s: WatchdogState = INITIAL_WATCHDOG_STATE;
  let paged = 0;
  for (let i = 1; i <= WATCHDOG_FAIL_THRESHOLD + 2; i++) {
    const d = watchdogDecide(s, DOWN, T0 + i * 60_000);
    if (d.action === "page-down") paged++;
    s = d.next;
  }
  assertEquals(paged, 1, "one page at the threshold; still-down minutes within the repage window stay silent");
  assertEquals(s.paged, true);
});

Deno.test("watchdog: re-pages after WATCHDOG_REPAGE_MS while still down", () => {
  let s: WatchdogState = INITIAL_WATCHDOG_STATE;
  // reach the first page
  for (let i = 1; i <= WATCHDOG_FAIL_THRESHOLD; i++) s = watchdogDecide(s, DOWN, T0 + i * 60_000).next;
  assertEquals(s.paged, true);
  // one minute later: silent
  assertEquals(watchdogDecide(s, DOWN, s.lastPageAt + 60_000).action, undefined);
  // past the repage window: pages again
  const d = watchdogDecide(s, DOWN, s.lastPageAt + WATCHDOG_REPAGE_MS + 1);
  assertEquals(d.action, "page-down");
});

Deno.test("watchdog: recovery after a page sends the recovery message and resets", () => {
  let s: WatchdogState = INITIAL_WATCHDOG_STATE;
  for (let i = 1; i <= WATCHDOG_FAIL_THRESHOLD; i++) s = watchdogDecide(s, DOWN, T0 + i * 60_000).next;
  const d = watchdogDecide(s, UP, T0 + 10 * 60_000);
  assertEquals(d.action, "recover");
  assertEquals(d.next.paged, false);
  assertEquals(d.next.consecutiveFails, 0);
  // a later success does NOT send another recovery
  assertEquals(watchdogDecide(d.next, UP, T0 + 11 * 60_000).action, undefined);
});

Deno.test("watchdog: recovery WITHOUT a prior page stays silent (blip that never paged)", () => {
  let s: WatchdogState = INITIAL_WATCHDOG_STATE;
  s = watchdogDecide(s, DOWN, T0).next; // 1 failure, below threshold
  const d = watchdogDecide(s, UP, T0 + 60_000);
  assertEquals(d.action, undefined);
  assertEquals(d.next.consecutiveFails, 0);
});

Deno.test("watchdog: degraded status counts as UP for liveness (owned by in-process alerting)", () => {
  const d = watchdogDecide(INITIAL_WATCHDOG_STATE, { ok: true, status: "degraded" }, T0);
  assertEquals(d.action, undefined);
  assertEquals(d.next.consecutiveFails, 0);
});

Deno.test("watchdog: summary due immediately on first tick, then only after the interval", () => {
  assert(isSummaryDue(INITIAL_WATCHDOG_STATE, T0), "lastSummaryAt=0 → first tick sends");
  const after: WatchdogState = { ...INITIAL_WATCHDOG_STATE, lastSummaryAt: T0 };
  assert(!isSummaryDue(after, T0 + WATCHDOG_SUMMARY_INTERVAL - 1));
  assert(isSummaryDue(after, T0 + WATCHDOG_SUMMARY_INTERVAL));
});

Deno.test("watchdog: message builders include target, detail, and the telegram-unconfigured warning", () => {
  const target = "https://example.com/api/health";
  const down = buildDownMessage(target, { ...INITIAL_WATCHDOG_STATE, consecutiveFails: 3 }, { ok: false, error: "probe timeout (10000ms)" });
  assert(down.includes(target));
  assert(down.includes("probe timeout"));
  assert(down.includes("3 consecutive failures"));
  const rec = buildRecoveryMessage(target, T0, T0 + 5 * 60_000);
  assert(rec.includes("recovered"));
  assert(rec.includes("~5 min"));
  const sum = buildSummaryMessage({ target, vpsStatus: "ok", workerQueueDepth: 0, workerDlq: 1, vpsTelegramConfigured: false });
  assert(sum.includes("telegramConfigured=false"), "a broken VPS alert channel must be loud in the summary");
  const sumOk = buildSummaryMessage({ target, vpsStatus: "ok", workerQueueDepth: 0, workerDlq: 0, vpsTelegramConfigured: true });
  assert(!sumOk.includes("telegramConfigured=false"));
});
