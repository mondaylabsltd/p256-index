/**
 * CF wiring for the external-liveness watchdog (decision logic in
 * shared/watchdog.ts). Runs from the worker's every-minute cron — independent
 * infrastructure from the VPS it monitors, with the Telegram secrets already
 * bound. MUST never throw: a watchdog crash would silently disable the very
 * layer that exists to catch silent failures, so every step fails soft.
 */
import {
  buildDownMessage,
  buildRecoveryMessage,
  buildSummaryMessage,
  DEFAULT_WATCHDOG_TARGET,
  INITIAL_WATCHDOG_STATE,
  isSummaryDue,
  type ProbeResult,
  WATCHDOG_PROBE_TIMEOUT_MS,
  watchdogDecide,
  type WatchdogState,
} from "../shared/watchdog.ts";
import { sendTelegram, type AppConfig } from "../shared/queue.ts";
import { getQueueStats, initQueue } from "./queue.ts";
import type { Env } from "./types.ts";

const STATE_KEY = "state";

// In-memory fallback so a D1 outage degrades to per-isolate throttling instead
// of disabling the watchdog (or page-spamming every minute).
let memoryState: WatchdogState | null = null;

// scheduled() can run in a cold isolate before any fetch ran initQueue — the
// watchdog_state table must exist BEFORE loadState, or every fresh isolate
// starts from lastSummaryAt=0 and re-sends the daily summary. Memoized like
// worker/index.ts; a failed init clears the memo so the next tick retries.
let initPromise: Promise<void> | null = null;
function ensureInit(env: Env): Promise<void> {
  if (!initPromise) {
    initPromise = initQueue(env.DB).catch((err) => {
      initPromise = null;
      throw err;
    });
  }
  return initPromise;
}

function telegramConfig(env: Env): AppConfig {
  // The watchdog needs only the Telegram fields — never touch PRIVATE_KEY here.
  return { privateKey: "", commitPrivateKey: "", telegramBotToken: env.TELEGRAM_BOT_TOKEN || "", telegramChatId: env.TELEGRAM_CHAT_ID || "" };
}

async function loadState(env: Env): Promise<WatchdogState> {
  try {
    const row = await env.DB.prepare("SELECT v FROM watchdog_state WHERE k = ?").bind(STATE_KEY).first<{ v: string }>();
    if (row?.v) return { ...INITIAL_WATCHDOG_STATE, ...JSON.parse(row.v) };
  } catch { /* fall through to memory */ }
  return memoryState ?? INITIAL_WATCHDOG_STATE;
}

async function saveState(env: Env, state: WatchdogState): Promise<void> {
  memoryState = state;
  try {
    await env.DB.prepare("INSERT INTO watchdog_state (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v")
      .bind(STATE_KEY, JSON.stringify(state)).run();
  } catch { /* memory fallback already updated */ }
}

async function probe(target: string): Promise<ProbeResult & { body?: { status?: string; telegramConfigured?: boolean } }> {
  try {
    const res = await fetch(target, { signal: AbortSignal.timeout(WATCHDOG_PROBE_TIMEOUT_MS) });
    if (!res.ok) return { ok: false, httpStatus: res.status };
    const body = await res.json() as { status?: string; telegramConfigured?: boolean };
    // Any parseable health body from a 2xx counts as UP — "degraded" is owned
    // by the target's in-process alerting, not the external liveness layer.
    return { ok: true, status: body.status, body };
  } catch (err) {
    const msg = err instanceof Error ? (err.name === "TimeoutError" ? `probe timeout (${WATCHDOG_PROBE_TIMEOUT_MS}ms)` : err.message) : String(err);
    return { ok: false, error: msg.slice(0, 120) };
  }
}

export async function runWatchdog(env: Env): Promise<void> {
  try {
    const target = env.WATCHDOG_TARGET_URL || DEFAULT_WATCHDOG_TARGET;
    const now = Date.now();
    try { await ensureInit(env); } catch { /* loadState falls back to memory */ }
    const state = await loadState(env);
    const result = await probe(target);
    const downSince = state.lastPageAt;
    const { next, action } = watchdogDecide(state, result, now);

    if (action === "page-down") {
      await sendTelegram(telegramConfig(env), buildDownMessage(target, next, result));
    } else if (action === "recover") {
      await sendTelegram(telegramConfig(env), buildRecoveryMessage(target, downSince, now));
    }

    // Daily summary: proves watchdog + worker + Telegram path are all alive.
    if (isSummaryDue(next, now)) {
      next.lastSummaryAt = now;
      let workerQueueDepth = -1, workerDlq = -1;
      try {
        const stats = await getQueueStats(env.DB);
        workerQueueDepth = stats.queueDepth;
        workerDlq = stats.dlqCount;
      } catch { /* report -1 = unknown */ }
      await sendTelegram(telegramConfig(env), buildSummaryMessage({
        target,
        vpsStatus: result.ok ? (result.status ?? "ok") : "DOWN",
        workerQueueDepth,
        workerDlq,
        vpsTelegramConfigured: result.body?.telegramConfigured,
      }));
    }

    await saveState(env, next);
  } catch (err) {
    // Last-resort guard: never let the watchdog take down scheduled().
    console.warn("[watchdog] cycle error:", err instanceof Error ? err.message : String(err));
  }
}
