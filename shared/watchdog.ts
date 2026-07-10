/**
 * External-liveness watchdog — decision logic (pure, deterministically
 * testable; the CF worker provides probing/state/Telegram wiring).
 *
 * WHY: every alert this service can send is emitted by the process being
 * monitored. If the VPS host dies, loses network, or systemd wedges, the
 * operator hears NOTHING — the exact "user can't create an account and nobody
 * knows" scenario the alerting matrix exists to prevent. The CF worker already
 * runs an every-minute cron in independent infrastructure with the Telegram
 * secrets — that cron IS the external probe layer.
 *
 * Semantics:
 * - DOWN page after WATCHDOG_FAIL_THRESHOLD consecutive probe failures
 *   (network error / timeout / non-2xx / unparseable body) — one blip never
 *   pages. Re-pages every WATCHDOG_REPAGE_MS while still down.
 * - RECOVERY message when a probe succeeds after a page was sent.
 * - `status: "degraded"` is NOT a watchdog page: the target is up and its own
 *   in-process alerting owns the degradation details. It is surfaced in the
 *   daily summary instead.
 * - Daily summary every WATCHDOG_SUMMARY_INTERVAL: proves the watchdog itself
 *   (and the worker runtime) is alive — a silent channel becomes a signal.
 */

export const WATCHDOG_FAIL_THRESHOLD = 3;
export const WATCHDOG_REPAGE_MS = 30 * 60_000;
export const WATCHDOG_SUMMARY_INTERVAL = 24 * 60 * 60_000;
export const WATCHDOG_PROBE_TIMEOUT_MS = 10_000;
export const DEFAULT_WATCHDOG_TARGET = "https://webauthnp256-publickey-index.biubiu.tools/api/health";

export interface WatchdogState {
  consecutiveFails: number;
  /** timestamp of the last DOWN page (0 = never). */
  lastPageAt: number;
  /** true while a DOWN page has been sent and no recovery has been seen. */
  paged: boolean;
  /** timestamp of the last daily summary (0 = never → first tick sends one). */
  lastSummaryAt: number;
}

export const INITIAL_WATCHDOG_STATE: WatchdogState = {
  consecutiveFails: 0,
  lastPageAt: 0,
  paged: false,
  lastSummaryAt: 0,
};

export interface ProbeResult {
  /** HTTP 2xx with a parseable JSON body. */
  ok: boolean;
  /** body.status when parseable ("ok" | "degraded" | ...). */
  status?: string;
  httpStatus?: number;
  /** short error description for the page text (timeout / fetch error / ...). */
  error?: string;
}

export interface WatchdogDecision {
  next: WatchdogState;
  /** "page-down" | "recover" | undefined (no message). */
  action?: "page-down" | "recover";
}

export function watchdogDecide(state: WatchdogState, probe: ProbeResult, now: number): WatchdogDecision {
  if (probe.ok) {
    const recovered = state.paged;
    return {
      next: { ...state, consecutiveFails: 0, paged: false },
      action: recovered ? "recover" : undefined,
    };
  }
  const consecutiveFails = state.consecutiveFails + 1;
  const shouldPage = consecutiveFails >= WATCHDOG_FAIL_THRESHOLD &&
    (!state.paged || now - state.lastPageAt >= WATCHDOG_REPAGE_MS);
  if (shouldPage) {
    return {
      next: { ...state, consecutiveFails, paged: true, lastPageAt: now },
      action: "page-down",
    };
  }
  return { next: { ...state, consecutiveFails } };
}

export function isSummaryDue(state: WatchdogState, now: number): boolean {
  return now - state.lastSummaryAt >= WATCHDOG_SUMMARY_INTERVAL;
}

export function buildDownMessage(target: string, state: WatchdogState, probe: ProbeResult): string {
  const detail = probe.error ?? (probe.httpStatus !== undefined ? `HTTP ${probe.httpStatus}` : "unparseable response");
  return (
    `🔴 [webauthnp256-publickey-index] [watchdog@CF] VPS health probe DOWN\n` +
    `${state.consecutiveFails} consecutive failures (~${state.consecutiveFails} min): ${detail}\n` +
    `target: ${target}\n` +
    `Creates via the main domain are NOT being served. Check the VPS (systemd, host, network); ` +
    `the CF worker endpoint remains available as fallback.`
  );
}

export function buildRecoveryMessage(target: string, downSinceMs: number, now: number): string {
  const mins = downSinceMs > 0 ? Math.max(1, Math.round((now - downSinceMs) / 60_000)) : 0;
  return (
    `✅ [webauthnp256-publickey-index] [watchdog@CF] VPS health probe recovered` +
    (mins > 0 ? ` (down ~${mins} min)` : "") +
    `\ntarget: ${target}`
  );
}

export interface SummaryInput {
  target: string;
  vpsStatus: string; // "ok" | "degraded" | "DOWN" | ...
  workerQueueDepth: number;
  workerDlq: number;
  vpsTelegramConfigured?: boolean;
}

export function buildSummaryMessage(s: SummaryInput): string {
  const tgWarn = s.vpsTelegramConfigured === false
    ? "\n⚠️ VPS reports telegramConfigured=false — its own alerts are NOT being delivered!"
    : "";
  return (
    `💓 [webauthnp256-publickey-index] [watchdog@CF] daily watchdog summary\n` +
    `VPS (${s.target}): ${s.vpsStatus}${tgWarn}\n` +
    `worker queue: ${s.workerQueueDepth} active, ${s.workerDlq} DLQ`
  );
}
