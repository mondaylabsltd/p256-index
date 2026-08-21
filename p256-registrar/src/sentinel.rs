//! The ops sentinel: reliability policy for an unattended, fund-spending
//! queue. Everything here is pure and deterministically unit-tested; the
//! side-effecting wiring (Telegram delivery, chain reads, the periodic
//! loops) lives in the server's `telegram`, `maintenance` and `worker`.
//!
//! Owns:
//! - the exponential backoff schedule for transient chain failures
//!   ([`backoff_delay`], the legacy `5000 * 3^(retries-1)` curve);
//! - service health assessment ([`health_reasons`] over [`QueueHealth`], the
//!   thresholds previously inlined in the HTTP health handler);
//! - operator-alert policy: thresholds, the 6h per-kind throttle window
//!   ([`alert_due`]) and the exact message texts;
//! - the daily heartbeat message and funding-runway estimate.

use std::time::Duration;

// ── Exponential backoff ────────────────────────────────────────────────────

/// Base delay for the first retry (matches the legacy `5000 * 3^(retries-1)` schedule).
const BACKOFF_BASE: Duration = Duration::from_secs(5);
/// The legacy schedule caps a single item's back-off at 12 hours.
const BACKOFF_MAX: Duration = Duration::from_secs(12 * 60 * 60);

/// Back-off before the next attempt after `retries` consecutive transient failures (1-based):
/// `min(5s * 3^(retries-1), 12h)`. `retries == 0` is treated as the first attempt.
pub fn backoff_delay(retries: u32) -> Duration {
    let exponent = retries.saturating_sub(1).min(32);
    let scaled = BACKOFF_BASE
        .as_secs()
        .saturating_mul(3u64.saturating_pow(exponent));
    Duration::from_secs(scaled.min(BACKOFF_MAX.as_secs()))
}

// ── Service health ─────────────────────────────────────────────────────────

/// Queue projections the health verdict is judged on.
#[derive(Clone, Copy, Debug)]
pub struct QueueHealth {
    pub depth: u64,
    pub dlq_count: u64,
    pub oldest_active_age_ms: u64,
}

/// Health thresholds, previously inlined in the HTTP handler.
pub const HEALTH_QUEUE_DEPTH: u64 = 2_000;
pub const HEALTH_DLQ_COUNT: u64 = 25;
pub const HEALTH_OLDEST_JOB_MS: u64 = 30 * 60_000;

/// Degradation reasons in report order; empty means healthy.
pub fn health_reasons(queue: &QueueHealth) -> Vec<&'static str> {
    let mut reasons = Vec::new();
    if queue.depth >= HEALTH_QUEUE_DEPTH {
        reasons.push("queue-depth");
    }
    if queue.dlq_count >= HEALTH_DLQ_COUNT {
        reasons.push("dlq");
    }
    if queue.oldest_active_age_ms >= HEALTH_OLDEST_JOB_MS {
        reasons.push("oldest-job");
    }
    reasons
}

// ── Operator alerts ────────────────────────────────────────────────────────

/// Minimum spacing between repeats of the same alert kind.
pub const ALERT_THROTTLE: Duration = Duration::from_secs(6 * 60 * 60);
/// Alert when the estimated create runway drops below this many creates.
pub const LOW_RUNWAY_CREATES: f64 = 200.0;
/// Alert when the DLQ reaches this depth.
pub const DLQ_ALERT_THRESHOLD: u64 = 10;

/// Whether an alert may fire again, given when this kind last fired.
pub fn alert_due(last_fired_ms: Option<u64>, now_ms: u64) -> bool {
    match last_fired_ms {
        Some(at) => now_ms.saturating_sub(at) >= ALERT_THROTTLE.as_millis() as u64,
        None => true,
    }
}

pub fn rpc_circuit_alert() -> &'static str {
    "⚠️ [webauthnp256-publickey-index] all chain RPC read endpoints are in cooldown \
     (circuit open) — queries may be served stale."
}

pub fn dlq_alert(dlq_count: u64) -> String {
    format!(
        "⚠️ [webauthnp256-publickey-index] DLQ has {dlq_count} quarantined create(s) — inspect."
    )
}

pub fn low_runway_alert(runway: f64, balance_xdai: f64, gas_price_gwei: f64) -> String {
    format!(
        "🪫 [webauthnp256-publickey-index] create wallet funding low: ~{} creates left \
         ({balance_xdai:.6} xDAI @ {gas_price_gwei:.3} gwei). Top up soon.",
        runway as i64,
    )
}

// ── Daily heartbeat ────────────────────────────────────────────────────────

pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
/// Rough all-in gas per register(), used only for the runway estimate.
/// A group + 1 member unit is ~1.1M gas on a precompile chain; multi-key
/// units cost more, so treat the runway as an optimistic ceiling.
pub const EST_GAS_PER_CREATE: u64 = 1_100_000;

pub struct HeartbeatInput<'a> {
    pub runtime: &'a str,
    pub queue_depth: u64,
    pub dlq_count: u64,
    pub wallet_address: &'a str,
    pub wallet_balance_xdai: f64,
    pub gas_price_gwei: f64,
    pub uptime: Duration,
    pub release: Option<&'a str>,
}

/// Estimated number of creates the balance can still pay for at a gas price. A non-positive gas
/// price yields `f64::INFINITY` (never a division blow-up), matching the legacy helper.
pub fn estimate_create_runway(balance_xdai: f64, gas_price_gwei: f64) -> f64 {
    if gas_price_gwei <= 0.0 {
        return f64::INFINITY;
    }
    ((balance_xdai * 1e9) / (EST_GAS_PER_CREATE as f64 * gas_price_gwei)).floor()
}

pub fn build_heartbeat_message(input: &HeartbeatInput) -> String {
    let runway = estimate_create_runway(input.wallet_balance_xdai, input.gas_price_gwei);
    let runway_text = if runway.is_infinite() {
        "∞".to_owned()
    } else {
        format!("~{}", runway as i64)
    };
    let up_hours = (input.uptime.as_secs() / 3_600) as i64;
    let up_text = if up_hours >= 48 {
        format!("{}d", up_hours / 24)
    } else {
        format!("{up_hours}h")
    };
    let attention = if input.dlq_count > 0 {
        format!(
            "⚠️ DLQ has {} item(s) — inspect when convenient\n",
            input.dlq_count
        )
    } else {
        String::new()
    };
    let release = input
        .release
        .map(|release| format!(", release {release}"))
        .unwrap_or_default();
    format!(
        "💓 [webauthnp256-publickey-registry] [{}] [Gnosis] daily heartbeat\n\
         {attention}\
         queue: {} active, {} DLQ\n\
         wallet {}: {:.6} xDAI ({runway_text} registrations @ {:.3} gwei)\n\
         up {up_text}{release}",
        input.runtime,
        input.queue_depth,
        input.dlq_count,
        input.wallet_address,
        input.wallet_balance_xdai,
        input.gas_price_gwei,
    )
}

/// wei → xDAI for display and runway math.
pub fn wei_to_xdai(wei: u128) -> f64 {
    wei as f64 / 1e18
}

/// wei → gwei for display and runway math.
pub fn wei_to_gwei(wei: u128) -> f64 {
    wei as f64 / 1e9
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_follows_the_legacy_schedule() {
        assert_eq!(backoff_delay(1), Duration::from_secs(5));
        assert_eq!(backoff_delay(2), Duration::from_secs(15));
        assert_eq!(backoff_delay(3), Duration::from_secs(45));
        assert_eq!(backoff_delay(0), Duration::from_secs(5));
        // Capped at 12h no matter how many retries.
        assert_eq!(backoff_delay(100), Duration::from_secs(12 * 60 * 60));
    }

    #[test]
    fn runway_multiplies_before_dividing() {
        assert_eq!(EST_GAS_PER_CREATE, 1_100_000);
        assert_eq!(estimate_create_runway(1.1, 1.0), 1000.0);
        assert_eq!(estimate_create_runway(1.1, 10.0), 100.0);
        assert!(estimate_create_runway(1.1, 0.0).is_infinite());
    }

    #[test]
    fn heartbeat_message_carries_balances_runway_queue_uptime_release() {
        let message = build_heartbeat_message(&HeartbeatInput {
            runtime: "Rust",
            queue_depth: 2,
            dlq_count: 0,
            wallet_address: "0xAAA",
            wallet_balance_xdai: 0.7,
            gas_price_gwei: 1.0,
            uptime: Duration::from_secs(3 * 3_600),
            release: Some("20260710-004026"),
        });
        assert!(message.contains("daily heartbeat"));
        assert!(message.contains("2 active, 0 DLQ"));
        assert!(
            message.contains("0xAAA: 0.700000 xDAI (~636 registrations @ 1.000 gwei)"),
            "{message}"
        );
        assert!(message.contains("up 3h"));
        assert!(message.contains("release 20260710-004026"));
        assert!(
            !message.contains('⚠'),
            "no attention line when DLQ is empty"
        );
    }

    #[test]
    fn heartbeat_flags_dlq_and_shows_multi_day_uptime() {
        let message = build_heartbeat_message(&HeartbeatInput {
            runtime: "Rust",
            queue_depth: 0,
            dlq_count: 3,
            wallet_address: "0xAAA",
            wallet_balance_xdai: 0.1,
            gas_price_gwei: 1.5,
            uptime: Duration::from_secs(73 * 3_600),
            release: None,
        });
        assert!(message.contains("⚠️ DLQ has 3 item(s)"));
        assert!(message.contains("up 3d"));
        assert!(!message.contains("release"), "release omitted when unknown");
    }

    #[test]
    fn health_reasons_fire_at_their_inclusive_thresholds() {
        let healthy = QueueHealth {
            depth: HEALTH_QUEUE_DEPTH - 1,
            dlq_count: HEALTH_DLQ_COUNT - 1,
            oldest_active_age_ms: HEALTH_OLDEST_JOB_MS - 1,
        };
        assert!(health_reasons(&healthy).is_empty());

        let degraded = QueueHealth {
            depth: HEALTH_QUEUE_DEPTH,
            dlq_count: HEALTH_DLQ_COUNT,
            oldest_active_age_ms: HEALTH_OLDEST_JOB_MS,
        };
        assert_eq!(
            health_reasons(&degraded),
            vec!["queue-depth", "dlq", "oldest-job"]
        );
    }

    #[test]
    fn alert_throttle_is_a_six_hour_window() {
        let six_hours_ms = 6 * 60 * 60 * 1_000;
        assert!(alert_due(None, 0));
        assert!(!alert_due(Some(0), six_hours_ms - 1));
        assert!(alert_due(Some(0), six_hours_ms));
    }

    #[test]
    fn alert_messages_are_pinned_literally() {
        assert_eq!(
            dlq_alert(7),
            "⚠️ [webauthnp256-publickey-index] DLQ has 7 quarantined create(s) — inspect."
        );
        assert_eq!(
            low_runway_alert(123.9, 0.0123456, 1.5),
            "🪫 [webauthnp256-publickey-index] create wallet funding low: ~123 creates left \
             (0.012346 xDAI @ 1.500 gwei). Top up soon."
        );
        assert!(rpc_circuit_alert().contains("circuit open"));
    }
}
