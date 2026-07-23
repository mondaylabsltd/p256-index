//! Reliability primitives ported from the retired Deno/CF-Worker service so the Rust rewrite is a
//! true operational replacement for an unattended, fund-spending queue:
//!
//! - exponential backoff schedule for transient chain failures ([`backoff_delay`]),
//! - the daily heartbeat message + funding runway estimate ([`build_heartbeat_message`]).
//!
//! Everything here is pure and deterministically unit-tested; the side-effecting wiring (Telegram
//! delivery, chain reads, the periodic loops) lives in [`crate::telegram`], [`crate::worker`], and
//! `main.rs`.

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

// ── Daily heartbeat ────────────────────────────────────────────────────────

pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
/// Rough all-in gas per create (commit + createRecord shares). Only used for the runway estimate.
pub const EST_GAS_PER_CREATE: u64 = 300_000;

pub struct HeartbeatInput<'a> {
    pub runtime: &'a str,
    pub queue_depth: u64,
    pub dlq_count: u64,
    pub create_address: &'a str,
    pub create_balance_xdai: f64,
    pub commit_address: &'a str,
    pub commit_balance_xdai: f64,
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
    let runway = estimate_create_runway(input.create_balance_xdai, input.gas_price_gwei);
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
        "💓 [webauthnp256-publickey-index] [{}] [Gnosis] daily heartbeat\n\
         {attention}\
         queue: {} active, {} DLQ\n\
         create wallet {}: {:.6} xDAI ({runway_text} creates @ {:.3} gwei)\n\
         commit wallet {}: {:.6} xDAI\n\
         up {up_text}{release}",
        input.runtime,
        input.queue_depth,
        input.dlq_count,
        input.create_address,
        input.create_balance_xdai,
        input.gas_price_gwei,
        input.commit_address,
        input.commit_balance_xdai,
    )
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
        assert_eq!(EST_GAS_PER_CREATE, 300_000);
        assert_eq!(estimate_create_runway(0.3, 1.0), 1000.0);
        assert_eq!(estimate_create_runway(0.3, 10.0), 100.0);
        assert!(estimate_create_runway(0.3, 0.0).is_infinite());
    }

    #[test]
    fn heartbeat_message_carries_balances_runway_queue_uptime_release() {
        let message = build_heartbeat_message(&HeartbeatInput {
            runtime: "Rust",
            queue_depth: 2,
            dlq_count: 0,
            create_address: "0xAAA",
            create_balance_xdai: 0.3,
            commit_address: "0xBBB",
            commit_balance_xdai: 0.019,
            gas_price_gwei: 1.0,
            uptime: Duration::from_secs(3 * 3_600),
            release: Some("20260710-004026"),
        });
        assert!(message.contains("daily heartbeat"));
        assert!(message.contains("2 active, 0 DLQ"));
        assert!(
            message.contains("0xAAA: 0.300000 xDAI (~1000 creates @ 1.000 gwei)"),
            "{message}"
        );
        assert!(message.contains("0xBBB: 0.019000 xDAI"));
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
            create_address: "0xAAA",
            create_balance_xdai: 0.1,
            commit_address: "0xBBB",
            commit_balance_xdai: 0.01,
            gas_price_gwei: 1.5,
            uptime: Duration::from_secs(73 * 3_600),
            release: None,
        });
        assert!(message.contains("⚠️ DLQ has 3 item(s)"));
        assert!(message.contains("up 3d"));
        assert!(!message.contains("release"), "release omitted when unknown");
    }
}
