//! Stuck-transaction rescue: the decision half of the unstick sweep.
//!
//! A broadcast whose receipt never arrived jams its wallet's nonce sequence
//! and stalls every later send. The sweep's *judgement* lives here as a pure
//! plan over the broadcast ledger; the server's maintenance loop supplies
//! the inputs (ledger rows, confirmed nonce, clock) and executes the plan
//! (delete rows, send same-nonce cancels, page the operator).
//!
//! Rules, unchanged from the original loop:
//! - a row whose nonce is below the wallet's confirmed nonce was consumed
//!   (this tx or a replacement mined) → drop the ledger row;
//! - a row stuck past the attempt or age escalation threshold pages the
//!   operator (throttled shell-side) — and is *still* replaced if the cycle
//!   budget allows: escalation and replacement are not exclusive;
//! - at most [`MAX_UNSTICK_PER_CYCLE`] replacements per role per cycle;
//!   rows beyond the budget keep escalating but are not replaced this round;
//! - rows are processed in ascending nonce order (the jam clears front to
//!   back);
//! - a replacement is a same-nonce, zero-value self-transfer at
//!   [`bump_gas`] (150%) of the current network gas price; on success the
//!   ledger row is rewritten with the cancel hash, a fresh timestamp and an
//!   incremented attempt count, so the next attempt waits a full window.

use alloy::primitives::U256;

/// A broadcast older than this whose nonce is still un-mined is treated as stuck.
pub const STUCK_TX_AGE_MS: u64 = 2 * 60 * 1_000;
pub const MAX_UNSTICK_PER_CYCLE: usize = 5;
/// Page after this many failed replacements of one nonce, or once it has been stuck this long.
pub const UNSTICK_ALERT_ATTEMPTS: u32 = 5;
pub const UNSTICK_ALERT_AGE_MS: u64 = 10 * 60 * 1_000;
/// Replacement gas price = 150% of the current network gas price.
pub const CANCEL_GAS_NUM: u64 = 150;
pub const CANCEL_GAS_DEN: u64 = 100;

/// One broadcast-ledger row, as the store projects it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerRow {
    pub role: String,
    pub nonce: u64,
    pub hash: String,
    pub sent_at_ms: u64,
    pub attempts: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RescueAction {
    /// The nonce was consumed on chain: remove the ledger row.
    DropConsumedRow { nonce: u64 },
    /// Page the operator (subject to the shell's alert throttle).
    Escalate { message: String },
    /// Replace with a same-nonce cancel; on success the ledger row is
    /// rewritten with `attempts_after`.
    Replace { nonce: u64, attempts_after: u32 },
}

/// The replacement gas price: 150% of the current network price.
pub fn bump_gas(price: U256) -> U256 {
    price.saturating_mul(U256::from(CANCEL_GAS_NUM)) / U256::from(CANCEL_GAS_DEN)
}

/// Plan one role's sweep over the ledger. `ledger` may contain rows of any
/// role in any order; only `role`'s rows are considered, ascending by nonce.
pub fn plan_role_sweep(
    role: &str,
    confirmed_nonce: u64,
    ledger: &[LedgerRow],
    now_ms: u64,
) -> Vec<RescueAction> {
    let mut stuck: Vec<&LedgerRow> = ledger.iter().filter(|row| row.role == role).collect();
    stuck.sort_by_key(|row| row.nonce);

    let mut actions = Vec::new();
    let mut replaced = 0usize;
    for row in stuck {
        if row.nonce < confirmed_nonce {
            actions.push(RescueAction::DropConsumedRow { nonce: row.nonce });
            continue;
        }
        let age_ms = now_ms.saturating_sub(row.sent_at_ms);
        if row.attempts >= UNSTICK_ALERT_ATTEMPTS || age_ms >= UNSTICK_ALERT_AGE_MS {
            actions.push(RescueAction::Escalate {
                message: stuck_alert(&row.role, row.nonce, row.attempts, age_ms),
            });
        }
        if replaced >= MAX_UNSTICK_PER_CYCLE {
            continue;
        }
        replaced += 1;
        actions.push(RescueAction::Replace {
            nonce: row.nonce,
            attempts_after: row.attempts + 1,
        });
    }
    actions
}

/// The escalation message, byte-identical to the original.
pub fn stuck_alert(role: &str, nonce: u64, attempts: u32, age_ms: u64) -> String {
    format!(
        "🛑 [webauthnp256-publickey-index] stuck {} nonce {} not clearing \
         (attempts {}, stuck ~{} min). Manual intervention may be required.",
        role,
        nonce,
        attempts,
        age_ms / 60_000
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(role: &str, nonce: u64, sent_at_ms: u64, attempts: u32) -> LedgerRow {
        LedgerRow {
            role: role.to_owned(),
            nonce,
            hash: format!("0x{nonce:x}"),
            sent_at_ms,
            attempts,
        }
    }

    #[test]
    fn consumed_nonces_are_dropped_not_replaced() {
        let actions = plan_role_sweep("create", 10, &[row("create", 9, 0, 0)], 1_000);
        assert_eq!(actions, vec![RescueAction::DropConsumedRow { nonce: 9 }]);
    }

    #[test]
    fn the_currently_pending_nonce_is_rescued_not_dropped() {
        // nonce == confirmed_nonce is exactly the transaction the wallet is
        // waiting on. Judging it consumed would delete the ledger row and
        // leave the nonce sequence jammed forever — the consumed check must
        // be strictly less-than.
        let actions = plan_role_sweep("create", 5, &[row("create", 5, 0, 0)], 1_000);
        assert_eq!(
            actions,
            vec![RescueAction::Replace {
                nonce: 5,
                attempts_after: 1
            }]
        );
    }

    #[test]
    fn other_roles_rows_are_ignored() {
        let actions = plan_role_sweep("create", 0, &[row("commit", 1, 0, 0)], 1_000);
        assert!(actions.is_empty());
    }

    #[test]
    fn rows_are_processed_in_ascending_nonce_order() {
        let ledger = [row("create", 7, 0, 0), row("create", 3, 0, 0)];
        let actions = plan_role_sweep("create", 0, &ledger, 1_000);
        assert_eq!(
            actions,
            vec![
                RescueAction::Replace {
                    nonce: 3,
                    attempts_after: 1
                },
                RescueAction::Replace {
                    nonce: 7,
                    attempts_after: 1
                },
            ]
        );
    }

    #[test]
    fn escalation_fires_on_attempts_or_age_and_still_replaces() {
        // Attempts threshold (age fresh).
        let by_attempts = plan_role_sweep(
            "create",
            0,
            &[row("create", 1, 1_000, UNSTICK_ALERT_ATTEMPTS)],
            1_000,
        );
        assert_eq!(
            by_attempts,
            vec![
                RescueAction::Escalate {
                    message: stuck_alert("create", 1, UNSTICK_ALERT_ATTEMPTS, 0),
                },
                RescueAction::Replace {
                    nonce: 1,
                    attempts_after: UNSTICK_ALERT_ATTEMPTS + 1
                },
            ]
        );
        // Age threshold (attempts low).
        let by_age = plan_role_sweep("create", 0, &[row("create", 2, 0, 1)], UNSTICK_ALERT_AGE_MS);
        assert!(matches!(
            by_age.as_slice(),
            [
                RescueAction::Escalate { .. },
                RescueAction::Replace {
                    nonce: 2,
                    attempts_after: 2
                }
            ]
        ));
        // Just under both thresholds: replace only.
        let quiet = plan_role_sweep(
            "create",
            0,
            &[row("create", 3, 1, UNSTICK_ALERT_ATTEMPTS - 1)],
            UNSTICK_ALERT_AGE_MS,
        );
        assert_eq!(
            quiet,
            vec![RescueAction::Replace {
                nonce: 3,
                attempts_after: UNSTICK_ALERT_ATTEMPTS
            }]
        );
    }

    #[test]
    fn replacement_budget_caps_at_five_but_escalations_continue() {
        // Seven stuck rows, all old enough to escalate: every row escalates,
        // only the first five (by nonce) are replaced.
        let ledger: Vec<LedgerRow> = (1..=7).map(|n| row("create", n, 0, 0)).collect();
        let actions = plan_role_sweep("create", 0, &ledger, UNSTICK_ALERT_AGE_MS);
        let replaces: Vec<u64> = actions
            .iter()
            .filter_map(|action| match action {
                RescueAction::Replace { nonce, .. } => Some(*nonce),
                _ => None,
            })
            .collect();
        let escalations = actions
            .iter()
            .filter(|action| matches!(action, RescueAction::Escalate { .. }))
            .count();
        assert_eq!(replaces, vec![1, 2, 3, 4, 5]);
        assert_eq!(escalations, 7);
    }

    #[test]
    fn stuck_alert_message_is_pinned_literally() {
        assert_eq!(
            stuck_alert("create", 42, 6, 12 * 60_000),
            "🛑 [webauthnp256-publickey-index] stuck create nonce 42 not clearing \
             (attempts 6, stuck ~12 min). Manual intervention may be required."
        );
    }

    #[test]
    fn bump_gas_is_one_hundred_fifty_percent() {
        assert_eq!(bump_gas(U256::from(100u64)), U256::from(150u64));
        assert_eq!(bump_gas(U256::from(1u64)), U256::from(1u64)); // 1*150/100 = 1 (integer div)
        // The multiply saturates instead of overflowing.
        assert_eq!(bump_gas(U256::MAX), U256::MAX / U256::from(100u64));
    }
}
