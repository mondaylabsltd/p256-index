//! Gas pricing policy: the decision half of every chain write.
//!
//! Gnosis settles at a base fee near 9_000 wei (~0.000009 gwei), so cost is
//! never the operational problem here — *inclusion* is. The rules below exist
//! to keep three separate promises:
//!
//! - **A transaction stays includable while it waits.** EIP-1559 charges
//!   `min(max_fee, base_fee + tip)`, so headroom above the current base fee is
//!   free: it is a ceiling, not a price. Quoting `max_fee = base_fee` (what
//!   `eth_gasPrice` effectively returns on Gnosis, base fee + 1 wei) makes a
//!   transaction includable *only in the block it was quoted against* — the
//!   base fee may rise 12.5% per block, and Gnosis blocks routinely run over
//!   the 50% target that makes it rise. [`plan_fees`] buys
//!   [`BASE_FEE_HEADROOM_NUM`]% of headroom so a broadcast survives a burst
//!   instead of stranding the wallet's nonce.
//! - **A replacement actually replaces.** Nodes reject a same-nonce
//!   replacement priced under 110% of the original, so a bump must be computed
//!   from *the price that transaction was sent at*, never from the current
//!   market price ([`plan_replacement`]). Bumping against the market is how a
//!   falling market makes a stuck nonce permanently unrescuable.
//! - **A mispricing cannot drain the wallet.** [`plan_fees`] refuses to sign
//!   anything above an absolute cap, and the shell returns the work to the
//!   queue instead of spending. At the default cap this never triggers in
//!   normal operation; it bounds the tail.
//!
//! This module is pure: the shell reads the base fee and the wallet balance,
//! asks here what to do, and executes the answer.

use alloy::primitives::U256;

/// Absolute ceiling on `max_fee_per_gas`, in wei. The observed Gnosis base fee
/// is ~9_000 wei, so this is roughly 1000x headroom: it never throttles normal
/// operation and exists purely to bound a catastrophic mispricing (a bad RPC
/// answer, a chain-wide fee event). Override with
/// `P256_INDEX_MAX_GAS_PRICE_WEI`.
pub const DEFAULT_MAX_FEE_WEI: u128 = 10_000_000; // 0.01 gwei

/// Priority fee offered to the proposer, in wei. Observed Gnosis median tips
/// are 1–430 wei, so this is generous while costing ~3.4e-9 xDAI on a 3.4M-gas
/// transaction. A tip that rounds to nothing is how a transaction gets
/// deprioritised the one time the chain is busy.
pub const DEFAULT_TIP_WEI: u128 = 1_000;

/// `max_fee` targets this percentage of the current base fee (plus the tip).
/// 200% survives roughly six consecutive maximally-full blocks (1.125^5.88 ≈ 2)
/// — about 30s of sustained congestion at Gnosis block times. Because the
/// effective charge is `min(max_fee, base_fee + tip)`, this headroom is free.
pub const BASE_FEE_HEADROOM_NUM: u64 = 200;
pub const BASE_FEE_HEADROOM_DEN: u64 = 100;

/// A same-nonce replacement is priced at this percentage of the price the
/// stuck transaction was sent at.
pub const REPLACEMENT_NUM: u64 = 150;
pub const REPLACEMENT_DEN: u64 = 100;

/// The floor nodes enforce for a same-nonce replacement. [`plan_replacement`]
/// must never return a price below this multiple of the previous one, or the
/// node answers `replacement transaction underpriced` forever.
pub const MIN_REPLACEMENT_NUM: u64 = 110;
pub const MIN_REPLACEMENT_DEN: u64 = 100;

/// Refuse to broadcast a transaction asking for more gas than this. The Gnosis
/// block gas limit is 17,000,000; anything approaching it cannot be scheduled
/// reliably and signals a batch that should have been split.
pub const MAX_GAS_LIMIT: u64 = 12_000_000;

/// The two EIP-1559 fee fields. Distinct on purpose: collapsing them is what
/// removed all inclusion headroom in the first place.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeePlan {
    pub max_fee_per_gas: U256,
    pub max_priority_fee_per_gas: U256,
}

/// What to do about a pending chain write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FeeVerdict {
    /// Sign and broadcast at this price.
    Send(FeePlan),
    /// The price required to be includable exceeds the cap. The caller must
    /// return the work to the queue — never drop it, never spend.
    TooExpensive { required: U256, cap: U256 },
}

impl FeeVerdict {
    pub fn plan(&self) -> Option<FeePlan> {
        match self {
            Self::Send(plan) => Some(*plan),
            Self::TooExpensive { .. } => None,
        }
    }

    pub fn is_too_expensive(&self) -> bool {
        matches!(self, Self::TooExpensive { .. })
    }
}

/// Price a fresh transaction against the current base fee.
///
/// `max_fee` is `base_fee * headroom + tip`, clamped to `cap`. The verdict is
/// [`FeeVerdict::TooExpensive`] only when even the minimum includable price
/// (`base_fee + tip`) is over the cap — i.e. when no signable price exists,
/// rather than merely when the comfortable price does not fit.
pub fn plan_fees(base_fee: U256, tip: U256, cap: U256) -> FeeVerdict {
    let minimum = base_fee.saturating_add(tip);
    if minimum > cap {
        return FeeVerdict::TooExpensive {
            required: minimum,
            cap,
        };
    }
    let target = base_fee
        .saturating_mul(U256::from(BASE_FEE_HEADROOM_NUM))
        .wrapping_div(U256::from(BASE_FEE_HEADROOM_DEN))
        .saturating_add(tip);
    let max_fee = target.min(cap);
    FeeVerdict::Send(FeePlan {
        // The priority fee can never exceed the total ceiling, or the node
        // rejects the transaction outright.
        max_priority_fee_per_gas: tip.min(max_fee),
        max_fee_per_gas: max_fee,
    })
}

/// Price a same-nonce replacement for a stuck transaction.
///
/// **Both** fee fields are raised. Nodes do not check the ceiling alone: geth's
/// `legacypool` rejects a replacement unless the new `max_fee_per_gas` *and*
/// `max_priority_fee_per_gas` each strictly exceed the old value and each reach
/// [`MIN_REPLACEMENT_NUM`]% of it (`GasFeeCapCmp >= 0 || GasTipCapCmp >= 0` →
/// reject, then both threshold comparisons). Erigon and Nethermind enforce the
/// same pair. Raising only the ceiling leaves the proposer's take unchanged, so
/// such a "replacement" is refused — and the nonce stays jammed forever.
///
/// `previous` is `None` for ledger rows written before fees were recorded. The
/// price those broadcasts used is unknowable, so the ladder escalates from the
/// market by `attempts` until it clears the old bid or reaches the cap.
pub fn plan_replacement(
    previous: Option<FeePlan>,
    base_fee: U256,
    tip: U256,
    cap: U256,
    attempts: u32,
) -> FeeVerdict {
    let market_ceiling = base_fee
        .saturating_mul(U256::from(BASE_FEE_HEADROOM_NUM))
        .wrapping_div(U256::from(BASE_FEE_HEADROOM_DEN))
        .saturating_add(tip);

    // An unrecorded row is treated as if it had bid the current market, scaled
    // by how many times we have already tried. The pre-fix build set *both*
    // fields to `eth_gasPrice` (~base_fee + 1), so one escalation step already
    // clears a same-block bid; the ladder covers a broadcast made when the
    // base fee was higher than it is now.
    let previous = previous.unwrap_or_else(|| {
        // The build that wrote these rows set both fields to `eth_gasPrice`
        // (~base_fee + 1), so that is the bid to beat — not the whole ceiling.
        // Assuming the ceiling here would hand the proposer every wei of
        // headroom on the very path where we are least sure it is needed.
        let assumed_tip = escalate(base_fee.saturating_add(U256::from(1u64)), attempts);
        FeePlan {
            max_fee_per_gas: escalate(market_ceiling, attempts).max(assumed_tip),
            max_priority_fee_per_gas: assumed_tip,
        }
    });

    // Ceiling division, never equal to the previous value: truncation at small
    // values silently produces a "bump" the node still rejects (110% of 1
    // truncates back to 1).
    let fee_floor = strictly_above(
        previous.max_fee_per_gas,
        MIN_REPLACEMENT_NUM,
        MIN_REPLACEMENT_DEN,
    );
    let tip_floor = strictly_above(
        previous.max_priority_fee_per_gas,
        MIN_REPLACEMENT_NUM,
        MIN_REPLACEMENT_DEN,
    );

    // Refuse before bidding: the required floor on either axis, or the price
    // that makes the replacement itself includable, must fit under the cap.
    let required = fee_floor
        .max(tip_floor)
        .max(base_fee.saturating_add(tip_floor));
    if required > cap {
        return FeeVerdict::TooExpensive { required, cap };
    }

    // `.max(U256::from(1))`: `strictly_above(0, ..)` is 0 by construction, so a
    // previous tip of zero would otherwise leave the tip axis flat and the node
    // would refuse the replacement. Cheap to hold unconditionally rather than
    // rely on `tip` never being configured to zero.
    let new_tip = strictly_above(
        previous.max_priority_fee_per_gas,
        REPLACEMENT_NUM,
        REPLACEMENT_DEN,
    )
    .max(tip_floor)
    .max(tip)
    .max(U256::from(1u64))
    .min(cap);
    let new_max_fee = strictly_above(previous.max_fee_per_gas, REPLACEMENT_NUM, REPLACEMENT_DEN)
        .max(fee_floor)
        .max(market_ceiling)
        // The ceiling must still cover the tip it is paired with, or the
        // transaction is malformed.
        .max(new_tip)
        .min(cap);

    FeeVerdict::Send(FeePlan {
        max_fee_per_gas: new_max_fee,
        max_priority_fee_per_gas: new_tip.min(new_max_fee),
    })
}

/// `value * 1.5^attempts`, saturating. Used only when the previous bid is
/// unknown and the ladder must climb blind.
fn escalate(value: U256, attempts: u32) -> U256 {
    let mut result = value;
    for _ in 0..attempts.min(16) {
        result = strictly_above(result, REPLACEMENT_NUM, REPLACEMENT_DEN);
    }
    result
}

/// `ceil(value * num / den)`, and always greater than `value` itself when
/// `value` is non-zero. Both properties matter: nodes compare replacement fees
/// with integer arithmetic, so a bump that rounds back down to the original
/// price is rejected rather than merely under-effective.
fn strictly_above(value: U256, num: u64, den: u64) -> U256 {
    if value.is_zero() {
        return U256::ZERO;
    }
    let den = U256::from(den);
    let scaled = value.saturating_mul(U256::from(num));
    let ceiling = scaled
        .saturating_add(den.saturating_sub(U256::from(1u64)))
        .wrapping_div(den);
    ceiling.max(value.saturating_add(U256::from(1u64)))
}

/// Whether a gas estimate may be broadcast at all.
pub fn gas_limit_within_bounds(gas_limit: u64) -> bool {
    gas_limit <= MAX_GAS_LIMIT
}

/// The balance a wallet must hold to cover this transaction in the worst case
/// (every unit of gas charged at the ceiling).
pub fn required_balance(gas_limit: u64, max_fee_per_gas: U256) -> U256 {
    U256::from(gas_limit).saturating_mul(max_fee_per_gas)
}

/// The operator-facing reason a batch was returned to the queue unspent.
pub fn too_expensive_reason(required: U256, cap: U256) -> String {
    format!("gas price {required} wei exceeds the configured cap of {cap} wei; batch requeued")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(value: u128) -> U256 {
        U256::from(value)
    }

    const TIP: u128 = DEFAULT_TIP_WEI;
    const CAP: u128 = DEFAULT_MAX_FEE_WEI;

    #[test]
    fn fresh_price_carries_headroom_above_the_base_fee() {
        // The whole point: max_fee must exceed the base fee it was quoted
        // against, or the transaction is includable in exactly one block.
        let plan = plan_fees(u(9_255), u(TIP), u(CAP)).plan().unwrap();
        assert_eq!(plan.max_fee_per_gas, u(9_255 * 2 + TIP));
        assert_eq!(plan.max_priority_fee_per_gas, u(TIP));
        assert!(plan.max_fee_per_gas > u(9_255));
    }

    #[test]
    fn fresh_price_survives_the_maximum_base_fee_growth_for_several_blocks() {
        let base = 9_255u128;
        let plan = plan_fees(u(base), u(TIP), u(CAP)).plan().unwrap();
        // Six consecutive blocks each raising the base fee by the EIP-1559
        // maximum of 12.5% must still be payable.
        let mut grown = base as f64;
        for _ in 0..5 {
            grown *= 1.125;
        }
        assert!(U256::from(grown as u128) < plan.max_fee_per_gas);
    }

    #[test]
    fn priority_fee_never_exceeds_the_ceiling() {
        // A cap tighter than the tip must not produce an invalid transaction.
        let plan = plan_fees(u(10), u(500), u(600)).plan().unwrap();
        assert!(plan.max_priority_fee_per_gas <= plan.max_fee_per_gas);
    }

    #[test]
    fn refuses_only_when_no_includable_price_fits_under_the_cap() {
        // base + tip still fits: comfortable price is clamped, not refused.
        let verdict = plan_fees(u(400), u(TIP), u(1_500));
        assert_eq!(verdict.plan().unwrap().max_fee_per_gas, u(1_500));
        // base + tip does not fit: nothing signable exists.
        let verdict = plan_fees(u(1_000), u(TIP), u(1_500));
        assert_eq!(
            verdict,
            FeeVerdict::TooExpensive {
                required: u(2_000),
                cap: u(1_500)
            }
        );
    }

    #[test]
    fn default_cap_is_far_above_the_observed_gnosis_base_fee() {
        // Guards the operating assumption: at the shipped default the gate is
        // a tail-risk bound, not a throttle on normal traffic.
        assert!(plan_fees(u(9_960), u(TIP), u(CAP)).plan().is_some());
        assert!(u(CAP) > u(9_960) * u(1_000));
    }

    /// geth's actual admission rule for a same-nonce replacement, applied to
    /// both fee axes: strictly greater, and at least 110%. Erigon and
    /// Nethermind enforce the same pair. Every replacement test asserts this
    /// rather than checking `max_fee_per_gas` alone — checking one axis is
    /// exactly how the first version of this module shipped a bump that no
    /// node would have accepted.
    fn node_accepts_replacement(old: FeePlan, new: FeePlan) -> bool {
        let threshold = |value: U256| {
            value.saturating_mul(u(MIN_REPLACEMENT_NUM as u128)) / u(MIN_REPLACEMENT_DEN as u128)
        };
        new.max_fee_per_gas > old.max_fee_per_gas
            && new.max_priority_fee_per_gas > old.max_priority_fee_per_gas
            && new.max_fee_per_gas >= threshold(old.max_fee_per_gas)
            && new.max_priority_fee_per_gas >= threshold(old.max_priority_fee_per_gas)
            && new.max_priority_fee_per_gas <= new.max_fee_per_gas
    }

    fn plan(max_fee: u128, priority: u128) -> FeePlan {
        FeePlan {
            max_fee_per_gas: u(max_fee),
            max_priority_fee_per_gas: u(priority),
        }
    }

    #[test]
    fn replacement_raises_both_fee_axes_not_just_the_ceiling() {
        // Raising only max_fee leaves the proposer's take unchanged, so the
        // node refuses the replacement and the nonce never clears.
        let previous = plan(24_520, TIP);
        let next = plan_replacement(Some(previous), u(9_255), u(TIP), u(CAP), 0)
            .plan()
            .unwrap();
        assert!(
            node_accepts_replacement(previous, next),
            "old={previous:?} new={next:?}"
        );
    }

    #[test]
    fn replacement_rises_even_when_the_market_falls() {
        // Pricing a replacement off the current market lets a falling market
        // produce an underpriced bump, which the node rejects forever.
        let previous = plan(1_000_000, 500_000);
        let next = plan_replacement(Some(previous), u(9_255), u(TIP), u(CAP), 0)
            .plan()
            .unwrap();
        assert!(node_accepts_replacement(previous, next));
    }

    #[test]
    fn repeated_replacements_are_accepted_at_every_rung() {
        let mut current = plan(9_255 * 2 + TIP, TIP);
        for round in 0..6 {
            let next = plan_replacement(Some(current), u(9_255), u(TIP), u(CAP), round)
                .plan()
                .unwrap();
            assert!(
                node_accepts_replacement(current, next),
                "round {round}: old={current:?} new={next:?}"
            );
            current = next;
        }
    }

    #[test]
    fn the_ladder_stays_valid_all_the_way_up_to_the_cap() {
        // The rungs where `.min(cap)` actually clamps are the ones most likely
        // to silently produce a bid the node refuses, and they were previously
        // untested: the 6-rung test never came close to the cap.
        let mut current = plan(9_255 * 2 + TIP, TIP);
        let mut clamped_rungs = 0;
        for round in 0..40 {
            match plan_replacement(Some(current), u(9_255), u(TIP), u(CAP), round) {
                FeeVerdict::Send(next) => {
                    assert!(
                        node_accepts_replacement(current, next),
                        "round {round}: old={current:?} new={next:?}"
                    );
                    assert!(next.max_fee_per_gas <= u(CAP));
                    if next.max_fee_per_gas == u(CAP) {
                        clamped_rungs += 1;
                    }
                    current = next;
                }
                FeeVerdict::TooExpensive { .. } => {
                    assert!(clamped_rungs > 0, "ladder never exercised the clamp");
                    return;
                }
            }
        }
        panic!("ladder never terminated at the cap");
    }

    #[test]
    fn replacement_stops_at_the_cap_instead_of_bidding_past_it() {
        let verdict = plan_replacement(Some(plan(CAP, CAP)), u(9_255), u(TIP), u(CAP), 0);
        assert!(verdict.is_too_expensive());
    }

    #[test]
    fn replacement_clears_the_node_rule_even_at_values_that_truncate() {
        // Integer 110% of 1 truncates back to 1, which no node accepts.
        for value in [1u128, 2, 3, 9, 10, 99] {
            let previous = plan(value, value);
            let next = plan_replacement(Some(previous), U256::ZERO, U256::ZERO, u(CAP), 0)
                .plan()
                .unwrap();
            assert!(
                node_accepts_replacement(previous, next),
                "value {value}: old={previous:?} new={next:?}"
            );
        }
    }

    #[test]
    fn unrecorded_rows_escalate_until_they_outbid_the_pre_fix_price() {
        // The build being replaced set BOTH fields to eth_gasPrice (base + 1).
        // A ledger row from it carries no fee, so the ladder must climb past
        // that bid — including when the base fee has since fallen.
        let sent_at_base: u128 = 40_000;
        let old = plan(sent_at_base + 1, sent_at_base + 1);
        let now_base = u(9_255);
        let mut cleared = None;
        for attempts in 0..8 {
            let next = plan_replacement(None, now_base, u(TIP), u(CAP), attempts)
                .plan()
                .unwrap();
            if node_accepts_replacement(old, next) {
                cleared = Some(attempts);
                break;
            }
        }
        assert!(
            cleared.is_some(),
            "blind ladder never outbid a {sent_at_base} wei broadcast"
        );
    }

    #[test]
    fn gas_limit_bound_rejects_a_batch_that_cannot_be_scheduled() {
        assert!(gas_limit_within_bounds(3_425_790));
        assert!(!gas_limit_within_bounds(17_000_000));
    }

    #[test]
    fn required_balance_charges_every_unit_at_the_ceiling() {
        assert_eq!(
            required_balance(3_425_790, u(19_510)),
            u(3_425_790 * 19_510)
        );
    }
}
