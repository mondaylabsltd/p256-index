//! RPC node roster: the pure selection/cooldown state machine behind the
//! server's RPC pool.
//!
//! Owns the decisions the old `RpcPool` interleaved with its transport:
//! round-robin rotation per lane, a 60s failure cooldown with self-healing
//! expiry, the forced fallback pick when every node is cooling ("宁可试也
//! 不空转"), the per-call attempt budget, and the read-circuit verdict.
//! Read and write lanes rotate independently but share one failure table —
//! a URL failing on the read lane is also avoided by the write lane, exactly
//! as before.
//!
//! The shell (`chain.rs`) wraps one `Roster` in a mutex, feeds it a
//! monotonic clock, and keeps the HTTP transport, error translation and the
//! retry loop itself.

use std::collections::HashMap;

/// A failed node is skipped for this long before it becomes eligible again.
pub const RPC_COOLDOWN_MS: u64 = 60_000;
/// A read call tries at most this many distinct nodes.
pub const MAX_READ_ATTEMPTS: usize = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lane {
    Read,
    Write,
}

#[derive(Debug)]
pub struct Roster {
    reads: Vec<String>,
    writes: Vec<String>,
    read_cursor: usize,
    write_cursor: usize,
    /// url → failed_at_ms. Shared between lanes.
    failed: HashMap<String, u64>,
}

impl Roster {
    pub fn new(reads: Vec<String>, writes: Vec<String>) -> Self {
        Self {
            reads,
            writes,
            read_cursor: 0,
            write_cursor: 0,
            failed: HashMap::new(),
        }
    }

    /// Round-robin pick of the next available node; when every node is in
    /// cooldown, force-pick the next one anyway (the cursor still advances),
    /// so a total outage keeps probing instead of stalling.
    pub fn select(&mut self, lane: Lane, now_ms: u64) -> Option<String> {
        let len = match lane {
            Lane::Read => self.reads.len(),
            Lane::Write => self.writes.len(),
        };
        if len == 0 {
            return None;
        }
        for _ in 0..len {
            let current = self.advance(lane) % len;
            let url = match lane {
                Lane::Read => self.reads[current].clone(),
                Lane::Write => self.writes[current].clone(),
            };
            if self.available(&url, now_ms) {
                return Some(url);
            }
        }
        let current = self.advance(lane) % len;
        Some(match lane {
            Lane::Read => self.reads[current].clone(),
            Lane::Write => self.writes[current].clone(),
        })
    }

    fn advance(&mut self, lane: Lane) -> usize {
        let cursor = match lane {
            Lane::Read => &mut self.read_cursor,
            Lane::Write => &mut self.write_cursor,
        };
        let current = *cursor;
        *cursor = cursor.wrapping_add(1);
        current
    }

    /// Whether a node is currently eligible. An expired cooldown entry is
    /// removed on inspection (self-healing), exactly like the original.
    pub fn available(&mut self, url: &str, now_ms: u64) -> bool {
        match self.failed.get(url).copied() {
            Some(at) if now_ms.saturating_sub(at) < RPC_COOLDOWN_MS => false,
            Some(_) => {
                self.failed.remove(url);
                true
            }
            None => true,
        }
    }

    pub fn mark_failed(&mut self, url: &str, now_ms: u64) {
        self.failed.insert(url.to_owned(), now_ms);
    }

    /// A successful response immediately clears the node's failure mark.
    pub fn mark_healthy(&mut self, url: &str) {
        self.failed.remove(url);
    }

    /// The per-call attempt budget for read retries: `min(reads, 3)`.
    pub fn read_attempts(&self) -> usize {
        self.reads.len().min(MAX_READ_ATTEMPTS)
    }

    /// The health-check verdict: "closed" while at least one read node is
    /// eligible, "open" when all of them are cooling.
    pub fn circuit_state(&mut self, now_ms: u64) -> &'static str {
        let urls: Vec<String> = self.reads.clone();
        if urls.iter().any(|url| self.available(url, now_ms)) {
            "closed"
        } else {
            "open"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roster() -> Roster {
        Roster::new(
            vec!["a".into(), "b".into(), "c".into()],
            vec!["a".into(), "b".into()],
        )
    }

    #[test]
    fn rotation_is_round_robin_per_lane() {
        let mut roster = roster();
        assert_eq!(roster.select(Lane::Read, 0).as_deref(), Some("a"));
        assert_eq!(roster.select(Lane::Read, 0).as_deref(), Some("b"));
        assert_eq!(roster.select(Lane::Read, 0).as_deref(), Some("c"));
        assert_eq!(roster.select(Lane::Read, 0).as_deref(), Some("a"));
        // The write lane rotates independently.
        assert_eq!(roster.select(Lane::Write, 0).as_deref(), Some("a"));
        assert_eq!(roster.select(Lane::Write, 0).as_deref(), Some("b"));
    }

    #[test]
    fn cooling_nodes_are_skipped_until_the_cooldown_expires() {
        let mut roster = roster();
        roster.mark_failed("a", 1_000);
        assert_eq!(roster.select(Lane::Read, 1_000).as_deref(), Some("b"));
        // Just before expiry "a" is still skipped…
        roster.read_cursor = 0;
        assert_eq!(
            roster
                .select(Lane::Read, 1_000 + RPC_COOLDOWN_MS - 1)
                .as_deref(),
            Some("b")
        );
        // …at expiry it heals and is picked again.
        roster.read_cursor = 0;
        assert_eq!(
            roster
                .select(Lane::Read, 1_000 + RPC_COOLDOWN_MS)
                .as_deref(),
            Some("a")
        );
    }

    #[test]
    fn total_outage_force_picks_instead_of_stalling() {
        let mut roster = roster();
        roster.mark_failed("a", 0);
        roster.mark_failed("b", 0);
        roster.mark_failed("c", 0);
        // All cooling: the forced pick still returns a node, and repeated
        // calls keep rotating rather than hammering one endpoint.
        let first = roster.select(Lane::Read, 1).expect("forced pick");
        let second = roster.select(Lane::Read, 1).expect("forced pick");
        assert_ne!(first, second);
    }

    #[test]
    fn lanes_share_the_failure_table() {
        let mut roster = roster();
        roster.mark_failed("a", 0);
        // "a" failed on (say) the read lane; the write lane avoids it too.
        assert_eq!(roster.select(Lane::Write, 1).as_deref(), Some("b"));
    }

    #[test]
    fn mark_healthy_clears_the_cooldown_immediately() {
        let mut roster = roster();
        roster.mark_failed("a", 0);
        roster.mark_healthy("a");
        assert_eq!(roster.select(Lane::Read, 1).as_deref(), Some("a"));
    }

    #[test]
    fn repeated_failures_extend_the_cooldown_from_the_latest_one() {
        // A node that keeps failing must stay cooled from its most recent
        // failure, not sneak back in 60s after its first.
        let mut roster = roster();
        roster.mark_failed("a", 0);
        roster.mark_failed("a", 59_000);
        assert!(!roster.available("a", 61_000));
        assert!(roster.available("a", 59_000 + RPC_COOLDOWN_MS));
    }

    #[test]
    fn expired_entries_are_removed_on_inspection() {
        // The self-healing promise: checking availability after the cooldown
        // clears the entry, so the failure table cannot grow without bound.
        let mut roster = roster();
        roster.mark_failed("a", 0);
        assert!(roster.available("a", RPC_COOLDOWN_MS));
        assert!(
            roster.failed.is_empty(),
            "expired cooldown entries must be dropped, not retained"
        );
    }

    #[test]
    fn circuit_opens_only_when_every_read_node_is_cooling() {
        let mut roster = roster();
        assert_eq!(roster.circuit_state(0), "closed");
        roster.mark_failed("a", 0);
        roster.mark_failed("b", 0);
        assert_eq!(roster.circuit_state(1), "closed");
        roster.mark_failed("c", 0);
        assert_eq!(roster.circuit_state(1), "open");
        // Cooldown expiry closes it again (and self-heals the entries).
        assert_eq!(roster.circuit_state(RPC_COOLDOWN_MS), "closed");
    }

    #[test]
    fn read_attempt_budget_is_capped_at_three() {
        assert_eq!(roster().read_attempts(), 3);
        let small = Roster::new(vec!["a".into()], vec![]);
        assert_eq!(small.read_attempts(), 1);
        let large = Roster::new(
            vec!["a".into(), "b".into(), "c".into(), "d".into(), "e".into()],
            vec![],
        );
        assert_eq!(large.read_attempts(), 3);
    }

    #[test]
    fn empty_lane_yields_none_instead_of_panicking() {
        let mut empty = Roster::new(vec![], vec![]);
        assert_eq!(empty.select(Lane::Read, 0), None);
        assert_eq!(empty.circuit_state(0), "open");
    }
}
