//! Pure business logic for the WebAuthn P256 public-key index.
//!
//! This crate owns the service's business vocabulary and decision rules and is
//! deliberately I/O-free: no Redis, no Iggy, no HTTP, no clocks. The server
//! crate (`p256-index-server`) is the shell that executes the decisions made
//! here against real infrastructure.
//!
//! Modules are business domains, not architectural layers:
//!
//! - [`task`] — the `CreateTask` lifecycle vocabulary (Pending → Committed →
//!   Done/Failed) shared by every domain below.
//! - [`admission`] — the create endpoint's decision tree (crux app):
//!   validation with defaults, idempotent pre-checks, wallet-ref uniqueness
//!   across three sources, write gates, and the two-phase Redis/Iggy
//!   admission protocol. The server's HTTP handler is its shell.
//! - [`lookup`] — read-side vocabulary (records, site stats, pagination). The
//!   cache freshness/degradation rules migrate here from `http.rs`.
//! - [`commit_reveal`] — the task lifecycle state machine (crux app): batch
//!   reconciliation, commit → reveal → create orchestration, poison
//!   isolation, error classification and the batch verdict. The server's
//!   worker is its shell.
//! - [`protocol`] — the on-chain index protocol: calldata encoding, response
//!   decoding, commit-reveal commitment construction, and the single home for
//!   chain-error classification (previously four overlapping predicates in
//!   `chain.rs`).
//! - [`wallet`] — Safe counterfactual wallet-reference derivation (CREATE2)
//!   and its default metadata scheme.
//! - [`rescue`] — the stuck-transaction sweep's judgement: which ledger rows
//!   are consumed, which escalate, which get a same-nonce cancel.
//! - [`roster`] — RPC node selection: rotation, failure cooldown, forced
//!   fallback and the read-circuit verdict.
//! - [`sentinel`] — ops reliability policy: backoff schedule, health
//!   thresholds, alert throttling/messages, the daily heartbeat.

pub mod admission;
pub mod commit_reveal;
pub mod lookup;
pub mod protocol;
pub mod rescue;
pub mod roster;
pub mod sentinel;
pub mod task;
pub mod wallet;
