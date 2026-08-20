//! Pure business logic for the WebAuthn P-256 public-key registry service.
//!
//! This crate owns the service's business vocabulary and decision rules and is
//! deliberately I/O-free: no Redis, no Iggy, no HTTP, no clocks. The server
//! crate (`p256-index-server`) is the shell that executes the decisions made
//! here against real infrastructure.
//!
//! Modules are business domains, not architectural layers:
//!
//! - [`task`] — the `RegisterTask` lifecycle vocabulary (Pending →
//!   Done/Failed) shared by every domain below.
//! - [`verify`] — pure possession-proof verification, mirroring the registry
//!   contract check for check, so invalid proofs die at admission instead of
//!   burning gas.
//! - [`admission`] — the register endpoint's decision tree (crux app):
//!   validation, proof verification, idempotency by unitNonce, chain
//!   pre-checks, write gates and the two-phase Redis/Iggy admission protocol.
//!   The server's HTTP handler is its shell.
//! - [`lookup`] — read-side vocabulary (entries, site stats, pagination) and
//!   the cache freshness/degradation rules.
//! - [`submission`] — the task lifecycle state machine (crux app): one unit,
//!   one transaction; reconciliation by content hash, error classification
//!   and the batch verdict. The server's worker is its shell.
//! - [`gas`] — EIP-1559 fee policy: inclusion headroom, the absolute price
//!   cap that returns work to the queue instead of spending, and the
//!   monotonic same-nonce replacement ladder the unstick sweep prices against.
//! - [`protocol`] — the on-chain registry protocol: calldata encoding,
//!   response decoding, challenge/content-hash construction, and the single
//!   home for chain-error classification.
//! - [`rescue`] — the stuck-transaction sweep's judgement: which ledger rows
//!   are consumed, which escalate, which get a same-nonce cancel.
//! - [`roster`] — RPC node selection: rotation, failure cooldown, forced
//!   fallback and the read-circuit verdict.
//! - [`sentinel`] — ops reliability policy: backoff schedule, health
//!   thresholds, alert throttling/messages, the daily heartbeat.

pub mod admission;
pub mod gas;
pub mod lookup;
pub mod protocol;
pub mod rescue;
pub mod roster;
pub mod sentinel;
pub mod submission;
pub mod task;
pub mod verify;
