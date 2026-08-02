//! Shell for the WebAuthn P256 public-key index.
//!
//! Business vocabulary and decision rules live in the `p256-registrar` crate;
//! this crate wires them to real infrastructure: Axum (HTTP), Redis (state,
//! rate limits, caches), Iggy (durable queue), Gnosis RPC (chain I/O) and
//! Telegram (alerts).

pub mod chain;
pub mod config;
pub mod http;
pub mod maintenance;
pub mod queue;
pub mod store;
pub mod telegram;
pub mod worker;
