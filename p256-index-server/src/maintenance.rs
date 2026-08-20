//! Background maintenance loop — the operational safety net for an unattended, fund-spending
//! queue. The judgement lives in the registrar (`rescue` for the unstick sweep, `sentinel` for
//! alert policy and the heartbeat); this loop supplies the inputs (ledger rows, nonces, gas
//! price, clock) and executes the resulting plan against the chain, Redis and Telegram:
//!
//! - **stuck-nonce unstick sweep**: a broadcast whose receipt never arrived jams the wallet's
//!   nonce sequence and stalls every later send. The sweep replaces it with a same-nonce,
//!   zero-value self-transfer at a bumped gas price (via [`Chain::cancel_stuck_nonce`]).
//! - **operator alerts**: low funding runway, an open RPC read circuit, DLQ growth, and a nonce
//!   the sweep cannot clear — the failure modes that otherwise fail silently.
//! - **daily heartbeat**: proves the whole path (process, chain reads, Telegram) is alive.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use alloy::primitives::U256;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use p256_registrar::{
    gas::{self, FeePlan, FeeVerdict},
    protocol,
    rescue::{self, LedgerRow, RescueAction},
    sentinel,
};

use crate::{
    chain::{Chain, WalletRole},
    store::RedisStore,
    telegram::Telegram,
};

const TICK: Duration = Duration::from_secs(60);

pub struct MaintenanceHandle {
    shutdown: CancellationToken,
    task: JoinHandle<()>,
}

impl MaintenanceHandle {
    pub async fn shutdown(self) {
        self.shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(10), self.task).await;
    }
}

pub struct Maintenance {
    store: RedisStore,
    chain: Chain,
    telegram: Option<Telegram>,
    release: Option<String>,
    started: Instant,
    last_heartbeat: Option<Instant>,
    last_low_runway_alert: Option<Instant>,
    last_rpc_alert: Option<Instant>,
    last_dlq_alert: Option<Instant>,
    last_stuck_alert: Option<Instant>,
    last_gas_capped_alert: Option<Instant>,
}

impl Maintenance {
    pub fn start(
        store: RedisStore,
        chain: Chain,
        telegram: Option<Telegram>,
        release: Option<String>,
    ) -> MaintenanceHandle {
        let shutdown = CancellationToken::new();
        let maintenance = Self {
            store,
            chain,
            telegram,
            release,
            started: Instant::now(),
            last_heartbeat: None,
            last_low_runway_alert: None,
            last_rpc_alert: None,
            last_dlq_alert: None,
            last_stuck_alert: None,
            last_gas_capped_alert: None,
        };
        let task = tokio::spawn({
            let shutdown = shutdown.clone();
            async move { maintenance.run(shutdown).await }
        });
        MaintenanceHandle { shutdown, task }
    }

    async fn run(mut self, shutdown: CancellationToken) {
        tracing::info!("maintenance loop started (unstick sweep, alerts, heartbeat)");
        loop {
            self.tick().await;
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = tokio::time::sleep(TICK) => {}
            }
        }
    }

    async fn tick(&mut self) {
        self.unstick_sweep().await;
        self.check_alerts().await;
        self.maybe_heartbeat().await;
    }

    // ── Stuck-nonce unstick sweep ──────────────────────────────────────────

    async fn unstick_sweep(&mut self) {
        let now = now_ms();
        let sent_before = now.saturating_sub(rescue::STUCK_TX_AGE_MS);
        let ledger: Vec<LedgerRow> = match self.store.list_pending_txs(sent_before).await {
            Ok(rows) => rows
                .into_iter()
                .map(|row| LedgerRow {
                    role: row.role,
                    nonce: row.nonce,
                    hash: row.hash,
                    sent_at_ms: row.sent_at_ms,
                    attempts: row.attempts,
                    fees_wei: row.max_fee_wei.zip(row.max_priority_fee_wei),
                })
                .collect(),
            Err(_) => {
                tracing::warn!(operation = "unstick", "ledger read failed");
                return;
            }
        };
        if ledger.is_empty() {
            return;
        }

        // Replacements are priced per row, against the fee that row was sent
        // at. The base fee is only the floor that keeps the replacement itself
        // includable; it must never become the basis for the bump.
        let base_fee = match self.chain.base_fee().await {
            Ok(base_fee) => base_fee,
            Err(_) => {
                tracing::warn!(operation = "unstick", "base fee read failed");
                return;
            }
        };

        for role in [WalletRole::Register] {
            let confirmed = match self.chain.confirmed_nonce(role).await {
                Ok(nonce) => nonce,
                Err(_) => {
                    tracing::warn!(
                        operation = "unstick",
                        role = role_name(role),
                        "confirmed-nonce read failed"
                    );
                    continue;
                }
            };
            // The judgement is a pure plan; this loop just executes it.
            for action in rescue::plan_role_sweep(role_name(role), confirmed, &ledger, now) {
                match action {
                    RescueAction::DropConsumedRow { nonce } => {
                        let _ = self.store.delete_pending_tx(role_name(role), nonce).await;
                    }
                    RescueAction::Escalate { message } => {
                        self.alert_throttled(AlertKind::Stuck, &message).await;
                    }
                    RescueAction::Replace {
                        nonce,
                        attempts_after,
                        previous_fees_wei,
                    } => {
                        let previous = previous_fees_wei.map(|(max_fee, priority)| FeePlan {
                            max_fee_per_gas: U256::from(max_fee),
                            max_priority_fee_per_gas: U256::from(priority),
                        });
                        let fees = match gas::plan_replacement(
                            previous,
                            base_fee,
                            U256::from(gas::DEFAULT_TIP_WEI),
                            self.chain.max_gas_price_wei(),
                            attempts_after.saturating_sub(1),
                        ) {
                            FeeVerdict::Send(fees) => fees,
                            FeeVerdict::TooExpensive { required, cap } => {
                                // Bidding past the cap to clear a nonce is the
                                // one thing the cap exists to prevent. Page
                                // instead: this needs a human decision.
                                self.alert_throttled(
                                    AlertKind::GasCapped,
                                    &format!(
                                        "🛑 [webauthnp256-publickey-index] stuck {} nonce {} needs \
                                         {required} wei to replace, above the {cap} wei cap. \
                                         Raise P256_INDEX_MAX_GAS_PRICE_WEI or intervene manually.",
                                        role_name(role),
                                        nonce
                                    ),
                                )
                                .await;
                                continue;
                            }
                        };
                        let bid = u128::try_from(fees.max_fee_per_gas)
                            .ok()
                            .zip(u128::try_from(fees.max_priority_fee_per_gas).ok());
                        // Preserve the original row identity on failure: only a
                        // confirmed broadcast may overwrite the hash/timestamp.
                        let (row_hash, sent_at) = ledger
                            .iter()
                            .find(|row| row.role == role_name(role) && row.nonce == nonce)
                            .map(|row| (row.hash.clone(), row.sent_at_ms))
                            .unwrap_or_else(|| (String::new(), now));
                        match self.chain.cancel_stuck_nonce(role, nonce, fees).await {
                            Ok(cancel_hash) => {
                                tracing::warn!(
                                    operation = "unstick",
                                    outcome = "cancelled",
                                    role = role_name(role),
                                    nonce,
                                    attempts = attempts_after,
                                    "stuck tx replaced with same-nonce cancel"
                                );
                                // Reset sentAt and bump attempts so the next
                                // attempt waits a full window.
                                let _ = self
                                    .store
                                    .record_pending_tx(
                                        role_name(role),
                                        nonce,
                                        &cancel_hash,
                                        now,
                                        attempts_after,
                                        bid,
                                    )
                                    .await;
                            }
                            // The node saw this bid and judged it too low: the
                            // rung was genuinely climbed, so record it and let
                            // the next sweep ladder up from it.
                            Err(error) if protocol::is_replacement_underpriced(&error) => {
                                tracing::warn!(
                                    operation = "unstick",
                                    role = role_name(role),
                                    nonce,
                                    attempts = attempts_after,
                                    %error,
                                    "replacement refused as underpriced; raising the recorded bid"
                                );
                                let _ = self
                                    .store
                                    .record_pending_tx(
                                        role_name(role),
                                        nonce,
                                        &row_hash,
                                        sent_at,
                                        attempts_after,
                                        bid,
                                    )
                                    .await;
                            }
                            // Anything else — RPC 429/5xx, a timeout, an
                            // unfunded wallet — means the bid never reached the
                            // mempool. The ledger must not move: ratcheting on
                            // an unsent price walks the recorded bid up to the
                            // cap and permanently disables rescue for a nonce
                            // that a far cheaper replacement would clear. Age
                            // still grows (sent_at is untouched), so the
                            // escalation alert continues to fire.
                            Err(error) => {
                                tracing::warn!(
                                    operation = "unstick",
                                    role = role_name(role),
                                    nonce,
                                    %error,
                                    "unstick attempt did not reach the mempool; bid unchanged"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    // ── Operator alerts ────────────────────────────────────────────────────

    async fn check_alerts(&mut self) {
        // Open RPC read circuit: reads are failing over, chain data may be stale.
        if self.chain.rpc_circuit_state() == "open" {
            self.alert_throttled(AlertKind::Rpc, sentinel::rpc_circuit_alert())
                .await;
        }

        // DLQ growth: creates are being quarantined and need inspection.
        if let Ok(stats) = self.store.queue_stats().await
            && stats.dlq_count >= sentinel::DLQ_ALERT_THRESHOLD
        {
            let message = sentinel::dlq_alert(stats.dlq_count);
            self.alert_throttled(AlertKind::Dlq, &message).await;
        }

        // Low funding runway on the create wallet: top up before creates start failing.
        if let (Ok(balance), Ok(price)) = (
            self.chain.balance(WalletRole::Register).await,
            self.chain.gas_price().await,
        ) {
            let runway = sentinel::estimate_create_runway(wei_to_xdai(balance), wei_to_gwei(price));
            if runway.is_finite() && runway < sentinel::LOW_RUNWAY_CREATES {
                let message =
                    sentinel::low_runway_alert(runway, wei_to_xdai(balance), wei_to_gwei(price));
                self.alert_throttled(AlertKind::LowRunway, &message).await;
            }
        }
    }

    async fn alert_throttled(&mut self, kind: AlertKind, message: &str) {
        let slot = match kind {
            AlertKind::Stuck => &mut self.last_stuck_alert,
            AlertKind::GasCapped => &mut self.last_gas_capped_alert,
            AlertKind::Rpc => &mut self.last_rpc_alert,
            AlertKind::Dlq => &mut self.last_dlq_alert,
            AlertKind::LowRunway => &mut self.last_low_runway_alert,
        };
        if slot.is_some_and(|at| at.elapsed() < sentinel::ALERT_THROTTLE) {
            return;
        }
        *slot = Some(Instant::now());
        if let Some(telegram) = &self.telegram {
            telegram.send(message).await;
        } else {
            tracing::warn!(alert = message, "operator alert (Telegram not configured)");
        }
    }

    // ── Daily heartbeat ────────────────────────────────────────────────────

    async fn maybe_heartbeat(&mut self) {
        let due = self
            .last_heartbeat
            .map(|at| at.elapsed() >= sentinel::HEARTBEAT_INTERVAL)
            .unwrap_or(true);
        if !due {
            return;
        }
        self.last_heartbeat = Some(Instant::now());

        let stats = self.store.queue_stats().await.ok();
        let gas_price = self.chain.gas_price().await.ok();
        let wallet_address = self
            .chain
            .wallet_address(WalletRole::Register)
            .map(|a| a.to_string())
            .unwrap_or_default();
        let wallet_balance = self.chain.balance(WalletRole::Register).await.ok();

        let message = sentinel::build_heartbeat_message(&sentinel::HeartbeatInput {
            runtime: "Rust",
            queue_depth: stats.as_ref().map(|s| s.depth).unwrap_or(0),
            dlq_count: stats.as_ref().map(|s| s.dlq_count).unwrap_or(0),
            wallet_address: &wallet_address,
            wallet_balance_xdai: wallet_balance.map(wei_to_xdai).unwrap_or(0.0),
            gas_price_gwei: gas_price.map(wei_to_gwei).unwrap_or(0.0),
            uptime: self.started.elapsed(),
            release: self.release.as_deref(),
        });
        if let Some(telegram) = &self.telegram {
            telegram.send(&message).await;
        }
        tracing::info!(
            operation = "heartbeat",
            outcome = "sent",
            "daily heartbeat emitted"
        );
    }
}

enum AlertKind {
    Stuck,
    /// A nonce whose replacement price has reached the configured cap. Kept
    /// separate from `Stuck` because it shares the throttle window with it and
    /// is the only one of the two that names an action the operator can take.
    GasCapped,
    Rpc,
    Dlq,
    LowRunway,
}

fn role_name(role: WalletRole) -> &'static str {
    role.ledger_name()
}

fn wei_to_xdai(wei: U256) -> f64 {
    sentinel::wei_to_xdai(u128::try_from(wei).unwrap_or(u128::MAX))
}

fn wei_to_gwei(wei: U256) -> f64 {
    sentinel::wei_to_gwei(u128::try_from(wei).unwrap_or(u128::MAX))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
