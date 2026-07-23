//! Background maintenance loop — the operational safety net for an unattended, fund-spending
//! queue. Ported from the retired Deno/CF-Worker reliability cycle and adapted to Redis + Iggy:
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

use crate::{
    chain::{Chain, WalletRole},
    reliability::{HEARTBEAT_INTERVAL, HeartbeatInput, build_heartbeat_message},
    store::RedisStore,
    telegram::Telegram,
};

const TICK: Duration = Duration::from_secs(60);
/// A broadcast older than this whose nonce is still un-mined is treated as stuck.
const STUCK_TX_AGE: Duration = Duration::from_secs(2 * 60);
const MAX_UNSTICK_PER_CYCLE: usize = 5;
/// Page after this many failed replacements of one nonce, or once it has been stuck this long.
const UNSTICK_ALERT_ATTEMPTS: u32 = 5;
const UNSTICK_ALERT_AGE: Duration = Duration::from_secs(10 * 60);
/// Replacement gas price = 150% of the current network gas price.
const CANCEL_GAS_NUM: u64 = 150;
const CANCEL_GAS_DEN: u64 = 100;
/// Alert when the estimated create runway drops below this many creates.
const LOW_RUNWAY_CREATES: f64 = 200.0;
/// Alert when the DLQ reaches this depth.
const DLQ_ALERT_THRESHOLD: u64 = 10;
/// Minimum spacing between repeats of the same alert.
const ALERT_THROTTLE: Duration = Duration::from_secs(6 * 60 * 60);

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
        let sent_before = now.saturating_sub(STUCK_TX_AGE.as_millis() as u64);
        let ledger = match self.store.list_pending_txs(sent_before).await {
            Ok(rows) => rows,
            Err(_) => {
                tracing::warn!(operation = "unstick", "ledger read failed");
                return;
            }
        };
        if ledger.is_empty() {
            return;
        }

        let gas_price = match self.chain.gas_price().await {
            Ok(price) => bump_gas(price),
            Err(_) => {
                tracing::warn!(operation = "unstick", "gas price read failed");
                return;
            }
        };

        for role in [WalletRole::Create, WalletRole::Commit] {
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
            let mut stuck: Vec<_> = ledger
                .iter()
                .filter(|row| row.role == role_name(role))
                .collect();
            stuck.sort_by_key(|row| row.nonce);

            let mut replaced = 0usize;
            for row in stuck {
                if row.nonce < confirmed {
                    // The nonce was consumed (this or a replacement mined): drop the ledger row.
                    let _ = self.store.delete_pending_tx(&row.role, row.nonce).await;
                    continue;
                }
                let age_ms = now.saturating_sub(row.sent_at_ms);
                if row.attempts >= UNSTICK_ALERT_ATTEMPTS
                    || age_ms >= UNSTICK_ALERT_AGE.as_millis() as u64
                {
                    let message = format!(
                        "🛑 [webauthnp256-publickey-index] stuck {} nonce {} not clearing \
                         (attempts {}, stuck ~{} min). Manual intervention may be required.",
                        row.role,
                        row.nonce,
                        row.attempts,
                        age_ms / 60_000
                    );
                    self.alert_throttled(AlertKind::Stuck, &message).await;
                }
                if replaced >= MAX_UNSTICK_PER_CYCLE {
                    continue;
                }
                replaced += 1;
                match self
                    .chain
                    .cancel_stuck_nonce(role, row.nonce, gas_price)
                    .await
                {
                    Ok(cancel_hash) => {
                        tracing::warn!(
                            operation = "unstick",
                            outcome = "cancelled",
                            role = %row.role,
                            nonce = row.nonce,
                            attempts = row.attempts + 1,
                            "stuck tx replaced with same-nonce cancel"
                        );
                        // Reset sentAt and bump attempts so the next attempt waits a full window.
                        let _ = self
                            .store
                            .record_pending_tx(
                                &row.role,
                                row.nonce,
                                &cancel_hash,
                                now,
                                row.attempts + 1,
                            )
                            .await;
                    }
                    Err(error) => {
                        tracing::warn!(
                            operation = "unstick",
                            role = %row.role,
                            nonce = row.nonce,
                            %error,
                            "unstick attempt failed, will retry next cycle"
                        );
                    }
                }
            }
        }
    }

    // ── Operator alerts ────────────────────────────────────────────────────

    async fn check_alerts(&mut self) {
        // Open RPC read circuit: reads are failing over, chain data may be stale.
        if self.chain.rpc_circuit_state() == "open" {
            self.alert_throttled(
                AlertKind::Rpc,
                "⚠️ [webauthnp256-publickey-index] all chain RPC read endpoints are in cooldown \
                 (circuit open) — queries may be served stale.",
            )
            .await;
        }

        // DLQ growth: creates are being quarantined and need inspection.
        if let Ok(stats) = self.store.queue_stats().await
            && stats.dlq_count >= DLQ_ALERT_THRESHOLD
        {
            let message = format!(
                "⚠️ [webauthnp256-publickey-index] DLQ has {} quarantined create(s) — inspect.",
                stats.dlq_count
            );
            self.alert_throttled(AlertKind::Dlq, &message).await;
        }

        // Low funding runway on the create wallet: top up before creates start failing.
        if let (Ok(balance), Ok(price)) = (
            self.chain.balance(WalletRole::Create).await,
            self.chain.gas_price().await,
        ) {
            let runway = crate::reliability::estimate_create_runway(
                wei_to_xdai(balance),
                wei_to_gwei(price),
            );
            if runway.is_finite() && runway < LOW_RUNWAY_CREATES {
                let message = format!(
                    "🪫 [webauthnp256-publickey-index] create wallet funding low: ~{} creates left \
                     ({:.6} xDAI @ {:.3} gwei). Top up soon.",
                    runway as i64,
                    wei_to_xdai(balance),
                    wei_to_gwei(price),
                );
                self.alert_throttled(AlertKind::LowRunway, &message).await;
            }
        }
    }

    async fn alert_throttled(&mut self, kind: AlertKind, message: &str) {
        let slot = match kind {
            AlertKind::Stuck => &mut self.last_stuck_alert,
            AlertKind::Rpc => &mut self.last_rpc_alert,
            AlertKind::Dlq => &mut self.last_dlq_alert,
            AlertKind::LowRunway => &mut self.last_low_runway_alert,
        };
        if slot.is_some_and(|at| at.elapsed() < ALERT_THROTTLE) {
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
            .map(|at| at.elapsed() >= HEARTBEAT_INTERVAL)
            .unwrap_or(true);
        if !due {
            return;
        }
        self.last_heartbeat = Some(Instant::now());

        let stats = self.store.queue_stats().await.ok();
        let gas_price = self.chain.gas_price().await.ok();
        let create_address = self
            .chain
            .wallet_address(WalletRole::Create)
            .map(|a| a.to_string())
            .unwrap_or_default();
        let commit_address = self
            .chain
            .wallet_address(WalletRole::Commit)
            .map(|a| a.to_string())
            .unwrap_or_default();
        let create_balance = self.chain.balance(WalletRole::Create).await.ok();
        let commit_balance = self.chain.balance(WalletRole::Commit).await.ok();

        let message = build_heartbeat_message(&HeartbeatInput {
            runtime: "Rust",
            queue_depth: stats.as_ref().map(|s| s.depth).unwrap_or(0),
            dlq_count: stats.as_ref().map(|s| s.dlq_count).unwrap_or(0),
            create_address: &create_address,
            create_balance_xdai: create_balance.map(wei_to_xdai).unwrap_or(0.0),
            commit_address: &commit_address,
            commit_balance_xdai: commit_balance.map(wei_to_xdai).unwrap_or(0.0),
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
    Rpc,
    Dlq,
    LowRunway,
}

fn role_name(role: WalletRole) -> &'static str {
    match role {
        WalletRole::Create => "create",
        WalletRole::Commit => "commit",
    }
}

fn bump_gas(price: U256) -> U256 {
    price.saturating_mul(U256::from(CANCEL_GAS_NUM)) / U256::from(CANCEL_GAS_DEN)
}

fn wei_to_xdai(wei: U256) -> f64 {
    u128::try_from(wei).unwrap_or(u128::MAX) as f64 / 1e18
}

fn wei_to_gwei(wei: U256) -> f64 {
    u128::try_from(wei).unwrap_or(u128::MAX) as f64 / 1e9
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
