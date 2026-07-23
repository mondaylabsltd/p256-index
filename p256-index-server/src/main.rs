use anyhow::Result;
use p256_index_server::{
    chain::Chain,
    config::Config,
    http::{AppState, router},
    maintenance::{Maintenance, MaintenanceHandle},
    queue::CreateQueue,
    store::RedisStore,
    telegram::Telegram,
    worker::{CreateWorker, WorkerHandle},
};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::from_env()?;
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "p256_index_server=info,tower_http=info".into()),
        )
        .json()
        .init();

    let chain = Chain::new(&config)?;
    let store = RedisStore::connect(&config.redis_url).await?;
    let queue = CreateQueue::connect(
        &config.iggy_url,
        &config.iggy_provisioner_url,
        config.iggy_enqueue_timeout,
    )
    .await?;
    queue.ensure_topology().await?;

    let telegram = Telegram::from_config(&config);
    if telegram.is_none() {
        tracing::warn!(
            "TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID unset — operator alerts will not be delivered"
        );
    }

    let state = AppState::new(store.clone(), queue.clone(), chain.clone(), &config);
    let app = router(state);
    let listener = TcpListener::bind(config.listen_addr).await?;
    tracing::info!(listen_addr = %config.listen_addr, "HTTP server listening");

    let worker = start_worker_if_enabled(&config, store.clone(), chain.clone());
    let maintenance = start_maintenance_if_enabled(&config, store, chain, telegram);
    let serve_result = axum::serve(listener, app)
        .with_graceful_shutdown(wait_for_shutdown_signal())
        .await;
    if let Some(worker) = worker {
        worker.shutdown().await;
    }
    if let Some(maintenance) = maintenance {
        maintenance.shutdown().await;
    }
    serve_result?;
    Ok(())
}

/// The maintenance loop (unstick sweep, operator alerts, heartbeat) only runs when a signer is
/// present: without one there are no wallets to fund, unstick, or report on.
fn start_maintenance_if_enabled(
    config: &Config,
    store: RedisStore,
    chain: Chain,
    telegram: Option<Telegram>,
) -> Option<MaintenanceHandle> {
    if !config.queue_worker_enabled || !chain.has_signers() {
        return None;
    }
    let release = std::env::var("RELEASE")
        .ok()
        .filter(|value| !value.is_empty());
    Some(Maintenance::start(store, chain, telegram, release))
}

fn start_worker_if_enabled(
    config: &Config,
    store: RedisStore,
    chain: Chain,
) -> Option<WorkerHandle> {
    if !config.queue_worker_enabled {
        tracing::warn!("QUEUE_WORKER=0: background Iggy consumer is disabled");
        return None;
    }
    if !chain.has_signers() {
        tracing::warn!(
            "PRIVATE_KEY is unset: background Iggy consumer is disabled; read APIs remain available"
        );
        return None;
    }
    Some(CreateWorker::start(
        store,
        chain,
        config.iggy_consumer_url.clone(),
        config.iggy_consumer_group.clone(),
    ))
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut terminate = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c()
        .await
        .expect("install Ctrl-C handler");
}
