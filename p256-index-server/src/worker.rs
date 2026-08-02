//! Shell for the commit-reveal task lifecycle.
//!
//! All decisions live in `p256_registrar::commit_reveal`; this worker owns
//! the machinery: the Iggy consumer loop (offset advance, backoff, malformed
//! message discard), nonce management for the two signing wallets, the
//! pending-tx ledger for the unstick sweep, and the execution of Core
//! operations against Redis and the chain. One Core instance drives one
//! polled batch to a `BatchVerdict`.

use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::Duration,
};

use iggy::prelude::{
    Client, Consumer, ConsumerGroupClient, ConsumerOffsetClient, Identifier, IggyClient,
    MessageClient, PollingStrategy,
};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use p256_registrar::{
    commit_reveal::{
        BatchVerdict, CommitRevealApp, CommitRevealEffect, CommitRevealEvent,
        CommitRevealOperation, CommitRevealResult, TxOutcome,
    },
    protocol::parse_b256,
    task::CreateTask,
};

use crate::{
    chain::{Chain, ReceiptStatus, WalletRole},
    queue::{STREAM_NAME, TOPIC_NAME},
    store::RedisStore,
};

const POLL_BATCH_SIZE: u32 = 50;
const IGGY_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const RECEIPT_TIMEOUT: Duration = Duration::from_secs(60);

pub struct WorkerHandle {
    shutdown: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}

impl WorkerHandle {
    pub async fn shutdown(self) {
        self.shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(75), self.task).await;
    }
}

#[derive(Clone)]
pub struct CreateWorker {
    store: RedisStore,
    chain: Chain,
    consumer_url: String,
    consumer_group: String,
    nonces: Arc<NonceManager>,
}

struct NonceManager {
    values: Mutex<HashMap<NonceRole, Option<u64>>>,
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
enum NonceRole {
    Create,
    Commit,
}

impl CreateWorker {
    pub fn start(
        store: RedisStore,
        chain: Chain,
        consumer_url: String,
        consumer_group: String,
    ) -> WorkerHandle {
        let shutdown = CancellationToken::new();
        let worker = Self {
            store,
            chain,
            consumer_url,
            consumer_group,
            nonces: Arc::new(NonceManager {
                values: Mutex::new(HashMap::new()),
            }),
        };
        let task = tokio::spawn({
            let shutdown = shutdown.clone();
            async move {
                if let Err(error) = worker.run(shutdown).await {
                    tracing::error!(%error, "Iggy create worker stopped");
                }
            }
        });
        WorkerHandle { shutdown, task }
    }

    async fn run(self, shutdown: CancellationToken) -> Result<(), WorkerError> {
        let client = IggyClient::from_connection_string(&self.consumer_url)
            .map_err(|_| WorkerError::new("invalid Iggy consumer connection configuration"))?;
        tokio::time::timeout(IGGY_CONNECT_TIMEOUT, client.connect())
            .await
            .map_err(|_| WorkerError::new("Iggy consumer connection timed out"))?
            .map_err(|_| WorkerError::new("could not connect Iggy consumer"))?;

        let stream: Identifier = STREAM_NAME
            .try_into()
            .map_err(|_| WorkerError::new("invalid Iggy stream name"))?;
        let topic: Identifier = TOPIC_NAME
            .try_into()
            .map_err(|_| WorkerError::new("invalid Iggy topic name"))?;
        let group: Identifier = self
            .consumer_group
            .as_str()
            .try_into()
            .map_err(|_| WorkerError::new("invalid Iggy consumer group name"))?;
        ensure_consumer_group(&client, &stream, &topic, &group, &self.consumer_group).await?;
        client
            .join_consumer_group(&stream, &topic, &group)
            .await
            .map_err(|_| WorkerError::new("could not join Iggy consumer group"))?;

        let consumer = Consumer::group(group.clone());
        let polling = PollingStrategy::next();
        tracing::info!(stream = STREAM_NAME, topic = TOPIC_NAME, group = %self.consumer_group, "Iggy create worker started");

        // Consecutive transient batch failures drive an exponential re-poll backoff so a chain/RPC
        // outage is not hammered every 2s. Clamped to 60s: the poll loop is the whole queue's
        // retry driver, so it must recover promptly once the dependency returns.
        let mut consecutive_failures = 0u32;

        loop {
            let polled = tokio::select! {
                _ = shutdown.cancelled() => break,
                result = client.poll_messages(&stream, &topic, None, &consumer, &polling, POLL_BATCH_SIZE, false) =>
                    result.map_err(|_| WorkerError::new("could not poll Iggy create tasks"))?,
            };
            if polled.messages.is_empty() {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = tokio::time::sleep(Duration::from_millis(250)) => {}
                }
                continue;
            }

            let highest_offset = polled
                .messages
                .last()
                .map(|message| message.header.offset)
                .ok_or(WorkerError::new("Iggy poll returned no highest offset"))?;
            let tasks = polled
                .messages
                .into_iter()
                .filter_map(|message| {
                    match serde_json::from_slice::<CreateTask>(&message.payload) {
                        Ok(task) => Some(task),
                        Err(_) => {
                            // A malformed message cannot be executed and must not permanently block
                            // the single queue partition. Producer credentials are restricted; keeping
                            // an offset log is sufficient to investigate its original Iggy payload.
                            tracing::error!(
                                offset = message.header.offset,
                                "discarding malformed Iggy create task"
                            );
                            None
                        }
                    }
                })
                .collect::<Vec<_>>();

            match self.process_batch(tasks).await {
                Ok(()) => {
                    consecutive_failures = 0;
                    client
                        .store_consumer_offset(
                            &consumer,
                            &stream,
                            &topic,
                            Some(polled.partition_id),
                            highest_offset,
                        )
                        .await
                        .map_err(|_| WorkerError::new("could not store Iggy consumer offset"))?;
                }
                Err(error) => {
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    let backoff = p256_registrar::sentinel::backoff_delay(consecutive_failures)
                        .min(Duration::from_secs(60));
                    tracing::warn!(%error, retry_in_s = backoff.as_secs(), "Iggy create batch will be retried without advancing offset");
                    tokio::select! {
                        _ = shutdown.cancelled() => break,
                        _ = tokio::time::sleep(backoff) => {}
                    }
                }
            }
        }

        if client
            .leave_consumer_group(&stream, &topic, &group)
            .await
            .is_err()
        {
            tracing::warn!("could not leave Iggy create consumer group cleanly");
        }
        Ok(())
    }

    /// Drive one polled batch through the commit-reveal Core. The queue
    /// messages are only envelopes: the Core loads the authoritative records
    /// itself, so only the ids cross into it.
    async fn process_batch(&self, queue_tasks: Vec<CreateTask>) -> Result<(), WorkerError> {
        if queue_tasks.is_empty() {
            return Ok(());
        }
        let envelope_ids = queue_tasks.into_iter().map(|task| task.id).collect();

        let core: crux_core::Core<CommitRevealApp> = crux_core::Core::new();
        let mut effects: VecDeque<CommitRevealEffect> = core
            .process_event(CommitRevealEvent::Start { envelope_ids })
            .into_iter()
            .collect();
        while let Some(effect) = effects.pop_front() {
            let CommitRevealEffect::Work(mut request) = effect;
            let output = self.execute(&request.operation).await;
            let next = core
                .resolve(&mut request, output)
                .map_err(|_| WorkerError::new("could not resolve commit-reveal effect"))?;
            effects.extend(next);
        }

        match core.view().outcome {
            Some(BatchVerdict::Advance) => Ok(()),
            Some(BatchVerdict::Retry { reason }) => Err(WorkerError(reason)),
            None => Err(WorkerError::new("commit-reveal batch never settled")),
        }
    }

    /// Execute one Core operation against real infrastructure. Failures are
    /// mapped into result variants — the Core decides what they mean.
    async fn execute(&self, operation: &CommitRevealOperation) -> CommitRevealResult {
        match operation {
            CommitRevealOperation::LoadTasks { ids } => {
                let mut tasks = Vec::with_capacity(ids.len());
                for id in ids {
                    match self.store.get_task(id).await {
                        Ok(task) => tasks.push(task),
                        Err(_) => return CommitRevealResult::StoreUnavailable,
                    }
                }
                CommitRevealResult::TasksLoaded { tasks }
            }
            CommitRevealOperation::CheckRecord {
                rp_id,
                credential_id,
            } => match self.chain.has_record(rp_id, credential_id).await {
                Ok(exists) => CommitRevealResult::RecordChecked { exists },
                Err(_) => CommitRevealResult::ChainReadFailed,
            },
            CommitRevealOperation::GetCommitBlock { commitment } => {
                let Ok(commitment) = parse_b256(commitment) else {
                    return CommitRevealResult::ChainReadFailed;
                };
                match self.chain.get_commit_block(commitment).await {
                    Ok(block) => CommitRevealResult::CommitBlock {
                        block,
                        now_ms: monotonic_ms(),
                    },
                    Err(_) => CommitRevealResult::ChainReadFailed,
                }
            }
            CommitRevealOperation::GetCurrentBlock => match self.chain.current_block().await {
                Ok(block) => CommitRevealResult::CurrentBlock {
                    block,
                    now_ms: monotonic_ms(),
                },
                Err(_) => CommitRevealResult::ChainReadFailed,
            },
            CommitRevealOperation::Sleep { ms } => {
                tokio::time::sleep(Duration::from_millis(*ms)).await;
                CommitRevealResult::Slept {
                    now_ms: monotonic_ms(),
                }
            }
            CommitRevealOperation::SubmitCommit { tasks } => {
                CommitRevealResult::Tx(self.submit(NonceRole::Commit, tasks).await)
            }
            CommitRevealOperation::SubmitCreate { tasks } => {
                CommitRevealResult::Tx(self.submit(NonceRole::Create, tasks).await)
            }
            CommitRevealOperation::MarkCommitted { task_id } => {
                store_ack(self.store.mark_committed(task_id).await)
            }
            CommitRevealOperation::MarkDone { task_id, tx_hash } => {
                store_ack(self.store.mark_done(task_id, tx_hash.clone()).await)
            }
            CommitRevealOperation::MarkPendingAgain { task_id, reason } => {
                store_ack(self.store.mark_pending(task_id, Some(reason)).await)
            }
            CommitRevealOperation::MarkFailed {
                task_id,
                kind,
                message,
            } => store_ack(
                self.store
                    .mark_failed(task_id, kind.as_store_class(), message)
                    .await,
            ),
            CommitRevealOperation::RecordTransientFailure { task_id, message } => {
                store_ack(self.store.record_transient_failure(task_id, message).await)
            }
        }
    }

    /// Send one chain write and wait for its receipt, with the nonce and
    /// pending-tx-ledger rules unchanged from the original worker: the ledger
    /// row is recorded on broadcast, cleared only on a definite receipt
    /// (success or reverted), and deliberately kept on a receipt timeout so
    /// the unstick sweep still sees a possibly-stuck tx; the cached nonce is
    /// released on every failure path so the next send re-syncs with the
    /// chain.
    async fn submit(&self, role: NonceRole, tasks: &[CreateTask]) -> TxOutcome {
        let Ok(nonce) = self.acquire(role).await else {
            return TxOutcome::NoncePoolUnavailable;
        };
        let sent = match role {
            NonceRole::Commit => self.chain.commit(tasks, nonce).await,
            NonceRole::Create => self.chain.create(tasks, nonce).await,
        };
        match sent {
            Ok(hash) => {
                self.record_pending(role, nonce, &hash).await;
                match self.chain.wait_for_receipt(&hash, RECEIPT_TIMEOUT).await {
                    Ok(ReceiptStatus::Success) => {
                        self.clear_pending(role, nonce).await;
                        TxOutcome::Confirmed { tx_hash: hash }
                    }
                    Ok(ReceiptStatus::Reverted) => {
                        self.clear_pending(role, nonce).await;
                        self.release(role).await;
                        TxOutcome::Reverted { tx_hash: hash }
                    }
                    Err(error) => {
                        self.release(role).await;
                        TxOutcome::ReceiptUncertain { error }
                    }
                }
            }
            Err(error) => {
                self.release(role).await;
                TxOutcome::SendFailed { error }
            }
        }
    }

    async fn acquire(&self, role: NonceRole) -> Result<u64, WorkerError> {
        let mut values = self.nonces.values.lock().await;
        let value = values.entry(role).or_insert(None);
        if value.is_none() {
            let wallet_role = match role {
                NonceRole::Create => WalletRole::Create,
                NonceRole::Commit => WalletRole::Commit,
            };
            *value = Some(
                self.chain
                    .pending_nonce(wallet_role)
                    .await
                    .map_err(|_| WorkerError::new("could not acquire pending chain nonce"))?,
            );
        }
        let nonce = value.expect("nonce was initialized");
        *value = Some(nonce.saturating_add(1));
        Ok(nonce)
    }

    async fn release(&self, role: NonceRole) {
        self.nonces.values.lock().await.insert(role, None);
    }

    /// Record a freshly-broadcast tx in the ledger so the unstick sweep can replace it if its
    /// receipt never arrives. Best-effort: a ledger write failure must not fail the send path.
    async fn record_pending(&self, role: NonceRole, nonce: u64, hash: &str) {
        let _ = self
            .store
            .record_pending_tx(role_name(role), nonce, hash, now_ms(), 0)
            .await;
    }

    /// Clear the ledger only once a receipt is definite (success or reverted). On a receipt
    /// timeout the row is deliberately kept so the unstick sweep still sees a possibly-stuck tx.
    async fn clear_pending(&self, role: NonceRole, nonce: u64) {
        let _ = self.store.delete_pending_tx(role_name(role), nonce).await;
    }
}

fn store_ack<T>(result: Result<T, crate::store::StoreError>) -> CommitRevealResult {
    match result {
        Ok(_) => CommitRevealResult::Persisted,
        Err(_) => CommitRevealResult::StoreUnavailable,
    }
}

async fn ensure_consumer_group(
    client: &IggyClient,
    stream: &Identifier,
    topic: &Identifier,
    group: &Identifier,
    group_name: &str,
) -> Result<(), WorkerError> {
    if client
        .get_consumer_group(stream, topic, group)
        .await
        .map_err(|_| WorkerError::new("could not inspect Iggy consumer group"))?
        .is_some()
    {
        return Ok(());
    }
    if client
        .create_consumer_group(stream, topic, group_name)
        .await
        .is_ok()
    {
        return Ok(());
    }
    if client
        .get_consumer_group(stream, topic, group)
        .await
        .map_err(|_| WorkerError::new("could not inspect Iggy consumer group"))?
        .is_some()
    {
        return Ok(());
    }
    Err(WorkerError::new("could not create Iggy consumer group"))
}

fn role_name(role: NonceRole) -> &'static str {
    match role {
        NonceRole::Create => "create",
        NonceRole::Commit => "commit",
    }
}

/// Wall-clock milliseconds, used for the pending-tx ledger whose ages are
/// compared across processes by the unstick sweep.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Monotonic milliseconds for the Core's reveal-deadline arithmetic. The Core
/// only ever compares these timestamps to each other, so a process-local
/// monotonic clock is correct and immune to wall-clock steps — matching the
/// original worker's `Instant`-based elapsed check.
fn monotonic_ms() -> u64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    START
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_millis() as u64
}

#[derive(Debug)]
struct WorkerError(String);

impl WorkerError {
    fn new(message: &str) -> Self {
        Self(message.to_owned())
    }
}

impl std::fmt::Display for WorkerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for WorkerError {}

#[cfg(test)]
mod e2e_chain_tests {
    use std::{
        collections::HashMap,
        env,
        sync::Arc,
        time::{SystemTime, UNIX_EPOCH},
    };

    use p256::elliptic_curve::{Generate, sec1::ToSec1Point};
    use tokio::sync::Mutex;

    use super::{CreateWorker, NonceManager};
    use crate::{chain::Chain, config::Config, store::RedisStore};
    use p256_registrar::{
        task::{CreateTask, TaskStatus},
        wallet::{build_wallet_ref, default_metadata},
    };

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    /// Full replacement proof for the retired Deno queue worker's on-chain write path: a single
    /// create task is driven through commit -> reveal -> create -> done against the real Gnosis
    /// chain, then confirmed on-chain. This spends real gas from the funded `.env` PRIVATE_KEY, so
    /// it is double-gated: `#[ignore]` keeps it out of `cargo test`, and it no-ops unless
    /// `P256_INDEX_E2E_CHAIN=1` even when run with `--ignored`.
    ///
    /// ```sh
    /// P256_INDEX_E2E_CHAIN=1 cargo test --lib -- --ignored --nocapture \
    ///   e2e_chain_tests::create_persists_on_chain_end_to_end
    /// ```
    #[tokio::test]
    #[ignore = "requires P256_INDEX_E2E_CHAIN=1 and a funded PRIVATE_KEY (spends real gas)"]
    async fn create_persists_on_chain_end_to_end() {
        if env::var("P256_INDEX_E2E_CHAIN").as_deref() != Ok("1") {
            eprintln!("skipping on-chain e2e: set P256_INDEX_E2E_CHAIN=1 to run (spends gas)");
            return;
        }

        // Real chain (funded signer + Alchemy) and Redis come from the crate `.env`.
        let config = Config::from_env().expect("Config::from_env from .env");
        let chain = Chain::new(&config).expect("real Chain");
        assert!(
            chain.has_signers(),
            "PRIVATE_KEY with derived commit key is required for the on-chain e2e"
        );
        let redis_url =
            env::var("P256_INDEX_TEST_REDIS_URL").unwrap_or_else(|_| config.redis_url.clone());
        let store = RedisStore::connect(&redis_url)
            .await
            .expect("Redis connect");

        // A fresh, unique, valid task persisted as an admitted pending record.
        let signing_key = p256::SecretKey::generate();
        let public_key = hex::encode(signing_key.public_key().to_sec1_point(false).as_bytes());
        let wallet_ref = build_wallet_ref(&public_key).expect("wallet ref");
        let suffix = uuid::Uuid::new_v4();
        let task = CreateTask {
            id: format!("e2e-chain-{suffix}"),
            status: TaskStatus::Pending,
            rp_id: format!("e2e-chain-{suffix}.example"),
            credential_id: format!("cred-{suffix}"),
            wallet_ref: wallet_ref.clone(),
            public_key: public_key.clone(),
            name: "on-chain e2e".to_owned(),
            initial_credential_id: format!("cred-{suffix}"),
            metadata: default_metadata(&public_key).expect("default metadata"),
            tx_hash: None,
            error: None,
            retries: 0,
            created_at: now_ms() as i64,
            admitted: true,
        };
        store.admit(&task).await.expect("admit task");
        store.mark_admitted(&task.id).await.expect("mark admitted");

        // Drive exactly this task through the real worker chain logic — no Iggy topic drain, so no
        // other queued message can ever be written on-chain by this test.
        let worker = CreateWorker {
            store: store.clone(),
            chain: chain.clone(),
            consumer_url: config.iggy_consumer_url.clone(),
            consumer_group: config.iggy_consumer_group.clone(),
            nonces: Arc::new(NonceManager {
                values: Mutex::new(HashMap::new()),
            }),
        };
        worker
            .process_batch(vec![task.clone()])
            .await
            .expect("process_batch drives the task to done on-chain");

        // Terminal success in Redis, and the record is visible on-chain.
        let done = store
            .get_task(&task.id)
            .await
            .expect("load task")
            .expect("task still present");
        assert_eq!(done.status, TaskStatus::Done);
        assert!(done.tx_hash.is_some(), "a done task must carry its tx hash");
        assert!(
            chain
                .has_record(&task.rp_id, &task.credential_id)
                .await
                .expect("has_record"),
            "the credential must exist on-chain after the worker completes"
        );
        let record = chain
            .get_record(&task.rp_id, &task.credential_id)
            .await
            .expect("get_record")
            .expect("record present on-chain");
        assert_eq!(record.wallet_ref.to_lowercase(), wallet_ref.to_lowercase());
    }
}
