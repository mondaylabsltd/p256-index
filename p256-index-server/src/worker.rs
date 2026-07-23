use std::{collections::HashMap, sync::Arc, time::Duration};

use iggy::prelude::{
    Client, Consumer, ConsumerGroupClient, ConsumerOffsetClient, Identifier, IggyClient,
    MessageClient, PollingStrategy,
};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::{
    chain::{
        Chain, ChainError, ReceiptStatus, WalletRole, is_record_exists_error, is_transient,
        is_wallet_conflict_error,
    },
    contract::build_commitment,
    queue::{STREAM_NAME, TOPIC_NAME},
    store::RedisStore,
    types::{CreateTask, TaskStatus},
};

const POLL_BATCH_SIZE: u32 = 50;
const CREATE_SUB_BATCH_SIZE: usize = 10;
const IGGY_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const RECEIPT_TIMEOUT: Duration = Duration::from_secs(60);
const REVEAL_TIMEOUT: Duration = Duration::from_secs(75);

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
            .map_err(|_| WorkerError("invalid Iggy consumer connection configuration"))?;
        tokio::time::timeout(IGGY_CONNECT_TIMEOUT, client.connect())
            .await
            .map_err(|_| WorkerError("Iggy consumer connection timed out"))?
            .map_err(|_| WorkerError("could not connect Iggy consumer"))?;

        let stream: Identifier = STREAM_NAME
            .try_into()
            .map_err(|_| WorkerError("invalid Iggy stream name"))?;
        let topic: Identifier = TOPIC_NAME
            .try_into()
            .map_err(|_| WorkerError("invalid Iggy topic name"))?;
        let group: Identifier = self
            .consumer_group
            .as_str()
            .try_into()
            .map_err(|_| WorkerError("invalid Iggy consumer group name"))?;
        ensure_consumer_group(&client, &stream, &topic, &group, &self.consumer_group).await?;
        client
            .join_consumer_group(&stream, &topic, &group)
            .await
            .map_err(|_| WorkerError("could not join Iggy consumer group"))?;

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
                    result.map_err(|_| WorkerError("could not poll Iggy create tasks"))?,
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
                .ok_or(WorkerError("Iggy poll returned no highest offset"))?;
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
                        .map_err(|_| WorkerError("could not store Iggy consumer offset"))?;
                }
                Err(error) => {
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    let backoff = crate::reliability::backoff_delay(consecutive_failures)
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

    async fn process_batch(&self, queue_tasks: Vec<CreateTask>) -> Result<(), WorkerError> {
        if queue_tasks.is_empty() {
            return Ok(());
        }
        let mut canonical = Vec::new();
        for envelope in queue_tasks {
            match self.store.get_task(&envelope.id).await {
                Ok(Some(task)) if !task.status.is_terminal() => canonical.push(task),
                Ok(_) => {}
                Err(_) => return Err(WorkerError("could not load Redis create task")),
            }
        }
        deduplicate_by_id(&mut canonical);
        if canonical.is_empty() {
            return Ok(());
        }

        // Reconciliation comes first. It covers receipt-timeout and producer duplicate cases
        // without ever replaying a successful on-chain create.
        let mut pending = Vec::new();
        let mut committed = Vec::new();
        for task in canonical {
            match self
                .chain
                .has_record(&task.rp_id, &task.credential_id)
                .await
            {
                Ok(true) => {
                    self.store
                        .mark_done(&task.id, task.tx_hash.clone())
                        .await
                        .map_err(|_| WorkerError("could not persist reconciled task"))?;
                }
                Ok(false) if task.status == TaskStatus::Pending => pending.push(task),
                Ok(false) if task.status == TaskStatus::Committed => committed.push(task),
                Ok(false) => {}
                Err(_) => {
                    self.retry_task(&task, "hasRecord RPC temporarily unavailable")
                        .await?;
                    return Err(WorkerError("chain reconciliation failed"));
                }
            }
        }

        if !pending.is_empty() {
            self.commit_pending(&pending).await?;
            for task in pending {
                if let Some(task) = self
                    .store
                    .get_task(&task.id)
                    .await
                    .map_err(|_| WorkerError("could not reload committed task"))?
                    && task.status == TaskStatus::Committed
                {
                    committed.push(task);
                }
            }
        }
        if committed.is_empty() {
            return Ok(());
        }

        self.wait_for_reveal(&committed).await?;
        let mut missing = Vec::new();
        for task in committed {
            match self
                .chain
                .has_record(&task.rp_id, &task.credential_id)
                .await
            {
                Ok(true) => {
                    self.store
                        .mark_done(&task.id, task.tx_hash.clone())
                        .await
                        .map_err(|_| WorkerError("could not persist completed task"))?;
                }
                Ok(false) => missing.push(task),
                Err(_) => {
                    self.retry_task(&task, "hasRecord RPC temporarily unavailable")
                        .await?;
                    return Err(WorkerError("chain reconciliation failed"));
                }
            }
        }
        for chunk in missing.chunks(CREATE_SUB_BATCH_SIZE) {
            self.create_chunk(chunk).await?;
        }
        Ok(())
    }

    async fn commit_pending(&self, tasks: &[CreateTask]) -> Result<(), WorkerError> {
        let nonce = self.acquire(NonceRole::Commit).await?;
        match self.chain.commit(tasks, nonce).await {
            Ok(hash) => {
                self.record_pending(NonceRole::Commit, nonce, &hash).await;
                match self.chain.wait_for_receipt(&hash, RECEIPT_TIMEOUT).await {
                    Ok(ReceiptStatus::Success) => {
                        self.clear_pending(NonceRole::Commit, nonce).await;
                        for task in tasks {
                            self.store
                                .mark_committed(&task.id)
                                .await
                                .map_err(|_| WorkerError("could not persist committed task"))?;
                        }
                        Ok(())
                    }
                    Ok(ReceiptStatus::Reverted) => {
                        self.clear_pending(NonceRole::Commit, nonce).await;
                        self.release(NonceRole::Commit).await;
                        // Isolate the single culprit commitment instead of poisoning the whole
                        // batch, so innocent items still make forward progress.
                        self.isolate_commit(tasks).await
                    }
                    // Receipt timeout: the tx may be stuck. Keep the ledger row for the unstick
                    // sweep and let the batch retry.
                    Err(error) => {
                        self.release(NonceRole::Commit).await;
                        self.handle_batch_error(tasks, &error, "batchCommit").await
                    }
                }
            }
            Err(error) => {
                self.release(NonceRole::Commit).await;
                self.handle_batch_error(tasks, &error, "batchCommit").await
            }
        }
    }

    /// Poison isolation for batchCommit (mirror of [`Self::isolate_create`]): re-commit each task
    /// individually so a single deterministically-reverting commitment is quarantined while the
    /// rest advance. An already-recorded commitment is reconciled to `committed`.
    async fn isolate_commit(&self, tasks: &[CreateTask]) -> Result<(), WorkerError> {
        for task in tasks {
            if let Ok(commitment) = build_commitment(task)
                && let Ok(block) = self.chain.get_commit_block(commitment).await
                && block > 0
            {
                self.store
                    .mark_committed(&task.id)
                    .await
                    .map_err(|_| WorkerError("could not persist committed task"))?;
                continue;
            }
            let nonce = self.acquire(NonceRole::Commit).await?;
            match self.chain.commit(std::slice::from_ref(task), nonce).await {
                Ok(hash) => {
                    self.record_pending(NonceRole::Commit, nonce, &hash).await;
                    match self.chain.wait_for_receipt(&hash, RECEIPT_TIMEOUT).await {
                        Ok(ReceiptStatus::Success) => {
                            self.clear_pending(NonceRole::Commit, nonce).await;
                            self.store
                                .mark_committed(&task.id)
                                .await
                                .map_err(|_| WorkerError("could not persist committed task"))?;
                        }
                        Ok(ReceiptStatus::Reverted) => {
                            self.clear_pending(NonceRole::Commit, nonce).await;
                            self.release(NonceRole::Commit).await;
                            self.store
                                .mark_failed(&task.id, "POISON", "batchCommit transaction reverted")
                                .await
                                .map_err(|_| WorkerError("could not persist failed task"))?;
                        }
                        Err(error) => {
                            self.release(NonceRole::Commit).await;
                            self.handle_task_error(task, &error, "batchCommit").await?;
                            return Err(WorkerError("isolated commit receipt wait failed"));
                        }
                    }
                }
                Err(error) => {
                    self.release(NonceRole::Commit).await;
                    self.handle_task_error(task, &error, "batchCommit").await?;
                    if is_transient(&error) {
                        return Err(WorkerError("isolated commit temporarily failed"));
                    }
                }
            }
        }
        Ok(())
    }

    async fn wait_for_reveal(&self, tasks: &[CreateTask]) -> Result<(), WorkerError> {
        let started = tokio::time::Instant::now();
        loop {
            let block = self
                .chain
                .current_block()
                .await
                .map_err(|_| WorkerError("could not read current block"))?;
            let mut all_ready = true;
            for task in tasks {
                let commitment = build_commitment(task)
                    .map_err(|_| WorkerError("stored create task cannot be encoded"))?;
                match self.chain.get_commit_block(commitment).await {
                    Ok(0) => match self
                        .chain
                        .has_record(&task.rp_id, &task.credential_id)
                        .await
                    {
                        Ok(true) => {
                            self.store
                                .mark_done(&task.id, task.tx_hash.clone())
                                .await
                                .map_err(|_| WorkerError("could not persist reconciled task"))?;
                        }
                        Ok(false) => {
                            self.store
                                .mark_pending(&task.id, Some("commitment missing; re-committing"))
                                .await
                                .map_err(|_| WorkerError("could not reschedule task"))?;
                            return Err(WorkerError("commitment was not found"));
                        }
                        Err(_) => {
                            return Err(WorkerError("could not reconcile missing commitment"));
                        }
                    },
                    Ok(commit_block) if block >= commit_block.saturating_add(1) => {}
                    Ok(_) => all_ready = false,
                    Err(_) => return Err(WorkerError("could not read commit block")),
                }
            }
            if all_ready {
                return Ok(());
            }
            if started.elapsed() >= REVEAL_TIMEOUT {
                return Err(WorkerError("commit reveal delay exceeded timeout"));
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    async fn create_chunk(&self, tasks: &[CreateTask]) -> Result<(), WorkerError> {
        let nonce = self.acquire(NonceRole::Create).await?;
        match self.chain.create(tasks, nonce).await {
            Ok(hash) => {
                self.record_pending(NonceRole::Create, nonce, &hash).await;
                match self.chain.wait_for_receipt(&hash, RECEIPT_TIMEOUT).await {
                    Ok(ReceiptStatus::Success) => {
                        self.clear_pending(NonceRole::Create, nonce).await;
                        for task in tasks {
                            self.store
                                .mark_done(&task.id, Some(hash.clone()))
                                .await
                                .map_err(|_| WorkerError("could not persist done task"))?;
                        }
                        Ok(())
                    }
                    Ok(ReceiptStatus::Reverted) => {
                        self.clear_pending(NonceRole::Create, nonce).await;
                        self.release(NonceRole::Create).await;
                        self.isolate_create(tasks).await
                    }
                    Err(error) => {
                        self.release(NonceRole::Create).await;
                        self.handle_batch_error(tasks, &error, "batchCreateRecord")
                            .await
                    }
                }
            }
            Err(error) => {
                self.release(NonceRole::Create).await;
                if is_transient(&error) {
                    self.handle_batch_error(tasks, &error, "batchCreateRecord")
                        .await
                } else {
                    self.isolate_create(tasks).await
                }
            }
        }
    }

    async fn isolate_create(&self, tasks: &[CreateTask]) -> Result<(), WorkerError> {
        for task in tasks {
            match self
                .chain
                .has_record(&task.rp_id, &task.credential_id)
                .await
            {
                Ok(true) => {
                    self.store
                        .mark_done(&task.id, task.tx_hash.clone())
                        .await
                        .map_err(|_| WorkerError("could not persist reconciled task"))?;
                    continue;
                }
                Ok(false) => {}
                Err(_) => return Err(WorkerError("could not reconcile isolated task")),
            }
            let nonce = self.acquire(NonceRole::Create).await?;
            match self.chain.create(std::slice::from_ref(task), nonce).await {
                Ok(hash) => {
                    self.record_pending(NonceRole::Create, nonce, &hash).await;
                    match self.chain.wait_for_receipt(&hash, RECEIPT_TIMEOUT).await {
                        Ok(ReceiptStatus::Success) => {
                            self.clear_pending(NonceRole::Create, nonce).await;
                            self.store
                                .mark_done(&task.id, Some(hash))
                                .await
                                .map_err(|_| WorkerError("could not persist isolated task"))?;
                        }
                        Ok(ReceiptStatus::Reverted) => {
                            self.clear_pending(NonceRole::Create, nonce).await;
                            self.release(NonceRole::Create).await;
                            self.store
                                .mark_failed(
                                    &task.id,
                                    "POISON",
                                    "createRecord transaction reverted",
                                )
                                .await
                                .map_err(|_| WorkerError("could not persist failed task"))?;
                        }
                        Err(error) => {
                            self.release(NonceRole::Create).await;
                            self.handle_task_error(task, &error, "createRecord").await?;
                            return Err(WorkerError("isolated create receipt wait failed"));
                        }
                    }
                }
                Err(error) => {
                    self.release(NonceRole::Create).await;
                    self.handle_task_error(task, &error, "createRecord").await?;
                    if is_transient(&error) {
                        return Err(WorkerError("isolated create temporarily failed"));
                    }
                }
            }
        }
        Ok(())
    }

    async fn handle_batch_error(
        &self,
        tasks: &[CreateTask],
        error: &ChainError,
        operation: &str,
    ) -> Result<(), WorkerError> {
        for task in tasks {
            self.handle_task_error(task, error, operation).await?;
        }
        if is_transient(error) {
            Err(WorkerError("chain write temporarily failed"))
        } else {
            Ok(())
        }
    }

    async fn handle_task_error(
        &self,
        task: &CreateTask,
        error: &ChainError,
        operation: &str,
    ) -> Result<(), WorkerError> {
        let message = format!("{operation}: {error}");
        if is_record_exists_error(error) {
            self.store
                .mark_done(&task.id, task.tx_hash.clone())
                .await
                .map_err(|_| WorkerError("could not persist reconciled task"))?;
        } else if is_wallet_conflict_error(error) {
            self.store
                .mark_failed(&task.id, "CONFLICT", &message)
                .await
                .map_err(|_| WorkerError("could not persist conflict task"))?;
        } else if is_transient(error) {
            self.retry_task(task, &message).await?;
        } else {
            self.store
                .mark_failed(&task.id, "POISON", &message)
                .await
                .map_err(|_| WorkerError("could not persist poison task"))?;
        }
        Ok(())
    }

    async fn retry_task(&self, task: &CreateTask, message: &str) -> Result<(), WorkerError> {
        self.store
            .record_transient_failure(&task.id, message)
            .await
            .map_err(|_| WorkerError("could not persist task retry"))?;
        Ok(())
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
                    .map_err(|_| WorkerError("could not acquire pending chain nonce"))?,
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
        .map_err(|_| WorkerError("could not inspect Iggy consumer group"))?
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
        .map_err(|_| WorkerError("could not inspect Iggy consumer group"))?
        .is_some()
    {
        return Ok(());
    }
    Err(WorkerError("could not create Iggy consumer group"))
}

fn deduplicate_by_id(tasks: &mut Vec<CreateTask>) {
    let mut seen = std::collections::HashSet::new();
    tasks.retain(|task| seen.insert(task.id.clone()));
}

fn role_name(role: NonceRole) -> &'static str {
    match role {
        NonceRole::Create => "create",
        NonceRole::Commit => "commit",
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Debug)]
struct WorkerError(&'static str);

impl std::fmt::Display for WorkerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
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
    use crate::{
        chain::Chain,
        config::Config,
        contract::{build_wallet_ref, default_metadata},
        store::RedisStore,
        types::{CreateTask, TaskStatus},
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
