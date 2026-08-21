//! Shell for the submission task lifecycle.
//!
//! All decisions live in `p256_registrar::submission`; this worker owns the
//! machinery: the Iggy consumer loop (offset advance, backoff, malformed
//! message discard), nonce management for the single signing wallet, the
//! pending-tx ledger for the unstick sweep, and the execution of Core
//! operations against Redis and the chain. One Core instance drives one
//! polled batch to a `BatchVerdict`.

use std::{collections::VecDeque, sync::Arc, time::Duration};

use iggy::prelude::{
    Client, Consumer, ConsumerGroupClient, ConsumerOffsetClient, Identifier, IggyClient,
    MessageClient, PollingStrategy,
};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use p256_registrar::{
    gas::FeeVerdict,
    protocol::{parse_b256, parse_hex_bytes},
    submission::{
        BatchVerdict, SubmissionApp, SubmissionEffect, SubmissionEvent, SubmissionOperation,
        SubmissionResult, TxOutcome,
    },
    task::RegisterTask,
};

use crate::{
    chain::{Broadcast, Chain, ReceiptOutcome, WalletRole},
    store::RedisStore,
};

const POLL_BATCH_SIZE: u32 = 50;
const IGGY_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const RECEIPT_TIMEOUT: Duration = Duration::from_secs(60);
/// How long to wait before re-checking the fee after a batch was held back for
/// price. Short enough that a brief spike costs little latency, long enough not
/// to poll the RPC pool pointlessly.
const GAS_WAIT: Duration = Duration::from_secs(15);

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
    stream_name: String,
    topic_name: String,
    nonces: Arc<NonceManager>,
}

struct NonceManager {
    value: Mutex<Option<u64>>,
}

impl CreateWorker {
    pub fn start(
        store: RedisStore,
        chain: Chain,
        consumer_url: String,
        consumer_group: String,
        stream_name: String,
        topic_name: String,
    ) -> WorkerHandle {
        let shutdown = CancellationToken::new();
        let worker = Self {
            store,
            chain,
            consumer_url,
            consumer_group,
            stream_name,
            topic_name,
            nonces: Arc::new(NonceManager {
                value: Mutex::new(None),
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

        let stream: Identifier = self
            .stream_name
            .as_str()
            .try_into()
            .map_err(|_| WorkerError::new("invalid Iggy stream name"))?;
        let topic: Identifier = self
            .topic_name
            .as_str()
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
        tracing::info!(stream = %self.stream_name, topic = %self.topic_name, group = %self.consumer_group, "Iggy create worker started");

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
                    match serde_json::from_slice::<RegisterTask>(&message.payload) {
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

            // Pre-flight fee gate. Checked before any task work so that waiting
            // out an expensive market costs nothing: the offset does not
            // advance and no task's retry budget is consumed, so the batch is
            // simply re-polled later at a price we are willing to pay.
            if let Ok(FeeVerdict::TooExpensive { required, cap }) = self.chain.fee_plan().await {
                tracing::warn!(
                    required_wei = %required,
                    cap_wei = %cap,
                    "gas above the configured cap; batch requeued unspent"
                );
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = tokio::time::sleep(GAS_WAIT) => {}
                }
                continue;
            }

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

    /// Drive one polled batch through the submission Core. The queue
    /// messages are only envelopes: the Core loads the authoritative records
    /// itself, so only the ids cross into it.
    async fn process_batch(&self, queue_tasks: Vec<RegisterTask>) -> Result<(), WorkerError> {
        if queue_tasks.is_empty() {
            return Ok(());
        }
        let envelope_ids = queue_tasks.into_iter().map(|task| task.id).collect();

        let core: crux_core::Core<SubmissionApp> = crux_core::Core::new();
        let mut effects: VecDeque<SubmissionEffect> = core
            .process_event(SubmissionEvent::Start { envelope_ids })
            .into_iter()
            .collect();
        while let Some(effect) = effects.pop_front() {
            let SubmissionEffect::Work(mut request) = effect;
            let output = self.execute(&request.operation).await;
            let next = core
                .resolve(&mut request, output)
                .map_err(|_| WorkerError::new("could not resolve submission effect"))?;
            effects.extend(next);
        }

        match core.view().outcome {
            Some(BatchVerdict::Advance) => Ok(()),
            Some(BatchVerdict::Retry { reason }) => Err(WorkerError(reason)),
            None => Err(WorkerError::new("submission batch never settled")),
        }
    }

    /// Execute one Core operation against real infrastructure. Failures are
    /// mapped into result variants — the Core decides what they mean.
    async fn execute(&self, operation: &SubmissionOperation) -> SubmissionResult {
        match operation {
            SubmissionOperation::LoadTasks { ids } => {
                let mut tasks = Vec::with_capacity(ids.len());
                for id in ids {
                    match self.store.get_task(id).await {
                        Ok(task) => tasks.push(task),
                        Err(_) => return SubmissionResult::StoreUnavailable,
                    }
                }
                SubmissionResult::TasksLoaded { tasks }
            }
            SubmissionOperation::CheckContentRegistered { content_hash } => {
                let Ok(content_hash) = parse_b256(content_hash) else {
                    return SubmissionResult::ChainReadFailed;
                };
                match self.chain.is_content_registered(content_hash).await {
                    Ok(registered) => SubmissionResult::ContentChecked { registered },
                    Err(_) => SubmissionResult::ChainReadFailed,
                }
            }
            SubmissionOperation::CheckReferenced {
                group_public_key,
                member_public_key,
            } => {
                let (Ok(group), Ok(member)) = (
                    parse_hex_bytes(group_public_key),
                    parse_hex_bytes(member_public_key),
                ) else {
                    return SubmissionResult::ChainReadFailed;
                };
                match self.chain.is_referenced(group, member).await {
                    Ok(registered) => SubmissionResult::ContentChecked { registered },
                    Err(_) => SubmissionResult::ChainReadFailed,
                }
            }
            SubmissionOperation::SubmitRegister { task } => {
                SubmissionResult::Tx(self.submit(task).await)
            }
            SubmissionOperation::MarkDone {
                task_id,
                tx_hash,
                on_chain_id,
            } => store_ack(
                self.store
                    .mark_done(task_id, tx_hash.clone(), *on_chain_id)
                    .await,
            ),
            SubmissionOperation::MarkFailed {
                task_id,
                kind,
                message,
            } => store_ack(
                self.store
                    .mark_failed(task_id, kind.as_store_class(), message)
                    .await,
            ),
            SubmissionOperation::RecordTransientFailure { task_id, message } => {
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
    async fn submit(&self, task: &RegisterTask) -> TxOutcome {
        let Ok(nonce) = self.acquire().await else {
            return TxOutcome::NoncePoolUnavailable;
        };
        match self.chain.register(task, nonce).await {
            Ok(Broadcast { hash, fees_wei }) => {
                self.record_pending(nonce, &hash, fees_wei).await;
                match self.chain.wait_for_receipt(&hash, RECEIPT_TIMEOUT).await {
                    Ok(ReceiptOutcome::Success { on_chain_id }) => {
                        self.clear_pending(nonce).await;
                        TxOutcome::Confirmed {
                            tx_hash: hash,
                            on_chain_id,
                        }
                    }
                    Ok(ReceiptOutcome::Reverted) => {
                        self.clear_pending(nonce).await;
                        self.release().await;
                        TxOutcome::Reverted { tx_hash: hash }
                    }
                    Err(error) => {
                        self.release().await;
                        TxOutcome::ReceiptUncertain { error }
                    }
                }
            }
            Err(error) => {
                self.release().await;
                TxOutcome::SendFailed { error }
            }
        }
    }

    async fn acquire(&self) -> Result<u64, WorkerError> {
        let mut value = self.nonces.value.lock().await;
        if value.is_none() {
            *value = Some(
                self.chain
                    .pending_nonce(WalletRole::Register)
                    .await
                    .map_err(|_| WorkerError::new("could not acquire pending chain nonce"))?,
            );
        }
        let nonce = value.expect("nonce was initialized");
        *value = Some(nonce.saturating_add(1));
        Ok(nonce)
    }

    async fn release(&self) {
        *self.nonces.value.lock().await = None;
    }

    /// Record a freshly-broadcast tx in the ledger so the unstick sweep can replace it if its
    /// receipt never arrives. Best-effort: a ledger write failure must not fail the send path.
    async fn record_pending(&self, nonce: u64, hash: &str, fees_wei: Option<(u128, u128)>) {
        let _ = self
            .store
            .record_pending_tx(
                WalletRole::Register.ledger_name(),
                nonce,
                hash,
                now_ms(),
                0,
                fees_wei,
            )
            .await;
    }

    /// Clear the ledger only once a receipt is definite (success or reverted). On a receipt
    /// timeout the row is deliberately kept so the unstick sweep still sees a possibly-stuck tx.
    async fn clear_pending(&self, nonce: u64) {
        let _ = self
            .store
            .delete_pending_tx(WalletRole::Register.ledger_name(), nonce)
            .await;
    }
}

fn store_ack<T>(result: Result<T, crate::store::StoreError>) -> SubmissionResult {
    match result {
        Ok(_) => SubmissionResult::Persisted,
        Err(_) => SubmissionResult::StoreUnavailable,
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
        env,
        sync::Arc,
        time::{SystemTime, UNIX_EPOCH},
    };

    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use p256::elliptic_curve::Generate as _;
    use sha2::{Digest, Sha256};
    use tokio::sync::Mutex;

    use super::{CreateWorker, NonceManager};
    use crate::{chain::Chain, config::Config, store::RedisStore};
    use p256_registrar::{
        protocol::{challenge_for, content_hash_for, member_binding_for},
        task::{Member, Proof, RegisterTask, TaskKind, TaskStatus},
        verify::base64url_32,
    };

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    /// One register task is driven through submit -> done against the real
    /// Gnosis registry, then confirmed on-chain. This spends real gas from
    /// the funded `.env` PRIVATE_KEY, so it is double-gated: `#[ignore]`
    /// keeps it out of `cargo test`, and it no-ops unless
    /// `P256_INDEX_E2E_CHAIN=1` even when run with `--ignored`.
    ///
    /// ```sh
    /// P256_INDEX_E2E_CHAIN=1 cargo test --lib -- --ignored --nocapture \
    ///   e2e_chain_tests::register_persists_on_chain_end_to_end
    /// ```
    #[tokio::test]
    #[ignore = "requires P256_INDEX_E2E_CHAIN=1 and a funded PRIVATE_KEY (spends real gas)"]
    async fn register_persists_on_chain_end_to_end() {
        if env::var("P256_INDEX_E2E_CHAIN").as_deref() != Ok("1") {
            eprintln!("skipping on-chain e2e: set P256_INDEX_E2E_CHAIN=1 to run (spends gas)");
            return;
        }

        // Real chain (funded signer + registry address) and Redis come from
        // the crate `.env`.
        let config = Config::from_env().expect("Config::from_env from .env");
        let chain = Chain::new(&config).expect("real Chain");
        assert!(
            chain.has_signer(),
            "PRIVATE_KEY is required for the on-chain e2e"
        );
        let redis_url =
            env::var("P256_INDEX_TEST_REDIS_URL").unwrap_or_else(|_| config.redis_url.clone());
        let store = RedisStore::connect(&redis_url)
            .await
            .expect("Redis connect");

        // A fresh passkey plus a fresh group key, with REAL possession
        // proofs: the member binds (groupKey, own attestation), the group
        // key closes over the content hash.
        fn sign_proof(
            signing: &p256::ecdsa::SigningKey,
            challenge: alloy::primitives::B256,
            rp_id: &str,
        ) -> Proof {
            let client_data = format!(
                "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"https://example.com\"}}",
                base64url_32(&challenge)
            );
            let mut auth_data = Vec::new();
            auth_data.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
            auth_data.push(0x05);
            auth_data.extend_from_slice(&[0, 0, 0, 0]);
            let client_hash: [u8; 32] = Sha256::digest(client_data.as_bytes()).into();
            let mut signed = auth_data.clone();
            signed.extend_from_slice(&client_hash);
            let digest: [u8; 32] = Sha256::digest(&signed).into();
            let signature: p256::ecdsa::Signature = signing.sign_prehash(&digest).unwrap();
            let bytes = signature.to_bytes();
            Proof {
                authenticator_data: hex::encode(auth_data),
                client_data_json: client_data,
                challenge_index: 23,
                type_index: 1,
                r: format!("0x{}", hex::encode(&bytes[..32])),
                s: format!("0x{}", hex::encode(&bytes[32..])),
            }
        }

        let member_signing = p256::ecdsa::SigningKey::from(&p256::SecretKey::generate());
        let public_key = hex::encode(
            member_signing
                .verifying_key()
                .to_sec1_point(false)
                .as_bytes(),
        );
        let group_signing = p256::ecdsa::SigningKey::from(&p256::SecretKey::generate());
        let group_public_key = hex::encode(
            group_signing
                .verifying_key()
                .to_sec1_point(false)
                .as_bytes(),
        );
        let suffix = uuid::Uuid::new_v4();
        let rp_id = format!("e2e-chain-{suffix}.example");
        let registry = config.contract_address.parse().expect("registry address");

        let binding = member_binding_for(&hex::decode(&group_public_key).unwrap(), &[]);
        let member_challenge = challenge_for(
            chain.chain_id(),
            registry,
            &rp_id,
            &hex::decode(&public_key).unwrap(),
            binding,
        );

        let mut task = RegisterTask {
            id: format!("e2e-chain-{suffix}"),
            status: TaskStatus::Pending,
            kind: TaskKind::Register,
            rp_id: rp_id.clone(),
            metadata: "0xe2e0".into(),
            content_hash: String::new(),
            group_public_key: group_public_key.clone(),
            group_proof: Some(Proof {
                authenticator_data: String::new(),
                client_data_json: String::new(),
                challenge_index: 23,
                type_index: 1,
                r: String::new(),
                s: String::new(),
            }),
            members: vec![Member {
                public_key: public_key.clone(),
                attestation: String::new(),
                credential_id: String::new(),
                authenticator_attachment: String::new(),
                transports: String::new(),
                proof: sign_proof(&member_signing, member_challenge, &rp_id),
            }],
            tx_hash: None,
            on_chain_id: None,
            error: None,
            retries: 0,
            created_at: now_ms() as i64,
            admitted: true,
        };
        let content_hash = content_hash_for(&task).expect("content hash");
        task.content_hash = format!("{content_hash:#x}");
        let group_challenge = challenge_for(
            chain.chain_id(),
            registry,
            &rp_id,
            &hex::decode(&group_public_key).unwrap(),
            content_hash,
        );
        task.group_proof = Some(sign_proof(&group_signing, group_challenge, &rp_id));
        store.admit(&task).await.expect("admit task");

        let worker = CreateWorker {
            store: store.clone(),
            chain: chain.clone(),
            consumer_url: String::new(),
            consumer_group: String::new(),
            stream_name: String::new(),
            topic_name: String::new(),
            nonces: Arc::new(NonceManager {
                value: Mutex::new(None),
            }),
        };
        worker
            .process_batch(vec![task.clone()])
            .await
            .expect("process_batch drives the task to done on-chain");

        let stored = store
            .get_task(&task.id)
            .await
            .expect("load task")
            .expect("task exists");
        assert_eq!(stored.status, TaskStatus::Done, "error: {:?}", stored.error);
        assert!(stored.tx_hash.is_some());
        eprintln!(
            "on-chain e2e complete: tx {:?}, first entry {:?}",
            stored.tx_hash, stored.on_chain_id
        );

        // The key's global file and its group membership are now readable.
        let profile = chain
            .key_profile(&public_key, 1, 10, false)
            .await
            .expect("key profile")
            .expect("entry exists");
        assert_eq!(profile.entry.public_key, public_key);
        assert_eq!(profile.group_total, 1);
        let unit = chain
            .unit(profile.group_ids[0])
            .await
            .expect("unit read")
            .expect("unit exists");
        assert_eq!(unit.metadata, "e2e0");
        assert_eq!(unit.group_public_key, group_public_key);
    }
}
