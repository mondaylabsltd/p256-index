//! The single strongly-consistent authority for one funded wallet.
//!
//! One instance per deployment, addressed by `id_from_name("v1")`. Its
//! SQLite database holds what Redis and Iggy hold in the docker shell: the
//! authoritative task records, the content-hash idempotency index, the
//! per-key placeholders, the durable FIFO queue, the DLQ, the rate
//! counters and the broadcast ledger. The admission program
//! (`p256_registrar::admission`) runs here unchanged — its store
//! operations become local synchronous SQLite statements, so the docker
//! shell's Redis/Iggy two-phase admission narrows to sequential writes in
//! one single-threaded object, and a 202 is only ever sent after the queue
//! row is durably on disk (Durable Object output gates).
//!
//! The submission loop (`p256_registrar::submission`) is driven by this
//! object's alarm instead of a tokio consumer: poll a batch of envelopes,
//! drive the Core, delete the envelopes only on `BatchVerdict::Advance` —
//! exactly the Iggy offset rule. Tasks are therefore never lost between
//! admission and an on-chain receipt: a crash mid-flight re-delivers the
//! batch and reconciliation-by-content-hash absorbs the duplicates.

use std::{cell::Cell, cell::RefCell, time::Duration};

use crux_core::Core;
use serde::Deserialize;
use serde_json::json;
// `wasm_bindgen` must be a resolvable name at this scope: the
// #[durable_object] expansion refers to it by that ident.
use worker::{
    Date, DurableObject, Env, Request, Response, Result, SqlStorage, SqlStorageValue, State,
    durable_object, wasm_bindgen,
};

use alloy::primitives::U256;
use p256_registrar::{
    admission::{
        AdmissionApp, AdmissionEffect, AdmissionEvent, AdmissionOperation, AdmissionOutcome,
        AdmissionResult, AdmitOutcome, RETRY_COALESCE_TTL_SECS,
    },
    gas::{self, FeePlan, FeeVerdict},
    protocol::{CHAIN_ID, is_replacement_underpriced, parse_b256, parse_hex_bytes},
    rescue::{self, RescueAction},
    sentinel,
    submission::{
        BatchVerdict, SubmissionApp, SubmissionEffect, SubmissionEvent, SubmissionOperation,
        SubmissionResult, TxOutcome,
    },
    task::{RegisterTask, TaskStatus},
};

use crate::{
    chain::{Broadcast, Chain, ReceiptOutcome, WalletRole},
    config::CfConfig,
    proto::AdmitCall,
    telegram::Telegram,
};

const TASK_DONE_TTL_MS: i64 = 7 * 24 * 60 * 60 * 1000;
const TASK_FAILED_TTL_MS: i64 = 30 * 24 * 60 * 60 * 1000;
const POLL_BATCH_SIZE: u32 = 50;
const RECEIPT_TIMEOUT: Duration = Duration::from_secs(60);
const GAS_WAIT: Duration = Duration::from_secs(15);
const MAX_BATCH_BACKOFF: Duration = Duration::from_secs(60);

#[durable_object]
pub struct SubmitterDo {
    state: State,
    env: Env,
    /// Consecutive transient batch failures drive the re-poll backoff, like
    /// the docker worker's counter. In-memory: an eviction resets it, which
    /// is exactly what a container restart does.
    failures: Cell<u32>,
    /// The docker worker's NonceManager: a cached next-nonce, dropped on
    /// every failure path so the next send re-syncs with the chain.
    nonce: RefCell<Option<u64>>,
    chain: RefCell<Option<(CfConfig, Chain)>>,
}

// ── Row shapes ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct PayloadRow {
    payload: String,
}

#[derive(Deserialize)]
struct IdRow {
    task_id: String,
}

#[derive(Deserialize)]
struct CountRow {
    n: i64,
}

#[derive(Deserialize)]
struct OldestRow {
    oldest: Option<i64>,
}

#[derive(Deserialize)]
struct EnvelopeRow {
    seq: i64,
    task_id: String,
}

pub enum Admission {
    New,
    Existing(String),
}

impl DurableObject for SubmitterDo {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            failures: Cell::new(0),
            nonce: RefCell::new(None),
            chain: RefCell::new(None),
        }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        self.bootstrap()?;
        self.purge_expired()?;
        let url = req.url()?;
        match url.path() {
            "/admit" => {
                let call: AdmitCall = req.json().await?;
                let outcome = self.run_admission(call).await?;
                if let AdmissionOutcome::Queued { status, .. } = &outcome
                    && !status.is_terminal()
                {
                    self.ensure_alarm().await?;
                }
                Response::from_json(&outcome)
            }
            "/task" => {
                let id = query_param(&url, "id").unwrap_or_default();
                Response::from_json(&json!({ "task": self.get_task(&id)? }))
            }
            "/find-by-key" => {
                let key = query_param(&url, "key").unwrap_or_default();
                Response::from_json(&json!({ "task": self.find_by_public_key(&key)? }))
            }
            "/allow-read" => {
                let ip_hash = query_param(&url, "ip").unwrap_or_default();
                let allowed = self.bump_minute_counter(&format!("read:{ip_hash}"))? <= 120;
                Response::from_json(&json!({ "allowed": allowed }))
            }
            "/maintain" => {
                let report = self.run_maintenance().await?;
                Response::ok(report)
            }
            "/stats" => {
                let (depth, dlq, oldest_age_ms) = self.queue_stats()?;
                // depth > 0 with no alarm armed and a signer configured is
                // the CF equivalent of the docker shell's stalled worker.
                let alarm_armed = self.state.storage().get_alarm().await?.is_some();
                let has_signer = self.chain()?.1.has_signer();
                Response::from_json(&json!({
                    "depth": depth,
                    "dlq": dlq,
                    "oldestJobAgeMs": oldest_age_ms,
                    "workerStalled": has_signer && depth > 0 && !alarm_armed,
                }))
            }
            _ => Response::error("unknown durable object route", 404),
        }
    }

    async fn alarm(&self) -> Result<Response> {
        self.bootstrap()?;
        self.purge_expired()?;
        let (_, chain) = self.chain()?;
        if !chain.has_signer() {
            // Read-only deployment: tasks stay pending, exactly like the
            // docker shell with QUEUE_WORKER disabled. The next enqueue
            // re-arms the alarm, so adding a key later resumes the queue.
            return Response::ok("idle: no signer");
        }

        // Pre-flight fee gate: waiting out an expensive market costs
        // nothing — no envelope is consumed, no retry budget spent.
        if let Ok(p256_registrar::gas::FeeVerdict::TooExpensive { .. }) = chain.fee_plan().await {
            self.schedule(GAS_WAIT).await?;
            return Response::ok("gas above cap; batch requeued unspent");
        }

        let batch = self.poll_batch(POLL_BATCH_SIZE)?;
        if batch.is_empty() {
            return Response::ok("queue empty");
        }
        let ids: Vec<String> = batch
            .iter()
            .map(|envelope| envelope.task_id.clone())
            .collect();

        match self.process_batch(&chain, ids).await {
            Ok(()) => {
                self.failures.set(0);
                self.delete_batch(&batch)?;
                if self.queue_len()? > 0 {
                    self.schedule(Duration::from_millis(0)).await?;
                }
                Response::ok("batch advanced")
            }
            Err(reason) => {
                let failures = self.failures.get().saturating_add(1);
                self.failures.set(failures);
                let backoff = sentinel::backoff_delay(failures).min(MAX_BATCH_BACKOFF);
                self.schedule(backoff).await?;
                Response::ok(format!("batch retry in {}s: {reason}", backoff.as_secs()))
            }
        }
    }
}

impl SubmitterDo {
    fn sql(&self) -> SqlStorage {
        self.state.storage().sql()
    }

    fn chain(&self) -> Result<(CfConfig, Chain)> {
        if self.chain.borrow().is_none() {
            let config = CfConfig::from_env(&self.env)?;
            let chain = Chain::new(&config)?;
            *self.chain.borrow_mut() = Some((config, chain));
        }
        Ok(self.chain.borrow().clone().expect("chain was initialized"))
    }

    fn bootstrap(&self) -> Result<()> {
        self.sql().exec(
            "CREATE TABLE IF NOT EXISTS tasks (
                 id           TEXT PRIMARY KEY,
                 payload      TEXT NOT NULL,
                 status       TEXT NOT NULL,
                 admitted     INTEGER NOT NULL,
                 content_hash TEXT NOT NULL,
                 created_at   INTEGER NOT NULL,
                 active       INTEGER NOT NULL,
                 expires_at   INTEGER
             );
             CREATE INDEX IF NOT EXISTS idx_tasks_active ON tasks (active, created_at);
             CREATE TABLE IF NOT EXISTS content_index (
                 content_hash TEXT PRIMARY KEY,
                 task_id      TEXT NOT NULL,
                 expires_at   INTEGER
             );
             CREATE TABLE IF NOT EXISTS key_placeholders (
                 public_key TEXT PRIMARY KEY,
                 task_id    TEXT NOT NULL,
                 expires_at INTEGER
             );
             CREATE INDEX IF NOT EXISTS idx_placeholders_task ON key_placeholders (task_id);
             CREATE TABLE IF NOT EXISTS retry_digests (
                 digest     TEXT PRIMARY KEY,
                 task_id    TEXT NOT NULL,
                 expires_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS queue (
                 seq     INTEGER PRIMARY KEY AUTOINCREMENT,
                 task_id TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS dlq (task_id TEXT PRIMARY KEY);
             CREATE TABLE IF NOT EXISTS rate_counters (
                 key        TEXT PRIMARY KEY,
                 count      INTEGER NOT NULL,
                 window_end INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS ledger (
                 role         TEXT NOT NULL,
                 nonce        INTEGER NOT NULL,
                 hash         TEXT NOT NULL,
                 sent_at      INTEGER NOT NULL,
                 attempts     INTEGER NOT NULL,
                 max_fee      TEXT,
                 max_priority TEXT,
                 PRIMARY KEY (role, nonce)
             );
             CREATE TABLE IF NOT EXISTS alerts (
                 kind       TEXT PRIMARY KEY,
                 last_fired INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS meta (
                 key   TEXT PRIMARY KEY,
                 value INTEGER NOT NULL
             );",
            None,
        )?;
        Ok(())
    }

    /// The SQL stand-in for Redis TTL expiry, run at the top of every
    /// request and alarm.
    fn purge_expired(&self) -> Result<()> {
        let now = now_ms();
        for statement in [
            "DELETE FROM tasks WHERE expires_at IS NOT NULL AND expires_at <= ?1",
            "DELETE FROM content_index WHERE expires_at IS NOT NULL AND expires_at <= ?1",
            "DELETE FROM key_placeholders WHERE expires_at IS NOT NULL AND expires_at <= ?1",
            "DELETE FROM retry_digests WHERE expires_at <= ?1",
            "DELETE FROM rate_counters WHERE window_end <= ?1",
        ] {
            self.sql().exec(statement, vec![SqlStorageValue::from(now)])?;
        }
        Ok(())
    }

    async fn ensure_alarm(&self) -> Result<()> {
        if self.state.storage().get_alarm().await?.is_none() {
            self.schedule(Duration::from_millis(0)).await?;
        }
        Ok(())
    }

    async fn schedule(&self, delay: Duration) -> Result<()> {
        self.state.storage().set_alarm(delay).await
    }

    // ── Store: the Redis semantics on SQLite ───────────────────────────────

    pub fn get_task(&self, id: &str) -> Result<Option<RegisterTask>> {
        let rows: Vec<PayloadRow> = self
            .sql()
            .exec(
                "SELECT payload FROM tasks
                 WHERE id = ?1 AND (expires_at IS NULL OR expires_at > ?2)",
                vec![SqlStorageValue::from(id), SqlStorageValue::from(now_ms())],
            )?
            .to_array()?;
        // An unparseable record must read as missing, not as a store
        // outage: a single corrupt payload would otherwise jam every batch
        // that touches it, forever.
        Ok(rows
            .first()
            .and_then(|row| serde_json::from_str(&row.payload).ok()))
    }

    fn find_by_index(&self, table: &str, column: &str, value: &str) -> Result<Option<RegisterTask>> {
        let query = format!(
            "SELECT task_id FROM {table}
             WHERE {column} = ?1 AND (expires_at IS NULL OR expires_at > ?2)"
        );
        let rows: Vec<IdRow> = self
            .sql()
            .exec(
                &query,
                vec![SqlStorageValue::from(value), SqlStorageValue::from(now_ms())],
            )?
            .to_array()?;
        match rows.first() {
            Some(row) => self.get_task(&row.task_id),
            None => Ok(None),
        }
    }

    fn find_by_content(&self, content_hash: &str) -> Result<Option<RegisterTask>> {
        self.find_by_index(
            "content_index",
            "content_hash",
            &content_hash.to_ascii_lowercase(),
        )
    }

    fn find_by_public_key(&self, public_key: &str) -> Result<Option<RegisterTask>> {
        self.find_by_index(
            "key_placeholders",
            "public_key",
            &public_key.to_ascii_lowercase(),
        )
    }

    fn find_by_retry_digest(&self, digest: &str) -> Result<Option<RegisterTask>> {
        self.find_by_index("retry_digests", "digest", &digest.to_ascii_lowercase())
    }

    fn record_retry_digest(&self, digest: &str, task_id: &str, ttl_secs: u64) -> Result<()> {
        self.sql().exec(
            "INSERT OR REPLACE INTO retry_digests (digest, task_id, expires_at)
             VALUES (?1, ?2, ?3)",
            vec![
                SqlStorageValue::from(digest.to_ascii_lowercase()),
                SqlStorageValue::from(task_id),
                SqlStorageValue::from(now_ms() + (ttl_secs as i64) * 1000),
            ],
        )?;
        Ok(())
    }

    /// The atomic admission the docker shell runs as a Redis Lua script.
    /// The object is single-threaded and every statement here is
    /// synchronous, so the check-then-insert sequence cannot interleave
    /// with another admission.
    fn admit(&self, task: &RegisterTask) -> Result<Admission> {
        if let Some(existing) = self.find_by_content(&task.content_hash)? {
            return Ok(Admission::Existing(existing.id));
        }
        let payload = serde_json::to_string(task)
            .map_err(|_| worker::Error::RustError("could not serialize register task".into()))?;
        self.sql().exec(
            "INSERT OR REPLACE INTO tasks
                 (id, payload, status, admitted, content_hash, created_at, active, expires_at)
             VALUES (?1, ?2, 'pending', 0, ?3, ?4, 1, NULL)",
            vec![
                SqlStorageValue::from(task.id.as_str()),
                SqlStorageValue::from(payload),
                SqlStorageValue::from(task.content_hash.to_ascii_lowercase()),
                SqlStorageValue::from(task.created_at),
            ],
        )?;
        self.sql().exec(
            "INSERT OR REPLACE INTO content_index (content_hash, task_id, expires_at)
             VALUES (?1, ?2, NULL)",
            vec![
                SqlStorageValue::from(task.content_hash.to_ascii_lowercase()),
                SqlStorageValue::from(task.id.as_str()),
            ],
        )?;
        // Public-key placeholders: first active task keeps its claim, so a
        // later unit sharing a key can never strand the earlier one's
        // pre-chain visibility when it terminates.
        for key in member_key_placeholders(task) {
            self.sql().exec(
                "INSERT OR IGNORE INTO key_placeholders (public_key, task_id, expires_at)
                 VALUES (?1, ?2, NULL)",
                vec![
                    SqlStorageValue::from(key),
                    SqlStorageValue::from(task.id.as_str()),
                ],
            )?;
        }
        Ok(Admission::New)
    }

    fn enqueue(&self, task: &RegisterTask) -> Result<()> {
        self.sql().exec(
            "INSERT INTO queue (task_id) VALUES (?1)",
            vec![SqlStorageValue::from(task.id.as_str())],
        )?;
        Ok(())
    }

    fn mark_admitted(&self, id: &str) -> Result<Option<RegisterTask>> {
        let Some(before) = self.get_task(id)? else {
            return Ok(None);
        };
        // A terminal transition already set admitted (and owns the record's
        // TTL): never resurrect it into a TTL-less active task.
        if before.status.is_terminal() {
            return Ok(Some(before));
        }
        let mut task = before;
        task.admitted = true;
        let payload = serde_json::to_string(&task)
            .map_err(|_| worker::Error::RustError("could not serialize register task".into()))?;
        self.sql().exec(
            "UPDATE tasks SET payload = ?1, admitted = 1 WHERE id = ?2",
            vec![
                SqlStorageValue::from(payload),
                SqlStorageValue::from(id),
            ],
        )?;
        Ok(Some(task))
    }

    fn mark_done(
        &self,
        id: &str,
        tx_hash: Option<String>,
        on_chain_id: Option<u64>,
    ) -> Result<Option<RegisterTask>> {
        let Some(mut task) = self.get_task(id)? else {
            return Ok(None);
        };
        task.status = TaskStatus::Done;
        task.tx_hash = tx_hash.or(task.tx_hash);
        task.on_chain_id = on_chain_id.or(task.on_chain_id);
        task.error = None;
        task.admitted = true;
        self.transition_terminal(&task, TASK_DONE_TTL_MS, false)?;
        Ok(Some(task))
    }

    fn record_transient_failure(&self, id: &str, message: &str) -> Result<Option<RegisterTask>> {
        let Some(mut task) = self.get_task(id)? else {
            return Ok(None);
        };
        if task.status.is_terminal() {
            return Ok(Some(task));
        }
        task.retries = task.retries.saturating_add(1);
        task.error = Some(redact_error(message));
        if task.retries >= 10 {
            task.status = TaskStatus::Failed;
            task.error = Some(format!(
                "EXHAUSTED: {}",
                task.error.as_deref().unwrap_or("transient chain failure")
            ));
            self.transition_terminal(&task, TASK_FAILED_TTL_MS, true)?;
        } else {
            let payload = serde_json::to_string(&task).map_err(|_| {
                worker::Error::RustError("could not serialize register task".into())
            })?;
            self.sql().exec(
                "UPDATE tasks SET payload = ?1 WHERE id = ?2",
                vec![SqlStorageValue::from(payload), SqlStorageValue::from(id)],
            )?;
        }
        Ok(Some(task))
    }

    fn mark_failed(&self, id: &str, prefix: &str, message: &str) -> Result<Option<RegisterTask>> {
        let Some(mut task) = self.get_task(id)? else {
            return Ok(None);
        };
        task.status = TaskStatus::Failed;
        task.retries = task.retries.saturating_add(1);
        task.error = Some(format!("{prefix}: {}", redact_error(message)));
        self.transition_terminal(&task, TASK_FAILED_TTL_MS, true)?;
        Ok(Some(task))
    }

    /// The docker shell's transition_done / transition_failed Lua scripts.
    /// Done: the record and the indexes still pointing at this task pick up
    /// the retention TTL. Failed: the indexes are dropped immediately (a
    /// fresh attempt must not coalesce onto a dead task) and the task joins
    /// the DLQ.
    fn transition_terminal(&self, task: &RegisterTask, ttl_ms: i64, failed: bool) -> Result<()> {
        let payload = serde_json::to_string(task)
            .map_err(|_| worker::Error::RustError("could not serialize register task".into()))?;
        let expires_at = now_ms() + ttl_ms;
        let status = if failed { "failed" } else { "done" };
        self.sql().exec(
            "UPDATE tasks
             SET payload = ?1, status = ?2, admitted = 1, active = 0, expires_at = ?3
             WHERE id = ?4",
            vec![
                SqlStorageValue::from(payload),
                SqlStorageValue::from(status),
                SqlStorageValue::from(expires_at),
                SqlStorageValue::from(task.id.as_str()),
            ],
        )?;
        if failed {
            self.sql().exec(
                "DELETE FROM content_index WHERE task_id = ?1",
                vec![SqlStorageValue::from(task.id.as_str())],
            )?;
            self.sql().exec(
                "DELETE FROM key_placeholders WHERE task_id = ?1",
                vec![SqlStorageValue::from(task.id.as_str())],
            )?;
            self.sql().exec(
                "INSERT OR IGNORE INTO dlq (task_id) VALUES (?1)",
                vec![SqlStorageValue::from(task.id.as_str())],
            )?;
        } else {
            self.sql().exec(
                "UPDATE content_index SET expires_at = ?1 WHERE task_id = ?2",
                vec![
                    SqlStorageValue::from(expires_at),
                    SqlStorageValue::from(task.id.as_str()),
                ],
            )?;
            self.sql().exec(
                "UPDATE key_placeholders SET expires_at = ?1 WHERE task_id = ?2",
                vec![
                    SqlStorageValue::from(expires_at),
                    SqlStorageValue::from(task.id.as_str()),
                ],
            )?;
        }
        Ok(())
    }

    /// (depth, dlq_count, oldest_active_age_ms)
    fn queue_stats(&self) -> Result<(u64, u64, u64)> {
        let depth: CountRow = self
            .sql()
            .exec("SELECT count(*) AS n FROM tasks WHERE active = 1", None)?
            .one()?;
        let dlq: CountRow = self
            .sql()
            .exec("SELECT count(*) AS n FROM dlq", None)?
            .one()?;
        let oldest: OldestRow = self
            .sql()
            .exec(
                "SELECT min(created_at) AS oldest FROM tasks WHERE active = 1",
                None,
            )?
            .one()?;
        let oldest_age_ms = oldest
            .oldest
            .map(|created_at| now_ms().saturating_sub(created_at).max(0) as u64)
            .unwrap_or(0);
        Ok((depth.n.max(0) as u64, dlq.n.max(0) as u64, oldest_age_ms))
    }

    fn queue_len(&self) -> Result<u64> {
        let row: CountRow = self
            .sql()
            .exec("SELECT count(*) AS n FROM queue", None)?
            .one()?;
        Ok(row.n.max(0) as u64)
    }

    fn poll_batch(&self, limit: u32) -> Result<Vec<EnvelopeRow>> {
        self.sql()
            .exec(
                "SELECT seq, task_id FROM queue ORDER BY seq LIMIT ?1",
                vec![SqlStorageValue::from(limit as i64)],
            )?
            .to_array()
    }

    /// The Iggy offset advance: consume the polled envelopes only after the
    /// whole batch settled as Advance.
    fn delete_batch(&self, batch: &[EnvelopeRow]) -> Result<()> {
        for envelope in batch {
            self.sql().exec(
                "DELETE FROM queue WHERE seq = ?1",
                vec![SqlStorageValue::from(envelope.seq)],
            )?;
        }
        Ok(())
    }

    /// The Redis INCR + PEXPIRE minute window as one upsert.
    fn bump_minute_counter(&self, key: &str) -> Result<i64> {
        let now = now_ms();
        let row: CountRow = self
            .sql()
            .exec(
                "INSERT INTO rate_counters (key, count, window_end) VALUES (?1, 1, ?2)
                 ON CONFLICT (key) DO UPDATE SET
                     count = CASE WHEN window_end <= ?3 THEN 1 ELSE count + 1 END,
                     window_end = CASE WHEN window_end <= ?3 THEN ?2 ELSE window_end END
                 RETURNING count AS n",
                vec![
                    SqlStorageValue::from(key),
                    SqlStorageValue::from(now + 60_000),
                    SqlStorageValue::from(now),
                ],
            )?
            .one()?;
        Ok(row.n)
    }

    fn record_pending_tx(
        &self,
        role: &str,
        nonce: u64,
        hash: &str,
        sent_at_ms: i64,
        attempts: u32,
        fees: Option<(u128, u128)>,
    ) -> Result<()> {
        self.sql().exec(
            "INSERT OR REPLACE INTO ledger
                 (role, nonce, hash, sent_at, attempts, max_fee, max_priority)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            vec![
                SqlStorageValue::from(role),
                SqlStorageValue::from(nonce as i64),
                SqlStorageValue::from(hash),
                SqlStorageValue::from(sent_at_ms),
                SqlStorageValue::from(attempts as i64),
                fees.map(|(max_fee, _)| SqlStorageValue::from(max_fee.to_string()))
                    .unwrap_or(SqlStorageValue::Null),
                fees.map(|(_, priority)| SqlStorageValue::from(priority.to_string()))
                    .unwrap_or(SqlStorageValue::Null),
            ],
        )?;
        Ok(())
    }

    /// Ledger rows first broadcast before `sent_before_ms` — the unstick
    /// sweep's candidate set, in the registrar's own row vocabulary.
    fn list_pending_txs(&self, sent_before_ms: i64) -> Result<Vec<rescue::LedgerRow>> {
        #[derive(Deserialize)]
        struct Row {
            role: String,
            nonce: i64,
            hash: String,
            sent_at: i64,
            attempts: i64,
            max_fee: Option<String>,
            max_priority: Option<String>,
        }
        let rows: Vec<Row> = self
            .sql()
            .exec(
                "SELECT role, nonce, hash, sent_at, attempts, max_fee, max_priority
                 FROM ledger WHERE sent_at < ?1",
                vec![SqlStorageValue::from(sent_before_ms)],
            )?
            .to_array()?;
        Ok(rows
            .into_iter()
            .map(|row| rescue::LedgerRow {
                role: row.role,
                nonce: row.nonce.max(0) as u64,
                hash: row.hash,
                sent_at_ms: row.sent_at.max(0) as u64,
                attempts: row.attempts.clamp(0, u32::MAX as i64) as u32,
                fees_wei: row
                    .max_fee
                    .as_deref()
                    .and_then(|value| value.parse::<u128>().ok())
                    .zip(
                        row.max_priority
                            .as_deref()
                            .and_then(|value| value.parse::<u128>().ok()),
                    ),
            })
            .collect())
    }

    fn delete_pending_tx(&self, role: &str, nonce: u64) -> Result<()> {
        self.sql().exec(
            "DELETE FROM ledger WHERE role = ?1 AND nonce = ?2",
            vec![
                SqlStorageValue::from(role),
                SqlStorageValue::from(nonce as i64),
            ],
        )?;
        Ok(())
    }

    // ── Admission: the registrar's program against this store ──────────────

    async fn run_admission(&self, call: AdmitCall) -> Result<AdmissionOutcome> {
        let (config, chain) = self.chain()?;
        let core: Core<AdmissionApp> = Core::new();
        let mut effects = core.process_event(AdmissionEvent::Submit {
            request: call.request,
            new_task_id: uuid::Uuid::new_v4().to_string(),
            now_ms: now_ms() as u64,
            chain_id: CHAIN_ID,
            registry: chain.domain_registry_address(),
        });
        loop {
            let Some(effect) = effects.pop() else {
                break;
            };
            let AdmissionEffect::Work(mut request) = effect;
            let result = self
                .execute_admission(&config, &chain, &call.ip_hash, &request.operation)
                .await;
            effects = core
                .resolve(&mut request, result)
                .map_err(|_| worker::Error::RustError("could not resolve admission effect".into()))?;
        }
        core.view()
            .outcome
            .ok_or_else(|| worker::Error::RustError("admission never settled".into()))
    }

    async fn execute_admission(
        &self,
        config: &CfConfig,
        chain: &Chain,
        ip_hash: &str,
        operation: &AdmissionOperation,
    ) -> AdmissionResult {
        match operation {
            AdmissionOperation::AllowIpCreate => {
                match self.bump_minute_counter(&format!("create:{ip_hash}")) {
                    Ok(count) => AdmissionResult::Allowed { allowed: count <= 5 },
                    Err(_) => AdmissionResult::StoreUnavailable,
                }
            }
            AdmissionOperation::FindTaskByContent { content_hash } => {
                match self.find_by_content(content_hash) {
                    Ok(task) => AdmissionResult::TaskFound { task },
                    Err(_) => AdmissionResult::StoreUnavailable,
                }
            }
            AdmissionOperation::FindTaskByRetryDigest { digest } => {
                match self.find_by_retry_digest(digest) {
                    Ok(task) => AdmissionResult::TaskFound { task },
                    Err(_) => AdmissionResult::StoreUnavailable,
                }
            }
            AdmissionOperation::RecordRetryDigest { digest, task_id } => {
                match self.record_retry_digest(digest, task_id, RETRY_COALESCE_TTL_SECS) {
                    Ok(()) => AdmissionResult::Persisted,
                    Err(_) => AdmissionResult::StoreUnavailable,
                }
            }
            AdmissionOperation::CheckContentRegistered { content_hash } => {
                let Ok(content_hash) = parse_b256(content_hash) else {
                    return AdmissionResult::ChainReadFailed;
                };
                match chain.is_content_registered(content_hash).await {
                    Ok(value) => AdmissionResult::ChainBool { value },
                    Err(_) => AdmissionResult::ChainReadFailed,
                }
            }
            AdmissionOperation::CheckReferenced {
                group_public_key,
                member_public_key,
            } => {
                let (Ok(group), Ok(member)) = (
                    parse_hex_bytes(group_public_key),
                    parse_hex_bytes(member_public_key),
                ) else {
                    return AdmissionResult::ChainReadFailed;
                };
                match chain.is_referenced(group, member).await {
                    Ok(value) => AdmissionResult::ChainBool { value },
                    Err(_) => AdmissionResult::ChainReadFailed,
                }
            }
            AdmissionOperation::CheckGroupExists { group_public_key } => {
                let Ok(group) = parse_hex_bytes(group_public_key) else {
                    return AdmissionResult::ChainReadFailed;
                };
                match chain.unit_by_group_key(group).await {
                    Ok(unit) => AdmissionResult::ChainBool {
                        value: unit.is_some(),
                    },
                    Err(_) => AdmissionResult::ChainReadFailed,
                }
            }
            AdmissionOperation::FindTaskByKey { key_hash } => {
                match self.find_by_public_key(key_hash) {
                    Ok(task) => AdmissionResult::TaskFound { task },
                    Err(_) => AdmissionResult::StoreUnavailable,
                }
            }
            AdmissionOperation::QueueDepth => match self.queue_stats() {
                Ok((depth, _, _)) => AdmissionResult::Depth { depth },
                Err(_) => AdmissionResult::StoreUnavailable,
            },
            AdmissionOperation::AllowGlobalCreate => {
                match self.bump_minute_counter("create:global") {
                    Ok(count) => AdmissionResult::Allowed {
                        allowed: count as u64 <= config.global_write_limit,
                    },
                    Err(_) => AdmissionResult::StoreUnavailable,
                }
            }
            AdmissionOperation::Admit { task } => match self.admit(task) {
                Ok(Admission::New) => AdmissionResult::Admitted(AdmitOutcome::New),
                Ok(Admission::Existing(id)) => {
                    AdmissionResult::Admitted(AdmitOutcome::Existing { id })
                }
                Err(_) => AdmissionResult::StoreUnavailable,
            },
            AdmissionOperation::LoadTask { id } => match self.get_task(id) {
                Ok(task) => AdmissionResult::TaskFound { task },
                Err(_) => AdmissionResult::StoreUnavailable,
            },
            AdmissionOperation::Enqueue { task } => match self.enqueue(task) {
                Ok(()) => AdmissionResult::Enqueued,
                Err(_) => AdmissionResult::QueueUnavailable,
            },
            AdmissionOperation::MarkAdmitted { id } => match self.mark_admitted(id) {
                Ok(task) => AdmissionResult::TaskFound { task },
                Err(_) => AdmissionResult::StoreUnavailable,
            },
        }
    }

    // ── Submission: the registrar's batch program against this store ───────

    async fn process_batch(&self, chain: &Chain, envelope_ids: Vec<String>) -> std::result::Result<(), String> {
        let core: Core<SubmissionApp> = Core::new();
        let mut effects: std::collections::VecDeque<SubmissionEffect> = core
            .process_event(SubmissionEvent::Start { envelope_ids })
            .into_iter()
            .collect();
        while let Some(effect) = effects.pop_front() {
            let SubmissionEffect::Work(mut request) = effect;
            let output = self.execute_submission(chain, &request.operation).await;
            let next = core
                .resolve(&mut request, output)
                .map_err(|_| "could not resolve submission effect".to_owned())?;
            effects.extend(next);
        }
        match core.view().outcome {
            Some(BatchVerdict::Advance) => Ok(()),
            Some(BatchVerdict::Retry { reason }) => Err(reason),
            None => Err("submission batch never settled".to_owned()),
        }
    }

    async fn execute_submission(
        &self,
        chain: &Chain,
        operation: &SubmissionOperation,
    ) -> SubmissionResult {
        match operation {
            SubmissionOperation::LoadTasks { ids } => {
                let mut tasks = Vec::with_capacity(ids.len());
                for id in ids {
                    match self.get_task(id) {
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
                match chain.is_content_registered(content_hash).await {
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
                match chain.is_referenced(group, member).await {
                    Ok(registered) => SubmissionResult::ContentChecked { registered },
                    Err(_) => SubmissionResult::ChainReadFailed,
                }
            }
            SubmissionOperation::SubmitRegister { task } => {
                SubmissionResult::Tx(self.submit(chain, task).await)
            }
            SubmissionOperation::MarkDone {
                task_id,
                tx_hash,
                on_chain_id,
            } => store_ack(self.mark_done(task_id, tx_hash.clone(), *on_chain_id)),
            SubmissionOperation::MarkFailed {
                task_id,
                kind,
                message,
            } => store_ack(self.mark_failed(task_id, kind.as_store_class(), message)),
            SubmissionOperation::RecordTransientFailure { task_id, message } => {
                store_ack(self.record_transient_failure(task_id, message))
            }
        }
    }

    /// One chain write with the docker worker's nonce and ledger rules: the
    /// ledger row is recorded on broadcast, cleared only on a definite
    /// receipt, and deliberately kept on a receipt timeout so a future
    /// unstick sweep still sees a possibly-stuck tx; the cached nonce is
    /// released on every failure path so the next send re-syncs.
    async fn submit(&self, chain: &Chain, task: &RegisterTask) -> TxOutcome {
        let nonce = match self.acquire_nonce(chain).await {
            Ok(nonce) => nonce,
            Err(()) => return TxOutcome::NoncePoolUnavailable,
        };
        match chain.register(task, nonce).await {
            Ok(Broadcast { hash, fees_wei }) => {
                // Best-effort: a ledger write failure must not fail the send.
                let _ = self.record_pending_tx(
                    WalletRole::Register.ledger_name(),
                    nonce,
                    &hash,
                    now_ms(),
                    0,
                    fees_wei,
                );
                match chain.wait_for_receipt(&hash, RECEIPT_TIMEOUT).await {
                    Ok(ReceiptOutcome::Success { on_chain_id }) => {
                        let _ = self.delete_pending_tx(WalletRole::Register.ledger_name(), nonce);
                        TxOutcome::Confirmed {
                            tx_hash: hash,
                            on_chain_id,
                        }
                    }
                    Ok(ReceiptOutcome::Reverted) => {
                        let _ = self.delete_pending_tx(WalletRole::Register.ledger_name(), nonce);
                        *self.nonce.borrow_mut() = None;
                        TxOutcome::Reverted { tx_hash: hash }
                    }
                    Err(error) => {
                        *self.nonce.borrow_mut() = None;
                        TxOutcome::ReceiptUncertain { error }
                    }
                }
            }
            Err(error) => {
                *self.nonce.borrow_mut() = None;
                TxOutcome::SendFailed { error }
            }
        }
    }

    async fn acquire_nonce(&self, chain: &Chain) -> std::result::Result<u64, ()> {
        if self.nonce.borrow().is_none() {
            let synced = chain
                .pending_nonce(WalletRole::Register)
                .await
                .map_err(|_| ())?;
            *self.nonce.borrow_mut() = Some(synced);
        }
        let nonce = self.nonce.borrow().expect("nonce was initialized");
        *self.nonce.borrow_mut() = Some(nonce.saturating_add(1));
        Ok(nonce)
    }

    // ── Maintenance: the docker shell's loop, driven by a cron trigger ─────
    //
    // The judgement lives in the registrar (`rescue` for the unstick sweep,
    // `sentinel` for alert policy and the heartbeat); this pass supplies the
    // inputs and executes the plan. It runs inside the object because the
    // ledger and the wallet are this object's to touch. Alert-throttle
    // timestamps live in SQLite, not memory: the object is evicted between
    // cron ticks, and an in-memory throttle would re-page on every wake.

    async fn run_maintenance(&self) -> Result<String> {
        let (config, chain) = self.chain()?;
        if !chain.has_signer() {
            // Without a signer there are no wallets to fund, unstick or
            // report on — same gate as the docker shell.
            return Ok("idle: no signer".into());
        }
        let telegram = Telegram::new(
            config.telegram_bot_token.clone(),
            config.telegram_chat_id.clone(),
        );
        self.unstick_sweep(&chain, telegram.as_ref()).await;
        self.check_alerts(&chain, telegram.as_ref()).await;
        self.maybe_heartbeat(&config, &chain, telegram.as_ref())
            .await;
        Ok("maintenance pass complete".into())
    }

    async fn unstick_sweep(&self, chain: &Chain, telegram: Option<&Telegram>) {
        let now = now_ms();
        let sent_before = now.saturating_sub(rescue::STUCK_TX_AGE_MS as i64);
        let Ok(ledger) = self.list_pending_txs(sent_before) else {
            worker::console_warn!("unstick: ledger read failed");
            return;
        };
        if ledger.is_empty() {
            return;
        }

        // Replacements are priced per row, against the fee that row was sent
        // at. The base fee is only the floor that keeps the replacement
        // itself includable; it must never become the basis for the bump.
        let Ok(base_fee) = chain.base_fee().await else {
            worker::console_warn!("unstick: base fee read failed");
            return;
        };

        for role in [WalletRole::Register] {
            let Ok(confirmed) = chain.confirmed_nonce(role).await else {
                worker::console_warn!("unstick: confirmed-nonce read failed");
                continue;
            };
            for action in
                rescue::plan_role_sweep(role.ledger_name(), confirmed, &ledger, now as u64)
            {
                match action {
                    RescueAction::DropConsumedRow { nonce } => {
                        let _ = self.delete_pending_tx(role.ledger_name(), nonce);
                    }
                    RescueAction::Escalate { message } => {
                        self.alert_throttled(telegram, "stuck", &message).await;
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
                            chain.max_gas_price_wei(),
                            attempts_after.saturating_sub(1),
                        ) {
                            FeeVerdict::Send(fees) => fees,
                            FeeVerdict::TooExpensive { required, cap } => {
                                // Bidding past the cap to clear a nonce is the
                                // one thing the cap exists to prevent. Page
                                // instead: this needs a human decision.
                                self.alert_throttled(
                                    telegram,
                                    "gas-capped",
                                    &format!(
                                        "🛑 [webauthnp256-publickey-index] stuck {} nonce {} needs \
                                         {required} wei to replace, above the {cap} wei cap. \
                                         Raise P256_INDEX_MAX_GAS_PRICE_WEI or intervene manually.",
                                        role.ledger_name(),
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
                        // Preserve the original row identity on failure: only
                        // a confirmed broadcast may overwrite hash/timestamp.
                        let (row_hash, sent_at) = ledger
                            .iter()
                            .find(|row| row.role == role.ledger_name() && row.nonce == nonce)
                            .map(|row| (row.hash.clone(), row.sent_at_ms as i64))
                            .unwrap_or_else(|| (String::new(), now));
                        match chain.cancel_stuck_nonce(role, nonce, fees).await {
                            Ok(cancel_hash) => {
                                // Reset sentAt and bump attempts so the next
                                // attempt waits a full window.
                                let _ = self.record_pending_tx(
                                    role.ledger_name(),
                                    nonce,
                                    &cancel_hash,
                                    now,
                                    attempts_after,
                                    bid,
                                );
                            }
                            // The node saw this bid and judged it too low: the
                            // rung was genuinely climbed, so record it and let
                            // the next sweep ladder up from it.
                            Err(error) if is_replacement_underpriced(&error) => {
                                let _ = self.record_pending_tx(
                                    role.ledger_name(),
                                    nonce,
                                    &row_hash,
                                    sent_at,
                                    attempts_after,
                                    bid,
                                );
                            }
                            // Anything else means the bid never reached the
                            // mempool. The ledger must not move: ratcheting on
                            // an unsent price walks the recorded bid up to the
                            // cap and permanently disables rescue for a nonce
                            // a far cheaper replacement would clear.
                            Err(_) => {
                                worker::console_warn!(
                                    "unstick: attempt for nonce {nonce} did not reach the mempool; bid unchanged"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    async fn check_alerts(&self, chain: &Chain, telegram: Option<&Telegram>) {
        // Open RPC read circuit: reads are failing over, data may be stale.
        if chain.rpc_circuit_state() == "open" {
            self.alert_throttled(telegram, "rpc", sentinel::rpc_circuit_alert())
                .await;
        }

        // DLQ growth: creates are being quarantined and need inspection.
        if let Ok((_, dlq_count, _)) = self.queue_stats()
            && dlq_count >= sentinel::DLQ_ALERT_THRESHOLD
        {
            let message = sentinel::dlq_alert(dlq_count);
            self.alert_throttled(telegram, "dlq", &message).await;
        }

        // Low funding runway: top up before creates start failing.
        if let (Ok(balance), Ok(price)) = (
            chain.balance(WalletRole::Register).await,
            chain.gas_price().await,
        ) {
            let balance_xdai = sentinel::wei_to_xdai(u128::try_from(balance).unwrap_or(u128::MAX));
            let price_gwei = sentinel::wei_to_gwei(u128::try_from(price).unwrap_or(u128::MAX));
            let runway = sentinel::estimate_create_runway(balance_xdai, price_gwei);
            if runway.is_finite() && runway < sentinel::LOW_RUNWAY_CREATES {
                let message = sentinel::low_runway_alert(runway, balance_xdai, price_gwei);
                self.alert_throttled(telegram, "low-runway", &message).await;
            }
        }
    }

    async fn alert_throttled(&self, telegram: Option<&Telegram>, kind: &str, message: &str) {
        let now = now_ms();
        let last_fired = self.meta_alert_last_fired(kind).unwrap_or(None);
        if !sentinel::alert_due(last_fired, now as u64) {
            return;
        }
        if self
            .sql()
            .exec(
                "INSERT OR REPLACE INTO alerts (kind, last_fired) VALUES (?1, ?2)",
                vec![SqlStorageValue::from(kind), SqlStorageValue::from(now)],
            )
            .is_err()
        {
            return;
        }
        match telegram {
            Some(telegram) => telegram.send(message).await,
            None => worker::console_warn!("operator alert (Telegram not configured): {message}"),
        }
    }

    fn meta_alert_last_fired(&self, kind: &str) -> Result<Option<u64>> {
        #[derive(Deserialize)]
        struct Row {
            last_fired: i64,
        }
        let rows: Vec<Row> = self
            .sql()
            .exec(
                "SELECT last_fired FROM alerts WHERE kind = ?1",
                vec![SqlStorageValue::from(kind)],
            )?
            .to_array()?;
        Ok(rows.first().map(|row| row.last_fired.max(0) as u64))
    }

    async fn maybe_heartbeat(&self, config: &CfConfig, chain: &Chain, telegram: Option<&Telegram>) {
        let now = now_ms();
        let started_at = self.meta_get_or_insert("started_at", now).unwrap_or(now);
        let last = self.meta_get("last_heartbeat").unwrap_or(None);
        let due = last
            .map(|at| now.saturating_sub(at) >= sentinel::HEARTBEAT_INTERVAL.as_millis() as i64)
            .unwrap_or(true);
        if !due {
            return;
        }
        if self.meta_set("last_heartbeat", now).is_err() {
            return;
        }

        let stats = self.queue_stats().ok();
        let gas_price = chain.gas_price().await.ok();
        let wallet_address = chain
            .wallet_address(WalletRole::Register)
            .map(|address| address.to_string())
            .unwrap_or_default();
        let wallet_balance = chain.balance(WalletRole::Register).await.ok();

        let message = sentinel::build_heartbeat_message(&sentinel::HeartbeatInput {
            runtime: "Rust/Workers",
            queue_depth: stats.map(|(depth, _, _)| depth).unwrap_or(0),
            dlq_count: stats.map(|(_, dlq, _)| dlq).unwrap_or(0),
            wallet_address: &wallet_address,
            wallet_balance_xdai: wallet_balance
                .map(|balance| sentinel::wei_to_xdai(u128::try_from(balance).unwrap_or(u128::MAX)))
                .unwrap_or(0.0),
            gas_price_gwei: gas_price
                .map(|price| sentinel::wei_to_gwei(u128::try_from(price).unwrap_or(u128::MAX)))
                .unwrap_or(0.0),
            uptime: Duration::from_millis(now.saturating_sub(started_at).max(0) as u64),
            release: config.release.as_deref(),
        });
        if let Some(telegram) = telegram {
            telegram.send(&message).await;
        }
    }

    fn meta_get(&self, key: &str) -> Result<Option<i64>> {
        #[derive(Deserialize)]
        struct Row {
            value: i64,
        }
        let rows: Vec<Row> = self
            .sql()
            .exec(
                "SELECT value FROM meta WHERE key = ?1",
                vec![SqlStorageValue::from(key)],
            )?
            .to_array()?;
        Ok(rows.first().map(|row| row.value))
    }

    fn meta_set(&self, key: &str, value: i64) -> Result<()> {
        self.sql().exec(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
            vec![SqlStorageValue::from(key), SqlStorageValue::from(value)],
        )?;
        Ok(())
    }

    fn meta_get_or_insert(&self, key: &str, value: i64) -> Result<i64> {
        if let Some(existing) = self.meta_get(key)? {
            return Ok(existing);
        }
        self.meta_set(key, value)?;
        Ok(value)
    }
}

fn store_ack<T>(result: Result<T>) -> SubmissionResult {
    match result {
        Ok(_) => SubmissionResult::Persisted,
        Err(_) => SubmissionResult::StoreUnavailable,
    }
}

fn member_key_placeholders(task: &RegisterTask) -> Vec<String> {
    let mut keys: Vec<String> = task
        .members
        .iter()
        .map(|member| member.public_key.to_ascii_lowercase())
        .collect();
    keys.push(task.group_public_key.to_ascii_lowercase());
    keys
}

fn redact_error(value: &str) -> String {
    value.chars().take(200).collect()
}

fn now_ms() -> i64 {
    Date::now().as_millis() as i64
}

fn query_param(url: &worker::Url, name: &str) -> Option<String> {
    url.query_pairs()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
}
