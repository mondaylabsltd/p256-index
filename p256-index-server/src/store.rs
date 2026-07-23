use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use redis::{FromRedisValue, Script, aio::MultiplexedConnection};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::types::{CreateTask, TaskStatus};

const TASK_DONE_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const TASK_FAILED_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);
const CACHE_FRESH_TTL: Duration = Duration::from_secs(5 * 60);
const CACHE_NEGATIVE_TTL: Duration = Duration::from_secs(60);
const CACHE_RECORD_STALE_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const CACHE_STATS_STALE_TTL: Duration = Duration::from_secs(60 * 60);

#[derive(Clone)]
pub struct RedisStore {
    connection: MultiplexedConnection,
    command_timeout: Duration,
}

#[derive(Debug)]
pub struct StoreError(&'static str);

impl std::fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for StoreError {}

#[derive(Debug, Eq, PartialEq)]
pub enum Admission {
    New(String),
    Existing(String),
    WalletConflict(String),
}

#[derive(Clone, Debug)]
pub struct QueueStats {
    pub depth: u64,
    pub dlq_count: u64,
    pub oldest_active_age_ms: u64,
}

pub enum CacheRead {
    Fresh(Value),
    Negative,
    Stale { value: Value, age_ms: u64 },
    Miss,
}

#[derive(Serialize, Deserialize)]
struct CacheEntry {
    value: Option<Value>,
    stored_at_ms: u64,
    fresh_until_ms: u64,
}

#[derive(Serialize, Deserialize)]
struct PendingTxEntry {
    hash: String,
    sent_at_ms: u64,
    attempts: u32,
}

/// A broadcast-ledger row: a `(role, nonce)` tx that was sent and not yet reconciled.
#[derive(Clone, Debug)]
pub struct PendingTx {
    pub role: String,
    pub nonce: u64,
    pub hash: String,
    pub sent_at_ms: u64,
    pub attempts: u32,
}

impl RedisStore {
    pub async fn connect(url: &str) -> Result<Self, StoreError> {
        let client = redis::Client::open(url)
            .map_err(|_| StoreError("invalid Redis connection configuration"))?;
        let connection = tokio::time::timeout(
            Duration::from_secs(5),
            client.get_multiplexed_async_connection(),
        )
        .await
        .map_err(|_| StoreError("Redis connection timed out"))?
        .map_err(|_| StoreError("could not connect to Redis"))?;
        let store = Self {
            connection,
            command_timeout: Duration::from_secs(3),
        };
        let pong: String = store.query(redis::cmd("PING")).await?;
        if pong != "PONG" {
            return Err(StoreError("Redis health check failed"));
        }
        Ok(store)
    }

    /// Atomically establishes the Redis half of Iggy admission. The caller must retain a new
    /// record when Iggy has an ambiguous delivery outcome: a later identical request safely
    /// re-appends it, while the worker treats duplicate task IDs idempotently.
    pub async fn admit(&self, task: &CreateTask) -> Result<Admission, StoreError> {
        let payload = serde_json::to_string(task)
            .map_err(|_| StoreError("could not serialize create task"))?;
        let script = Script::new(
            r#"
            local existing = redis.call('GET', KEYS[1])
            if existing then return 'existing|' .. existing end
            local wallet = redis.call('GET', KEYS[2])
            if wallet then return 'conflict|' .. wallet end
            redis.call('SET', KEYS[1], ARGV[1])
            redis.call('SET', KEYS[2], ARGV[1])
            redis.call('SET', KEYS[3], ARGV[2])
            redis.call('SADD', KEYS[4], ARGV[1])
            redis.call('ZADD', KEYS[5], ARGV[3], ARGV[1])
            return 'new|' .. ARGV[1]
        "#,
        );
        let response: String = self
            .run_script(
                script
                    .key(record_active_key(&task.rp_id, &task.credential_id))
                    .key(wallet_active_key(&task.wallet_ref))
                    .key(task_key(&task.id))
                    .key(active_set_key())
                    .key(active_age_key())
                    .arg(&task.id)
                    .arg(payload)
                    .arg(task.created_at),
            )
            .await?;
        let (kind, id) = response
            .split_once('|')
            .ok_or(StoreError("invalid Redis admission response"))?;
        match kind {
            "new" => Ok(Admission::New(id.to_owned())),
            "existing" => Ok(Admission::Existing(id.to_owned())),
            "conflict" => Ok(Admission::WalletConflict(id.to_owned())),
            _ => Err(StoreError("invalid Redis admission response")),
        }
    }

    pub async fn get_task(&self, id: &str) -> Result<Option<CreateTask>, StoreError> {
        let mut command = redis::cmd("GET");
        command.arg(task_key(id));
        let payload: Option<String> = self.query(command).await?;
        payload
            .map(|payload| {
                serde_json::from_str(&payload)
                    .map_err(|_| StoreError("stored create task is invalid"))
            })
            .transpose()
    }

    pub async fn find_by_record(
        &self,
        rp_id: &str,
        credential_id: &str,
    ) -> Result<Option<CreateTask>, StoreError> {
        self.find_by_index(record_active_key(rp_id, credential_id))
            .await
    }

    pub async fn find_by_wallet_ref(
        &self,
        wallet_ref: &str,
    ) -> Result<Option<CreateTask>, StoreError> {
        self.find_by_index(wallet_active_key(wallet_ref)).await
    }

    async fn find_by_index(&self, key: String) -> Result<Option<CreateTask>, StoreError> {
        let mut command = redis::cmd("GET");
        command.arg(key);
        let id: Option<String> = self.query(command).await?;
        match id {
            Some(id) => self.get_task(&id).await,
            None => Ok(None),
        }
    }

    pub async fn mark_admitted(&self, id: &str) -> Result<Option<CreateTask>, StoreError> {
        let Some(mut task) = self.get_task(id).await? else {
            return Ok(None);
        };
        task.admitted = true;
        self.write_active_task(&task).await?;
        Ok(Some(task))
    }

    pub async fn mark_committed(&self, id: &str) -> Result<Option<CreateTask>, StoreError> {
        let Some(mut task) = self.get_task(id).await? else {
            return Ok(None);
        };
        if task.status == TaskStatus::Pending {
            task.status = TaskStatus::Committed;
            task.error = None;
            self.write_active_task(&task).await?;
        }
        Ok(Some(task))
    }

    pub async fn mark_pending(
        &self,
        id: &str,
        message: Option<&str>,
    ) -> Result<Option<CreateTask>, StoreError> {
        let Some(mut task) = self.get_task(id).await? else {
            return Ok(None);
        };
        if !task.status.is_terminal() {
            task.status = TaskStatus::Pending;
            task.error = message.map(redact_error);
            self.write_active_task(&task).await?;
        }
        Ok(Some(task))
    }

    pub async fn mark_done(
        &self,
        id: &str,
        tx_hash: Option<String>,
    ) -> Result<Option<CreateTask>, StoreError> {
        let Some(mut task) = self.get_task(id).await? else {
            return Ok(None);
        };
        task.status = TaskStatus::Done;
        task.tx_hash = tx_hash.or(task.tx_hash);
        task.error = None;
        task.admitted = true;
        self.transition_done(&task).await?;
        Ok(Some(task))
    }

    pub async fn record_transient_failure(
        &self,
        id: &str,
        message: &str,
    ) -> Result<Option<CreateTask>, StoreError> {
        let Some(mut task) = self.get_task(id).await? else {
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
            self.transition_failed(&task).await?;
        } else {
            self.write_active_task(&task).await?;
        }
        Ok(Some(task))
    }

    pub async fn mark_failed(
        &self,
        id: &str,
        prefix: &str,
        message: &str,
    ) -> Result<Option<CreateTask>, StoreError> {
        let Some(mut task) = self.get_task(id).await? else {
            return Ok(None);
        };
        task.status = TaskStatus::Failed;
        task.retries = task.retries.saturating_add(1);
        task.error = Some(format!("{prefix}: {}", redact_error(message)));
        self.transition_failed(&task).await?;
        Ok(Some(task))
    }

    pub async fn queue_stats(&self) -> Result<QueueStats, StoreError> {
        let mut depth = redis::cmd("SCARD");
        depth.arg(active_set_key());
        let mut dlq = redis::cmd("SCARD");
        dlq.arg(dlq_set_key());
        let mut oldest = redis::cmd("ZRANGE");
        oldest.arg(active_age_key()).arg(0).arg(0).arg("WITHSCORES");
        let (depth, dlq_count, oldest): (u64, u64, Vec<String>) =
            tokio::try_join!(self.query(depth), self.query(dlq), self.query(oldest),)?;
        let oldest_active_age_ms = oldest
            .get(1)
            .and_then(|value| value.parse::<u64>().ok())
            .map(|created_at| now_ms().saturating_sub(created_at))
            .unwrap_or(0);
        Ok(QueueStats {
            depth,
            dlq_count,
            oldest_active_age_ms,
        })
    }

    /// Broadcast ledger for the stuck-nonce unstick sweep: record an in-flight `(role, nonce)`
    /// with the tx hash and how many times it has been replaced.
    pub async fn record_pending_tx(
        &self,
        role: &str,
        nonce: u64,
        hash: &str,
        sent_at_ms: u64,
        attempts: u32,
    ) -> Result<(), StoreError> {
        let payload = serde_json::to_string(&PendingTxEntry {
            hash: hash.to_owned(),
            sent_at_ms,
            attempts,
        })
        .map_err(|_| StoreError("could not serialize broadcast ledger entry"))?;
        let mut command = redis::cmd("HSET");
        command
            .arg(broadcast_ledger_key())
            .arg(ledger_field(role, nonce))
            .arg(payload);
        let _: i64 = self.query(command).await?;
        Ok(())
    }

    /// Remove a ledger row once its tx is known to be mined (success OR reverted).
    pub async fn delete_pending_tx(&self, role: &str, nonce: u64) -> Result<(), StoreError> {
        let mut command = redis::cmd("HDEL");
        command
            .arg(broadcast_ledger_key())
            .arg(ledger_field(role, nonce));
        let _: i64 = self.query(command).await?;
        Ok(())
    }

    /// Ledger rows first broadcast before `sent_before_ms` — the unstick sweep's candidate set.
    pub async fn list_pending_txs(
        &self,
        sent_before_ms: u64,
    ) -> Result<Vec<PendingTx>, StoreError> {
        let mut command = redis::cmd("HGETALL");
        command.arg(broadcast_ledger_key());
        let entries: std::collections::HashMap<String, String> = self.query(command).await?;
        let mut result = Vec::new();
        for (field, value) in entries {
            let Some((role, nonce)) = field.split_once(':') else {
                continue;
            };
            let Ok(nonce) = nonce.parse::<u64>() else {
                continue;
            };
            let Ok(entry) = serde_json::from_str::<PendingTxEntry>(&value) else {
                continue;
            };
            if entry.sent_at_ms < sent_before_ms {
                result.push(PendingTx {
                    role: role.to_owned(),
                    nonce,
                    hash: entry.hash,
                    sent_at_ms: entry.sent_at_ms,
                    attempts: entry.attempts,
                });
            }
        }
        Ok(result)
    }

    pub async fn allow_ip_create(&self, ip_hash: &str) -> Result<bool, StoreError> {
        let per_ip_key = format!("p256-index:rate:create:{ip_hash}");
        Ok(self.increment_minute(&per_ip_key).await? <= 5)
    }

    pub async fn allow_global_create(&self, global_limit: u64) -> Result<bool, StoreError> {
        Ok(self
            .increment_minute("p256-index:rate:create:global")
            .await?
            <= global_limit)
    }

    pub async fn allow_read(&self, ip_hash: &str) -> Result<bool, StoreError> {
        Ok(self
            .increment_minute(&format!("p256-index:rate:read:{ip_hash}"))
            .await?
            <= 120)
    }

    pub async fn cache_get(
        &self,
        key: &str,
        stale_limit: Duration,
    ) -> Result<CacheRead, StoreError> {
        let mut command = redis::cmd("GET");
        command.arg(cache_key(key));
        let payload: Option<String> = self.query(command).await?;
        let Some(payload) = payload else {
            return Ok(CacheRead::Miss);
        };
        let entry: CacheEntry = serde_json::from_str(&payload)
            .map_err(|_| StoreError("stored cache entry is invalid"))?;
        let now = now_ms();
        match entry.value {
            None if now <= entry.fresh_until_ms => Ok(CacheRead::Negative),
            None => Ok(CacheRead::Miss),
            Some(value) if now <= entry.fresh_until_ms => Ok(CacheRead::Fresh(value)),
            Some(value)
                if now.saturating_sub(entry.stored_at_ms) <= stale_limit.as_millis() as u64 =>
            {
                Ok(CacheRead::Stale {
                    value,
                    age_ms: now.saturating_sub(entry.stored_at_ms),
                })
            }
            Some(_) => Ok(CacheRead::Miss),
        }
    }

    pub async fn cache_set(&self, key: &str, value: Value, stats: bool) -> Result<(), StoreError> {
        self.write_cache(
            key,
            Some(value),
            CACHE_FRESH_TTL,
            if stats {
                CACHE_STATS_STALE_TTL
            } else {
                CACHE_RECORD_STALE_TTL
            },
        )
        .await
    }

    pub async fn cache_set_negative(&self, key: &str) -> Result<(), StoreError> {
        self.write_cache(key, None, CACHE_NEGATIVE_TTL, CACHE_NEGATIVE_TTL)
            .await
    }

    async fn write_cache(
        &self,
        key: &str,
        value: Option<Value>,
        fresh_ttl: Duration,
        retention: Duration,
    ) -> Result<(), StoreError> {
        let stored_at_ms = now_ms();
        let payload = serde_json::to_string(&CacheEntry {
            value,
            stored_at_ms,
            fresh_until_ms: stored_at_ms.saturating_add(fresh_ttl.as_millis() as u64),
        })
        .map_err(|_| StoreError("could not serialize cache entry"))?;
        let mut command = redis::cmd("SET");
        command
            .arg(cache_key(key))
            .arg(payload)
            .arg("PX")
            .arg(retention.as_millis() as u64);
        let _: String = self.query(command).await?;
        Ok(())
    }

    async fn increment_minute(&self, key: &str) -> Result<u64, StoreError> {
        let mut command = redis::cmd("INCR");
        command.arg(key);
        let count: u64 = self.query(command).await?;
        if count == 1 {
            let mut expire = redis::cmd("PEXPIRE");
            expire.arg(key).arg(60_000);
            let _: bool = self.query(expire).await?;
        }
        Ok(count)
    }

    async fn write_active_task(&self, task: &CreateTask) -> Result<(), StoreError> {
        self.set_task(task, None).await
    }

    async fn transition_done(&self, task: &CreateTask) -> Result<(), StoreError> {
        let payload = serde_json::to_string(task)
            .map_err(|_| StoreError("could not serialize create task"))?;
        let script = Script::new(
            r#"
            redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
            redis.call('SREM', KEYS[2], ARGV[3])
            redis.call('ZREM', KEYS[3], ARGV[3])
            redis.call('PEXPIRE', KEYS[4], ARGV[2])
            redis.call('PEXPIRE', KEYS[5], ARGV[2])
            return 1
        "#,
        );
        let _: i64 = self
            .run_script(
                script
                    .key(task_key(&task.id))
                    .key(active_set_key())
                    .key(active_age_key())
                    .key(record_active_key(&task.rp_id, &task.credential_id))
                    .key(wallet_active_key(&task.wallet_ref))
                    .arg(payload)
                    .arg(TASK_DONE_TTL.as_millis() as u64)
                    .arg(&task.id),
            )
            .await?;
        Ok(())
    }

    async fn transition_failed(&self, task: &CreateTask) -> Result<(), StoreError> {
        let payload = serde_json::to_string(task)
            .map_err(|_| StoreError("could not serialize create task"))?;
        let script = Script::new(
            r#"
            redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
            redis.call('SREM', KEYS[2], ARGV[3])
            redis.call('ZREM', KEYS[3], ARGV[3])
            redis.call('SADD', KEYS[4], ARGV[3])
            if redis.call('GET', KEYS[5]) == ARGV[3] then redis.call('DEL', KEYS[5]) end
            if redis.call('GET', KEYS[6]) == ARGV[3] then redis.call('DEL', KEYS[6]) end
            return 1
        "#,
        );
        let _: i64 = self
            .run_script(
                script
                    .key(task_key(&task.id))
                    .key(active_set_key())
                    .key(active_age_key())
                    .key(dlq_set_key())
                    .key(record_active_key(&task.rp_id, &task.credential_id))
                    .key(wallet_active_key(&task.wallet_ref))
                    .arg(payload)
                    .arg(TASK_FAILED_TTL.as_millis() as u64)
                    .arg(&task.id),
            )
            .await?;
        Ok(())
    }

    async fn set_task(&self, task: &CreateTask, ttl: Option<Duration>) -> Result<(), StoreError> {
        let payload = serde_json::to_string(task)
            .map_err(|_| StoreError("could not serialize create task"))?;
        let mut command = redis::cmd("SET");
        command.arg(task_key(&task.id)).arg(payload);
        if let Some(ttl) = ttl {
            command.arg("PX").arg(ttl.as_millis() as u64);
        }
        let _: String = self.query(command).await?;
        Ok(())
    }

    async fn query<T: FromRedisValue>(&self, command: redis::Cmd) -> Result<T, StoreError> {
        let mut connection = self.connection.clone();
        tokio::time::timeout(self.command_timeout, command.query_async(&mut connection))
            .await
            .map_err(|_| StoreError("Redis command timed out"))?
            .map_err(|_| StoreError("Redis command failed"))
    }

    async fn run_script<T: FromRedisValue>(
        &self,
        invocation: &mut redis::ScriptInvocation<'_>,
    ) -> Result<T, StoreError> {
        let mut connection = self.connection.clone();
        tokio::time::timeout(
            self.command_timeout,
            invocation.invoke_async(&mut connection),
        )
        .await
        .map_err(|_| StoreError("Redis command timed out"))?
        .map_err(|_| StoreError("Redis command failed"))
    }
}

pub fn hash_ip(salt: &str, ip: &str) -> String {
    hex::encode(Sha256::digest(format!("{salt}\0{ip}").as_bytes()))[..16].to_owned()
}

pub fn derive_ip_salt(secret: Option<&str>) -> String {
    hex::encode(Sha256::digest(
        format!("ip-salt\0{}", secret.unwrap_or("webauthnp256-index")).as_bytes(),
    ))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn escaped_hash(input: &str) -> String {
    hex::encode(Sha256::digest(input.as_bytes()))
}

fn task_key(id: &str) -> String {
    format!("p256-index:task:{id}")
}
fn record_active_key(rp_id: &str, credential_id: &str) -> String {
    format!(
        "p256-index:active:record:{}",
        escaped_hash(&format!("{rp_id}\0{credential_id}"))
    )
}
fn wallet_active_key(wallet_ref: &str) -> String {
    format!(
        "p256-index:active:wallet:{}",
        wallet_ref.to_ascii_lowercase()
    )
}
fn active_set_key() -> &'static str {
    "p256-index:active-tasks"
}
fn active_age_key() -> &'static str {
    "p256-index:active-created-at"
}
fn dlq_set_key() -> &'static str {
    "p256-index:dlq-tasks"
}
fn cache_key(key: &str) -> String {
    format!("p256-index:cache:{}", escaped_hash(key))
}
fn broadcast_ledger_key() -> &'static str {
    "p256-index:broadcast-ledger"
}
fn ledger_field(role: &str, nonce: u64) -> String {
    format!("{role}:{nonce}")
}

fn redact_error(value: &str) -> String {
    value.chars().take(200).collect()
}

#[cfg(test)]
mod tests {
    use std::env;

    use super::{RedisStore, derive_ip_salt, hash_ip};

    #[test]
    fn ip_hashes_are_salted_and_fixed_width() {
        let salt = derive_ip_salt(Some("not-a-real-key"));
        let first = hash_ip(&salt, "192.0.2.1");
        assert_eq!(first.len(), 16);
        assert_ne!(first, hash_ip(&salt, "192.0.2.2"));
        assert_ne!(first, hash_ip(&derive_ip_salt(Some("other")), "192.0.2.1"));
    }

    #[tokio::test]
    #[ignore = "requires P256_INDEX_TEST_REDIS_URL"]
    async fn authenticates_to_the_configured_redis_endpoint() {
        let url = env::var("P256_INDEX_TEST_REDIS_URL")
            .expect("P256_INDEX_TEST_REDIS_URL is required for this integration test");
        RedisStore::connect(&url)
            .await
            .expect("Redis ping through the configured endpoint");
    }
}
