//! The lookup domain: read-side vocabulary, the read-through cache policy,
//! and the pre-reveal disclosure rules.
//!
//! One [`LookupApp`] instance drives one query request. The five server
//! handlers (`/api/query` by record or wallet ref, `/api/stats/total`,
//! `/api/stats/sites`, `/api/stats/keys`) used to hand-expand the same
//! read-through skeleton five times; here it is one program parameterized by
//! [`LookupEndpoint`]:
//!
//! - parameter validation and pagination clamps (page ≥ 1, pageSize 1..=100
//!   default 20, descending unless `order=asc`), with the page > 10 000
//!   short-circuit that answers an empty page without touching the chain;
//! - cache read with per-kind freshness: record/wallet reads honour negative
//!   entries (falling back to in-flight tasks), stats reads treat a negative
//!   entry as a miss — exactly as the original handlers did;
//! - the uncached-read rate limit, fail-open on store errors;
//! - chain fetch, then a must-succeed cache backfill (`allow_stale` differs
//!   by kind), a negative-cache write on empty record results, and the
//!   stale-downgrade decision when the chain is unavailable;
//! - the queue fallback re-uses [`crate::admission::is_active_placeholder`]:
//!   a non-Failed in-flight task answers for a record the chain does not
//!   have yet.
//!
//! Disclosure is commit-reveal policy and lives here as pure functions:
//! [`task_status_body`] reveals the sensitive fields (credentialId,
//! walletRef, txHash) only once a task is Done; [`queue_fallback_body`] is
//! the fallback shape. Both used to be duplicated response builders in
//! `http.rs`.

use crux_core::{App, Command, command::CommandContext, macros::effect};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::admission::{is_active_placeholder, validate_strings, validate_wallet_ref};
use crate::task::{CreateTask, TaskStatus};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Record {
    pub rp_id: String,
    pub credential_id: String,
    pub wallet_ref: String,
    pub public_key: String,
    pub name: String,
    pub initial_credential_id: String,
    pub metadata: String,
    pub created_at: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteItem {
    pub rp_id: String,
    pub public_key_count: u64,
    pub created_at: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Page<T> {
    pub total: u64,
    pub page: u64,
    pub page_size: u64,
    pub items: Vec<T>,
}

// ── Disclosure (commit-reveal policy) ──────────────────────────────────────

/// The `/api/create/{id}` status body. Before a task reaches Done, the
/// commitment must stay unrevealable: credentialId, walletRef and txHash are
/// withheld and the last error is shown instead.
pub fn task_status_body(task: &CreateTask) -> Value {
    if task.status == TaskStatus::Done {
        return json!({
            "id": task.id,
            "status": task.status,
            "rpId": task.rp_id,
            "credentialId": task.credential_id,
            "walletRef": task.wallet_ref,
            "publicKey": task.public_key,
            "name": task.name,
            "txHash": task.tx_hash,
            "createdAt": task.created_at,
        });
    }
    json!({
        "id": task.id,
        "status": task.status,
        "rpId": task.rp_id,
        "publicKey": task.public_key,
        "name": task.name,
        "error": task.error,
        "createdAt": task.created_at,
    })
}

/// The queue-fallback body served when a record is not on chain yet but an
/// active task is in flight. Same pre-reveal discipline: no credentialId, no
/// walletRef, no txHash.
pub fn queue_fallback_body(task: &CreateTask) -> Value {
    json!({
        "rpId": task.rp_id,
        "publicKey": task.public_key,
        "name": task.name,
        "metadata": task.metadata,
        "createdAt": task.created_at,
        "_queue": { "id": task.id, "status": task.status },
    })
}

// ── Shell protocol ─────────────────────────────────────────────────────────

/// Which endpoint the shell routed. `Query` covers `/api/query`: the Core
/// decides between the record and wallet flows from the parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LookupEndpoint {
    Query,
    Total,
    Sites,
    Keys,
}

/// Raw query parameters, mirroring the HTTP layer's deserialized shape.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LookupParams {
    pub rp_id: Option<String>,
    pub credential_id: Option<String>,
    pub wallet_ref: Option<String>,
    pub page: Option<u64>,
    pub page_size: Option<u64>,
    pub order: Option<String>,
}

/// Logical cache keys; the shell owns the physical key strings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LookupCacheKey {
    Record {
        rp_id: String,
        credential_id: String,
    },
    Wallet {
        wallet_ref: String,
    },
    StatsTotal,
    StatsSites {
        page: u64,
        page_size: u64,
        descending: bool,
    },
    StatsKeys {
        rp_id: String,
        page: u64,
        page_size: u64,
        descending: bool,
    },
}

/// Which staleness budget the cache read runs under; the shell maps these to
/// its configured durations (24h for records, 1h for stats).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TtlClass {
    Record,
    Stats,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LookupOperation {
    ReadCache {
        key: LookupCacheKey,
        ttl: TtlClass,
    },
    /// May this client perform an uncached read?
    AllowRead,
    FetchRecord {
        rp_id: String,
        credential_id: String,
    },
    FetchRecordByWalletRef {
        wallet_ref: String,
    },
    FetchTotal,
    FetchSites {
        page: u64,
        page_size: u64,
        descending: bool,
    },
    FetchKeys {
        rp_id: String,
        page: u64,
        page_size: u64,
        descending: bool,
    },
    StoreCache {
        key: LookupCacheKey,
        value: Value,
        allow_stale: bool,
    },
    StoreNegative {
        key: LookupCacheKey,
    },
    FindTaskByRecord {
        rp_id: String,
        credential_id: String,
    },
    FindTaskByWalletRef {
        wallet_ref: String,
    },
}

impl crux_core::capability::Operation for LookupOperation {
    type Output = LookupResult;
}

// One result value exists per request at a time and lives microseconds;
// boxing the task-bearing variants would complicate the protocol for nothing.
#[expect(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LookupResult {
    CacheFresh {
        value: Value,
    },
    CacheNegative,
    CacheStale {
        value: Value,
        age_ms: u64,
    },
    CacheMiss,
    Allowed {
        allowed: bool,
    },
    /// Record-shaped fetches: found (serialized record) or definitively absent.
    Fetched {
        value: Option<Value>,
    },
    /// Stats fetches: the serialized payload.
    Data {
        value: Value,
    },
    /// The total-credentials count.
    Total {
        total: u64,
    },
    ChainReadFailed,
    TaskFound {
        task: Option<CreateTask>,
    },
    Persisted,
    StoreUnavailable,
}

#[effect]
pub enum LookupEffect {
    Work(LookupOperation),
}

// ── App ────────────────────────────────────────────────────────────────────

/// The lookup verdict; the shell renders these into the exact original
/// responses (status codes, cache headers, stale markers).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LookupOutcome {
    /// 400 with the validation message.
    Invalid { message: String },
    /// 200 with `Cache-Control: public, max-age=3600`.
    CachedOk { value: Value },
    /// 200 empty page: the page > 10 000 short-circuit.
    EmptyPage { page: u64, page_size: u64 },
    /// 429 for uncached reads over the limit.
    ReadLimited,
    /// 200 with `_stale`/`_staleAgeMs` markers and no-cache headers; the
    /// markers are already inserted into `value`.
    ServedStale { value: Value },
    /// 200 queue fallback; `body` is the disclosed shape.
    QueueFallback { body: Value },
    /// 404 "not found".
    NotFound,
    /// 503 retryable, naming the failed dependency ("redis" / "rpc").
    DependencyUnavailable { dependency: String },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LookupEvent {
    Query {
        endpoint: LookupEndpoint,
        params: LookupParams,
    },
    Settled(LookupOutcome),
}

#[derive(Default)]
pub struct LookupModel {
    outcome: Option<LookupOutcome>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LookupViewModel {
    pub outcome: Option<LookupOutcome>,
}

#[derive(Default)]
pub struct LookupApp;

impl App for LookupApp {
    type Event = LookupEvent;
    type Model = LookupModel;
    type ViewModel = LookupViewModel;
    type Effect = LookupEffect;

    fn update(
        &self,
        event: Self::Event,
        model: &mut Self::Model,
    ) -> Command<Self::Effect, Self::Event> {
        match event {
            LookupEvent::Query { endpoint, params } => Command::new(|ctx| async move {
                let outcome = match drive_lookup(&ctx, endpoint, params).await {
                    Ok(outcome) | Err(outcome) => outcome,
                };
                ctx.send_event(LookupEvent::Settled(outcome));
            }),
            LookupEvent::Settled(outcome) => {
                model.outcome = Some(outcome);
                Command::done()
            }
        }
    }

    fn view(&self, model: &Self::Model) -> Self::ViewModel {
        LookupViewModel {
            outcome: model.outcome.clone(),
        }
    }
}

// ── The lookup program ─────────────────────────────────────────────────────

type Ctx = CommandContext<LookupEffect, LookupEvent>;
type Flow<T> = Result<T, LookupOutcome>;

fn dependency(name: &str) -> LookupOutcome {
    LookupOutcome::DependencyUnavailable {
        dependency: name.to_owned(),
    }
}

fn invalid(message: impl Into<String>) -> LookupOutcome {
    LookupOutcome::Invalid {
        message: message.into(),
    }
}

async fn request(ctx: &Ctx, operation: LookupOperation) -> LookupResult {
    ctx.request_from_shell(operation).await
}

/// Pagination clamps, unchanged: page at least 1, pageSize 1..=100 with a
/// default of 20, descending unless `order=asc`.
pub fn pagination(params: &LookupParams) -> (u64, u64, bool) {
    let page = params.page.unwrap_or(1).max(1);
    let page_size = params.page_size.unwrap_or(20).clamp(1, 100);
    let descending = params.order.as_deref() != Some("asc");
    (page, page_size, descending)
}

async fn drive_lookup(
    ctx: &Ctx,
    endpoint: LookupEndpoint,
    params: LookupParams,
) -> Flow<LookupOutcome> {
    match endpoint {
        LookupEndpoint::Query => query_flow(ctx, params).await,
        LookupEndpoint::Total => {
            stats_flow(ctx, LookupCacheKey::StatsTotal, StatsFetch::Total).await
        }
        LookupEndpoint::Sites => {
            let (page, page_size, descending) = pagination(&params);
            if page > 10_000 {
                return Ok(LookupOutcome::EmptyPage { page, page_size });
            }
            stats_flow(
                ctx,
                LookupCacheKey::StatsSites {
                    page,
                    page_size,
                    descending,
                },
                StatsFetch::Sites {
                    page,
                    page_size,
                    descending,
                },
            )
            .await
        }
        LookupEndpoint::Keys => {
            let (page, page_size, descending) = pagination(&params);
            let Some(rp_id) = params.rp_id else {
                return Ok(invalid("rpId is required"));
            };
            if let Err(message) = validate_strings(&[("rpId", &rp_id, 253)]) {
                return Ok(invalid(message));
            }
            if page > 10_000 {
                return Ok(LookupOutcome::EmptyPage { page, page_size });
            }
            stats_flow(
                ctx,
                LookupCacheKey::StatsKeys {
                    rp_id: rp_id.clone(),
                    page,
                    page_size,
                    descending,
                },
                StatsFetch::Keys {
                    rp_id,
                    page,
                    page_size,
                    descending,
                },
            )
            .await
        }
    }
}

/// `/api/query`: by wallet ref when supplied, else by (rpId, credentialId).
async fn query_flow(ctx: &Ctx, params: LookupParams) -> Flow<LookupOutcome> {
    if let Some(wallet_ref) = params.wallet_ref {
        return wallet_flow(ctx, wallet_ref).await;
    }
    let (Some(rp_id), Some(credential_id)) = (params.rp_id, params.credential_id) else {
        return Ok(invalid("rpId and credentialId are required (or walletRef)"));
    };
    if let Err(message) = validate_strings(&[
        ("rpId", &rp_id, 253),
        ("credentialId", &credential_id, 1024),
    ]) {
        return Ok(invalid(message));
    }
    record_flow(
        ctx,
        LookupCacheKey::Record {
            rp_id: rp_id.clone(),
            credential_id: credential_id.clone(),
        },
        RecordFetch::ByRecord {
            rp_id,
            credential_id,
        },
    )
    .await
}

async fn wallet_flow(ctx: &Ctx, wallet_ref: String) -> Flow<LookupOutcome> {
    if !wallet_ref.starts_with("0x") || wallet_ref.len() != 66 {
        return Ok(invalid(
            "walletRef must be a 0x-prefixed 32-byte hex string",
        ));
    }
    if let Err(message) = validate_wallet_ref(&wallet_ref) {
        return Ok(invalid(message));
    }
    let wallet_ref = wallet_ref.to_ascii_lowercase();
    record_flow(
        ctx,
        LookupCacheKey::Wallet {
            wallet_ref: wallet_ref.clone(),
        },
        RecordFetch::ByWalletRef { wallet_ref },
    )
    .await
}

enum RecordFetch {
    ByRecord {
        rp_id: String,
        credential_id: String,
    },
    ByWalletRef {
        wallet_ref: String,
    },
}

impl RecordFetch {
    fn fetch_operation(&self) -> LookupOperation {
        match self {
            Self::ByRecord {
                rp_id,
                credential_id,
            } => LookupOperation::FetchRecord {
                rp_id: rp_id.clone(),
                credential_id: credential_id.clone(),
            },
            Self::ByWalletRef { wallet_ref } => LookupOperation::FetchRecordByWalletRef {
                wallet_ref: wallet_ref.clone(),
            },
        }
    }

    fn find_task_operation(&self) -> LookupOperation {
        match self {
            Self::ByRecord {
                rp_id,
                credential_id,
            } => LookupOperation::FindTaskByRecord {
                rp_id: rp_id.clone(),
                credential_id: credential_id.clone(),
            },
            Self::ByWalletRef { wallet_ref } => LookupOperation::FindTaskByWalletRef {
                wallet_ref: wallet_ref.clone(),
            },
        }
    }
}

/// The record/wallet read-through: negative entries answer via the queue
/// fallback; a chain hit backfills the cache (never stale-tolerant); a chain
/// miss writes a negative entry then falls back; a chain failure downgrades
/// to stale data when available.
async fn record_flow(ctx: &Ctx, key: LookupCacheKey, fetch: RecordFetch) -> Flow<LookupOutcome> {
    let stale = match request(
        ctx,
        LookupOperation::ReadCache {
            key: key.clone(),
            ttl: TtlClass::Record,
        },
    )
    .await
    {
        LookupResult::CacheFresh { value } => return Ok(LookupOutcome::CachedOk { value }),
        LookupResult::CacheNegative => return queue_fallback(ctx, &fetch).await,
        LookupResult::CacheStale { value, age_ms } => Some((value, age_ms)),
        LookupResult::CacheMiss => None,
        LookupResult::StoreUnavailable => return Err(dependency("redis")),
        _ => return Err(dependency("redis")),
    };

    allow_read(ctx).await?;

    match request(ctx, fetch.fetch_operation()).await {
        LookupResult::Fetched { value: Some(value) } => {
            match request(
                ctx,
                LookupOperation::StoreCache {
                    key,
                    value: value.clone(),
                    allow_stale: false,
                },
            )
            .await
            {
                LookupResult::Persisted => Ok(LookupOutcome::CachedOk { value }),
                _ => Err(dependency("redis")),
            }
        }
        LookupResult::Fetched { value: None } => {
            match request(ctx, LookupOperation::StoreNegative { key }).await {
                LookupResult::Persisted => queue_fallback(ctx, &fetch).await,
                _ => Err(dependency("redis")),
            }
        }
        LookupResult::ChainReadFailed => Ok(serve_stale_or(stale, "rpc")),
        _ => Err(dependency("rpc")),
    }
}

enum StatsFetch {
    Total,
    Sites {
        page: u64,
        page_size: u64,
        descending: bool,
    },
    Keys {
        rp_id: String,
        page: u64,
        page_size: u64,
        descending: bool,
    },
}

/// The stats read-through: negative entries are treated as misses (the
/// original handlers never checked for them), and cache backfills are
/// stale-tolerant.
async fn stats_flow(ctx: &Ctx, key: LookupCacheKey, fetch: StatsFetch) -> Flow<LookupOutcome> {
    let stale = match request(
        ctx,
        LookupOperation::ReadCache {
            key: key.clone(),
            ttl: TtlClass::Stats,
        },
    )
    .await
    {
        LookupResult::CacheFresh { value } => return Ok(LookupOutcome::CachedOk { value }),
        LookupResult::CacheStale { value, age_ms } => Some((value, age_ms)),
        LookupResult::CacheNegative | LookupResult::CacheMiss => None,
        _ => return Err(dependency("redis")),
    };

    allow_read(ctx).await?;

    let fetched = match fetch {
        StatsFetch::Total => match request(ctx, LookupOperation::FetchTotal).await {
            LookupResult::Total { total } => Ok(json!({ "totalCredentials": total })),
            LookupResult::ChainReadFailed => Err(()),
            _ => return Err(dependency("rpc")),
        },
        StatsFetch::Sites {
            page,
            page_size,
            descending,
        } => match request(
            ctx,
            LookupOperation::FetchSites {
                page,
                page_size,
                descending,
            },
        )
        .await
        {
            LookupResult::Data { value } => Ok(value),
            LookupResult::ChainReadFailed => Err(()),
            _ => return Err(dependency("rpc")),
        },
        StatsFetch::Keys {
            rp_id,
            page,
            page_size,
            descending,
        } => match request(
            ctx,
            LookupOperation::FetchKeys {
                rp_id,
                page,
                page_size,
                descending,
            },
        )
        .await
        {
            LookupResult::Data { value } => Ok(value),
            LookupResult::ChainReadFailed => Err(()),
            _ => return Err(dependency("rpc")),
        },
    };
    match fetched {
        Ok(value) => {
            match request(
                ctx,
                LookupOperation::StoreCache {
                    key,
                    value: value.clone(),
                    allow_stale: true,
                },
            )
            .await
            {
                LookupResult::Persisted => Ok(LookupOutcome::CachedOk { value }),
                _ => Err(dependency("redis")),
            }
        }
        Err(()) => Ok(serve_stale_or(stale, "rpc")),
    }
}

/// The uncached-read rate limit. Fail-open: a store failure counts as
/// allowed, exactly like the original `unwrap_or(true)`.
async fn allow_read(ctx: &Ctx) -> Flow<()> {
    match request(ctx, LookupOperation::AllowRead).await {
        LookupResult::Allowed { allowed: false } => Err(LookupOutcome::ReadLimited),
        _ => Ok(()),
    }
}

/// The in-flight-task fallback shared by the negative-cache and chain-miss
/// paths: an active placeholder answers with the disclosed queue shape.
async fn queue_fallback(ctx: &Ctx, fetch: &RecordFetch) -> Flow<LookupOutcome> {
    match request(ctx, fetch.find_task_operation()).await {
        LookupResult::TaskFound { task: Some(task) } if is_active_placeholder(&task) => {
            Ok(LookupOutcome::QueueFallback {
                body: queue_fallback_body(&task),
            })
        }
        LookupResult::TaskFound { .. } => Ok(LookupOutcome::NotFound),
        _ => Err(dependency("redis")),
    }
}

/// Serve stale data with the `_stale` markers inserted, or report the failed
/// dependency when nothing stale is available.
fn serve_stale_or(stale: Option<(Value, u64)>, dependency_name: &str) -> LookupOutcome {
    match stale {
        Some((mut value, age_ms)) => {
            if let Some(object) = value.as_object_mut() {
                object.insert("_stale".into(), Value::Bool(true));
                object.insert("_staleAgeMs".into(), json!(age_ms));
            }
            LookupOutcome::ServedStale { value }
        }
        None => dependency(dependency_name),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use crux_core::{Core, Request};

    use super::*;

    // ── Test driver (same shape as the other apps') ────────────────────────

    struct Driver {
        core: Core<LookupApp>,
        queue: VecDeque<Request<LookupOperation>>,
    }

    impl Driver {
        fn query(endpoint: LookupEndpoint, params: LookupParams) -> Self {
            let core = Core::new();
            let effects = core.process_event(LookupEvent::Query { endpoint, params });
            let mut driver = Self {
                core,
                queue: VecDeque::new(),
            };
            driver.absorb(effects);
            driver
        }

        fn absorb(&mut self, effects: Vec<LookupEffect>) {
            for effect in effects {
                let LookupEffect::Work(request) = effect;
                self.queue.push_back(request);
            }
            assert!(
                self.queue.len() <= 1,
                "the lookup program must be strictly sequential"
            );
        }

        fn step(&mut self, expected: LookupOperation, result: LookupResult) {
            let mut request = self
                .queue
                .pop_front()
                .unwrap_or_else(|| panic!("no operation in flight; expected {expected:?}"));
            assert_eq!(request.operation, expected);
            let effects = self
                .core
                .resolve(&mut request, result)
                .expect("resolve must succeed");
            self.absorb(effects);
        }

        fn assert_settled(&self, expected: LookupOutcome) {
            assert!(self.queue.is_empty(), "no operation may remain in flight");
            assert_eq!(self.core.view().outcome, Some(expected));
        }
    }

    fn record_params() -> LookupParams {
        LookupParams {
            rp_id: Some("example.com".into()),
            credential_id: Some("cred-1".into()),
            ..LookupParams::default()
        }
    }

    const WALLET: &str = "0x000000000000000000000000d602f36e97fa37801565e3dc02f78ee0769d8fd6";

    fn record_key() -> LookupCacheKey {
        LookupCacheKey::Record {
            rp_id: "example.com".into(),
            credential_id: "cred-1".into(),
        }
    }

    fn read_record_cache() -> LookupOperation {
        LookupOperation::ReadCache {
            key: record_key(),
            ttl: TtlClass::Record,
        }
    }

    fn value() -> Value {
        json!({ "rpId": "example.com", "credentialId": "cred-1" })
    }

    fn task(status: TaskStatus) -> CreateTask {
        CreateTask {
            id: "t1".into(),
            status,
            rp_id: "example.com".into(),
            credential_id: "cred-1".into(),
            wallet_ref: WALLET.into(),
            public_key: "04ab".into(),
            name: "n".into(),
            initial_credential_id: "cred-1".into(),
            metadata: "0x00".into(),
            tx_hash: Some("0xdeadbeef".into()),
            error: Some("last error".into()),
            retries: 2,
            created_at: 7,
            admitted: true,
        }
    }

    // ── Disclosure ─────────────────────────────────────────────────────────

    #[test]
    fn done_task_status_reveals_everything() {
        let body = task_status_body(&task(TaskStatus::Done));
        assert_eq!(
            body,
            json!({
                "id": "t1",
                "status": "done",
                "rpId": "example.com",
                "credentialId": "cred-1",
                "walletRef": WALLET,
                "publicKey": "04ab",
                "name": "n",
                "txHash": "0xdeadbeef",
                "createdAt": 7,
            })
        );
    }

    #[test]
    fn pre_done_task_status_withholds_the_revealable_fields() {
        for status in [
            TaskStatus::Pending,
            TaskStatus::Committed,
            TaskStatus::Failed,
        ] {
            let body = task_status_body(&task(status.clone()));
            assert!(body.get("credentialId").is_none());
            assert!(body.get("walletRef").is_none());
            assert!(body.get("txHash").is_none());
            assert_eq!(body["error"], json!("last error"));
            assert_eq!(body["id"], json!("t1"));
        }
    }

    #[test]
    fn queue_fallback_body_is_the_disclosed_shape() {
        let body = queue_fallback_body(&task(TaskStatus::Pending));
        assert_eq!(
            body,
            json!({
                "rpId": "example.com",
                "publicKey": "04ab",
                "name": "n",
                "metadata": "0x00",
                "createdAt": 7,
                "_queue": { "id": "t1", "status": "pending" },
            })
        );
    }

    // ── Validation and clamps ──────────────────────────────────────────────

    #[test]
    fn pagination_clamps_to_the_published_contract() {
        let params = LookupParams {
            page: Some(0),
            page_size: Some(101),
            order: Some("asc".into()),
            ..LookupParams::default()
        };
        assert_eq!(pagination(&params), (1, 100, false));
        assert_eq!(pagination(&LookupParams::default()), (1, 20, true));
        let tiny = LookupParams {
            page_size: Some(0),
            ..LookupParams::default()
        };
        assert_eq!(pagination(&tiny), (1, 1, true));
    }

    #[test]
    fn query_without_identifiers_is_invalid() {
        let driver = Driver::query(LookupEndpoint::Query, LookupParams::default());
        driver.assert_settled(LookupOutcome::Invalid {
            message: "rpId and credentialId are required (or walletRef)".into(),
        });
    }

    #[test]
    fn malformed_wallet_ref_is_invalid() {
        let driver = Driver::query(
            LookupEndpoint::Query,
            LookupParams {
                wallet_ref: Some("d602f36e".into()),
                ..LookupParams::default()
            },
        );
        driver.assert_settled(LookupOutcome::Invalid {
            message: "walletRef must be a 0x-prefixed 32-byte hex string".into(),
        });
    }

    #[test]
    fn keys_without_rp_id_is_invalid() {
        let driver = Driver::query(LookupEndpoint::Keys, LookupParams::default());
        driver.assert_settled(LookupOutcome::Invalid {
            message: "rpId is required".into(),
        });
    }

    #[test]
    fn deep_pages_short_circuit_without_any_io() {
        for endpoint in [LookupEndpoint::Sites, LookupEndpoint::Keys] {
            let driver = Driver::query(
                endpoint,
                LookupParams {
                    rp_id: Some("example.com".into()),
                    page: Some(10_001),
                    ..LookupParams::default()
                },
            );
            driver.assert_settled(LookupOutcome::EmptyPage {
                page: 10_001,
                page_size: 20,
            });
        }
    }

    #[test]
    fn keys_validation_fires_before_the_short_circuit() {
        // rpId is validated before the page > 10 000 short-circuit, exactly
        // like the original handler ordering.
        let driver = Driver::query(
            LookupEndpoint::Keys,
            LookupParams {
                page: Some(10_001),
                ..LookupParams::default()
            },
        );
        driver.assert_settled(LookupOutcome::Invalid {
            message: "rpId is required".into(),
        });
    }

    // ── Record read-through ────────────────────────────────────────────────

    #[test]
    fn fresh_cache_answers_without_rate_limiting() {
        let mut driver = Driver::query(LookupEndpoint::Query, record_params());
        driver.step(
            read_record_cache(),
            LookupResult::CacheFresh { value: value() },
        );
        driver.assert_settled(LookupOutcome::CachedOk { value: value() });
    }

    #[test]
    fn negative_cache_falls_back_to_an_active_task() {
        let mut driver = Driver::query(LookupEndpoint::Query, record_params());
        driver.step(read_record_cache(), LookupResult::CacheNegative);
        driver.step(
            LookupOperation::FindTaskByRecord {
                rp_id: "example.com".into(),
                credential_id: "cred-1".into(),
            },
            LookupResult::TaskFound {
                task: Some(task(TaskStatus::Pending)),
            },
        );
        // Literal expectation, deliberately NOT derived from
        // queue_fallback_body: the integration path must fail on its own if
        // the disclosed shape ever leaks credentialId/walletRef/txHash.
        driver.assert_settled(LookupOutcome::QueueFallback {
            body: json!({
                "rpId": "example.com",
                "publicKey": "04ab",
                "name": "n",
                "metadata": "0x00",
                "createdAt": 7,
                "_queue": { "id": "t1", "status": "pending" },
            }),
        });
    }

    #[test]
    fn negative_cache_with_failed_task_is_not_found() {
        let mut driver = Driver::query(LookupEndpoint::Query, record_params());
        driver.step(read_record_cache(), LookupResult::CacheNegative);
        driver.step(
            LookupOperation::FindTaskByRecord {
                rp_id: "example.com".into(),
                credential_id: "cred-1".into(),
            },
            LookupResult::TaskFound {
                task: Some(task(TaskStatus::Failed)),
            },
        );
        driver.assert_settled(LookupOutcome::NotFound);
    }

    #[test]
    fn chain_hit_backfills_without_stale_tolerance_then_answers() {
        let mut driver = Driver::query(LookupEndpoint::Query, record_params());
        driver.step(read_record_cache(), LookupResult::CacheMiss);
        driver.step(
            LookupOperation::AllowRead,
            LookupResult::Allowed { allowed: true },
        );
        driver.step(
            LookupOperation::FetchRecord {
                rp_id: "example.com".into(),
                credential_id: "cred-1".into(),
            },
            LookupResult::Fetched {
                value: Some(value()),
            },
        );
        driver.step(
            LookupOperation::StoreCache {
                key: record_key(),
                value: value(),
                allow_stale: false,
            },
            LookupResult::Persisted,
        );
        driver.assert_settled(LookupOutcome::CachedOk { value: value() });
    }

    #[test]
    fn chain_miss_writes_negative_then_falls_back() {
        let mut driver = Driver::query(LookupEndpoint::Query, record_params());
        driver.step(read_record_cache(), LookupResult::CacheMiss);
        driver.step(
            LookupOperation::AllowRead,
            LookupResult::Allowed { allowed: true },
        );
        driver.step(
            LookupOperation::FetchRecord {
                rp_id: "example.com".into(),
                credential_id: "cred-1".into(),
            },
            LookupResult::Fetched { value: None },
        );
        driver.step(
            LookupOperation::StoreNegative { key: record_key() },
            LookupResult::Persisted,
        );
        driver.step(
            LookupOperation::FindTaskByRecord {
                rp_id: "example.com".into(),
                credential_id: "cred-1".into(),
            },
            LookupResult::TaskFound { task: None },
        );
        driver.assert_settled(LookupOutcome::NotFound);
    }

    #[test]
    fn chain_failure_serves_stale_with_markers() {
        let mut driver = Driver::query(LookupEndpoint::Query, record_params());
        driver.step(
            read_record_cache(),
            LookupResult::CacheStale {
                value: value(),
                age_ms: 5_000,
            },
        );
        driver.step(
            LookupOperation::AllowRead,
            LookupResult::Allowed { allowed: true },
        );
        driver.step(
            LookupOperation::FetchRecord {
                rp_id: "example.com".into(),
                credential_id: "cred-1".into(),
            },
            LookupResult::ChainReadFailed,
        );
        let mut expected = value();
        expected["_stale"] = json!(true);
        expected["_staleAgeMs"] = json!(5_000);
        driver.assert_settled(LookupOutcome::ServedStale { value: expected });
    }

    #[test]
    fn chain_failure_without_stale_names_the_rpc_dependency() {
        let mut driver = Driver::query(LookupEndpoint::Query, record_params());
        driver.step(read_record_cache(), LookupResult::CacheMiss);
        driver.step(
            LookupOperation::AllowRead,
            LookupResult::Allowed { allowed: true },
        );
        driver.step(
            LookupOperation::FetchRecord {
                rp_id: "example.com".into(),
                credential_id: "cred-1".into(),
            },
            LookupResult::ChainReadFailed,
        );
        driver.assert_settled(LookupOutcome::DependencyUnavailable {
            dependency: "rpc".into(),
        });
    }

    #[test]
    fn read_limit_rejects_uncached_reads() {
        let mut driver = Driver::query(LookupEndpoint::Query, record_params());
        driver.step(read_record_cache(), LookupResult::CacheMiss);
        driver.step(
            LookupOperation::AllowRead,
            LookupResult::Allowed { allowed: false },
        );
        driver.assert_settled(LookupOutcome::ReadLimited);
    }

    #[test]
    fn read_limit_fails_open_on_store_errors() {
        let mut driver = Driver::query(LookupEndpoint::Query, record_params());
        driver.step(read_record_cache(), LookupResult::CacheMiss);
        driver.step(LookupOperation::AllowRead, LookupResult::StoreUnavailable);
        // The flow continues to the chain fetch: fail-open.
        driver.step(
            LookupOperation::FetchRecord {
                rp_id: "example.com".into(),
                credential_id: "cred-1".into(),
            },
            LookupResult::ChainReadFailed,
        );
        driver.assert_settled(LookupOutcome::DependencyUnavailable {
            dependency: "rpc".into(),
        });
    }

    // ── Wallet flow ────────────────────────────────────────────────────────

    #[test]
    fn wallet_query_lowercases_before_keying_and_fetching() {
        let uppercase = WALLET.to_uppercase().replace("0X", "0x");
        let mut driver = Driver::query(
            LookupEndpoint::Query,
            LookupParams {
                wallet_ref: Some(uppercase),
                ..LookupParams::default()
            },
        );
        driver.step(
            LookupOperation::ReadCache {
                key: LookupCacheKey::Wallet {
                    wallet_ref: WALLET.into(),
                },
                ttl: TtlClass::Record,
            },
            LookupResult::CacheMiss,
        );
        driver.step(
            LookupOperation::AllowRead,
            LookupResult::Allowed { allowed: true },
        );
        driver.step(
            LookupOperation::FetchRecordByWalletRef {
                wallet_ref: WALLET.into(),
            },
            LookupResult::Fetched { value: None },
        );
        driver.step(
            LookupOperation::StoreNegative {
                key: LookupCacheKey::Wallet {
                    wallet_ref: WALLET.into(),
                },
            },
            LookupResult::Persisted,
        );
        driver.step(
            LookupOperation::FindTaskByWalletRef {
                wallet_ref: WALLET.into(),
            },
            LookupResult::TaskFound { task: None },
        );
        driver.assert_settled(LookupOutcome::NotFound);
    }

    // ── Stats flows ────────────────────────────────────────────────────────

    #[test]
    fn total_builds_the_payload_and_backfills_stale_tolerant() {
        let mut driver = Driver::query(LookupEndpoint::Total, LookupParams::default());
        driver.step(
            LookupOperation::ReadCache {
                key: LookupCacheKey::StatsTotal,
                ttl: TtlClass::Stats,
            },
            LookupResult::CacheMiss,
        );
        driver.step(
            LookupOperation::AllowRead,
            LookupResult::Allowed { allowed: true },
        );
        driver.step(
            LookupOperation::FetchTotal,
            LookupResult::Total { total: 42 },
        );
        driver.step(
            LookupOperation::StoreCache {
                key: LookupCacheKey::StatsTotal,
                value: json!({ "totalCredentials": 42 }),
                allow_stale: true,
            },
            LookupResult::Persisted,
        );
        driver.assert_settled(LookupOutcome::CachedOk {
            value: json!({ "totalCredentials": 42 }),
        });
    }

    #[test]
    fn stats_treat_a_negative_entry_as_a_miss() {
        // The original stats handlers never checked for negative entries; a
        // stray one must not 404 the stats read.
        let mut driver = Driver::query(LookupEndpoint::Total, LookupParams::default());
        driver.step(
            LookupOperation::ReadCache {
                key: LookupCacheKey::StatsTotal,
                ttl: TtlClass::Stats,
            },
            LookupResult::CacheNegative,
        );
        driver.step(
            LookupOperation::AllowRead,
            LookupResult::Allowed { allowed: true },
        );
        driver.step(LookupOperation::FetchTotal, LookupResult::ChainReadFailed);
        driver.assert_settled(LookupOutcome::DependencyUnavailable {
            dependency: "rpc".into(),
        });
    }

    #[test]
    fn sites_flow_pins_pagination_into_key_and_fetch() {
        let mut driver = Driver::query(
            LookupEndpoint::Sites,
            LookupParams {
                page: Some(2),
                page_size: Some(50),
                order: Some("asc".into()),
                ..LookupParams::default()
            },
        );
        driver.step(
            LookupOperation::ReadCache {
                key: LookupCacheKey::StatsSites {
                    page: 2,
                    page_size: 50,
                    descending: false,
                },
                ttl: TtlClass::Stats,
            },
            LookupResult::CacheMiss,
        );
        driver.step(
            LookupOperation::AllowRead,
            LookupResult::Allowed { allowed: true },
        );
        driver.step(
            LookupOperation::FetchSites {
                page: 2,
                page_size: 50,
                descending: false,
            },
            LookupResult::Data {
                value: json!({ "total": 1 }),
            },
        );
        driver.step(
            LookupOperation::StoreCache {
                key: LookupCacheKey::StatsSites {
                    page: 2,
                    page_size: 50,
                    descending: false,
                },
                value: json!({ "total": 1 }),
                allow_stale: true,
            },
            LookupResult::Persisted,
        );
        driver.assert_settled(LookupOutcome::CachedOk {
            value: json!({ "total": 1 }),
        });
    }

    #[test]
    fn keys_flow_carries_rp_id_through_key_and_fetch() {
        let mut driver = Driver::query(
            LookupEndpoint::Keys,
            LookupParams {
                rp_id: Some("example.com".into()),
                ..LookupParams::default()
            },
        );
        driver.step(
            LookupOperation::ReadCache {
                key: LookupCacheKey::StatsKeys {
                    rp_id: "example.com".into(),
                    page: 1,
                    page_size: 20,
                    descending: true,
                },
                ttl: TtlClass::Stats,
            },
            LookupResult::CacheStale {
                value: json!({ "total": 9 }),
                age_ms: 1_000,
            },
        );
        driver.step(
            LookupOperation::AllowRead,
            LookupResult::Allowed { allowed: true },
        );
        driver.step(
            LookupOperation::FetchKeys {
                rp_id: "example.com".into(),
                page: 1,
                page_size: 20,
                descending: true,
            },
            LookupResult::ChainReadFailed,
        );
        driver.assert_settled(LookupOutcome::ServedStale {
            value: json!({ "total": 9, "_stale": true, "_staleAgeMs": 1_000 }),
        });
    }

    #[test]
    fn stats_cache_write_failure_is_a_redis_dependency_error() {
        let mut driver = Driver::query(LookupEndpoint::Total, LookupParams::default());
        driver.step(
            LookupOperation::ReadCache {
                key: LookupCacheKey::StatsTotal,
                ttl: TtlClass::Stats,
            },
            LookupResult::CacheMiss,
        );
        driver.step(
            LookupOperation::AllowRead,
            LookupResult::Allowed { allowed: true },
        );
        driver.step(
            LookupOperation::FetchTotal,
            LookupResult::Total { total: 1 },
        );
        driver.step(
            LookupOperation::StoreCache {
                key: LookupCacheKey::StatsTotal,
                value: json!({ "totalCredentials": 1 }),
                allow_stale: true,
            },
            LookupResult::StoreUnavailable,
        );
        driver.assert_settled(LookupOutcome::DependencyUnavailable {
            dependency: "redis".into(),
        });
    }

    // ── Mutation-killing coverage ──────────────────────────────────────────

    #[test]
    fn record_cache_backfill_failure_is_a_redis_dependency_error() {
        // The record-side mirror of the stats test: the post-fetch backfill
        // is must-succeed, never best-effort.
        let mut driver = Driver::query(LookupEndpoint::Query, record_params());
        driver.step(read_record_cache(), LookupResult::CacheMiss);
        driver.step(
            LookupOperation::AllowRead,
            LookupResult::Allowed { allowed: true },
        );
        driver.step(
            LookupOperation::FetchRecord {
                rp_id: "example.com".into(),
                credential_id: "cred-1".into(),
            },
            LookupResult::Fetched {
                value: Some(value()),
            },
        );
        driver.step(
            LookupOperation::StoreCache {
                key: record_key(),
                value: value(),
                allow_stale: false,
            },
            LookupResult::StoreUnavailable,
        );
        driver.assert_settled(LookupOutcome::DependencyUnavailable {
            dependency: "redis".into(),
        });
    }

    #[test]
    fn negative_cache_write_failure_is_a_redis_dependency_error() {
        let mut driver = Driver::query(LookupEndpoint::Query, record_params());
        driver.step(read_record_cache(), LookupResult::CacheMiss);
        driver.step(
            LookupOperation::AllowRead,
            LookupResult::Allowed { allowed: true },
        );
        driver.step(
            LookupOperation::FetchRecord {
                rp_id: "example.com".into(),
                credential_id: "cred-1".into(),
            },
            LookupResult::Fetched { value: None },
        );
        driver.step(
            LookupOperation::StoreNegative { key: record_key() },
            LookupResult::StoreUnavailable,
        );
        driver.assert_settled(LookupOutcome::DependencyUnavailable {
            dependency: "redis".into(),
        });
    }

    #[test]
    fn page_exactly_ten_thousand_reads_through_normally() {
        // The short-circuit is strictly greater-than: page 10 000 itself
        // still hits the cache and chain.
        let mut driver = Driver::query(
            LookupEndpoint::Sites,
            LookupParams {
                page: Some(10_000),
                ..LookupParams::default()
            },
        );
        driver.step(
            LookupOperation::ReadCache {
                key: LookupCacheKey::StatsSites {
                    page: 10_000,
                    page_size: 20,
                    descending: true,
                },
                ttl: TtlClass::Stats,
            },
            LookupResult::CacheFresh {
                value: json!({ "total": 0 }),
            },
        );
        driver.assert_settled(LookupOutcome::CachedOk {
            value: json!({ "total": 0 }),
        });
    }
}
