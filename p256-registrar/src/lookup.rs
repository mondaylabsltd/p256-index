//! Read-side vocabulary and cache policy: the decision half of every query
//! endpoint.
//!
//! One [`LookupApp`] instance drives one HTTP query to a [`LookupOutcome`].
//! The rules:
//!
//! - read-through cache per rendered response page: fresh hit → serve, no
//!   RPC; miss → rate-limited chain fetch → backfill;
//! - stale grace: when the chain read fails and a stale copy exists within
//!   its TTL class (records 24h, stats 1h — durations owned by the shell),
//!   serve it marked `_stale`;
//! - a key with no on-chain entries but an in-flight task answers with a
//!   `_queue` marker instead of an empty page, so "submitted to p256-index"
//!   is always visible before it lands on-chain ("没上链前先查 p256-index");
//!   group-by-key gets the same guarantee via the group-key placeholder;
//! - entry-by-id and unit-by-id misses are negative-cached briefly to
//!   absorb hot 404s (immutable-id lookups only — never key lookups).
//!
//! The shell owns key naming, TTL values, Redis and RPC execution.

use crux_core::{App, Command, command::CommandContext, macros::effect};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::task::{RegisterTask, TaskStatus};

/// One passkey's global file, as served to clients.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub entry_id: u64,
    pub public_key: String,
    pub attestation: String,
    /// The WebAuthn credential id (hex), stored on the entry.
    pub credential_id: String,
    /// Browser-reported display hints (UTF-8 tokens), stored on the entry:
    /// authenticatorAttachment ("platform" / "cross-platform") and the
    /// transports list (e.g. "hybrid,internal").
    pub authenticator_attachment: String,
    pub transports: String,
    pub created_at: u64,
}

/// One group's frozen record, as served to clients.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Unit {
    pub unit_id: u64,
    pub rp_id: String,
    pub metadata: String,
    pub group_public_key: String,
    pub content_hash: String,
    pub member_count: u32,
    pub created_at: u64,
}

/// One reference row, as served to clients.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReferenceRecord {
    pub reference_id: u64,
    pub entry_id: u64,
    pub unit_id: u64,
    pub metadata: String,
    pub created_at: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteItem {
    pub rp_id: String,
    pub entry_count: u64,
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

/// "A non-Failed in-flight task is a valid placeholder."
pub fn is_active_placeholder(task: &RegisterTask) -> bool {
    task.status != TaskStatus::Failed
}

// ── Response bodies ────────────────────────────────────────────────────────

/// The `/api/task/{id}` status body. With no commit-reveal there is nothing
/// to redact: the full unit (minus the bulky proofs) is disclosed.
pub fn task_status_body(task: &RegisterTask) -> Value {
    json!({
        "id": task.id,
        "status": task.status,
        "kind": task.kind,
        "rpId": task.rp_id,
        "metadata": task.metadata,
        "contentHash": task.content_hash,
        "groupPublicKey": task.group_public_key,
        "members": task.members.iter().map(|member| json!({
            "publicKey": member.public_key,
            "attestation": member.attestation,
            "credentialId": member.credential_id,
            "authenticatorAttachment": member.authenticator_attachment,
            "transports": member.transports,
        })).collect::<Vec<_>>(),
        "txHash": task.tx_hash,
        "onChainId": task.on_chain_id,
        "error": task.error,
        "createdAt": task.created_at,
    })
}

/// Served for a key with no on-chain entries but an in-flight task: the
/// pre-chain visibility guarantee.
pub fn queue_pending_body(task: &RegisterTask, public_key: &str) -> Value {
    json!({
        "total": 0,
        "items": [],
        "_queue": { "id": task.id, "status": task.status, "publicKey": public_key },
    })
}

// ── Shell protocol ─────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LookupParams {
    pub public_key: Option<String>,
    pub entry_id: Option<String>,
    pub unit_id: Option<String>,
    pub group_public_key: Option<String>,
    pub page: Option<u64>,
    pub page_size: Option<u64>,
    pub order: Option<String>,
}

/// Which endpoint the shell routed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LookupEndpoint {
    /// `/api/query` — by publicKey (paged), by entryId, by unitId, or by
    /// groupPublicKey (both group-detail views, paged).
    Query { params: LookupParams },
    /// `/api/stats/total`
    StatsTotal,
    /// `/api/stats/sites`
    StatsSites { params: LookupParams },
    /// `/api/stats/keys?rpId=`
    StatsKeys { rp_id: String, params: LookupParams },
}

/// Cache identity of one rendered response. The shell maps this to a key
/// string; TTL freshness/staleness verdicts also happen shell-side against
/// the [`TtlClass`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LookupCacheKey {
    EntriesByKey {
        key_hash: String,
        page: u64,
        page_size: u64,
        descending: bool,
    },
    Entry {
        entry_id: u64,
    },
    Unit {
        unit_id: u64,
        page: u64,
        page_size: u64,
        descending: bool,
    },
    Group {
        group_key: String,
        page: u64,
        page_size: u64,
        descending: bool,
    },
    StatsTotal,
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

impl LookupCacheKey {
    /// Which stale-grace window applies when RPC is down.
    pub fn ttl_class(&self) -> TtlClass {
        match self {
            Self::EntriesByKey { .. }
            | Self::Entry { .. }
            | Self::Unit { .. }
            | Self::Group { .. } => TtlClass::Record,
            Self::StatsTotal | Self::Sites { .. } | Self::Keys { .. } => TtlClass::Stats,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TtlClass {
    Record,
    Stats,
}

/// What the shell fetches from the chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ChainFetch {
    EntriesByKey {
        public_key: String,
        offset: u64,
        limit: u64,
        descending: bool,
    },
    Entry {
        entry_id: u64,
    },
    GroupById {
        unit_id: u64,
        offset: u64,
        limit: u64,
        descending: bool,
    },
    GroupByKey {
        group_public_key: String,
        offset: u64,
        limit: u64,
        descending: bool,
    },
    Totals,
    Sites {
        offset: u64,
        limit: u64,
        descending: bool,
    },
    Keys {
        rp_id: String,
        offset: u64,
        limit: u64,
        descending: bool,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LookupOperation {
    ReadCache {
        key: LookupCacheKey,
    },
    /// `negative: true` caches a short-lived 404 marker.
    WriteCache {
        key: LookupCacheKey,
        value: Value,
        negative: bool,
    },
    /// May this client take a cache miss to RPC? (Fail-open shell-side.)
    AllowRead,
    FetchChain {
        fetch: ChainFetch,
    },
    /// The in-flight placeholder for a member public key (hash), if any.
    FindTaskByKey {
        key_hash: String,
    },
}

impl crux_core::capability::Operation for LookupOperation {
    type Output = LookupResult;
}

#[allow(clippy::large_enum_variant)]
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
    Persisted,
    StoreUnavailable,
    Allowed {
        allowed: bool,
    },
    /// A successful chain fetch, already rendered by the shell into the
    /// response JSON for this endpoint. `not_found` marks a revert that
    /// means "no such entry".
    Chain {
        value: Value,
    },
    ChainNotFound,
    ChainFailed,
    TaskFound {
        task: Option<RegisterTask>,
    },
}

#[effect]
pub enum LookupEffect {
    Work(LookupOperation),
}

// ── App ────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LookupOutcome {
    /// 200 with Cache-Control (served from fresh cache).
    CachedOk { value: Value },
    /// 200, freshly fetched.
    Ok { value: Value },
    /// 200 with `_stale` markers and no-cache headers.
    StaleOk { value: Value, age_ms: u64 },
    /// 200: nothing on-chain but an in-flight task exists for the key.
    QueuePending { value: Value },
    /// 400 with the validation message.
    Invalid { message: String },
    /// 404.
    NotFound,
    /// 429 for a cache miss over the read budget.
    ReadLimited,
    /// 503 naming the dependency ("redis" / "rpc").
    DependencyUnavailable { dependency: String },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LookupEvent {
    Start { endpoint: LookupEndpoint },
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
            LookupEvent::Start { endpoint } => Command::new(|ctx| async move {
                let outcome = match drive_lookup(&ctx, endpoint).await {
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

fn redis_down() -> LookupOutcome {
    LookupOutcome::DependencyUnavailable {
        dependency: "redis".to_owned(),
    }
}

fn rpc_down() -> LookupOutcome {
    LookupOutcome::DependencyUnavailable {
        dependency: "rpc".to_owned(),
    }
}

async fn request(ctx: &Ctx, operation: LookupOperation) -> LookupResult {
    ctx.request_from_shell(operation).await
}

/// Page params clamp to the published contract: page ≥ 1, pageSize 1..=100
/// (default 20), newest-first unless `order=asc`.
pub fn pagination(params: &LookupParams) -> (u64, u64, bool) {
    let page = params.page.unwrap_or(1).max(1);
    let page_size = params.page_size.unwrap_or(20).clamp(1, 100);
    let descending = params.order.as_deref() != Some("asc");
    (page, page_size, descending)
}

/// Hex-normalize and validate an uncompressed P-256 key parameter.
pub fn normalize_public_key_param(value: &str) -> Result<String, String> {
    let raw = value.strip_prefix("0x").unwrap_or(value);
    if raw.len() != 130 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("publicKey must be an uncompressed P-256 point (04 + 128 hex chars)".into());
    }
    if !raw.starts_with("04") {
        return Err("publicKey must start with the uncompressed prefix 04".into());
    }
    Ok(raw.to_ascii_lowercase())
}

async fn drive_lookup(ctx: &Ctx, endpoint: LookupEndpoint) -> Flow<LookupOutcome> {
    match endpoint {
        LookupEndpoint::Query { params } => query_flow(ctx, params).await,
        LookupEndpoint::StatsTotal => {
            stats_flow(ctx, LookupCacheKey::StatsTotal, ChainFetch::Totals).await
        }
        LookupEndpoint::StatsSites { params } => {
            let (page, page_size, descending) = pagination(&params);
            stats_flow(
                ctx,
                LookupCacheKey::Sites {
                    page,
                    page_size,
                    descending,
                },
                ChainFetch::Sites {
                    offset: (page - 1) * page_size,
                    limit: page_size,
                    descending,
                },
            )
            .await
        }
        LookupEndpoint::StatsKeys { rp_id, params } => {
            if rp_id.is_empty() {
                return Ok(LookupOutcome::Invalid {
                    message: "rpId is required".into(),
                });
            }
            if rp_id.len() > 253 {
                return Ok(LookupOutcome::Invalid {
                    message: "rpId exceeds max length (253)".into(),
                });
            }
            let (page, page_size, descending) = pagination(&params);
            stats_flow(
                ctx,
                LookupCacheKey::Keys {
                    rp_id: rp_id.clone(),
                    page,
                    page_size,
                    descending,
                },
                ChainFetch::Keys {
                    rp_id,
                    offset: (page - 1) * page_size,
                    limit: page_size,
                    descending,
                },
            )
            .await
        }
    }
}

async fn query_flow(ctx: &Ctx, params: LookupParams) -> Flow<LookupOutcome> {
    if let Some(entry_id) = params.entry_id.as_deref() {
        let Ok(entry_id) = entry_id.parse::<u64>() else {
            return Ok(LookupOutcome::Invalid {
                message: "entryId must be an unsigned integer".into(),
            });
        };
        return entry_flow(ctx, entry_id).await;
    }
    if let Some(unit_id) = params.unit_id.as_deref() {
        let Ok(unit_id) = unit_id.parse::<u64>() else {
            return Ok(LookupOutcome::Invalid {
                message: "unitId must be an unsigned integer".into(),
            });
        };
        let (page, page_size, descending) = pagination(&params);
        return group_by_id_flow(ctx, unit_id, page, page_size, descending).await;
    }
    if let Some(group_key) = params.group_public_key.as_deref() {
        let group_key = match normalize_public_key_param(group_key) {
            Ok(value) => value,
            Err(message) => {
                return Ok(LookupOutcome::Invalid {
                    message: message.replacen("publicKey", "groupPublicKey", 1),
                });
            }
        };
        let (page, page_size, descending) = pagination(&params);
        return group_by_key_flow(ctx, group_key, page, page_size, descending).await;
    }
    let Some(public_key) = params.public_key.as_deref() else {
        return Ok(LookupOutcome::Invalid {
            message: "publicKey, entryId, unitId or groupPublicKey is required".into(),
        });
    };
    let public_key = match normalize_public_key_param(public_key) {
        Ok(value) => value,
        Err(message) => return Ok(LookupOutcome::Invalid { message }),
    };
    let (page, page_size, descending) = pagination(&params);
    entries_by_key_flow(ctx, public_key, page, page_size, descending).await
}

/// The shell's canonical key-hash string for placeholders and cache keys:
/// hex(keccak256(raw key bytes)) is computed shell-side; the Core passes the
/// normalized hex key and the shell hashes it. To keep the Core pure we use
/// the normalized key itself as the logical identity here.
async fn entries_by_key_flow(
    ctx: &Ctx,
    public_key: String,
    page: u64,
    page_size: u64,
    descending: bool,
) -> Flow<LookupOutcome> {
    let cache_key = LookupCacheKey::EntriesByKey {
        key_hash: public_key.clone(),
        page,
        page_size,
        descending,
    };
    let mut stale: Option<(Value, u64)> = None;
    match request(
        ctx,
        LookupOperation::ReadCache {
            key: cache_key.clone(),
        },
    )
    .await
    {
        LookupResult::CacheFresh { value } => return Ok(LookupOutcome::CachedOk { value }),
        LookupResult::CacheStale { value, age_ms } => stale = Some((value, age_ms)),
        LookupResult::CacheNegative | LookupResult::CacheMiss => {}
        LookupResult::StoreUnavailable => return Err(redis_down()),
        _ => return Err(redis_down()),
    }
    allow_read(ctx).await?;
    match request(
        ctx,
        LookupOperation::FetchChain {
            fetch: ChainFetch::EntriesByKey {
                public_key: public_key.clone(),
                offset: (page - 1) * page_size,
                limit: page_size,
                descending,
            },
        },
    )
    .await
    {
        LookupResult::Chain { value } => {
            let _ = request(
                ctx,
                LookupOperation::WriteCache {
                    key: cache_key,
                    value: value.clone(),
                    negative: false,
                },
            )
            .await;
            Ok(LookupOutcome::Ok { value })
        }
        // The key has no on-chain file (yet). Pre-chain visibility: an
        // in-flight task for this key answers instead of an empty body,
        // so "submitted to p256-index" is never invisible.
        LookupResult::ChainNotFound => {
            match request(
                ctx,
                LookupOperation::FindTaskByKey {
                    key_hash: public_key.clone(),
                },
            )
            .await
            {
                LookupResult::TaskFound { task: Some(task) } if is_active_placeholder(&task) => {
                    Ok(LookupOutcome::QueuePending {
                        value: queue_pending_body(&task, &public_key),
                    })
                }
                LookupResult::TaskFound { .. } => Ok(LookupOutcome::Ok {
                    value: empty_key_profile_body(),
                }),
                _ => Err(redis_down()),
            }
        }
        LookupResult::ChainFailed => match stale {
            Some((value, age_ms)) => Ok(LookupOutcome::StaleOk { value, age_ms }),
            None => Err(rpc_down()),
        },
        _ => Err(rpc_down()),
    }
}

/// The stable shape for "this key has no file yet and no in-flight task".
fn empty_key_profile_body() -> Value {
    json!({
        "entry": Value::Null,
        "groups": { "total": 0, "unitIds": [] },
        "references": { "total": 0, "referenceIds": [] },
    })
}

async fn entry_flow(ctx: &Ctx, entry_id: u64) -> Flow<LookupOutcome> {
    let cache_key = LookupCacheKey::Entry { entry_id };
    let mut stale: Option<(Value, u64)> = None;
    match request(
        ctx,
        LookupOperation::ReadCache {
            key: cache_key.clone(),
        },
    )
    .await
    {
        LookupResult::CacheFresh { value } => return Ok(LookupOutcome::CachedOk { value }),
        LookupResult::CacheNegative => return Ok(LookupOutcome::NotFound),
        LookupResult::CacheStale { value, age_ms } => stale = Some((value, age_ms)),
        LookupResult::CacheMiss => {}
        LookupResult::StoreUnavailable => return Err(redis_down()),
        _ => return Err(redis_down()),
    }
    allow_read(ctx).await?;
    match request(
        ctx,
        LookupOperation::FetchChain {
            fetch: ChainFetch::Entry { entry_id },
        },
    )
    .await
    {
        LookupResult::Chain { value } => {
            let _ = request(
                ctx,
                LookupOperation::WriteCache {
                    key: cache_key,
                    value: value.clone(),
                    negative: false,
                },
            )
            .await;
            Ok(LookupOutcome::Ok { value })
        }
        LookupResult::ChainNotFound => {
            let _ = request(
                ctx,
                LookupOperation::WriteCache {
                    key: cache_key,
                    value: Value::Null,
                    negative: true,
                },
            )
            .await;
            Ok(LookupOutcome::NotFound)
        }
        LookupResult::ChainFailed => match stale {
            Some((value, age_ms)) => Ok(LookupOutcome::StaleOk { value, age_ms }),
            None => Err(rpc_down()),
        },
        _ => Err(rpc_down()),
    }
}

/// Group detail by immutable unit id. Ids are append-only, so a miss is
/// negative-cached briefly like entry-by-id.
async fn group_by_id_flow(
    ctx: &Ctx,
    unit_id: u64,
    page: u64,
    page_size: u64,
    descending: bool,
) -> Flow<LookupOutcome> {
    let cache_key = LookupCacheKey::Unit {
        unit_id,
        page,
        page_size,
        descending,
    };
    let mut stale: Option<(Value, u64)> = None;
    match request(
        ctx,
        LookupOperation::ReadCache {
            key: cache_key.clone(),
        },
    )
    .await
    {
        LookupResult::CacheFresh { value } => return Ok(LookupOutcome::CachedOk { value }),
        LookupResult::CacheNegative => return Ok(LookupOutcome::NotFound),
        LookupResult::CacheStale { value, age_ms } => stale = Some((value, age_ms)),
        LookupResult::CacheMiss => {}
        LookupResult::StoreUnavailable => return Err(redis_down()),
        _ => return Err(redis_down()),
    }
    allow_read(ctx).await?;
    match request(
        ctx,
        LookupOperation::FetchChain {
            fetch: ChainFetch::GroupById {
                unit_id,
                offset: (page - 1) * page_size,
                limit: page_size,
                descending,
            },
        },
    )
    .await
    {
        LookupResult::Chain { value } => {
            let _ = request(
                ctx,
                LookupOperation::WriteCache {
                    key: cache_key,
                    value: value.clone(),
                    negative: false,
                },
            )
            .await;
            Ok(LookupOutcome::Ok { value })
        }
        LookupResult::ChainNotFound => {
            let _ = request(
                ctx,
                LookupOperation::WriteCache {
                    key: cache_key,
                    value: Value::Null,
                    negative: true,
                },
            )
            .await;
            Ok(LookupOutcome::NotFound)
        }
        LookupResult::ChainFailed => match stale {
            Some((value, age_ms)) => Ok(LookupOutcome::StaleOk { value, age_ms }),
            None => Err(rpc_down()),
        },
        _ => Err(rpc_down()),
    }
}

/// Group detail by group public key — the group's stable identity. A group
/// key with no on-chain unit but an in-flight register task answers with
/// the `_queue` marker (register placeholders cover the group key); the
/// miss is NOT negative-cached, because "queued → registered" is exactly
/// the transition a brief 404 window would hide.
async fn group_by_key_flow(
    ctx: &Ctx,
    group_key: String,
    page: u64,
    page_size: u64,
    descending: bool,
) -> Flow<LookupOutcome> {
    let cache_key = LookupCacheKey::Group {
        group_key: group_key.clone(),
        page,
        page_size,
        descending,
    };
    let mut stale: Option<(Value, u64)> = None;
    match request(
        ctx,
        LookupOperation::ReadCache {
            key: cache_key.clone(),
        },
    )
    .await
    {
        LookupResult::CacheFresh { value } => return Ok(LookupOutcome::CachedOk { value }),
        LookupResult::CacheStale { value, age_ms } => stale = Some((value, age_ms)),
        LookupResult::CacheNegative | LookupResult::CacheMiss => {}
        LookupResult::StoreUnavailable => return Err(redis_down()),
        _ => return Err(redis_down()),
    }
    allow_read(ctx).await?;
    match request(
        ctx,
        LookupOperation::FetchChain {
            fetch: ChainFetch::GroupByKey {
                group_public_key: group_key.clone(),
                offset: (page - 1) * page_size,
                limit: page_size,
                descending,
            },
        },
    )
    .await
    {
        LookupResult::Chain { value } => {
            let _ = request(
                ctx,
                LookupOperation::WriteCache {
                    key: cache_key,
                    value: value.clone(),
                    negative: false,
                },
            )
            .await;
            Ok(LookupOutcome::Ok { value })
        }
        LookupResult::ChainNotFound => {
            match request(
                ctx,
                LookupOperation::FindTaskByKey {
                    key_hash: group_key.clone(),
                },
            )
            .await
            {
                LookupResult::TaskFound { task: Some(task) } if is_active_placeholder(&task) => {
                    Ok(LookupOutcome::QueuePending {
                        value: queue_pending_body(&task, &group_key),
                    })
                }
                LookupResult::TaskFound { .. } => Ok(LookupOutcome::NotFound),
                _ => Err(redis_down()),
            }
        }
        LookupResult::ChainFailed => match stale {
            Some((value, age_ms)) => Ok(LookupOutcome::StaleOk { value, age_ms }),
            None => Err(rpc_down()),
        },
        _ => Err(rpc_down()),
    }
}

async fn stats_flow(ctx: &Ctx, key: LookupCacheKey, fetch: ChainFetch) -> Flow<LookupOutcome> {
    let mut stale: Option<(Value, u64)> = None;
    match request(ctx, LookupOperation::ReadCache { key: key.clone() }).await {
        LookupResult::CacheFresh { value } => return Ok(LookupOutcome::CachedOk { value }),
        LookupResult::CacheStale { value, age_ms } => stale = Some((value, age_ms)),
        LookupResult::CacheNegative | LookupResult::CacheMiss => {}
        LookupResult::StoreUnavailable => return Err(redis_down()),
        _ => return Err(redis_down()),
    }
    allow_read(ctx).await?;
    match request(ctx, LookupOperation::FetchChain { fetch }).await {
        LookupResult::Chain { value } => {
            let _ = request(
                ctx,
                LookupOperation::WriteCache {
                    key,
                    value: value.clone(),
                    negative: false,
                },
            )
            .await;
            Ok(LookupOutcome::Ok { value })
        }
        LookupResult::ChainFailed => match stale {
            Some((value, age_ms)) => Ok(LookupOutcome::StaleOk { value, age_ms }),
            None => Err(rpc_down()),
        },
        _ => Err(rpc_down()),
    }
}

/// The read budget applies only to cache misses; the shell's limiter is
/// fail-open on store errors.
async fn allow_read(ctx: &Ctx) -> Flow<()> {
    match request(ctx, LookupOperation::AllowRead).await {
        LookupResult::Allowed { allowed: true } => Ok(()),
        LookupResult::Allowed { allowed: false } => Err(LookupOutcome::ReadLimited),
        _ => Ok(()), // fail-open, as ever
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use crux_core::{Core, Request};
    use serde_json::json;

    use super::*;
    use crate::task::{Member, Proof, RegisterTask};

    const KEY: &str = "045ff257819a8927dc548d62eeb90a7a61a8e90afd70c9f774e7ed78d0c5bbbc0e8ed0f6a55f675f162b2e8450f79cd0e6766e56f10f762430ec15d2a4388f19fb";

    struct Driver {
        core: Core<LookupApp>,
        queue: VecDeque<Request<LookupOperation>>,
    }

    impl Driver {
        fn start(endpoint: LookupEndpoint) -> Self {
            let core = Core::new();
            let effects = core.process_event(LookupEvent::Start { endpoint });
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

    fn by_key() -> LookupEndpoint {
        LookupEndpoint::Query {
            params: LookupParams {
                public_key: Some(KEY.into()),
                ..LookupParams::default()
            },
        }
    }

    fn key_cache() -> LookupCacheKey {
        LookupCacheKey::EntriesByKey {
            key_hash: KEY.into(),
            page: 1,
            page_size: 20,
            descending: true,
        }
    }

    fn key_fetch() -> LookupOperation {
        LookupOperation::FetchChain {
            fetch: ChainFetch::EntriesByKey {
                public_key: KEY.into(),
                offset: 0,
                limit: 20,
                descending: true,
            },
        }
    }

    fn task(status: TaskStatus) -> RegisterTask {
        RegisterTask {
            id: "t1".into(),
            status,
            kind: crate::task::TaskKind::Register,
            rp_id: "example.com".into(),
            metadata: "0xaa".into(),
            content_hash: format!("0x{}", "11".repeat(32)),
            group_public_key: "049e666db13bc6d0a76ec6801fbe24864030f15eca3b2d07ebcaf824bb2dc4f0aea8221dc27980b7c133a00d910c39723eb1523e88ad050a7303bba8bde07367fa".into(),
            group_proof: Some(Proof {
                authenticator_data: String::new(),
                client_data_json: String::new(),
                challenge_index: 0,
                type_index: 0,
                r: String::new(),
                s: String::new(),
            }),
            members: vec![Member {
                public_key: KEY.into(),
                attestation: String::new(),
                credential_id: String::new(),
                authenticator_attachment: String::new(),
                transports: String::new(),
                proof: Proof {
                    authenticator_data: String::new(),
                    client_data_json: String::new(),
                    challenge_index: 0,
                    type_index: 0,
                    r: String::new(),
                    s: String::new(),
                },
            }],
            tx_hash: None,
            on_chain_id: None,
            error: None,
            retries: 0,
            created_at: 7,
            admitted: true,
        }
    }

    #[test]
    fn fresh_cache_hit_serves_without_rpc() {
        let mut driver = Driver::start(by_key());
        driver.step(
            LookupOperation::ReadCache { key: key_cache() },
            LookupResult::CacheFresh {
                value: json!({"total": 1}),
            },
        );
        driver.assert_settled(LookupOutcome::CachedOk {
            value: json!({"total": 1}),
        });
    }

    #[test]
    fn miss_fetches_backfills_and_serves() {
        let mut driver = Driver::start(by_key());
        driver.step(
            LookupOperation::ReadCache { key: key_cache() },
            LookupResult::CacheMiss,
        );
        driver.step(
            LookupOperation::AllowRead,
            LookupResult::Allowed { allowed: true },
        );
        let page = json!({"total": 1, "items": [{"entryId": 0}]});
        driver.step(
            key_fetch(),
            LookupResult::Chain {
                value: page.clone(),
            },
        );
        driver.step(
            LookupOperation::WriteCache {
                key: key_cache(),
                value: page.clone(),
                negative: false,
            },
            LookupResult::Persisted,
        );
        driver.assert_settled(LookupOutcome::Ok { value: page });
    }

    #[test]
    fn missing_file_with_active_task_answers_queue_pending() {
        let mut driver = Driver::start(by_key());
        driver.step(
            LookupOperation::ReadCache { key: key_cache() },
            LookupResult::CacheMiss,
        );
        driver.step(
            LookupOperation::AllowRead,
            LookupResult::Allowed { allowed: true },
        );
        driver.step(key_fetch(), LookupResult::ChainNotFound);
        driver.step(
            LookupOperation::FindTaskByKey {
                key_hash: KEY.into(),
            },
            LookupResult::TaskFound {
                task: Some(task(TaskStatus::Pending)),
            },
        );
        driver.assert_settled(LookupOutcome::QueuePending {
            value: queue_pending_body(&task(TaskStatus::Pending), KEY),
        });
    }

    #[test]
    fn missing_file_without_task_serves_the_empty_profile() {
        let mut driver = Driver::start(by_key());
        driver.step(
            LookupOperation::ReadCache { key: key_cache() },
            LookupResult::CacheMiss,
        );
        driver.step(
            LookupOperation::AllowRead,
            LookupResult::Allowed { allowed: true },
        );
        driver.step(key_fetch(), LookupResult::ChainNotFound);
        driver.step(
            LookupOperation::FindTaskByKey {
                key_hash: KEY.into(),
            },
            LookupResult::TaskFound { task: None },
        );
        driver.assert_settled(LookupOutcome::Ok {
            value: json!({
                "entry": Value::Null,
                "groups": { "total": 0, "unitIds": [] },
                "references": { "total": 0, "referenceIds": [] },
            }),
        });
    }

    #[test]
    fn failed_task_is_not_a_placeholder() {
        let mut driver = Driver::start(by_key());
        driver.step(
            LookupOperation::ReadCache { key: key_cache() },
            LookupResult::CacheMiss,
        );
        driver.step(
            LookupOperation::AllowRead,
            LookupResult::Allowed { allowed: true },
        );
        driver.step(key_fetch(), LookupResult::ChainNotFound);
        driver.step(
            LookupOperation::FindTaskByKey {
                key_hash: KEY.into(),
            },
            LookupResult::TaskFound {
                task: Some(task(TaskStatus::Failed)),
            },
        );
        driver.assert_settled(LookupOutcome::Ok {
            value: json!({
                "entry": Value::Null,
                "groups": { "total": 0, "unitIds": [] },
                "references": { "total": 0, "referenceIds": [] },
            }),
        });
    }

    #[test]
    fn chain_failure_serves_stale_within_grace() {
        let mut driver = Driver::start(by_key());
        driver.step(
            LookupOperation::ReadCache { key: key_cache() },
            LookupResult::CacheStale {
                value: json!({"total": 2}),
                age_ms: 60_000,
            },
        );
        driver.step(
            LookupOperation::AllowRead,
            LookupResult::Allowed { allowed: true },
        );
        driver.step(key_fetch(), LookupResult::ChainFailed);
        driver.assert_settled(LookupOutcome::StaleOk {
            value: json!({"total": 2}),
            age_ms: 60_000,
        });
    }

    #[test]
    fn chain_failure_without_stale_names_rpc() {
        let mut driver = Driver::start(by_key());
        driver.step(
            LookupOperation::ReadCache { key: key_cache() },
            LookupResult::CacheMiss,
        );
        driver.step(
            LookupOperation::AllowRead,
            LookupResult::Allowed { allowed: true },
        );
        driver.step(key_fetch(), LookupResult::ChainFailed);
        driver.assert_settled(LookupOutcome::DependencyUnavailable {
            dependency: "rpc".into(),
        });
    }

    #[test]
    fn read_budget_rejects_cache_misses_only() {
        let mut driver = Driver::start(by_key());
        driver.step(
            LookupOperation::ReadCache { key: key_cache() },
            LookupResult::CacheMiss,
        );
        driver.step(
            LookupOperation::AllowRead,
            LookupResult::Allowed { allowed: false },
        );
        driver.assert_settled(LookupOutcome::ReadLimited);
    }

    #[test]
    fn read_limiter_store_failure_is_fail_open() {
        let mut driver = Driver::start(by_key());
        driver.step(
            LookupOperation::ReadCache { key: key_cache() },
            LookupResult::CacheMiss,
        );
        driver.step(LookupOperation::AllowRead, LookupResult::StoreUnavailable);
        let page = json!({"total": 3});
        driver.step(
            key_fetch(),
            LookupResult::Chain {
                value: page.clone(),
            },
        );
        driver.step(
            LookupOperation::WriteCache {
                key: key_cache(),
                value: page.clone(),
                negative: false,
            },
            LookupResult::Persisted,
        );
        driver.assert_settled(LookupOutcome::Ok { value: page });
    }

    #[test]
    fn entry_by_id_walks_negative_cache_and_not_found() {
        let endpoint = LookupEndpoint::Query {
            params: LookupParams {
                entry_id: Some("5".into()),
                ..LookupParams::default()
            },
        };
        // Negative cache answers 404 without RPC.
        let mut driver = Driver::start(endpoint.clone());
        driver.step(
            LookupOperation::ReadCache {
                key: LookupCacheKey::Entry { entry_id: 5 },
            },
            LookupResult::CacheNegative,
        );
        driver.assert_settled(LookupOutcome::NotFound);

        // A chain miss caches the negative marker.
        let mut driver = Driver::start(endpoint);
        driver.step(
            LookupOperation::ReadCache {
                key: LookupCacheKey::Entry { entry_id: 5 },
            },
            LookupResult::CacheMiss,
        );
        driver.step(
            LookupOperation::AllowRead,
            LookupResult::Allowed { allowed: true },
        );
        driver.step(
            LookupOperation::FetchChain {
                fetch: ChainFetch::Entry { entry_id: 5 },
            },
            LookupResult::ChainNotFound,
        );
        driver.step(
            LookupOperation::WriteCache {
                key: LookupCacheKey::Entry { entry_id: 5 },
                value: Value::Null,
                negative: true,
            },
            LookupResult::Persisted,
        );
        driver.assert_settled(LookupOutcome::NotFound);
    }

    const GROUP_KEY: &str = "049e666db13bc6d0a76ec6801fbe24864030f15eca3b2d07ebcaf824bb2dc4f0aea8221dc27980b7c133a00d910c39723eb1523e88ad050a7303bba8bde07367fa";

    fn by_group_key() -> LookupEndpoint {
        LookupEndpoint::Query {
            params: LookupParams {
                group_public_key: Some(GROUP_KEY.into()),
                ..LookupParams::default()
            },
        }
    }

    fn group_cache() -> LookupCacheKey {
        LookupCacheKey::Group {
            group_key: GROUP_KEY.into(),
            page: 1,
            page_size: 20,
            descending: true,
        }
    }

    fn group_fetch() -> LookupOperation {
        LookupOperation::FetchChain {
            fetch: ChainFetch::GroupByKey {
                group_public_key: GROUP_KEY.into(),
                offset: 0,
                limit: 20,
                descending: true,
            },
        }
    }

    #[test]
    fn group_by_key_miss_fetches_backfills_and_serves() {
        let mut driver = Driver::start(by_group_key());
        driver.step(
            LookupOperation::ReadCache { key: group_cache() },
            LookupResult::CacheMiss,
        );
        driver.step(
            LookupOperation::AllowRead,
            LookupResult::Allowed { allowed: true },
        );
        let detail = json!({"unit": {"unitId": 3}, "members": {"total": 1}});
        driver.step(
            group_fetch(),
            LookupResult::Chain {
                value: detail.clone(),
            },
        );
        driver.step(
            LookupOperation::WriteCache {
                key: group_cache(),
                value: detail.clone(),
                negative: false,
            },
            LookupResult::Persisted,
        );
        driver.assert_settled(LookupOutcome::Ok { value: detail });
    }

    #[test]
    fn unknown_group_key_with_active_register_task_answers_queue_pending() {
        let mut driver = Driver::start(by_group_key());
        driver.step(
            LookupOperation::ReadCache { key: group_cache() },
            LookupResult::CacheMiss,
        );
        driver.step(
            LookupOperation::AllowRead,
            LookupResult::Allowed { allowed: true },
        );
        driver.step(group_fetch(), LookupResult::ChainNotFound);
        driver.step(
            LookupOperation::FindTaskByKey {
                key_hash: GROUP_KEY.into(),
            },
            LookupResult::TaskFound {
                task: Some(task(TaskStatus::Pending)),
            },
        );
        driver.assert_settled(LookupOutcome::QueuePending {
            value: queue_pending_body(&task(TaskStatus::Pending), GROUP_KEY),
        });
    }

    #[test]
    fn unknown_group_key_without_task_is_not_found_and_never_negative_cached() {
        let mut driver = Driver::start(by_group_key());
        driver.step(
            LookupOperation::ReadCache { key: group_cache() },
            LookupResult::CacheMiss,
        );
        driver.step(
            LookupOperation::AllowRead,
            LookupResult::Allowed { allowed: true },
        );
        driver.step(group_fetch(), LookupResult::ChainNotFound);
        driver.step(
            LookupOperation::FindTaskByKey {
                key_hash: GROUP_KEY.into(),
            },
            LookupResult::TaskFound { task: None },
        );
        // Settles straight to NotFound: no WriteCache{negative} operation
        // may be in flight (the driver asserts an empty queue).
        driver.assert_settled(LookupOutcome::NotFound);
    }

    #[test]
    fn unit_by_id_walks_negative_cache_and_not_found() {
        let endpoint = LookupEndpoint::Query {
            params: LookupParams {
                unit_id: Some("5".into()),
                ..LookupParams::default()
            },
        };
        let unit_cache = LookupCacheKey::Unit {
            unit_id: 5,
            page: 1,
            page_size: 20,
            descending: true,
        };
        // Negative cache answers 404 without RPC.
        let mut driver = Driver::start(endpoint.clone());
        driver.step(
            LookupOperation::ReadCache {
                key: unit_cache.clone(),
            },
            LookupResult::CacheNegative,
        );
        driver.assert_settled(LookupOutcome::NotFound);

        // A chain miss caches the negative marker.
        let mut driver = Driver::start(endpoint);
        driver.step(
            LookupOperation::ReadCache {
                key: unit_cache.clone(),
            },
            LookupResult::CacheMiss,
        );
        driver.step(
            LookupOperation::AllowRead,
            LookupResult::Allowed { allowed: true },
        );
        driver.step(
            LookupOperation::FetchChain {
                fetch: ChainFetch::GroupById {
                    unit_id: 5,
                    offset: 0,
                    limit: 20,
                    descending: true,
                },
            },
            LookupResult::ChainNotFound,
        );
        driver.step(
            LookupOperation::WriteCache {
                key: unit_cache,
                value: Value::Null,
                negative: true,
            },
            LookupResult::Persisted,
        );
        driver.assert_settled(LookupOutcome::NotFound);
    }

    #[test]
    fn group_params_validate_before_any_operation() {
        let driver = Driver::start(LookupEndpoint::Query {
            params: LookupParams {
                unit_id: Some("not-a-number".into()),
                ..LookupParams::default()
            },
        });
        driver.assert_settled(LookupOutcome::Invalid {
            message: "unitId must be an unsigned integer".into(),
        });

        let driver = Driver::start(LookupEndpoint::Query {
            params: LookupParams {
                group_public_key: Some("02abc".into()),
                ..LookupParams::default()
            },
        });
        driver.assert_settled(LookupOutcome::Invalid {
            message: "groupPublicKey must be an uncompressed P-256 point (04 + 128 hex chars)"
                .into(),
        });
    }

    #[test]
    fn validation_rejects_bad_params() {
        let driver = Driver::start(LookupEndpoint::Query {
            params: LookupParams::default(),
        });
        driver.assert_settled(LookupOutcome::Invalid {
            message: "publicKey, entryId, unitId or groupPublicKey is required".into(),
        });

        let driver = Driver::start(LookupEndpoint::Query {
            params: LookupParams {
                public_key: Some("02abc".into()),
                ..LookupParams::default()
            },
        });
        driver.assert_settled(LookupOutcome::Invalid {
            message: "publicKey must be an uncompressed P-256 point (04 + 128 hex chars)".into(),
        });

        let driver = Driver::start(LookupEndpoint::Query {
            params: LookupParams {
                entry_id: Some("not-a-number".into()),
                ..LookupParams::default()
            },
        });
        driver.assert_settled(LookupOutcome::Invalid {
            message: "entryId must be an unsigned integer".into(),
        });
    }

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
    fn task_status_body_discloses_the_full_unit_without_proofs() {
        let body = task_status_body(&task(TaskStatus::Pending));
        assert_eq!(body["id"], "t1");
        assert_eq!(body["status"], "pending");
        assert_eq!(body["members"][0]["publicKey"], KEY);
        assert!(body["members"][0].get("proof").is_none());
        assert_eq!(body["contentHash"], format!("0x{}", "11".repeat(32)));
    }
}
