//! HTTP shell: routing, transport concerns, and the execution of admission
//! and lookup Core operations against Redis, the chain and Iggy.
//!
//! Every decision — validation (including possession-proof verification),
//! idempotency, cache policy, degradation — lives in `p256_registrar`; this
//! module renders outcomes into responses and owns key naming and TTLs.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderValue, Request, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use crux_core::Core;
use rand::Rng as _;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

use p256_registrar::{
    admission::{
        AdmissionApp, AdmissionEffect, AdmissionEvent, AdmissionOperation, AdmissionOutcome,
        AdmissionResult, AdmitOutcome, RegisterRequest,
    },
    lookup::{
        ChainFetch, LookupApp, LookupCacheKey, LookupEffect, LookupEndpoint, LookupEvent,
        LookupOperation, LookupOutcome, LookupParams, LookupResult, TtlClass, task_status_body,
    },
    protocol::{challenge_for, parse_b256, parse_hex_bytes},
    sentinel,
    task::TaskStatus,
};

use crate::{
    chain::ReadChain,
    config::Config,
    queue::RegisterTaskQueue,
    store::{Admission, CacheRead, RedisStore, derive_ip_salt, hash_ip},
};

const MAX_BODY_SIZE: usize = 128 * 1024;
const RECORD_STALE_LIMIT: Duration = Duration::from_secs(24 * 60 * 60);
const STATS_STALE_LIMIT: Duration = Duration::from_secs(60 * 60);

#[derive(Clone)]
pub struct AppState {
    store: RedisStore,
    queue: Arc<dyn RegisterTaskQueue>,
    chain: Arc<dyn ReadChain>,
    ip_salt: String,
    global_write_limit: u64,
    telegram_configured: bool,
    chain_id: u64,
}

impl AppState {
    pub fn new(
        store: RedisStore,
        queue: Arc<dyn RegisterTaskQueue>,
        chain: Arc<dyn ReadChain>,
        config: &Config,
    ) -> Self {
        Self {
            store,
            queue,
            chain,
            ip_salt: derive_ip_salt(config.private_key.as_deref()),
            global_write_limit: config.global_write_limit,
            telegram_configured: config.telegram_bot_token.is_some()
                && config.telegram_chat_id.is_some(),
            chain_id: p256_registrar::protocol::CHAIN_ID,
        }
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(root))
        .route("/api/health", get(health))
        .route("/api/challenge", post(challenge))
        .route("/api/register", post(register))
        .route("/api/task/", get(missing_task_id))
        .route("/api/task/{id}", get(task_status))
        .route("/api/query", get(query))
        .route("/api/stats/total", get(stats_total))
        .route("/api/stats/sites", get(stats_sites))
        .route("/api/stats/keys", get(stats_keys))
        .layer(axum::middleware::from_fn(cors))
        .with_state(state)
}

pub async fn serve(
    state: AppState,
    address: SocketAddr,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(address).await?;
    tracing::info!(%address, "HTTP API listening");
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move { shutdown.cancelled().await })
    .await?;
    Ok(())
}

async fn cors(request: Request<Body>, next: axum::middleware::Next) -> Response {
    if request.method() == axum::http::Method::OPTIONS {
        let mut response = StatusCode::NO_CONTENT.into_response();
        apply_cors(response.headers_mut());
        return response;
    }
    let mut response = next.run(request).await;
    apply_cors(response.headers_mut());
    response
}

fn apply_cors(headers: &mut axum::http::HeaderMap) {
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, POST, OPTIONS"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("content-type"),
    );
    headers.insert(
        header::ACCESS_CONTROL_MAX_AGE,
        HeaderValue::from_static("86400"),
    );
}

async fn root() -> Response {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        "<!doctype html><html><head><title>WebAuthn P256 Public Key Registry</title></head><body><h1>WebAuthn P256 Public Key Registry</h1><p>See the REST API documentation in this service repository.</p></body></html>",
    ).into_response()
}

async fn health(State(state): State<AppState>) -> Response {
    match state.store.queue_stats().await {
        Ok(stats) => {
            // The thresholds are sentinel policy; this handler only renders.
            let reasons = sentinel::health_reasons(&sentinel::QueueHealth {
                depth: stats.depth,
                dlq_count: stats.dlq_count,
                oldest_active_age_ms: stats.oldest_active_age_ms,
            });
            let status = if reasons.is_empty() { "ok" } else { "degraded" };
            let mut body = json!({
                "service": "webauthn-p256-publickey-registry",
                "version": "2.0.0",
                "chainId": state.chain_id,
                "registry": state.chain.registry_address(),
                "rpcCircuit": state.chain.rpc_circuit_state(),
                "telegramConfigured": state.telegram_configured,
                "status": status,
                "queue": {
                    "depth": stats.depth,
                    "dlq": stats.dlq_count,
                    "oldestJobAgeMs": stats.oldest_active_age_ms,
                },
            });
            if !reasons.is_empty() {
                body["reasons"] = json!(reasons);
            }
            json_response(StatusCode::OK, body)
        }
        Err(_) => json_response(
            StatusCode::OK,
            json!({
                "service": "webauthn-p256-publickey-registry",
                "version": "2.0.0",
                "chainId": state.chain_id,
                "registry": state.chain.registry_address(),
                "rpcCircuit": state.chain.rpc_circuit_state(),
                "telegramConfigured": state.telegram_configured,
                "status": "degraded",
                "reasons": ["stats-unavailable"],
                "queue": { "error": "queue stats unavailable" },
            }),
        ),
    }
}

/// Convenience: compute the storage-authorization challenge one member's key
/// must sign for this registry and chain — pure arithmetic, so clients that
/// would rather not implement abi.encode/keccak can fetch it. With no body it
/// returns a random unitNonce suggestion.
async fn challenge(State(state): State<AppState>, request: Request<Body>) -> Response {
    let Ok(bytes) = to_bytes(request.into_body(), MAX_BODY_SIZE).await else {
        return error_response(StatusCode::PAYLOAD_TOO_LARGE, "request body too large");
    };
    if bytes.is_empty() {
        let mut nonce = [0u8; 32];
        rand::rng().fill(&mut nonce);
        return json_response(
            StatusCode::OK,
            json!({ "unitNonce": format!("0x{}", hex::encode(nonce)) }),
        );
    }
    let Ok(body) = serde_json::from_slice::<Value>(&bytes) else {
        return error_response(StatusCode::BAD_REQUEST, "invalid JSON body");
    };
    let (Some(rp_id), Some(public_key), Some(unit_nonce)) = (
        body.get("rpId").and_then(Value::as_str),
        body.get("publicKey").and_then(Value::as_str),
        body.get("unitNonce").and_then(Value::as_str),
    ) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "rpId, publicKey, and unitNonce are required",
        );
    };
    let Ok(registry) = state.chain.registry_address().parse() else {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "registry misconfigured");
    };
    let (Ok(key_bytes), Ok(nonce)) = (parse_hex_bytes(public_key), parse_b256(unit_nonce)) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "publicKey must be hex and unitNonce 32-byte hex",
        );
    };
    let challenge = challenge_for(state.chain_id, registry, rp_id, &key_bytes, nonce);
    json_response(
        StatusCode::OK,
        json!({
            "challenge": format!("{challenge:#x}"),
            "challengeBase64url": URL_SAFE_NO_PAD.encode(challenge.0),
        }),
    )
}

async fn register(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response {
    let content_length = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok());
    if request.headers().contains_key(header::CONTENT_LENGTH) && content_length.is_none() {
        return error_response(StatusCode::PAYLOAD_TOO_LARGE, "request body too large");
    }
    if content_length.is_some_and(|length| length > MAX_BODY_SIZE) {
        return error_response(StatusCode::PAYLOAD_TOO_LARGE, "request body too large");
    }
    let Ok(bytes) = to_bytes(request.into_body(), MAX_BODY_SIZE).await else {
        return error_response(StatusCode::PAYLOAD_TOO_LARGE, "request body too large");
    };
    let Ok(body) = serde_json::from_slice::<RegisterRequest>(&bytes) else {
        return error_response(StatusCode::BAD_REQUEST, "invalid JSON body");
    };

    let ip_hash = hash_ip(&state.ip_salt, &peer.ip().to_string());
    let core: Core<AdmissionApp> = Core::new();
    let mut effects = core.process_event(AdmissionEvent::Submit {
        request: body,
        new_task_id: uuid::Uuid::new_v4().to_string(),
        now_ms: now_ms(),
        chain_id: state.chain_id,
        registry: state.chain.registry_address(),
    });

    loop {
        let Some(effect) = effects.pop() else {
            break;
        };
        let AdmissionEffect::Work(mut request) = effect;
        let result = execute_admission(&state, &ip_hash, &request.operation).await;
        match core.resolve(&mut request, result) {
            Ok(next) => effects = next,
            Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
        }
    }

    match core.view().outcome {
        Some(outcome) => render_admission(outcome),
        None => error_response(StatusCode::INTERNAL_SERVER_ERROR, "admission never settled"),
    }
}

async fn execute_admission(
    state: &AppState,
    ip_hash: &str,
    operation: &AdmissionOperation,
) -> AdmissionResult {
    match operation {
        AdmissionOperation::AllowIpCreate => match state.store.allow_ip_create(ip_hash).await {
            Ok(allowed) => AdmissionResult::Allowed { allowed },
            Err(_) => AdmissionResult::StoreUnavailable,
        },
        AdmissionOperation::FindTaskByNonce { unit_nonce } => {
            match state.store.find_by_nonce(unit_nonce).await {
                Ok(task) => AdmissionResult::TaskFound { task },
                Err(_) => AdmissionResult::StoreUnavailable,
            }
        }
        AdmissionOperation::CheckContentRegistered { content_hash } => {
            let Ok(content_hash) = parse_b256(content_hash) else {
                return AdmissionResult::ChainReadFailed;
            };
            match state.chain.is_content_registered(content_hash).await {
                Ok(value) => AdmissionResult::ChainBool { value },
                Err(_) => AdmissionResult::ChainReadFailed,
            }
        }
        AdmissionOperation::CheckNonceUsed {
            unit_nonce,
            public_keys,
        } => {
            let Ok(unit_nonce) = parse_b256(unit_nonce) else {
                return AdmissionResult::ChainReadFailed;
            };
            // True as soon as any member's (key, nonce) pair is spent;
            // a read failure without a positive stays fail-open.
            let mut any_failed = false;
            for public_key in public_keys {
                let Ok(key_bytes) = parse_hex_bytes(&public_key) else {
                    return AdmissionResult::ChainReadFailed;
                };
                match state.chain.is_nonce_used(key_bytes, unit_nonce).await {
                    Ok(true) => return AdmissionResult::ChainBool { value: true },
                    Ok(false) => {}
                    Err(_) => any_failed = true,
                }
            }
            if any_failed {
                AdmissionResult::ChainReadFailed
            } else {
                AdmissionResult::ChainBool { value: false }
            }
        }
        AdmissionOperation::QueueDepth => match state.store.queue_stats().await {
            Ok(stats) => AdmissionResult::Depth { depth: stats.depth },
            Err(_) => AdmissionResult::StoreUnavailable,
        },
        AdmissionOperation::AllowGlobalCreate => {
            match state
                .store
                .allow_global_create(state.global_write_limit)
                .await
            {
                Ok(allowed) => AdmissionResult::Allowed { allowed },
                Err(_) => AdmissionResult::StoreUnavailable,
            }
        }
        AdmissionOperation::Admit { task } => match state.store.admit(task).await {
            Ok(Admission::New(_)) => AdmissionResult::Admitted(AdmitOutcome::New),
            Ok(Admission::Existing(id)) => AdmissionResult::Admitted(AdmitOutcome::Existing { id }),
            Err(_) => AdmissionResult::StoreUnavailable,
        },
        AdmissionOperation::LoadTask { id } => match state.store.get_task(id).await {
            Ok(task) => AdmissionResult::TaskFound { task },
            Err(_) => AdmissionResult::StoreUnavailable,
        },
        AdmissionOperation::Enqueue { task } => match state.queue.enqueue(task).await {
            Ok(()) => AdmissionResult::Enqueued,
            // Do not delete the Redis admission: Iggy could have appended
            // before its acknowledgement was lost. Retrying the same request
            // reuses the task ID and is safe for the consumer.
            Err(_) => AdmissionResult::QueueUnavailable,
        },
        AdmissionOperation::MarkAdmitted { id } => match state.store.mark_admitted(id).await {
            Ok(task) => AdmissionResult::TaskFound { task },
            Err(_) => AdmissionResult::StoreUnavailable,
        },
    }
}

fn render_admission(outcome: AdmissionOutcome) -> Response {
    match outcome {
        AdmissionOutcome::Invalid { message } => error_response(StatusCode::BAD_REQUEST, &message),
        AdmissionOutcome::RateLimited => error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "rate limit exceeded, max 5 requests per minute",
        ),
        AdmissionOutcome::Queued { id, status } => {
            let code = match status {
                TaskStatus::Done => StatusCode::OK,
                _ => StatusCode::ACCEPTED,
            };
            json_response(code, json!({ "id": id, "status": status }))
        }
        AdmissionOutcome::AlreadyRegistered { content_hash } => json_response(
            StatusCode::OK,
            json!({ "status": "done", "contentHash": content_hash }),
        ),
        AdmissionOutcome::NonceConflict { message } => {
            json_response(StatusCode::CONFLICT, json!({ "error": message }))
        }
        AdmissionOutcome::Busy => error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "service is busy, please retry later",
        ),
        AdmissionOutcome::DependencyUnavailable { dependency } => error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &format!("{dependency} temporarily unavailable, please retry"),
        ),
    }
}

async fn missing_task_id() -> Response {
    error_response(StatusCode::BAD_REQUEST, "task id is required")
}

async fn task_status(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    match state.store.get_task(&id).await {
        Ok(Some(task)) => json_response(StatusCode::OK, task_status_body(&task)),
        Ok(None) => error_response(StatusCode::NOT_FOUND, "not found"),
        Err(_) => error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "redis temporarily unavailable, please retry",
        ),
    }
}

async fn query(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Query(params): Query<LookupParams>,
) -> Response {
    run_lookup(&state, peer, LookupEndpoint::Query { params }).await
}

async fn stats_total(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> Response {
    run_lookup(&state, peer, LookupEndpoint::StatsTotal).await
}

async fn stats_sites(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Query(params): Query<LookupParams>,
) -> Response {
    run_lookup(&state, peer, LookupEndpoint::StatsSites { params }).await
}

#[derive(serde::Deserialize)]
struct KeysParams {
    #[serde(rename = "rpId")]
    rp_id: Option<String>,
    #[serde(flatten)]
    params: LookupParams,
}

async fn stats_keys(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Query(keys): Query<KeysParams>,
) -> Response {
    let Some(rp_id) = keys.rp_id else {
        return error_response(StatusCode::BAD_REQUEST, "rpId is required");
    };
    run_lookup(
        &state,
        peer,
        LookupEndpoint::StatsKeys {
            rp_id,
            params: keys.params,
        },
    )
    .await
}

async fn run_lookup(state: &AppState, peer: SocketAddr, endpoint: LookupEndpoint) -> Response {
    let ip_hash = hash_ip(&state.ip_salt, &peer.ip().to_string());
    let core: Core<LookupApp> = Core::new();
    let mut effects = core.process_event(LookupEvent::Start { endpoint });

    loop {
        let Some(effect) = effects.pop() else {
            break;
        };
        let LookupEffect::Work(mut request) = effect;
        let result = execute_lookup(state, &ip_hash, &request.operation).await;
        match core.resolve(&mut request, result) {
            Ok(next) => effects = next,
            Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
        }
    }

    match core.view().outcome {
        Some(outcome) => render_lookup(outcome),
        None => error_response(StatusCode::INTERNAL_SERVER_ERROR, "lookup never settled"),
    }
}

async fn execute_lookup(
    state: &AppState,
    ip_hash: &str,
    operation: &LookupOperation,
) -> LookupResult {
    match operation {
        LookupOperation::ReadCache { key } => {
            let stale_limit = match key.ttl_class() {
                TtlClass::Record => RECORD_STALE_LIMIT,
                TtlClass::Stats => STATS_STALE_LIMIT,
            };
            match state
                .store
                .cache_get(&cache_key_string(key), stale_limit)
                .await
            {
                Ok(CacheRead::Fresh(value)) => LookupResult::CacheFresh { value },
                Ok(CacheRead::Negative) => LookupResult::CacheNegative,
                Ok(CacheRead::Stale { value, age_ms }) => {
                    LookupResult::CacheStale { value, age_ms }
                }
                Ok(CacheRead::Miss) => LookupResult::CacheMiss,
                Err(_) => LookupResult::StoreUnavailable,
            }
        }
        LookupOperation::WriteCache {
            key,
            value,
            negative,
        } => {
            let key = cache_key_string(key);
            let write = if *negative {
                state.store.cache_set_negative(&key).await
            } else {
                state.store.cache_set(&key, value.clone(), false).await
            };
            match write {
                Ok(()) => LookupResult::Persisted,
                Err(_) => LookupResult::StoreUnavailable,
            }
        }
        LookupOperation::AllowRead => match state.store.allow_read(ip_hash).await {
            Ok(allowed) => LookupResult::Allowed { allowed },
            Err(_) => LookupResult::StoreUnavailable,
        },
        LookupOperation::FetchChain { fetch } => execute_fetch(state, fetch).await,
        LookupOperation::FindTaskByKey { key_hash } => {
            match state.store.find_by_public_key(key_hash).await {
                Ok(task) => LookupResult::TaskFound { task },
                Err(_) => LookupResult::StoreUnavailable,
            }
        }
    }
}

async fn execute_fetch(state: &AppState, fetch: &ChainFetch) -> LookupResult {
    match fetch {
        ChainFetch::EntriesByKey {
            public_key,
            offset,
            limit,
            descending,
        } => {
            let page = offset / limit + 1;
            match state
                .chain
                .entries_by_key(public_key, page, *limit, *descending)
                .await
            {
                Ok(page) => LookupResult::Chain {
                    value: serde_json::to_value(&page).unwrap_or(Value::Null),
                },
                Err(_) => LookupResult::ChainFailed,
            }
        }
        ChainFetch::Entry { entry_id } => match state.chain.entry(*entry_id).await {
            Ok(Some(entry)) => LookupResult::Chain {
                value: serde_json::to_value(&entry).unwrap_or(Value::Null),
            },
            Ok(None) => LookupResult::ChainNotFound,
            Err(_) => LookupResult::ChainFailed,
        },
        ChainFetch::Totals => match state.chain.totals().await {
            Ok((entries, units, rp_ids)) => LookupResult::Chain {
                value: json!({
                    "totalEntries": entries,
                    "totalUnits": units,
                    "totalRpIds": rp_ids,
                }),
            },
            Err(_) => LookupResult::ChainFailed,
        },
        ChainFetch::Sites {
            offset,
            limit,
            descending,
        } => {
            let page = offset / limit + 1;
            match state.chain.rp_ids(page, *limit, *descending).await {
                Ok(page) => LookupResult::Chain {
                    value: serde_json::to_value(&page).unwrap_or(Value::Null),
                },
                Err(_) => LookupResult::ChainFailed,
            }
        }
        ChainFetch::Keys {
            rp_id,
            offset,
            limit,
            descending,
        } => {
            let page = offset / limit + 1;
            match state
                .chain
                .entries_by_rp_id(rp_id, page, *limit, *descending)
                .await
            {
                Ok(page) => LookupResult::Chain {
                    value: serde_json::to_value(&page).unwrap_or(Value::Null),
                },
                Err(_) => LookupResult::ChainFailed,
            }
        }
    }
}

fn render_lookup(outcome: LookupOutcome) -> Response {
    match outcome {
        LookupOutcome::CachedOk { value } => cached_response(value),
        LookupOutcome::Ok { value } | LookupOutcome::QueuePending { value } => {
            json_response(StatusCode::OK, value)
        }
        LookupOutcome::StaleOk { value, age_ms } => stale_response(value, age_ms),
        LookupOutcome::Invalid { message } => error_response(StatusCode::BAD_REQUEST, &message),
        LookupOutcome::NotFound => error_response(StatusCode::NOT_FOUND, "not found"),
        LookupOutcome::ReadLimited => error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "rate limit exceeded, please retry later",
        ),
        LookupOutcome::DependencyUnavailable { dependency } => error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &format!("{dependency} temporarily unavailable, please retry"),
        ),
    }
}

fn cache_key_string(key: &LookupCacheKey) -> String {
    match key {
        LookupCacheKey::EntriesByKey {
            key_hash,
            page,
            page_size,
            descending,
        } => format!("query:key:{key_hash}:{page}:{page_size}:{descending}"),
        LookupCacheKey::Entry { entry_id } => format!("query:entry:{entry_id}"),
        LookupCacheKey::StatsTotal => "stats:total".into(),
        LookupCacheKey::Sites {
            page,
            page_size,
            descending,
        } => format!("stats:rpIds:{page}:{page_size}:{descending}"),
        LookupCacheKey::Keys {
            rp_id,
            page,
            page_size,
            descending,
        } => format!("stats:keys:{rp_id}:{page}:{page_size}:{descending}"),
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn json_response(status: StatusCode, body: Value) -> Response {
    (status, axum::Json(body)).into_response()
}

fn error_response(status: StatusCode, message: &str) -> Response {
    json_response(status, json!({ "error": message }))
}

fn cached_response(value: Value) -> Response {
    let mut response = json_response(StatusCode::OK, value);
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=3600"),
    );
    response
}

fn stale_response(value: Value, age_ms: u64) -> Response {
    let mut body = value;
    if let Some(object) = body.as_object_mut() {
        object.insert("_stale".into(), Value::Bool(true));
        object.insert("_staleAgeMs".into(), json!(age_ms));
    }
    let mut response = json_response(StatusCode::OK, body);
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    response
        .headers_mut()
        .insert("x-served-stale", HeaderValue::from_static("true"));
    response
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use axum::body::to_bytes;
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use p256::elliptic_curve::Generate as _;
    use p256_registrar::lookup::{Entry, Page, SiteItem};
    use p256_registrar::task::RegisterTask;
    use p256_registrar::verify::base64url_32;
    use sha2::{Digest, Sha256};
    use tower::ServiceExt;

    use super::*;
    use crate::chain::ChainError;
    use crate::queue::QueueError;

    const REGISTRY: &str = "0x1111111111111111111111111111111111111111";

    #[derive(Default)]
    struct FakeQueue {
        tasks: Mutex<Vec<RegisterTask>>,
    }

    #[async_trait]
    impl RegisterTaskQueue for FakeQueue {
        async fn enqueue(&self, task: &RegisterTask) -> Result<(), QueueError> {
            self.tasks
                .lock()
                .expect("test queue lock")
                .push(task.clone());
            Ok(())
        }
    }

    /// A chain with no entries and closed circuit: enough for the HTTP
    /// contract, which never needs a live RPC.
    struct OfflineChain;

    #[async_trait]
    impl ReadChain for OfflineChain {
        fn rpc_circuit_state(&self) -> &'static str {
            "open"
        }

        fn registry_address(&self) -> String {
            REGISTRY.into()
        }

        async fn entry(&self, _: u64) -> Result<Option<Entry>, ChainError> {
            Err(ChainError::Unavailable)
        }

        async fn entries_by_key(
            &self,
            _: &str,
            page: u64,
            page_size: u64,
            _: bool,
        ) -> Result<Page<Entry>, ChainError> {
            Ok(Page {
                total: 0,
                page,
                page_size,
                items: Vec::new(),
            })
        }

        async fn entries_by_rp_id(
            &self,
            _: &str,
            _: u64,
            _: u64,
            _: bool,
        ) -> Result<Page<Entry>, ChainError> {
            Err(ChainError::Unavailable)
        }

        async fn rp_ids(&self, _: u64, _: u64, _: bool) -> Result<Page<SiteItem>, ChainError> {
            Err(ChainError::Unavailable)
        }

        async fn totals(&self) -> Result<(u64, u64, u64), ChainError> {
            Err(ChainError::Unavailable)
        }

        async fn is_nonce_used(
            &self,
            _: Vec<u8>,
            _: alloy::primitives::B256,
        ) -> Result<bool, ChainError> {
            Err(ChainError::Unavailable)
        }

        async fn is_content_registered(
            &self,
            _: alloy::primitives::B256,
        ) -> Result<bool, ChainError> {
            Err(ChainError::Unavailable)
        }
    }

    fn test_config() -> Config {
        Config {
            listen_addr: "127.0.0.1:0".parse().expect("test address"),
            // This test-only salt keeps rate-limit keys isolated across repeated runs against
            // the same Redis instance; no chain writer is constructed from this config.
            private_key: Some(format!("test-ip-salt-{}", uuid::Uuid::new_v4())),
            alchemy_api_key: None,
            iggy_url: "iggy+tcp://unused".into(),
            iggy_consumer_url: "iggy+tcp://unused".into(),
            iggy_provisioner_url: "iggy+tcp://unused".into(),
            redis_url: "redis://unused".into(),
            queue_worker_enabled: false,
            telegram_bot_token: None,
            telegram_chat_id: None,
            max_gas_price_wei: p256_registrar::gas::DEFAULT_MAX_FEE_WEI,
            global_write_limit: 10_000,
            iggy_enqueue_timeout: std::time::Duration::from_secs(1),
            iggy_consumer_group: "test".into(),
            contract_address: REGISTRY.into(),
        }
    }

    async fn request(app: &Router, method: &str, uri: &str, body: &str) -> Response {
        app.clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("content-type", "application/json")
                    .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 4000))))
                    .body(Body::from(body.to_owned()))
                    .expect("test request"),
            )
            .await
            .expect("router response")
    }

    async fn response_json(response: Response) -> Value {
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        serde_json::from_slice(&bytes).expect("json body")
    }

    /// One member with a REAL possession proof over its storage challenge.
    fn signed_member_json(rp_id: &str, nonce_hex: &str) -> (Value, String) {
        let signing = p256::ecdsa::SigningKey::from(&p256::SecretKey::generate());
        let public = hex::encode(signing.verifying_key().to_sec1_point(false).as_bytes());
        let nonce = parse_b256(nonce_hex).unwrap();
        let challenge = challenge_for(
            p256_registrar::protocol::CHAIN_ID,
            REGISTRY.parse().unwrap(),
            rp_id,
            &hex::decode(&public).unwrap(),
            nonce,
        );
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
        (
            json!({
                "publicKey": public,
                "proof": {
                    "authenticatorData": hex::encode(auth_data),
                    "clientDataJSON": client_data,
                    "challengeIndex": 23,
                    "typeIndex": 1,
                    "r": format!("0x{}", hex::encode(&bytes[..32])),
                    "s": format!("0x{}", hex::encode(&bytes[32..])),
                }
            }),
            public,
        )
    }

    /// The full HTTP contract over real Redis (Iggy is faked; the chain is
    /// offline). Gated because CI has no infrastructure.
    #[tokio::test]
    #[ignore = "requires P256_INDEX_TEST_REDIS_URL"]
    async fn http_contract_over_real_redis() {
        let Some(redis_url) = std::env::var("P256_INDEX_TEST_REDIS_URL").ok() else {
            return;
        };
        let store = crate::store::RedisStore::connect(&redis_url)
            .await
            .expect("test Redis");
        let initial_queue_depth = store.queue_stats().await.expect("stats").depth;
        let queue = Arc::new(FakeQueue::default());
        let state = AppState::new(
            store.clone(),
            queue.clone(),
            Arc::new(OfflineChain),
            &test_config(),
        );
        let app = router(state);

        let options = request(&app, "OPTIONS", "/api/register", "").await;
        assert_eq!(options.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            options
                .headers()
                .get("access-control-allow-origin")
                .and_then(|value| value.to_str().ok()),
            Some("*")
        );

        let invalid = request(&app, "POST", "/api/register", "not-json").await;
        assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);

        // Nonce suggestion from the empty-body challenge endpoint.
        let suggestion = request(&app, "POST", "/api/challenge", "").await;
        assert_eq!(suggestion.status(), StatusCode::OK);
        let nonce_hex = response_json(suggestion).await["unitNonce"]
            .as_str()
            .expect("nonce")
            .to_owned();

        // A fully-proven single-member registration.
        let (member, public_key) = signed_member_json("http.example", &nonce_hex);
        let body = json!({
            "rpId": "http.example",
            "metadata": "0xaabb",
            "unitNonce": nonce_hex,
            "members": [member],
        })
        .to_string();

        let created = request(&app, "POST", "/api/register", &body).await;
        assert_eq!(created.status(), StatusCode::ACCEPTED);
        let created = response_json(created).await;
        assert_eq!(created["status"], "pending");
        let id = created["id"].as_str().expect("task id").to_owned();
        assert_eq!(queue.tasks.lock().expect("lock").len(), 1);

        // Same unit resubmitted → the same task (idempotency by nonce).
        let duplicate = request(&app, "POST", "/api/register", &body).await;
        assert_eq!(duplicate.status(), StatusCode::ACCEPTED);
        assert_eq!(response_json(duplicate).await["id"], id);
        assert_eq!(queue.tasks.lock().expect("lock").len(), 1);

        // A DIFFERENT unit on the same nonce → 409.
        let (other_member, _) = signed_member_json("http.example", &nonce_hex);
        let conflicting = json!({
            "rpId": "http.example",
            "metadata": "0xcc",
            "unitNonce": nonce_hex,
            "members": [other_member],
        })
        .to_string();
        let conflict = request(&app, "POST", "/api/register", &conflicting).await;
        assert_eq!(conflict.status(), StatusCode::CONFLICT);

        // An invalid proof never reaches Redis or the queue.
        let mut tampered: Value = serde_json::from_str(&body).unwrap();
        tampered["members"][0]["proof"]["typeIndex"] = json!(2);
        let rejected = request(&app, "POST", "/api/register", &tampered.to_string()).await;
        assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
        assert_eq!(queue.tasks.lock().expect("lock").len(), 1);

        // Task status disclosure.
        let status = request(&app, "GET", &format!("/api/task/{id}"), "").await;
        assert_eq!(status.status(), StatusCode::OK);
        let status = response_json(status).await;
        assert_eq!(status["status"], "pending");
        assert_eq!(status["members"][0]["publicKey"], public_key);
        assert!(status["members"][0].get("proof").is_none());

        // Pre-chain visibility: the member key answers with a queue marker.
        let pending = request(
            &app,
            "GET",
            &format!("/api/query?publicKey={public_key}"),
            "",
        )
        .await;
        assert_eq!(pending.status(), StatusCode::OK);
        let pending = response_json(pending).await;
        assert_eq!(pending["total"], 0);
        assert_eq!(pending["_queue"]["id"], id);

        // Param validation.
        let bad = request(&app, "GET", "/api/query?publicKey=02ab", "").await;
        assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
        let none = request(&app, "GET", "/api/query", "").await;
        assert_eq!(none.status(), StatusCode::BAD_REQUEST);

        // Health names the registry and the queue depth.
        let health = request(&app, "GET", "/api/health", "").await;
        assert_eq!(health.status(), StatusCode::OK);
        let health = response_json(health).await;
        assert_eq!(health["registry"], REGISTRY);
        assert_eq!(health["queue"]["depth"], initial_queue_depth + 1);
    }
}
