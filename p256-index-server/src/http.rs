use std::{collections::VecDeque, sync::Arc, time::Duration};

use axum::{
    Router,
    body::to_bytes,
    extract::{Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::Rng;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use p256_registrar::{
    admission::{
        AdmissionApp, AdmissionEffect, AdmissionEvent, AdmissionOperation, AdmissionOutcome,
        AdmissionResult, AdmitOutcome, CacheScope, CreateRequest,
    },
    lookup::{
        LookupApp, LookupCacheKey, LookupEffect, LookupEndpoint, LookupEvent, LookupOperation,
        LookupOutcome, LookupParams, LookupResult, Record, TtlClass, task_status_body,
    },
    protocol::CHAIN_ID,
    sentinel,
    task::TaskStatus,
};

use crate::{
    chain::{Chain, ReadChain},
    config::Config,
    queue::{CreateQueue, CreateTaskQueue},
    store::{Admission, CacheRead, RedisStore, derive_ip_salt, hash_ip},
};

const MAX_BODY_SIZE: usize = 32 * 1024;
const RECORD_STALE_LIMIT: Duration = Duration::from_secs(24 * 60 * 60);
const STATS_STALE_LIMIT: Duration = Duration::from_secs(60 * 60);

#[derive(Clone)]
pub struct AppState {
    store: RedisStore,
    queue: Arc<dyn CreateTaskQueue>,
    chain: Arc<dyn ReadChain>,
    global_write_limit: u64,
    ip_hash_salt: Arc<str>,
    telegram_configured: bool,
}

impl AppState {
    pub fn new(store: RedisStore, queue: CreateQueue, chain: Chain, config: &Config) -> Self {
        Self::with_clients(store, Arc::new(queue), Arc::new(chain), config)
    }

    pub fn with_clients(
        store: RedisStore,
        queue: Arc<dyn CreateTaskQueue>,
        chain: Arc<dyn ReadChain>,
        config: &Config,
    ) -> Self {
        Self {
            store,
            queue,
            chain,
            global_write_limit: config.global_write_limit,
            ip_hash_salt: Arc::from(derive_ip_salt(config.private_key.as_deref())),
            telegram_configured: config.telegram_bot_token.is_some()
                && config.telegram_chat_id.is_some(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct QueryParams {
    rp_id: Option<String>,
    credential_id: Option<String>,
    wallet_ref: Option<String>,
    page: Option<u64>,
    page_size: Option<u64>,
    order: Option<String>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(home))
        .route("/api/health", get(health))
        .route("/api/challenge", get(challenge))
        .route("/api/query", get(query_record))
        .route("/api/create", post(create))
        .route("/api/create/", get(create_status_missing))
        .route("/api/create/{id}", get(create_status))
        .route("/api/stats/total", get(total_credentials))
        .route("/api/stats/sites", get(list_sites))
        .route("/api/stats/keys", get(list_keys))
        .fallback(not_found)
        .layer(middleware::from_fn(cors_and_request_id))
        .with_state(state)
}

async fn cors_and_request_id(request: Request, next: Next) -> Response {
    if request.method() == Method::OPTIONS {
        let requested_headers = request
            .headers()
            .get("access-control-request-headers")
            .cloned();
        let mut response = StatusCode::NO_CONTENT.into_response();
        apply_cors(response.headers_mut(), requested_headers.as_ref());
        return response;
    }
    let request_id = Uuid::new_v4().simple().to_string()[..8].to_owned();
    let mut response = next.run(request).await;
    apply_cors(response.headers_mut(), None);
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", value);
    }
    response
}

fn apply_cors(headers: &mut HeaderMap, requested_headers: Option<&HeaderValue>) {
    headers.insert("access-control-allow-origin", HeaderValue::from_static("*"));
    headers.insert(
        "access-control-allow-methods",
        HeaderValue::from_static("GET, POST, OPTIONS"),
    );
    headers.insert(
        "access-control-allow-headers",
        requested_headers
            .cloned()
            .unwrap_or_else(|| HeaderValue::from_static("*")),
    );
    headers.insert("access-control-max-age", HeaderValue::from_static("86400"));
}

async fn home() -> Response {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        "<!doctype html><html><head><title>WebAuthn P256 Public Key Index</title></head><body><h1>WebAuthn P256 Public Key Index</h1><p>See the REST API documentation in this service repository.</p></body></html>",
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
                "service": "webauthn-p256-publickey-index",
                "version": "1.0.0",
                "chainId": CHAIN_ID,
                "contract": p256_registrar::protocol::CONTRACT_ADDRESS,
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
                "service": "webauthn-p256-publickey-index",
                "version": "1.0.0",
                "chainId": CHAIN_ID,
                "contract": p256_registrar::protocol::CONTRACT_ADDRESS,
                "rpcCircuit": state.chain.rpc_circuit_state(),
                "telegramConfigured": state.telegram_configured,
                "status": "degraded",
                "reasons": ["stats-unavailable"],
                "queue": { "error": "queue stats unavailable" },
            }),
        ),
    }
}

async fn challenge() -> Response {
    let mut bytes = [0u8; 32];
    rand::rng().fill(&mut bytes);
    json_response(
        StatusCode::OK,
        json!({ "challenge": URL_SAFE_NO_PAD.encode(bytes) }),
    )
}

async fn create(State(state): State<AppState>, request: Request) -> Response {
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
    let ip = client_ip(request.headers());
    let body = match to_bytes(request.into_body(), MAX_BODY_SIZE + 1).await {
        Ok(body) if body.len() <= MAX_BODY_SIZE => body,
        Ok(_) | Err(_) => {
            return error_response(StatusCode::PAYLOAD_TOO_LARGE, "request body too large");
        }
    };
    let request: CreateRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid JSON body"),
    };

    let ip_hash = hash_ip(&state.ip_hash_salt, &ip);
    render_admission(run_admission(&state, &ip_hash, request).await)
}

/// Drive one create request through the admission Core. The shell supplies
/// task identity and time, executes each operation against Redis / the chain
/// / Iggy, and renders the outcome; every admission decision lives in
/// `p256_registrar::admission`.
async fn run_admission(
    state: &AppState,
    ip_hash: &str,
    request: CreateRequest,
) -> AdmissionOutcome {
    let core: crux_core::Core<AdmissionApp> = crux_core::Core::new();
    let mut effects: VecDeque<AdmissionEffect> = core
        .process_event(AdmissionEvent::Submit {
            request,
            new_task_id: Uuid::new_v4().to_string(),
            now_ms: now_ms(),
        })
        .into_iter()
        .collect();
    while let Some(effect) = effects.pop_front() {
        let AdmissionEffect::Work(mut request) = effect;
        let output = execute_admission(state, ip_hash, &request.operation).await;
        match core.resolve(&mut request, output) {
            Ok(next) => effects.extend(next),
            Err(_) => {
                return AdmissionOutcome::DependencyUnavailable {
                    dependency: "redis".to_owned(),
                };
            }
        }
    }
    core.view()
        .outcome
        .unwrap_or(AdmissionOutcome::DependencyUnavailable {
            dependency: "redis".to_owned(),
        })
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
        AdmissionOperation::ReadCache { scope } => {
            match state
                .store
                .cache_get(&cache_scope_key(scope), RECORD_STALE_LIMIT)
                .await
            {
                Ok(CacheRead::Fresh(value)) => AdmissionResult::CacheHit { value },
                Ok(_) => AdmissionResult::CacheMiss,
                Err(_) => AdmissionResult::StoreUnavailable,
            }
        }
        AdmissionOperation::FetchChainRecord {
            rp_id,
            credential_id,
        } => match state.chain.get_record(rp_id, credential_id).await {
            Ok(record) => AdmissionResult::ChainRecord {
                value: record.as_ref().map(record_value),
            },
            Err(_) => AdmissionResult::ChainReadFailed,
        },
        AdmissionOperation::FetchChainRecordByWalletRef { wallet_ref } => {
            let Ok(wallet_ref) = wallet_ref.parse() else {
                return AdmissionResult::ChainReadFailed;
            };
            match state.chain.get_record_by_wallet_ref(wallet_ref).await {
                Ok(record) => AdmissionResult::ChainRecord {
                    value: record.as_ref().map(record_value),
                },
                Err(_) => AdmissionResult::ChainReadFailed,
            }
        }
        AdmissionOperation::StoreCache {
            scope,
            value,
            best_effort,
        } => {
            let write = state
                .store
                .cache_set(&cache_scope_key(scope), value.clone(), false)
                .await;
            if *best_effort || write.is_ok() {
                AdmissionResult::Persisted
            } else {
                AdmissionResult::StoreUnavailable
            }
        }
        AdmissionOperation::FindTaskByRecord {
            rp_id,
            credential_id,
        } => match state.store.find_by_record(rp_id, credential_id).await {
            Ok(task) => AdmissionResult::TaskFound { task },
            Err(_) => AdmissionResult::StoreUnavailable,
        },
        AdmissionOperation::FindTaskByWalletRef { wallet_ref } => {
            match state.store.find_by_wallet_ref(wallet_ref).await {
                Ok(task) => AdmissionResult::TaskFound { task },
                Err(_) => AdmissionResult::StoreUnavailable,
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
            Ok(Admission::WalletConflict(_)) => {
                AdmissionResult::Admitted(AdmitOutcome::WalletConflict)
            }
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

fn cache_scope_key(scope: &CacheScope) -> String {
    match scope {
        CacheScope::Record {
            rp_id,
            credential_id,
        } => record_cache_key(rp_id, credential_id),
        CacheScope::Wallet { wallet_ref } => wallet_cache_key(wallet_ref),
    }
}

fn render_admission(outcome: AdmissionOutcome) -> Response {
    match outcome {
        AdmissionOutcome::Invalid { message } => error_response(StatusCode::BAD_REQUEST, &message),
        AdmissionOutcome::RateLimited => error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "rate limit exceeded, max 5 requests per minute",
        ),
        AdmissionOutcome::AlreadyDone { record } => done_response(record),
        AdmissionOutcome::Queued { id, status } => queued_response(&id, &status),
        AdmissionOutcome::WalletConflict {
            wallet_ref,
            message,
        } => wallet_conflict(&wallet_ref, &message),
        AdmissionOutcome::Busy => busy_response(),
        AdmissionOutcome::DependencyUnavailable { dependency } => {
            retryable_service_unavailable(&dependency)
        }
    }
}

async fn create_status(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    match state.store.get_task(&id).await {
        // Disclosure (which fields may be shown before Done) is commit-reveal
        // policy and lives in the registrar.
        Ok(Some(task)) => json_response(StatusCode::OK, task_status_body(&task)),
        Ok(None) => error_response(StatusCode::NOT_FOUND, "not found"),
        Err(_) => dependency_error("redis"),
    }
}

async fn create_status_missing() -> Response {
    error_response(StatusCode::BAD_REQUEST, "id is required")
}

async fn query_record(
    State(state): State<AppState>,
    Query(params): Query<QueryParams>,
    headers: HeaderMap,
) -> Response {
    run_lookup(
        &state,
        &headers,
        LookupEndpoint::Query,
        lookup_params(params),
    )
    .await
}

async fn total_credentials(State(state): State<AppState>, headers: HeaderMap) -> Response {
    run_lookup(
        &state,
        &headers,
        LookupEndpoint::Total,
        LookupParams::default(),
    )
    .await
}

async fn list_sites(
    State(state): State<AppState>,
    Query(params): Query<QueryParams>,
    headers: HeaderMap,
) -> Response {
    run_lookup(
        &state,
        &headers,
        LookupEndpoint::Sites,
        lookup_params(params),
    )
    .await
}

async fn list_keys(
    State(state): State<AppState>,
    Query(params): Query<QueryParams>,
    headers: HeaderMap,
) -> Response {
    run_lookup(
        &state,
        &headers,
        LookupEndpoint::Keys,
        lookup_params(params),
    )
    .await
}

fn lookup_params(params: QueryParams) -> LookupParams {
    LookupParams {
        rp_id: params.rp_id,
        credential_id: params.credential_id,
        wallet_ref: params.wallet_ref,
        page: params.page,
        page_size: params.page_size,
        order: params.order,
    }
}

/// Drive one query through the lookup Core and render its outcome; every
/// read-through decision lives in `p256_registrar::lookup`.
async fn run_lookup(
    state: &AppState,
    headers: &HeaderMap,
    endpoint: LookupEndpoint,
    params: LookupParams,
) -> Response {
    let ip_hash = hash_ip(&state.ip_hash_salt, &client_ip(headers));
    let core: crux_core::Core<LookupApp> = crux_core::Core::new();
    let mut effects: VecDeque<LookupEffect> = core
        .process_event(LookupEvent::Query { endpoint, params })
        .into_iter()
        .collect();
    while let Some(effect) = effects.pop_front() {
        let LookupEffect::Work(mut request) = effect;
        let output = execute_lookup(state, &ip_hash, &request.operation).await;
        match core.resolve(&mut request, output) {
            Ok(next) => effects.extend(next),
            Err(_) => return dependency_error("redis"),
        }
    }
    match core.view().outcome {
        Some(outcome) => render_lookup(outcome),
        None => dependency_error("redis"),
    }
}

async fn execute_lookup(
    state: &AppState,
    ip_hash: &str,
    operation: &LookupOperation,
) -> LookupResult {
    match operation {
        LookupOperation::ReadCache { key, ttl } => {
            let limit = match ttl {
                TtlClass::Record => RECORD_STALE_LIMIT,
                TtlClass::Stats => STATS_STALE_LIMIT,
            };
            match state.store.cache_get(&lookup_cache_key(key), limit).await {
                Ok(CacheRead::Fresh(value)) => LookupResult::CacheFresh { value },
                Ok(CacheRead::Negative) => LookupResult::CacheNegative,
                Ok(CacheRead::Stale { value, age_ms }) => {
                    LookupResult::CacheStale { value, age_ms }
                }
                Ok(CacheRead::Miss) => LookupResult::CacheMiss,
                Err(_) => LookupResult::StoreUnavailable,
            }
        }
        LookupOperation::AllowRead => match state.store.allow_read(ip_hash).await {
            Ok(allowed) => LookupResult::Allowed { allowed },
            Err(_) => LookupResult::StoreUnavailable,
        },
        LookupOperation::FetchRecord {
            rp_id,
            credential_id,
        } => match state.chain.get_record(rp_id, credential_id).await {
            Ok(record) => LookupResult::Fetched {
                value: record.as_ref().map(record_value),
            },
            Err(_) => LookupResult::ChainReadFailed,
        },
        LookupOperation::FetchRecordByWalletRef { wallet_ref } => {
            let Ok(wallet_ref) = wallet_ref.parse() else {
                return LookupResult::ChainReadFailed;
            };
            match state.chain.get_record_by_wallet_ref(wallet_ref).await {
                Ok(record) => LookupResult::Fetched {
                    value: record.as_ref().map(record_value),
                },
                Err(_) => LookupResult::ChainReadFailed,
            }
        }
        LookupOperation::FetchTotal => match state.chain.total_credentials().await {
            Ok(total) => LookupResult::Total { total },
            Err(_) => LookupResult::ChainReadFailed,
        },
        LookupOperation::FetchSites {
            page,
            page_size,
            descending,
        } => match state.chain.list_sites(*page, *page_size, *descending).await {
            Ok(page) => LookupResult::Data {
                value: serde_json::to_value(page).expect("serializable sites page"),
            },
            Err(_) => LookupResult::ChainReadFailed,
        },
        LookupOperation::FetchKeys {
            rp_id,
            page,
            page_size,
            descending,
        } => match state
            .chain
            .list_keys(rp_id, *page, *page_size, *descending)
            .await
        {
            Ok(page) => LookupResult::Data {
                value: serde_json::to_value(page).expect("serializable keys page"),
            },
            Err(_) => LookupResult::ChainReadFailed,
        },
        LookupOperation::StoreCache {
            key,
            value,
            allow_stale,
        } => {
            match state
                .store
                .cache_set(&lookup_cache_key(key), value.clone(), *allow_stale)
                .await
            {
                Ok(()) => LookupResult::Persisted,
                Err(_) => LookupResult::StoreUnavailable,
            }
        }
        LookupOperation::StoreNegative { key } => {
            match state.store.cache_set_negative(&lookup_cache_key(key)).await {
                Ok(()) => LookupResult::Persisted,
                Err(_) => LookupResult::StoreUnavailable,
            }
        }
        LookupOperation::FindTaskByRecord {
            rp_id,
            credential_id,
        } => match state.store.find_by_record(rp_id, credential_id).await {
            Ok(task) => LookupResult::TaskFound { task },
            Err(_) => LookupResult::StoreUnavailable,
        },
        LookupOperation::FindTaskByWalletRef { wallet_ref } => {
            match state.store.find_by_wallet_ref(wallet_ref).await {
                Ok(task) => LookupResult::TaskFound { task },
                Err(_) => LookupResult::StoreUnavailable,
            }
        }
    }
}

fn lookup_cache_key(key: &LookupCacheKey) -> String {
    match key {
        LookupCacheKey::Record {
            rp_id,
            credential_id,
        } => record_cache_key(rp_id, credential_id),
        LookupCacheKey::Wallet { wallet_ref } => wallet_cache_key(wallet_ref),
        LookupCacheKey::StatsTotal => "stats:totalCredentials".to_owned(),
        LookupCacheKey::StatsSites {
            page,
            page_size,
            descending,
        } => format!("stats:rpIds:{page}:{page_size}:{descending}"),
        LookupCacheKey::StatsKeys {
            rp_id,
            page,
            page_size,
            descending,
        } => format!("stats:keys:{rp_id}:{page}:{page_size}:{descending}"),
    }
}

fn render_lookup(outcome: LookupOutcome) -> Response {
    match outcome {
        LookupOutcome::Invalid { message } => error_response(StatusCode::BAD_REQUEST, &message),
        LookupOutcome::CachedOk { value } => cached_response(value),
        LookupOutcome::EmptyPage { page, page_size } => json_response(
            StatusCode::OK,
            json!({ "total": 0, "page": page, "pageSize": page_size, "items": [] }),
        ),
        LookupOutcome::ReadLimited => read_limited(),
        LookupOutcome::ServedStale { value } => served_stale_response(value),
        LookupOutcome::QueueFallback { body } => json_response(StatusCode::OK, body),
        LookupOutcome::NotFound => error_response(StatusCode::NOT_FOUND, "not found"),
        LookupOutcome::DependencyUnavailable { dependency } => {
            retryable_service_unavailable(&dependency)
        }
    }
}

async fn not_found() -> Response {
    error_response(StatusCode::NOT_FOUND, "not found")
}

fn client_ip(headers: &HeaderMap) -> String {
    headers
        .get("cf-connecting-ip")
        .or_else(|| headers.get("x-forwarded-for"))
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(',')
                .next()
                .unwrap_or("unknown")
                .trim()
                .to_owned()
        })
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "unknown".into())
}

fn record_cache_key(rp_id: &str, credential_id: &str) -> String {
    format!("query:{rp_id}:{credential_id}")
}
fn wallet_cache_key(wallet_ref: &str) -> String {
    format!("query:walletRef:{wallet_ref}")
}
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn record_value(record: &Record) -> Value {
    serde_json::to_value(record).expect("record is serializable")
}

fn queued_response(id: &str, status: &TaskStatus) -> Response {
    json_response(StatusCode::ACCEPTED, json!({ "id": id, "status": status }))
}

fn done_response(value: Value) -> Response {
    let mut body = value;
    if let Some(object) = body.as_object_mut() {
        object.insert("status".into(), Value::String("done".into()));
    }
    json_response(StatusCode::CREATED, body)
}

fn wallet_conflict(wallet_ref: &str, error: &str) -> Response {
    json_response(
        StatusCode::CONFLICT,
        json!({ "error": error, "walletRef": wallet_ref }),
    )
}

fn cached_response(value: Value) -> Response {
    let mut response = json_response(StatusCode::OK, value);
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=3600"),
    );
    response
}

fn served_stale_response(value: Value) -> Response {
    // The `_stale`/`_staleAgeMs` markers are already in the value (Core).
    let mut response = json_response(StatusCode::OK, value);
    response
        .headers_mut()
        .insert("x-served-stale", HeaderValue::from_static("true"));
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    response
}

fn read_limited() -> Response {
    let mut response = json_response(
        StatusCode::TOO_MANY_REQUESTS,
        json!({
            "error": "too many uncached reads, slow down",
            "retryable": true,
        }),
    );
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("10"));
    response
}

fn busy_response() -> Response {
    let mut response = json_response(
        StatusCode::SERVICE_UNAVAILABLE,
        json!({
            "error": "service busy, please retry shortly",
            "retryable": true,
        }),
    );
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("30"));
    response
}

fn retryable_service_unavailable(dependency: &str) -> Response {
    let mut response = json_response(
        StatusCode::SERVICE_UNAVAILABLE,
        json!({
            "error": "upstream dependency temporarily unavailable, please retry",
            "retryable": true,
            "dependency": dependency,
        }),
    );
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("2"));
    response
}

fn dependency_error(dependency: &str) -> Response {
    retryable_service_unavailable(dependency)
}
fn error_response(status: StatusCode, error: &str) -> Response {
    json_response(status, json!({ "error": error }))
}
fn json_response(status: StatusCode, body: Value) -> Response {
    (status, axum::Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    use std::{
        env,
        net::SocketAddr,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use async_trait::async_trait;
    use axum::{
        Router,
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use p256::elliptic_curve::{Generate, sec1::ToSec1Point};
    use serde_json::{Value, json};
    use tower::ServiceExt;

    use super::{AppState, record_cache_key, router, wallet_cache_key};
    use crate::{
        chain::{ChainError, ReadChain},
        config::Config,
        queue::{CreateTaskQueue, QueueError},
        store::RedisStore,
    };
    use p256_registrar::{
        lookup::{Page, Record, SiteItem},
        task::CreateTask,
    };

    #[derive(Default)]
    struct FakeQueue {
        tasks: Mutex<Vec<CreateTask>>,
    }

    #[async_trait]
    impl CreateTaskQueue for FakeQueue {
        async fn enqueue(&self, task: &CreateTask) -> Result<(), QueueError> {
            self.tasks
                .lock()
                .expect("test queue lock")
                .push(task.clone());
            Ok(())
        }
    }

    struct OfflineChain;

    #[async_trait]
    impl ReadChain for OfflineChain {
        fn rpc_circuit_state(&self) -> &'static str {
            "open"
        }

        async fn get_record(&self, _: &str, _: &str) -> Result<Option<Record>, ChainError> {
            Err(ChainError::Unavailable)
        }

        async fn get_record_by_wallet_ref(
            &self,
            _: alloy::primitives::B256,
        ) -> Result<Option<Record>, ChainError> {
            Err(ChainError::Unavailable)
        }

        async fn total_credentials(&self) -> Result<u64, ChainError> {
            Err(ChainError::Unavailable)
        }

        async fn list_sites(&self, _: u64, _: u64, _: bool) -> Result<Page<SiteItem>, ChainError> {
            Err(ChainError::Unavailable)
        }

        async fn list_keys(
            &self,
            _: &str,
            _: u64,
            _: u64,
            _: bool,
        ) -> Result<Page<Record>, ChainError> {
            Err(ChainError::Unavailable)
        }
    }

    fn test_config() -> Config {
        Config {
            listen_addr: "127.0.0.1:0".parse::<SocketAddr>().expect("test address"),
            // This test-only salt keeps rate-limit keys isolated across repeated runs against
            // the same Redis instance; no chain writer is constructed from this config.
            private_key: Some(format!("test-ip-salt-{}", uuid::Uuid::new_v4())),
            commit_private_key: None,
            alchemy_api_key: None,
            iggy_url: "iggy+tcp://unused".into(),
            iggy_consumer_url: "iggy+tcp://unused".into(),
            iggy_provisioner_url: "iggy+tcp://unused".into(),
            redis_url: "redis://unused".into(),
            queue_worker_enabled: false,
            telegram_bot_token: None,
            telegram_chat_id: None,
            global_write_limit: 10_000,
            iggy_enqueue_timeout: Duration::from_secs(1),
            iggy_consumer_group: "test".into(),
        }
    }

    async fn request(
        app: &Router,
        method: &str,
        uri: &str,
        body: &str,
    ) -> axum::response::Response {
        app.clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_owned()))
                    .expect("test request"),
            )
            .await
            .expect("router response")
    }

    async fn response_json(response: axum::response::Response) -> Value {
        let body = to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("response body");
        serde_json::from_slice(&body).expect("JSON response")
    }

    #[tokio::test]
    #[ignore = "requires P256_INDEX_TEST_REDIS_URL"]
    async fn http_contract_is_preserved_with_real_redis() {
        let redis_url = env::var("P256_INDEX_TEST_REDIS_URL")
            .expect("P256_INDEX_TEST_REDIS_URL is required for this integration test");
        let store = RedisStore::connect(&redis_url).await.expect("test Redis");
        let initial_queue_depth = store
            .queue_stats()
            .await
            .expect("initial queue stats")
            .depth;
        let queue = Arc::new(FakeQueue::default());
        let state = AppState::with_clients(
            store.clone(),
            queue.clone(),
            Arc::new(OfflineChain),
            &test_config(),
        );
        let app = router(state);
        let suffix = uuid::Uuid::new_v4();
        let signing_key = p256::SecretKey::generate();
        let public_key = hex::encode(signing_key.public_key().to_sec1_point(false).as_bytes());
        let wallet_ref =
            p256_registrar::wallet::build_wallet_ref(&public_key).expect("valid P-256 key");
        let rp_id = format!("http-contract-{suffix}.invalid");
        let credential_id = format!("credential-{suffix}");
        let create_body = json!({
            "rpId": rp_id,
            "credentialId": credential_id,
            "publicKey": public_key,
            "name": "Contract verification key",
        })
        .to_string();

        let options = request(&app, "OPTIONS", "/api/create", "").await;
        assert_eq!(options.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            options
                .headers()
                .get("access-control-allow-origin")
                .and_then(|value| value.to_str().ok()),
            Some("*")
        );

        let invalid = request(&app, "POST", "/api/create", "not-json").await;
        assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);

        let invalid_length = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/create")
                    .header("content-type", "application/json")
                    .header("content-length", "not-a-number")
                    .body(Body::from("{}"))
                    .expect("test request"),
            )
            .await
            .expect("router response");
        assert_eq!(invalid_length.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let missing_id = request(&app, "GET", "/api/create/", "").await;
        assert_eq!(missing_id.status(), StatusCode::BAD_REQUEST);

        let challenge = request(&app, "GET", "/api/challenge", "").await;
        assert_eq!(challenge.status(), StatusCode::OK);
        let challenge = response_json(challenge).await;
        assert!(challenge["challenge"].as_str().is_some_and(|value| {
            value.len() == 43
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        }));

        let created = request(&app, "POST", "/api/create", &create_body).await;
        assert_eq!(created.status(), StatusCode::ACCEPTED);
        let created = response_json(created).await;
        assert_eq!(created["status"], "pending");
        let id = created["id"].as_str().expect("create id").to_owned();

        let duplicate = request(&app, "POST", "/api/create", &create_body).await;
        assert_eq!(duplicate.status(), StatusCode::ACCEPTED);
        assert_eq!(response_json(duplicate).await["id"], id);
        assert_eq!(queue.tasks.lock().expect("test queue lock").len(), 1);

        let status = request(&app, "GET", &format!("/api/create/{id}"), "").await;
        assert_eq!(status.status(), StatusCode::OK);
        let status = response_json(status).await;
        assert_eq!(status["status"], "pending");
        assert!(status.get("credentialId").is_none());
        assert!(status.get("walletRef").is_none());

        let conflict_body = json!({
            "rpId": format!("other-{suffix}.invalid"),
            "credentialId": format!("other-{suffix}"),
            "publicKey": public_key,
            "name": "Conflicting key",
        })
        .to_string();
        let conflict = request(&app, "POST", "/api/create", &conflict_body).await;
        assert_eq!(conflict.status(), StatusCode::CONFLICT);
        assert!(response_json(conflict).await["walletRef"].is_string());

        store
            .cache_set_negative(&record_cache_key(&rp_id, &credential_id))
            .await
            .expect("negative record cache");
        let record_query = request(
            &app,
            "GET",
            &format!("/api/query?rpId={rp_id}&credentialId={credential_id}"),
            "",
        )
        .await;
        assert_eq!(record_query.status(), StatusCode::OK);
        let record_query = response_json(record_query).await;
        assert_eq!(record_query["_queue"]["id"], id);
        assert!(record_query.get("credentialId").is_none());
        assert!(record_query.get("walletRef").is_none());

        store
            .cache_set_negative(&wallet_cache_key(&wallet_ref))
            .await
            .expect("negative wallet cache");
        let wallet_query = request(
            &app,
            "GET",
            &format!("/api/query?walletRef={wallet_ref}"),
            "",
        )
        .await;
        assert_eq!(wallet_query.status(), StatusCode::OK);
        assert_eq!(response_json(wallet_query).await["_queue"]["id"], id);

        let invalid_wallet = request(&app, "GET", "/api/query?walletRef=abc", "").await;
        assert_eq!(invalid_wallet.status(), StatusCode::BAD_REQUEST);

        let health = request(&app, "GET", "/api/health", "").await;
        assert_eq!(health.status(), StatusCode::OK);
        let health = response_json(health).await;
        assert_eq!(health["status"], "ok");
        assert_eq!(health["queue"]["depth"], initial_queue_depth + 1);
    }
}
