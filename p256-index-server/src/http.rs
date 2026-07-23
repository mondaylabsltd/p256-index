use std::{sync::Arc, time::Duration};

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

use crate::{
    chain::{Chain, ReadChain},
    config::Config,
    contract::{build_wallet_ref, default_metadata, parse_b256},
    queue::{CreateQueue, CreateTaskQueue},
    store::{Admission, CacheRead, RedisStore, derive_ip_salt, hash_ip},
    types::{CHAIN_ID, CreateRequest, CreateTask, Record, TaskStatus},
};

const MAX_BODY_SIZE: usize = 32 * 1024;
const MAX_ACTIVE_QUEUE_DEPTH: u64 = 10_000;
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
            let mut reasons = Vec::new();
            if stats.depth >= 2_000 {
                reasons.push("queue-depth");
            }
            if stats.dlq_count >= 25 {
                reasons.push("dlq");
            }
            if stats.oldest_active_age_ms >= 30 * 60_000 {
                reasons.push("oldest-job");
            }
            let status = if reasons.is_empty() { "ok" } else { "degraded" };
            let mut body = json!({
                "service": "webauthn-p256-publickey-index",
                "version": "1.0.0",
                "chainId": CHAIN_ID,
                "contract": crate::types::CONTRACT_ADDRESS,
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
                "contract": crate::types::CONTRACT_ADDRESS,
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
    let input = match validate_create(request) {
        Ok(input) => input,
        Err(message) => return error_response(StatusCode::BAD_REQUEST, &message),
    };

    let ip_hash = hash_ip(&state.ip_hash_salt, &ip);
    match state.store.allow_ip_create(&ip_hash).await {
        Ok(true) => {}
        Ok(false) => {
            return error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "rate limit exceeded, max 5 requests per minute",
            );
        }
        Err(_) => return dependency_error("redis"),
    }

    let cache_key = record_cache_key(&input.rp_id, &input.credential_id);
    match state.store.cache_get(&cache_key, RECORD_STALE_LIMIT).await {
        Ok(CacheRead::Fresh(value)) => return done_response(value),
        Ok(_) => {}
        Err(_) => return dependency_error("redis"),
    }
    match state
        .chain
        .get_record(&input.rp_id, &input.credential_id)
        .await
    {
        Ok(Some(record)) => {
            let value = record_value(&record);
            if state
                .store
                .cache_set(&cache_key, value.clone(), false)
                .await
                .is_err()
            {
                return dependency_error("redis");
            }
            return done_response(value);
        }
        Ok(None) => {}
        Err(_) => {} // Existing Deno behavior is fail-open for chain prechecks.
    }

    match state
        .store
        .find_by_record(&input.rp_id, &input.credential_id)
        .await
    {
        Ok(Some(task)) if task.status != TaskStatus::Failed => {
            return queued_response(&task);
        }
        Ok(_) => {}
        Err(_) => return dependency_error("redis"),
    }
    match state.store.find_by_wallet_ref(&input.wallet_ref).await {
        Ok(Some(task))
            if task.status != TaskStatus::Failed
                && (task.rp_id != input.rp_id || task.credential_id != input.credential_id) =>
        {
            return wallet_conflict(
                &input.wallet_ref,
                "this publicKey is already being registered under a different credential (walletRef conflict)",
            );
        }
        Ok(_) => {}
        Err(_) => return dependency_error("redis"),
    }
    let wallet_cache_key = wallet_cache_key(&input.wallet_ref);
    match state
        .store
        .cache_get(&wallet_cache_key, RECORD_STALE_LIMIT)
        .await
    {
        Ok(CacheRead::Fresh(value)) => {
            if same_record(&value, &input.rp_id, &input.credential_id) {
                return done_response(value);
            }
            return wallet_conflict(
                &input.wallet_ref,
                "this publicKey is already registered under a different credential (walletRef conflict)",
            );
        }
        Ok(_) => {}
        Err(_) => return dependency_error("redis"),
    }
    match state
        .chain
        .get_record_by_wallet_ref(input.wallet_ref.parse().expect("validated bytes32"))
        .await
    {
        Ok(Some(record)) => {
            let value = record_value(&record);
            if state
                .store
                .cache_set(&wallet_cache_key, value.clone(), false)
                .await
                .is_err()
            {
                return dependency_error("redis");
            }
            if same_record(&value, &input.rp_id, &input.credential_id) {
                let _ = state
                    .store
                    .cache_set(&cache_key, value.clone(), false)
                    .await;
                return done_response(value);
            }
            return wallet_conflict(
                &input.wallet_ref,
                "this publicKey is already registered under a different credential (walletRef conflict)",
            );
        }
        Ok(None) => {}
        Err(_) => {}
    }

    match state.store.queue_stats().await {
        Ok(stats) if stats.depth >= MAX_ACTIVE_QUEUE_DEPTH => return busy_response(),
        Ok(_) => {}
        Err(_) => return dependency_error("redis"),
    }
    match state
        .store
        .allow_global_create(state.global_write_limit)
        .await
    {
        Ok(true) => {}
        Ok(false) => return busy_response(),
        Err(_) => return dependency_error("redis"),
    }

    let task = CreateTask {
        id: Uuid::new_v4().to_string(),
        status: TaskStatus::Pending,
        rp_id: input.rp_id,
        credential_id: input.credential_id,
        wallet_ref: input.wallet_ref,
        public_key: input.public_key,
        name: input.name,
        initial_credential_id: input.initial_credential_id,
        metadata: input.metadata,
        tx_hash: None,
        error: None,
        retries: 0,
        created_at: now_ms() as i64,
        admitted: false,
    };
    match state.store.admit(&task).await {
        Ok(Admission::WalletConflict(_)) => wallet_conflict(
            &task.wallet_ref,
            "this publicKey is already being registered under a different credential (walletRef conflict)",
        ),
        Ok(Admission::Existing(id)) => match state.store.get_task(&id).await {
            Ok(Some(existing)) if existing.admitted => queued_response(&existing),
            Ok(Some(existing)) => enqueue_task(&state, &existing).await,
            Ok(None) => dependency_error("redis"),
            Err(_) => dependency_error("redis"),
        },
        Ok(Admission::New(_)) => enqueue_task(&state, &task).await,
        Err(_) => dependency_error("redis"),
    }
}

async fn enqueue_task(state: &AppState, task: &CreateTask) -> Response {
    match state.queue.enqueue(task).await {
        Ok(()) => match state.store.mark_admitted(&task.id).await {
            Ok(Some(task)) => queued_response(&task),
            _ => dependency_error("redis"),
        },
        // Do not delete Redis admission: Iggy could have appended before its acknowledgement was
        // lost. Retrying the same request reuses the task ID and is safe for the consumer.
        Err(_) => retryable_service_unavailable("queue"),
    }
}

async fn create_status(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    match state.store.get_task(&id).await {
        Ok(Some(task)) => task_status_response(&task),
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
    if let Some(wallet_ref) = params.wallet_ref {
        return query_by_wallet_ref(state, wallet_ref, headers).await;
    }
    let (Some(rp_id), Some(credential_id)) = (params.rp_id, params.credential_id) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "rpId and credentialId are required (or walletRef)",
        );
    };
    if let Err(message) = validate_strings(&[
        ("rpId", &rp_id, 253),
        ("credentialId", &credential_id, 1024),
    ]) {
        return error_response(StatusCode::BAD_REQUEST, &message);
    }
    let cache_key = record_cache_key(&rp_id, &credential_id);
    let cached = match state.store.cache_get(&cache_key, RECORD_STALE_LIMIT).await {
        Ok(cached) => cached,
        Err(_) => return dependency_error("redis"),
    };
    if let CacheRead::Fresh(value) = cached {
        return cached_response(value);
    }
    if matches!(cached, CacheRead::Negative) {
        return match state.store.find_by_record(&rp_id, &credential_id).await {
            Ok(Some(task)) if task.status != TaskStatus::Failed => queue_fallback(&task),
            Ok(_) => error_response(StatusCode::NOT_FOUND, "not found"),
            Err(_) => dependency_error("redis"),
        };
    }
    let stale = match cached {
        CacheRead::Stale { value, age_ms } => Some((value, age_ms)),
        _ => None,
    };
    if !allow_read(&state, &headers).await {
        return read_limited();
    }
    match state.chain.get_record(&rp_id, &credential_id).await {
        Ok(Some(record)) => {
            let value = record_value(&record);
            if state
                .store
                .cache_set(&cache_key, value.clone(), false)
                .await
                .is_err()
            {
                return dependency_error("redis");
            }
            cached_response(value)
        }
        Ok(None) => {
            if state.store.cache_set_negative(&cache_key).await.is_err() {
                return dependency_error("redis");
            }
            match state.store.find_by_record(&rp_id, &credential_id).await {
                Ok(Some(task)) if task.status != TaskStatus::Failed => queue_fallback(&task),
                Ok(_) => error_response(StatusCode::NOT_FOUND, "not found"),
                Err(_) => dependency_error("redis"),
            }
        }
        Err(_) => stale_or_dependency(stale, "rpc"),
    }
}

async fn query_by_wallet_ref(state: AppState, wallet_ref: String, headers: HeaderMap) -> Response {
    if !wallet_ref.starts_with("0x") || wallet_ref.len() != 66 {
        return error_response(
            StatusCode::BAD_REQUEST,
            "walletRef must be a 0x-prefixed 32-byte hex string",
        );
    }
    if let Err(message) = validate_wallet_ref(&wallet_ref) {
        return error_response(StatusCode::BAD_REQUEST, &message);
    }
    let wallet_ref = wallet_ref.to_ascii_lowercase();
    let cache_key = wallet_cache_key(&wallet_ref);
    let cached = match state.store.cache_get(&cache_key, RECORD_STALE_LIMIT).await {
        Ok(cached) => cached,
        Err(_) => return dependency_error("redis"),
    };
    if let CacheRead::Fresh(value) = cached {
        return cached_response(value);
    }
    if matches!(cached, CacheRead::Negative) {
        return match state.store.find_by_wallet_ref(&wallet_ref).await {
            Ok(Some(task)) if task.status != TaskStatus::Failed => queue_fallback(&task),
            Ok(_) => error_response(StatusCode::NOT_FOUND, "not found"),
            Err(_) => dependency_error("redis"),
        };
    }
    let stale = match cached {
        CacheRead::Stale { value, age_ms } => Some((value, age_ms)),
        _ => None,
    };
    if !allow_read(&state, &headers).await {
        return read_limited();
    }
    match state
        .chain
        .get_record_by_wallet_ref(wallet_ref.parse().expect("validated bytes32"))
        .await
    {
        Ok(Some(record)) => {
            let value = record_value(&record);
            if state
                .store
                .cache_set(&cache_key, value.clone(), false)
                .await
                .is_err()
            {
                return dependency_error("redis");
            }
            cached_response(value)
        }
        Ok(None) => {
            if state.store.cache_set_negative(&cache_key).await.is_err() {
                return dependency_error("redis");
            }
            match state.store.find_by_wallet_ref(&wallet_ref).await {
                Ok(Some(task)) if task.status != TaskStatus::Failed => queue_fallback(&task),
                Ok(_) => error_response(StatusCode::NOT_FOUND, "not found"),
                Err(_) => dependency_error("redis"),
            }
        }
        Err(_) => stale_or_dependency(stale, "rpc"),
    }
}

async fn total_credentials(State(state): State<AppState>, headers: HeaderMap) -> Response {
    const KEY: &str = "stats:totalCredentials";
    let cached = match state.store.cache_get(KEY, STATS_STALE_LIMIT).await {
        Ok(cached) => cached,
        Err(_) => return dependency_error("redis"),
    };
    if let CacheRead::Fresh(value) = cached {
        return cached_response(value);
    }
    let stale = match cached {
        CacheRead::Stale { value, age_ms } => Some((value, age_ms)),
        _ => None,
    };
    if !allow_read(&state, &headers).await {
        return read_limited();
    }
    match state.chain.total_credentials().await {
        Ok(total) => {
            let value = json!({ "totalCredentials": total });
            if state
                .store
                .cache_set(KEY, value.clone(), true)
                .await
                .is_err()
            {
                return dependency_error("redis");
            }
            cached_response(value)
        }
        Err(_) => stale_or_dependency(stale, "rpc"),
    }
}

async fn list_sites(
    State(state): State<AppState>,
    Query(params): Query<QueryParams>,
    headers: HeaderMap,
) -> Response {
    let (page, page_size, descending) = pagination(&params);
    if page > 10_000 {
        return json_response(
            StatusCode::OK,
            json!({ "total": 0, "page": page, "pageSize": page_size, "items": [] }),
        );
    }
    let key = format!("stats:rpIds:{page}:{page_size}:{descending}");
    let cached = match state.store.cache_get(&key, STATS_STALE_LIMIT).await {
        Ok(value) => value,
        Err(_) => return dependency_error("redis"),
    };
    if let CacheRead::Fresh(value) = cached {
        return cached_response(value);
    }
    let stale = match cached {
        CacheRead::Stale { value, age_ms } => Some((value, age_ms)),
        _ => None,
    };
    if !allow_read(&state, &headers).await {
        return read_limited();
    }
    match state.chain.list_sites(page, page_size, descending).await {
        Ok(page) => {
            let value = serde_json::to_value(page).expect("serializable sites page");
            if state
                .store
                .cache_set(&key, value.clone(), true)
                .await
                .is_err()
            {
                return dependency_error("redis");
            }
            cached_response(value)
        }
        Err(_) => stale_or_dependency(stale, "rpc"),
    }
}

async fn list_keys(
    State(state): State<AppState>,
    Query(params): Query<QueryParams>,
    headers: HeaderMap,
) -> Response {
    let (page, page_size, descending) = pagination(&params);
    let Some(rp_id) = params.rp_id else {
        return error_response(StatusCode::BAD_REQUEST, "rpId is required");
    };
    if let Err(message) = validate_strings(&[("rpId", &rp_id, 253)]) {
        return error_response(StatusCode::BAD_REQUEST, &message);
    }
    if page > 10_000 {
        return json_response(
            StatusCode::OK,
            json!({ "total": 0, "page": page, "pageSize": page_size, "items": [] }),
        );
    }
    let key = format!("stats:keys:{rp_id}:{page}:{page_size}:{descending}");
    let cached = match state.store.cache_get(&key, STATS_STALE_LIMIT).await {
        Ok(value) => value,
        Err(_) => return dependency_error("redis"),
    };
    if let CacheRead::Fresh(value) = cached {
        return cached_response(value);
    }
    let stale = match cached {
        CacheRead::Stale { value, age_ms } => Some((value, age_ms)),
        _ => None,
    };
    if !allow_read(&state, &headers).await {
        return read_limited();
    }
    match state
        .chain
        .list_keys(&rp_id, page, page_size, descending)
        .await
    {
        Ok(page) => {
            let value = serde_json::to_value(page).expect("serializable keys page");
            if state
                .store
                .cache_set(&key, value.clone(), true)
                .await
                .is_err()
            {
                return dependency_error("redis");
            }
            cached_response(value)
        }
        Err(_) => stale_or_dependency(stale, "rpc"),
    }
}

async fn not_found() -> Response {
    error_response(StatusCode::NOT_FOUND, "not found")
}

struct ValidCreate {
    rp_id: String,
    credential_id: String,
    wallet_ref: String,
    public_key: String,
    name: String,
    initial_credential_id: String,
    metadata: String,
}

fn validate_create(request: CreateRequest) -> Result<ValidCreate, String> {
    let (Some(rp_id), Some(credential_id), Some(public_key), Some(name)) = (
        request.rp_id,
        request.credential_id,
        request.public_key,
        request.name,
    ) else {
        return Err("rpId, credentialId, publicKey, and name are required".into());
    };
    if rp_id.is_empty() || credential_id.is_empty() || public_key.is_empty() || name.is_empty() {
        return Err("rpId, credentialId, publicKey, and name are required".into());
    }
    validate_strings(&[
        ("rpId", &rp_id, 253),
        ("credentialId", &credential_id, 1024),
        ("publicKey", &public_key, 130),
        ("name", &name, 256),
    ])?;
    validate_public_key(&public_key)?;
    if let Some(wallet_ref) = request.wallet_ref.as_deref() {
        validate_wallet_ref(wallet_ref)?;
    }
    if let Some(initial) = request.initial_credential_id.as_deref() {
        validate_strings(&[("initialCredentialId", initial, 1024)])?;
    }
    if let Some(metadata) = request.metadata.as_deref() {
        validate_metadata(metadata)?;
    }
    let wallet_ref = build_wallet_ref(&public_key).map_err(|error| error.to_string())?;
    if let Some(supplied) = request.wallet_ref
        && supplied.to_ascii_lowercase() != wallet_ref
    {
        return Err("walletRef does not match publicKey".into());
    }
    let initial_credential_id = request
        .initial_credential_id
        .unwrap_or_else(|| credential_id.clone());
    let metadata = match request.metadata {
        Some(metadata) => metadata,
        None => default_metadata(&public_key).map_err(|error| error.to_string())?,
    };
    Ok(ValidCreate {
        rp_id,
        credential_id,
        wallet_ref,
        public_key,
        name,
        initial_credential_id,
        metadata,
    })
}

fn validate_public_key(value: &str) -> Result<(), String> {
    let raw = value.strip_prefix("0x").unwrap_or(value);
    if !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("publicKey must be a valid hex string".into());
    }
    if raw.len() != 130 || !raw.starts_with("04") {
        return Err("publicKey must be an uncompressed P-256 point (04 + 64-byte X/Y)".into());
    }
    Ok(())
}

fn validate_strings(values: &[(&str, &str, usize)]) -> Result<(), String> {
    for (name, value, maximum) in values {
        if value.len() > *maximum {
            return Err(format!("{name} exceeds max length ({maximum})"));
        }
    }
    Ok(())
}

fn validate_wallet_ref(value: &str) -> Result<(), String> {
    if value.len() > 66 {
        return Err("walletRef exceeds max length (66)".into());
    }
    let raw = value.strip_prefix("0x").unwrap_or(value);
    if raw.len() != 64 {
        return Err("walletRef must be a 32-byte hex string (64 hex chars)".into());
    }
    let normalized = if value.starts_with("0x") {
        value.to_owned()
    } else {
        format!("0x{value}")
    };
    parse_b256(&normalized).map_err(|_| "walletRef must be a valid hex string".to_owned())?;
    Ok(())
}

fn validate_metadata(value: &str) -> Result<(), String> {
    if value.len() > 4096 {
        return Err("metadata exceeds max length (4096)".into());
    }
    let raw = value.strip_prefix("0x").unwrap_or(value);
    if !raw.len().is_multiple_of(2) {
        return Err("metadata must be byte-aligned hex (even number of hex chars)".into());
    }
    if !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("metadata must be a valid hex string".into());
    }
    Ok(())
}

fn pagination(params: &QueryParams) -> (u64, u64, bool) {
    let page = params.page.unwrap_or(1).max(1);
    let page_size = params.page_size.unwrap_or(20).clamp(1, 100);
    let descending = params.order.as_deref() != Some("asc");
    (page, page_size, descending)
}

async fn allow_read(state: &AppState, headers: &HeaderMap) -> bool {
    let hash = hash_ip(&state.ip_hash_salt, &client_ip(headers));
    state.store.allow_read(&hash).await.unwrap_or(true)
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

fn same_record(value: &Value, rp_id: &str, credential_id: &str) -> bool {
    value.get("rpId").and_then(Value::as_str) == Some(rp_id)
        && value.get("credentialId").and_then(Value::as_str) == Some(credential_id)
}

fn queued_response(task: &CreateTask) -> Response {
    json_response(
        StatusCode::ACCEPTED,
        json!({ "id": task.id, "status": task.status }),
    )
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

fn task_status_response(task: &CreateTask) -> Response {
    if task.status == TaskStatus::Done {
        return json_response(
            StatusCode::OK,
            json!({
                "id": task.id,
                "status": task.status,
                "rpId": task.rp_id,
                "credentialId": task.credential_id,
                "walletRef": task.wallet_ref,
                "publicKey": task.public_key,
                "name": task.name,
                "txHash": task.tx_hash,
                "createdAt": task.created_at,
            }),
        );
    }
    json_response(
        StatusCode::OK,
        json!({
            "id": task.id,
            "status": task.status,
            "rpId": task.rp_id,
            "publicKey": task.public_key,
            "name": task.name,
            "error": task.error,
            "createdAt": task.created_at,
        }),
    )
}

fn queue_fallback(task: &CreateTask) -> Response {
    json_response(
        StatusCode::OK,
        json!({
            "rpId": task.rp_id,
            "publicKey": task.public_key,
            "name": task.name,
            "metadata": task.metadata,
            "createdAt": task.created_at,
            "_queue": { "id": task.id, "status": task.status },
        }),
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

fn stale_or_dependency(stale: Option<(Value, u64)>, dependency: &str) -> Response {
    match stale {
        Some((mut value, age_ms)) => {
            if let Some(object) = value.as_object_mut() {
                object.insert("_stale".into(), Value::Bool(true));
                object.insert("_staleAgeMs".into(), json!(age_ms));
            }
            let mut response = json_response(StatusCode::OK, value);
            response
                .headers_mut()
                .insert("x-served-stale", HeaderValue::from_static("true"));
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
            response
        }
        None => dependency_error(dependency),
    }
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

    use super::{
        AppState, pagination, record_cache_key, router, validate_create, wallet_cache_key,
    };
    use crate::{
        chain::{ChainError, ReadChain},
        config::Config,
        queue::{CreateTaskQueue, QueueError},
        store::RedisStore,
        types::{CreateRequest, CreateTask, Page, Record, SiteItem},
    };

    const KEY: &str = "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";

    #[test]
    fn create_validation_derives_wallet_ref_and_metadata() {
        let input = validate_create(CreateRequest {
            rp_id: Some("example.com".into()),
            credential_id: Some("credential".into()),
            wallet_ref: None,
            public_key: Some(KEY.into()),
            name: Some("My passkey".into()),
            initial_credential_id: None,
            metadata: None,
        })
        .unwrap();
        assert_eq!(
            input.wallet_ref,
            "0x000000000000000000000000d602f36e97fa37801565e3dc02f78ee0769d8fd6"
        );
        assert!(input.metadata.starts_with("0x"));
    }

    #[test]
    fn pagination_clamps_to_the_published_contract() {
        let params = super::QueryParams {
            rp_id: None,
            credential_id: None,
            wallet_ref: None,
            page: Some(0),
            page_size: Some(101),
            order: Some("asc".into()),
        };
        assert_eq!(pagination(&params), (1, 100, false));
    }

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
        let wallet_ref = crate::contract::build_wallet_ref(&public_key).expect("valid P-256 key");
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
