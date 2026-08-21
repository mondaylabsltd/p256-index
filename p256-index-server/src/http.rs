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
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

use p256_registrar::{
    admission::{
        AdmissionApp, AdmissionEffect, AdmissionEvent, AdmissionOperation, AdmissionOutcome,
        AdmissionRequest, AdmissionResult, AdmitOutcome, ReferRequest, RegisterRequest,
    },
    admission::{validate_attestation_hex, validate_public_key_hex},
    lookup::{
        ChainFetch, LookupApp, LookupCacheKey, LookupEffect, LookupEndpoint, LookupEvent,
        LookupOperation, LookupOutcome, LookupParams, LookupResult, TtlClass, task_status_body,
    },
    protocol::{
        challenge_for, content_hash_for, member_binding_for, parse_b256, parse_hex_bytes,
        reference_binding_for,
    },
    sentinel,
    task::TaskStatus,
};

use crate::{
    chain::{GroupDetail, ReadChain},
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
        .route("/api/refer", post(refer))
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

/// Compute storage-authorization challenges, enforcing exactly what
/// admission (and the contract) will accept — a challenge handed out here
/// is never one that register must reject.
///
/// Three modes, mirroring the three signing roles:
/// - MEMBER mode ({rpId, groupPublicKey, publicKey, attestation?}): the
///   binding a passkey signs the moment it is created — independent of the
///   metadata and of every sibling.
/// - REFERENCE mode (member mode body plus "refer": true and an optional
///   "metadata"): the binding a passkey signs to point at an existing
///   group.
/// - GROUP mode ({rpId, metadata?, groupPublicKey, members: [{publicKey,
///   attestation?}]}): the group's content hash and the group key's
///   closing challenge, once the group is final (member challenges are
///   echoed too).
async fn challenge(State(state): State<AppState>, request: Request<Body>) -> Response {
    let Ok(bytes) = to_bytes(request.into_body(), MAX_BODY_SIZE).await else {
        return error_response(StatusCode::PAYLOAD_TOO_LARGE, "request body too large");
    };
    let Ok(body) = serde_json::from_slice::<Value>(&bytes) else {
        return error_response(StatusCode::BAD_REQUEST, "invalid JSON body");
    };

    let Some(rp_id) = body.get("rpId").and_then(Value::as_str) else {
        return error_response(StatusCode::BAD_REQUEST, "rpId is required");
    };
    if rp_id.is_empty() || rp_id.len() > 253 {
        return error_response(StatusCode::BAD_REQUEST, "rpId must be 1..=253 bytes");
    }
    let Some(group_public_key) = body.get("groupPublicKey").and_then(Value::as_str) else {
        return error_response(StatusCode::BAD_REQUEST, "groupPublicKey is required");
    };
    let group_public_key = match validate_public_key_hex(group_public_key) {
        Ok(normalized) => normalized,
        Err(message) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                &format!("groupPublicKey: {message}"),
            );
        }
    };
    let group_key_bytes = hex::decode(&group_public_key).expect("validated hex");
    let Ok(registry) = state.chain.registry_address().parse() else {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "registry misconfigured");
    };

    let render_challenge = |challenge: alloy::primitives::B256| {
        json!({
            "challenge": format!("{challenge:#x}"),
            "challengeBase64url": URL_SAFE_NO_PAD.encode(challenge.0),
        })
    };

    if body.get("members").is_some() && body.get("refer").and_then(Value::as_bool) == Some(true) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "choose one mode: members (group) or refer (reference), not both",
        );
    }

    // MEMBER mode: one passkey signing at creation.
    if body.get("members").is_none() {
        let Some(public_key) = body.get("publicKey").and_then(Value::as_str) else {
            return error_response(
                StatusCode::BAD_REQUEST,
                "publicKey (member mode) or members (group mode) is required",
            );
        };
        let public_key = match validate_public_key_hex(public_key) {
            Ok(normalized) => normalized,
            Err(message) => {
                return error_response(StatusCode::BAD_REQUEST, &format!("publicKey: {message}"));
            }
        };
        if public_key == group_public_key {
            return error_response(
                StatusCode::BAD_REQUEST,
                "the group key cannot also be a member",
            );
        }
        let attestation = match validate_attestation_hex(
            body.get("attestation")
                .and_then(Value::as_str)
                .unwrap_or(""),
        ) {
            Ok(normalized) => normalized,
            Err(message) => {
                return error_response(StatusCode::BAD_REQUEST, &format!("attestation: {message}"));
            }
        };
        let attestation_bytes = parse_hex_bytes(&attestation).expect("validated hex");
        let binding = if body.get("refer").and_then(Value::as_bool).unwrap_or(false) {
            let metadata = body.get("metadata").and_then(Value::as_str).unwrap_or("");
            let metadata_bytes = match parse_hex_bytes(metadata) {
                Ok(bytes) if bytes.len() <= p256_registrar::admission::MAX_METADATA_BYTES => bytes,
                Ok(_) => {
                    return error_response(StatusCode::BAD_REQUEST, "metadata exceeds max length");
                }
                Err(_) => return error_response(StatusCode::BAD_REQUEST, "metadata must be hex"),
            };
            reference_binding_for(&group_key_bytes, &attestation_bytes, &metadata_bytes)
        } else {
            member_binding_for(&group_key_bytes, &attestation_bytes)
        };
        let key_bytes = hex::decode(&public_key).expect("validated hex");
        let challenge = challenge_for(state.chain_id, registry, rp_id, &key_bytes, binding);
        let mut response = render_challenge(challenge);
        response["binding"] = json!(format!("{binding:#x}"));
        return json_response(StatusCode::OK, response);
    }

    // GROUP mode: the finished unit's content hash and closing challenge.
    let members = body
        .get("members")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if members.is_empty() || members.len() > p256_registrar::admission::MAX_MEMBERS {
        return error_response(
            StatusCode::BAD_REQUEST,
            "members must contain 1 to 7 entries",
        );
    }
    let metadata = body.get("metadata").and_then(Value::as_str).unwrap_or("");
    let metadata_bytes = match parse_hex_bytes(metadata) {
        Ok(bytes) if bytes.len() <= p256_registrar::admission::MAX_METADATA_BYTES => bytes,
        Ok(_) => return error_response(StatusCode::BAD_REQUEST, "metadata exceeds max length"),
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "metadata must be hex"),
    };
    let metadata = if metadata_bytes.is_empty() {
        String::new()
    } else {
        format!("0x{}", hex::encode(&metadata_bytes))
    };

    let mut skeleton_members = Vec::with_capacity(members.len());
    for (index, member) in members.iter().enumerate() {
        let Some(public_key) = member.get("publicKey").and_then(Value::as_str) else {
            return error_response(
                StatusCode::BAD_REQUEST,
                &format!("members[{index}]: publicKey is required"),
            );
        };
        let public_key = match validate_public_key_hex(public_key) {
            Ok(normalized) => normalized,
            Err(message) => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    &format!("members[{index}]: {message}"),
                );
            }
        };
        if public_key == group_public_key {
            return error_response(
                StatusCode::BAD_REQUEST,
                &format!("members[{index}]: the group key cannot also be a member"),
            );
        }
        if skeleton_members
            .iter()
            .any(|earlier: &p256_registrar::task::Member| earlier.public_key == public_key)
        {
            return error_response(
                StatusCode::BAD_REQUEST,
                &format!("members[{index}]: duplicate public key within the unit"),
            );
        }
        let attestation = match validate_attestation_hex(
            member
                .get("attestation")
                .and_then(Value::as_str)
                .unwrap_or(""),
        ) {
            Ok(normalized) => normalized,
            Err(message) => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    &format!("members[{index}]: {message}"),
                );
            }
        };
        skeleton_members.push(p256_registrar::task::Member {
            public_key,
            attestation,
            proof: p256_registrar::task::Proof {
                authenticator_data: String::new(),
                client_data_json: String::new(),
                challenge_index: 0,
                type_index: 0,
                r: String::new(),
                s: String::new(),
            },
        });
    }
    let skeleton = p256_registrar::task::RegisterTask {
        id: String::new(),
        status: TaskStatus::Pending,
        kind: p256_registrar::task::TaskKind::Register,
        rp_id: rp_id.to_owned(),
        metadata,
        content_hash: String::new(),
        group_public_key: group_public_key.clone(),
        group_proof: Some(p256_registrar::task::Proof {
            authenticator_data: String::new(),
            client_data_json: String::new(),
            challenge_index: 0,
            type_index: 0,
            r: String::new(),
            s: String::new(),
        }),
        members: skeleton_members,
        tx_hash: None,
        on_chain_id: None,
        error: None,
        retries: 0,
        created_at: 0,
        admitted: false,
    };
    let content_hash = content_hash_for(&skeleton).expect("validated fields");

    let group_challenge = challenge_for(
        state.chain_id,
        registry,
        rp_id,
        &group_key_bytes,
        content_hash,
    );
    let member_challenges: Vec<Value> = skeleton
        .members
        .iter()
        .map(|member| {
            let key = hex::decode(&member.public_key).expect("validated hex");
            let attestation = parse_hex_bytes(&member.attestation).expect("validated hex");
            let binding = member_binding_for(&group_key_bytes, &attestation);
            let challenge = challenge_for(state.chain_id, registry, rp_id, &key, binding);
            let mut rendered = render_challenge(challenge);
            rendered["publicKey"] = json!(member.public_key);
            rendered
        })
        .collect();
    json_response(
        StatusCode::OK,
        json!({
            "contentHash": format!("{content_hash:#x}"),
            "groupChallenge": render_challenge(group_challenge),
            "members": member_challenges,
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
    drive_admission_request(state, peer, AdmissionRequest::Register(body)).await
}

/// POST /api/refer — one passkey pointing at an existing group.
async fn refer(
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
    let Ok(body) = serde_json::from_slice::<ReferRequest>(&bytes) else {
        return error_response(StatusCode::BAD_REQUEST, "invalid JSON body");
    };

    // Fail-open rpId cross-check: the contract verifies the proof against
    // the GROUP's frozen rpId, not the client's claim. When the chain can
    // tell us the group's record, reject a mismatch here instead of
    // admitting a task that can only revert. A missing group passes (it
    // may be racing through our own pipeline); an RPC failure passes.
    if let (Some(rp_id), Some(group_key)) =
        (body.rp_id.as_deref(), body.group_public_key.as_deref())
        && let Ok(group_key_bytes) = parse_hex_bytes(group_key)
        && let Ok(Some(unit)) = state.chain.unit_by_group_key(group_key_bytes).await
        && unit.rp_id != rp_id
    {
        return error_response(
            StatusCode::BAD_REQUEST,
            "rpId does not match the group's frozen record",
        );
    }
    drive_admission_request(state, peer, AdmissionRequest::Refer(body)).await
}

async fn drive_admission_request(
    state: AppState,
    peer: SocketAddr,
    submitted: AdmissionRequest,
) -> Response {
    let ip_hash = hash_ip(&state.ip_salt, &peer.ip().to_string());
    let core: Core<AdmissionApp> = Core::new();
    let mut effects = core.process_event(AdmissionEvent::Submit {
        request: submitted,
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
        AdmissionOperation::FindTaskByContent { content_hash } => {
            match state.store.find_by_content(content_hash).await {
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
            match state.chain.is_referenced(group, member).await {
                Ok(value) => AdmissionResult::ChainBool { value },
                Err(_) => AdmissionResult::ChainReadFailed,
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
                .key_profile(public_key, page, *limit, *descending)
                .await
            {
                Ok(Some(profile)) => LookupResult::Chain {
                    value: json!({
                        "entry": profile.entry,
                        "groups": { "total": profile.group_total, "unitIds": profile.group_ids },
                        "references": {
                            "total": profile.reference_total,
                            "referenceIds": profile.reference_ids,
                        },
                        "page": page,
                        "pageSize": limit,
                    }),
                },
                Ok(None) => LookupResult::ChainNotFound,
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
        ChainFetch::GroupById {
            unit_id,
            offset,
            limit,
            descending,
        } => {
            let page = offset / limit + 1;
            match state
                .chain
                .group_detail_by_id(*unit_id, page, *limit, *descending)
                .await
            {
                Ok(Some(detail)) => LookupResult::Chain {
                    value: group_detail_json(detail, page, *limit),
                },
                Ok(None) => LookupResult::ChainNotFound,
                Err(_) => LookupResult::ChainFailed,
            }
        }
        ChainFetch::GroupByKey {
            group_public_key,
            offset,
            limit,
            descending,
        } => {
            let Ok(key) = hex::decode(group_public_key) else {
                return LookupResult::ChainFailed;
            };
            let page = offset / limit + 1;
            match state
                .chain
                .group_detail_by_key(key, page, *limit, *descending)
                .await
            {
                Ok(Some(detail)) => LookupResult::Chain {
                    value: group_detail_json(detail, page, *limit),
                },
                Ok(None) => LookupResult::ChainNotFound,
                Err(_) => LookupResult::ChainFailed,
            }
        }
        ChainFetch::Totals => match state.chain.totals().await {
            Ok(totals) => LookupResult::Chain {
                value: json!({
                    "totalEntries": totals.entries,
                    "totalUnits": totals.units,
                    "totalReferences": totals.references,
                    "totalRpIds": totals.rp_ids,
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
                .groups_by_rp_id(rp_id, page, *limit, *descending)
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

/// The group-detail response body, shared by the unitId and groupPublicKey
/// views: the frozen record, one page of founding members, and the
/// discovery-only reference inbox.
fn group_detail_json(detail: GroupDetail, page: u64, page_size: u64) -> Value {
    json!({
        "unit": detail.unit,
        "members": { "total": detail.member_total, "items": detail.members },
        "references": {
            "total": detail.reference_total,
            "referenceIds": detail.reference_ids,
        },
        "page": page,
        "pageSize": page_size,
    })
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
        LookupCacheKey::Unit {
            unit_id,
            page,
            page_size,
            descending,
        } => format!("query:unit:{unit_id}:{page}:{page_size}:{descending}"),
        LookupCacheKey::Group {
            group_key,
            page,
            page_size,
            descending,
        } => format!("query:group:{group_key}:{page}:{page_size}:{descending}"),
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
    use p256_registrar::lookup::{Entry, Page, SiteItem, Unit};
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

        async fn unit(&self, _: u64) -> Result<Option<Unit>, ChainError> {
            Err(ChainError::Unavailable)
        }

        async fn key_profile(
            &self,
            _: &str,
            _: u64,
            _: u64,
            _: bool,
        ) -> Result<Option<crate::chain::KeyProfile>, ChainError> {
            Ok(None)
        }

        async fn groups_by_rp_id(
            &self,
            _: &str,
            _: u64,
            _: u64,
            _: bool,
        ) -> Result<Page<Unit>, ChainError> {
            Err(ChainError::Unavailable)
        }

        async fn is_referenced(&self, _: Vec<u8>, _: Vec<u8>) -> Result<bool, ChainError> {
            Err(ChainError::Unavailable)
        }
        async fn unit_by_group_key(&self, _: Vec<u8>) -> Result<Option<Unit>, ChainError> {
            Err(ChainError::Unavailable)
        }

        async fn group_detail_by_key(
            &self,
            _: Vec<u8>,
            _: u64,
            _: u64,
            _: bool,
        ) -> Result<Option<crate::chain::GroupDetail>, ChainError> {
            Ok(None)
        }

        async fn group_detail_by_id(
            &self,
            _: u64,
            _: u64,
            _: u64,
            _: bool,
        ) -> Result<Option<crate::chain::GroupDetail>, ChainError> {
            Ok(None)
        }

        async fn rp_ids(&self, _: u64, _: u64, _: bool) -> Result<Page<SiteItem>, ChainError> {
            Err(ChainError::Unavailable)
        }

        async fn totals(&self) -> Result<crate::chain::Totals, ChainError> {
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

    /// A raw WebAuthn-shaped proof JSON by `signing` over `challenge`.
    fn proof_json(
        signing: &p256::ecdsa::SigningKey,
        challenge: alloy::primitives::B256,
        rp_id: &str,
    ) -> Value {
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
        json!({
            "authenticatorData": hex::encode(auth_data),
            "clientDataJSON": client_data,
            "challengeIndex": 23,
            "typeIndex": 1,
            "r": format!("0x{}", hex::encode(&bytes[..32])),
            "s": format!("0x{}", hex::encode(&bytes[32..])),
        })
    }

    /// A fully-signed single-member unit exactly the way real clients build
    /// one: a fresh group key and a fresh passkey; the member binds
    /// (groupKey, own attestation), the group key closes over the content
    /// hash. Returns (register body, member pub hex, group pub hex).
    fn signed_unit_json(rp_id: &str, metadata_hex: &str) -> (Value, String, String) {
        let member_signing = p256::ecdsa::SigningKey::from(&p256::SecretKey::generate());
        let member_public = hex::encode(
            member_signing
                .verifying_key()
                .to_sec1_point(false)
                .as_bytes(),
        );
        let group_signing = p256::ecdsa::SigningKey::from(&p256::SecretKey::generate());
        let group_public = hex::encode(
            group_signing
                .verifying_key()
                .to_sec1_point(false)
                .as_bytes(),
        );
        let registry: alloy::primitives::Address = REGISTRY.parse().unwrap();

        let binding = member_binding_for(&hex::decode(&group_public).unwrap(), &[]);
        let member_challenge = challenge_for(
            p256_registrar::protocol::CHAIN_ID,
            registry,
            rp_id,
            &hex::decode(&member_public).unwrap(),
            binding,
        );
        let member_proof = proof_json(&member_signing, member_challenge, rp_id);

        let skeleton = p256_registrar::task::RegisterTask {
            id: String::new(),
            status: TaskStatus::Pending,
            kind: p256_registrar::task::TaskKind::Register,
            rp_id: rp_id.to_owned(),
            metadata: metadata_hex.to_owned(),
            content_hash: String::new(),
            group_public_key: group_public.clone(),
            group_proof: Some(p256_registrar::task::Proof {
                authenticator_data: String::new(),
                client_data_json: String::new(),
                challenge_index: 0,
                type_index: 0,
                r: String::new(),
                s: String::new(),
            }),
            members: vec![p256_registrar::task::Member {
                public_key: member_public.clone(),
                attestation: String::new(),
                proof: p256_registrar::task::Proof {
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
            created_at: 0,
            admitted: false,
        };
        let content_hash = content_hash_for(&skeleton).unwrap();
        let group_challenge = challenge_for(
            p256_registrar::protocol::CHAIN_ID,
            registry,
            rp_id,
            &hex::decode(&group_public).unwrap(),
            content_hash,
        );
        let group_proof = proof_json(&group_signing, group_challenge, rp_id);

        let body = json!({
            "rpId": rp_id,
            "metadata": metadata_hex,
            "groupPublicKey": group_public,
            "groupProof": group_proof,
            "members": [{
                "publicKey": member_public,
                "proof": member_proof,
            }],
        });
        (body, member_public, group_public)
    }

    #[test]
    fn group_detail_body_names_every_field() {
        let detail = crate::chain::GroupDetail {
            unit: Unit {
                unit_id: 3,
                rp_id: "example.com".into(),
                metadata: "aa".into(),
                group_public_key: "04ab".into(),
                content_hash: "0x11".into(),
                member_count: 2,
                created_at: 1_000,
            },
            member_total: 2,
            members: vec![Entry {
                entry_id: 7,
                public_key: "04cd".into(),
                attestation: String::new(),
                created_at: 1_000,
            }],
            reference_total: 1,
            reference_ids: vec![4],
        };
        let body = group_detail_json(detail, 1, 20);
        assert_eq!(body["unit"]["unitId"], 3);
        assert_eq!(body["unit"]["groupPublicKey"], "04ab");
        assert_eq!(body["unit"]["memberCount"], 2);
        assert_eq!(body["members"]["total"], 2);
        assert_eq!(body["members"]["items"][0]["entryId"], 7);
        assert_eq!(body["references"]["total"], 1);
        assert_eq!(body["references"]["referenceIds"][0], 4);
        assert_eq!(body["page"], 1);
        assert_eq!(body["pageSize"], 20);
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

        // A fully-proven single-member unit (group key + one passkey).
        let (body_json, public_key, group_public_key) = signed_unit_json("http.example", "0xaabb");
        let body = body_json.to_string();

        // MEMBER mode: the endpoint reproduces exactly the binding-bound
        // challenge the member signed.
        let member_mode = json!({
            "rpId": "http.example",
            "groupPublicKey": group_public_key,
            "publicKey": public_key,
        })
        .to_string();
        let derived = request(&app, "POST", "/api/challenge", &member_mode).await;
        assert_eq!(derived.status(), StatusCode::OK);
        let derived = response_json(derived).await;
        assert_eq!(
            derived["challengeBase64url"].as_str().expect("challenge"),
            body_json["members"][0]["proof"]["clientDataJSON"]
                .as_str()
                .expect("clientDataJSON")
                .split("\"challenge\":\"")
                .nth(1)
                .expect("challenge field")
                .split('\"')
                .next()
                .expect("challenge value")
        );

        // GROUP mode: content hash + the closing challenge the group signed.
        let group_mode = json!({
            "rpId": "http.example",
            "metadata": "0xaabb",
            "groupPublicKey": group_public_key,
            "members": [{ "publicKey": public_key }],
        })
        .to_string();
        let derived = request(&app, "POST", "/api/challenge", &group_mode).await;
        assert_eq!(derived.status(), StatusCode::OK);
        let derived = response_json(derived).await;
        assert!(
            derived["contentHash"]
                .as_str()
                .is_some_and(|hash| hash.starts_with("0x"))
        );
        assert_eq!(
            derived["groupChallenge"]["challengeBase64url"]
                .as_str()
                .expect("group challenge"),
            body_json["groupProof"]["clientDataJSON"]
                .as_str()
                .expect("group clientDataJSON")
                .split("\"challenge\":\"")
                .nth(1)
                .expect("challenge field")
                .split('\"')
                .next()
                .expect("challenge value")
        );

        // The endpoint enforces admission's checks: a malformed key is a
        // 400, never a mis-computed challenge.
        let bad_key = json!({
            "rpId": "http.example",
            "groupPublicKey": group_public_key,
            "publicKey": "0x0400",
        })
        .to_string();
        let refused = request(&app, "POST", "/api/challenge", &bad_key).await;
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST);

        let created = request(&app, "POST", "/api/register", &body).await;
        assert_eq!(created.status(), StatusCode::ACCEPTED);
        let created = response_json(created).await;
        assert_eq!(created["status"], "pending");
        let id = created["id"].as_str().expect("task id").to_owned();
        assert_eq!(queue.tasks.lock().expect("lock").len(), 1);

        // Same unit resubmitted → the same task (idempotency by content
        // hash).
        let duplicate = request(&app, "POST", "/api/register", &body).await;
        assert_eq!(duplicate.status(), StatusCode::ACCEPTED);
        assert_eq!(response_json(duplicate).await["id"], id);
        assert_eq!(queue.tasks.lock().expect("lock").len(), 1);

        // A different unit is simply a second registration.
        let (second_body, _, _) = signed_unit_json("http.example", "0xcc");
        let second = request(&app, "POST", "/api/register", &second_body.to_string()).await;
        assert_eq!(second.status(), StatusCode::ACCEPTED);
        assert_ne!(response_json(second).await["id"], id);
        assert_eq!(queue.tasks.lock().expect("lock").len(), 2);

        // An invalid proof never reaches Redis or the queue.
        let mut tampered: Value = serde_json::from_str(&body).unwrap();
        tampered["members"][0]["proof"]["typeIndex"] = json!(2);
        let rejected = request(&app, "POST", "/api/register", &tampered.to_string()).await;
        assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
        assert_eq!(queue.tasks.lock().expect("lock").len(), 2);

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

        // Pre-chain visibility for the GROUP key too: the register
        // placeholder covers it, so the group-detail view answers with the
        // same queue marker before the unit lands on-chain.
        let pending_group = request(
            &app,
            "GET",
            &format!("/api/query?groupPublicKey={group_public_key}"),
            "",
        )
        .await;
        assert_eq!(pending_group.status(), StatusCode::OK);
        let pending_group = response_json(pending_group).await;
        assert_eq!(pending_group["_queue"]["id"], id);

        // A well-formed group key nothing was ever submitted for is a 404.
        let absent = request(
            &app,
            "GET",
            &format!("/api/query?groupPublicKey=04{}", "ab".repeat(64)),
            "",
        )
        .await;
        assert_eq!(absent.status(), StatusCode::NOT_FOUND);

        // Unit ids are resolved on-chain only; this chain has none.
        let no_unit = request(&app, "GET", "/api/query?unitId=987654321", "").await;
        assert_eq!(no_unit.status(), StatusCode::NOT_FOUND);

        // Param validation.
        let bad = request(&app, "GET", "/api/query?publicKey=02ab", "").await;
        assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
        let bad_unit = request(&app, "GET", "/api/query?unitId=not-a-number", "").await;
        assert_eq!(bad_unit.status(), StatusCode::BAD_REQUEST);
        let bad_group = request(&app, "GET", "/api/query?groupPublicKey=02ab", "").await;
        assert_eq!(bad_group.status(), StatusCode::BAD_REQUEST);
        let none = request(&app, "GET", "/api/query", "").await;
        assert_eq!(none.status(), StatusCode::BAD_REQUEST);

        // Health names the registry and the queue depth: this run created
        // two units, so two active tasks joined whatever was there before.
        let health = request(&app, "GET", "/api/health", "").await;
        assert_eq!(health.status(), StatusCode::OK);
        let health = response_json(health).await;
        assert_eq!(health["registry"], REGISTRY);
        assert_eq!(health["queue"]["depth"], initial_queue_depth + 2);
    }
}
