//! The stateless edge layer: routing, transport concerns, the KV
//! read-through cache, and the execution of lookup Core operations. A port
//! of the docker shell's `http.rs` handlers onto `worker::{Request,
//! Response}` — every decision still lives in `p256_registrar`; writes are
//! validated here (CPU where it scales) and admitted inside the Durable
//! Object.

use std::cell::RefCell;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use crux_core::Core;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use worker::{Cache, Date, Env, Headers, Method, Request, RequestInit, Response, Result, Stub, Url};

use p256_registrar::{
    admission::{
        AdmissionOutcome, AdmissionRequest, MAX_MEMBERS, MAX_METADATA_BYTES, ReferRequest,
        RegisterRequest, validate_attestation_hex, validate_public_key_hex, validate_refer,
        validate_register,
    },
    lookup::{
        ChainFetch, LookupApp, LookupCacheKey, LookupEffect, LookupEndpoint, LookupEvent,
        LookupOperation, LookupOutcome, LookupParams, LookupResult, TtlClass, task_status_body,
    },
    protocol::{
        CHAIN_ID, challenge_for, content_hash_for, member_binding_for, parse_hex_bytes,
        reference_binding_for,
    },
    sentinel,
    task::TaskStatus,
};

use crate::{
    chain::{Chain, GroupDetail},
    config::CfConfig,
    proto::{AdmitCall, AllowedEnvelope, StatsEnvelope, TaskEnvelope},
};

const MAX_BODY_SIZE: usize = 128 * 1024;
const RECORD_STALE_LIMIT_MS: u64 = 24 * 60 * 60 * 1000;
const STATS_STALE_LIMIT_MS: u64 = 60 * 60 * 1000;
const CACHE_FRESH_TTL_MS: u64 = 5 * 60 * 1000;
const CACHE_NEGATIVE_TTL_MS: u64 = 60 * 1000;
/// Cache retention for positive entries: the record-class stale grace (the
/// docker shell retains all positive entries for 24h and clamps the stats
/// grace at read time — mirrored here). The store is the platform Cache
/// API — per-datacenter rather than global, chosen deliberately: it needs
/// no pre-created resource, so the repo deploys without editing any
/// tracked file. The envelope carries its own timestamps, so locality only
/// affects hit rate, never freshness verdicts.
const CACHE_RETENTION_SECS: u64 = 24 * 60 * 60;

thread_local! {
    /// One Chain per isolate so the RPC roster keeps its cooldown memory
    /// across requests, like the docker shell's process-wide pool.
    static CHAIN: RefCell<Option<Chain>> = const { RefCell::new(None) };
}

pub struct Edge {
    pub config: CfConfig,
    pub chain: Chain,
    pub env: Env,
}

impl Edge {
    pub fn new(env: Env) -> Result<Self> {
        let config = CfConfig::from_env(&env)?;
        let chain = CHAIN.with(|cell| -> Result<Chain> {
            if cell.borrow().is_none() {
                *cell.borrow_mut() = Some(Chain::new(&config)?);
            }
            Ok(cell.borrow().clone().expect("chain was initialized"))
        })?;
        Ok(Self { config, chain, env })
    }

    fn submitter(&self) -> Result<Stub> {
        self.env
            .durable_object("SUBMITTER")?
            .id_from_name("v1")?
            .get_stub()
    }

    async fn do_get<T: serde::de::DeserializeOwned>(&self, path_and_query: &str) -> Result<T> {
        let mut response = self
            .submitter()?
            .fetch_with_str(&format!("https://do{path_and_query}"))
            .await?;
        if response.status_code() >= 400 {
            return Err(worker::Error::RustError("durable object error".into()));
        }
        response.json().await
    }

    async fn do_post<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &impl serde::Serialize,
    ) -> Result<T> {
        let headers = Headers::new();
        headers.set("content-type", "application/json")?;
        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_headers(headers)
            .with_body(Some(
                serde_json::to_string(body)
                    .map_err(|_| worker::Error::RustError("could not serialize call".into()))?
                    .into(),
            ));
        let request = Request::new_with_init(&format!("https://do{path}"), &init)?;
        let mut response = self.submitter()?.fetch_with_request(request).await?;
        if response.status_code() >= 400 {
            return Err(worker::Error::RustError("durable object error".into()));
        }
        response.json().await
    }

    // ── Routing ────────────────────────────────────────────────────────────

    pub async fn route(&self, req: Request) -> Result<Response> {
        let url = req.url()?;
        let path = url.path().to_owned();
        match (req.method(), path.as_str()) {
            (Method::Get, "/") => root(),
            (Method::Get, "/api/health") => self.health().await,
            (Method::Post, "/api/challenge") => self.challenge(req).await,
            (Method::Post, "/api/register") => self.register(req).await,
            (Method::Post, "/api/refer") => self.refer(req).await,
            (Method::Get, "/api/task/") => error_response(400, "task id is required"),
            (Method::Get, path) if path.starts_with("/api/task/") => {
                let id = path.trim_start_matches("/api/task/").to_owned();
                self.task_status(&id).await
            }
            (Method::Get, "/api/query") => {
                self.run_lookup(
                    &req,
                    LookupEndpoint::Query {
                        params: lookup_params(&url),
                    },
                )
                .await
            }
            (Method::Get, "/api/stats/total") => {
                self.run_lookup(&req, LookupEndpoint::StatsTotal).await
            }
            (Method::Get, "/api/stats/sites") => {
                self.run_lookup(
                    &req,
                    LookupEndpoint::StatsSites {
                        params: lookup_params(&url),
                    },
                )
                .await
            }
            (Method::Get, "/api/stats/keys") => {
                let Some(rp_id) = query_param(&url, "rpId") else {
                    return error_response(400, "rpId is required");
                };
                self.run_lookup(
                    &req,
                    LookupEndpoint::StatsKeys {
                        rp_id,
                        params: lookup_params(&url),
                    },
                )
                .await
            }
            _ => error_response(404, "not found"),
        }
    }

    // ── Health ─────────────────────────────────────────────────────────────

    async fn health(&self) -> Result<Response> {
        let base = json!({
            "service": "webauthn-p256-publickey-registry",
            "version": env!("CARGO_PKG_VERSION"),
            "shell": "cloudflare-workers",
            "chainId": CHAIN_ID,
            "registry": self.chain.registry_address(),
            "domainRegistry": self.chain.domain_registry_address(),
            "rpcCircuit": self.chain.rpc_circuit_state(),
            "telegramConfigured": self.config.telegram_bot_token.is_some()
                && self.config.telegram_chat_id.is_some(),
        });
        match self.do_get::<StatsEnvelope>("/stats").await {
            Ok(stats) => {
                let mut reasons = sentinel::health_reasons(&sentinel::QueueHealth {
                    depth: stats.depth,
                    dlq_count: stats.dlq,
                    oldest_active_age_ms: stats.oldest_job_age_ms,
                });
                if stats.worker_stalled {
                    reasons.push("queue-worker-stalled");
                }
                let status = if stats.worker_stalled {
                    "unhealthy"
                } else if reasons.is_empty() {
                    "ok"
                } else {
                    "degraded"
                };
                let mut body = base;
                body["status"] = json!(status);
                body["queue"] = json!({
                    "depth": stats.depth,
                    "dlq": stats.dlq,
                    "oldestJobAgeMs": stats.oldest_job_age_ms,
                });
                if !reasons.is_empty() {
                    body["reasons"] = json!(reasons);
                }
                json_response(if stats.worker_stalled { 503 } else { 200 }, body)
            }
            Err(_) => {
                let mut body = base;
                body["status"] = json!("degraded");
                body["reasons"] = json!(["stats-unavailable"]);
                body["queue"] = json!({ "error": "queue stats unavailable" });
                json_response(200, body)
            }
        }
    }

    // ── Challenge (pure computation, straight port) ────────────────────────

    async fn challenge(&self, mut req: Request) -> Result<Response> {
        let Some(bytes) = bounded_body(&mut req).await? else {
            return error_response(413, "request body too large");
        };
        let Ok(body) = serde_json::from_slice::<Value>(&bytes) else {
            return error_response(400, "invalid JSON body");
        };

        let Some(rp_id) = body.get("rpId").and_then(Value::as_str) else {
            return error_response(400, "rpId is required");
        };
        if rp_id.is_empty() || rp_id.len() > 253 {
            return error_response(400, "rpId must be 1..=253 bytes");
        }
        let Some(group_public_key) = body.get("groupPublicKey").and_then(Value::as_str) else {
            return error_response(400, "groupPublicKey is required");
        };
        let group_public_key = match validate_public_key_hex(group_public_key) {
            Ok(normalized) => normalized,
            Err(message) => return error_response(400, &format!("groupPublicKey: {message}")),
        };
        let group_key_bytes = hex::decode(&group_public_key).expect("validated hex");
        let Ok(registry) = self.chain.domain_registry_address().parse() else {
            return error_response(500, "registry misconfigured");
        };

        let render_challenge = |challenge: alloy::primitives::B256| {
            json!({
                "challenge": format!("{challenge:#x}"),
                "challengeBase64url": URL_SAFE_NO_PAD.encode(challenge.0),
            })
        };

        if body.get("members").is_some() && body.get("refer").and_then(Value::as_bool) == Some(true)
        {
            return error_response(
                400,
                "choose one mode: members (group) or refer (reference), not both",
            );
        }

        // MEMBER mode: one passkey signing at creation.
        if body.get("members").is_none() {
            let Some(public_key) = body.get("publicKey").and_then(Value::as_str) else {
                return error_response(
                    400,
                    "publicKey (member mode) or members (group mode) is required",
                );
            };
            let public_key = match validate_public_key_hex(public_key) {
                Ok(normalized) => normalized,
                Err(message) => return error_response(400, &format!("publicKey: {message}")),
            };
            if public_key == group_public_key {
                return error_response(400, "the group key cannot also be a member");
            }
            let attestation = match validate_attestation_hex(
                body.get("attestation")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
            ) {
                Ok(normalized) => normalized,
                Err(message) => return error_response(400, &format!("attestation: {message}")),
            };
            let attestation_bytes = parse_hex_bytes(&attestation).expect("validated hex");
            let binding = if body.get("refer").and_then(Value::as_bool).unwrap_or(false) {
                let metadata = body.get("metadata").and_then(Value::as_str).unwrap_or("");
                let metadata_bytes = match parse_hex_bytes(metadata) {
                    Ok(bytes) if bytes.len() <= MAX_METADATA_BYTES => bytes,
                    Ok(_) => return error_response(400, "metadata exceeds max length"),
                    Err(_) => return error_response(400, "metadata must be hex"),
                };
                reference_binding_for(&group_key_bytes, &attestation_bytes, &metadata_bytes)
            } else {
                member_binding_for(&group_key_bytes, &attestation_bytes)
            };
            let key_bytes = hex::decode(&public_key).expect("validated hex");
            let challenge = challenge_for(CHAIN_ID, registry, rp_id, &key_bytes, binding);
            let mut response = render_challenge(challenge);
            response["binding"] = json!(format!("{binding:#x}"));
            return json_response(200, response);
        }

        // GROUP mode: the finished unit's content hash and closing challenge.
        let members = body
            .get("members")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if members.is_empty() || members.len() > MAX_MEMBERS {
            return error_response(400, "members must contain 1 to 7 entries");
        }
        let metadata = body.get("metadata").and_then(Value::as_str).unwrap_or("");
        let metadata_bytes = match parse_hex_bytes(metadata) {
            Ok(bytes) if bytes.len() <= MAX_METADATA_BYTES => bytes,
            Ok(_) => return error_response(400, "metadata exceeds max length"),
            Err(_) => return error_response(400, "metadata must be hex"),
        };
        let metadata = if metadata_bytes.is_empty() {
            String::new()
        } else {
            format!("0x{}", hex::encode(&metadata_bytes))
        };

        let mut skeleton_members = Vec::with_capacity(members.len());
        for (index, member) in members.iter().enumerate() {
            let Some(public_key) = member.get("publicKey").and_then(Value::as_str) else {
                return error_response(400, &format!("members[{index}]: publicKey is required"));
            };
            let public_key = match validate_public_key_hex(public_key) {
                Ok(normalized) => normalized,
                Err(message) => {
                    return error_response(400, &format!("members[{index}]: {message}"));
                }
            };
            if public_key == group_public_key {
                return error_response(
                    400,
                    &format!("members[{index}]: the group key cannot also be a member"),
                );
            }
            if skeleton_members
                .iter()
                .any(|earlier: &p256_registrar::task::Member| earlier.public_key == public_key)
            {
                return error_response(
                    400,
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
                    return error_response(400, &format!("members[{index}]: {message}"));
                }
            };
            skeleton_members.push(p256_registrar::task::Member {
                public_key,
                attestation,
                credential_id: String::new(),
                authenticator_attachment: String::new(),
                transports: String::new(),
                proof: empty_proof(),
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
            group_proof: Some(empty_proof()),
            members: skeleton_members,
            tx_hash: None,
            on_chain_id: None,
            error: None,
            retries: 0,
            created_at: 0,
            admitted: false,
        };
        let content_hash = content_hash_for(&skeleton).expect("validated fields");

        let group_challenge = challenge_for(CHAIN_ID, registry, rp_id, &group_key_bytes, content_hash);
        let member_challenges: Vec<Value> = skeleton
            .members
            .iter()
            .map(|member| {
                let key = hex::decode(&member.public_key).expect("validated hex");
                let attestation = parse_hex_bytes(&member.attestation).expect("validated hex");
                let binding = member_binding_for(&group_key_bytes, &attestation);
                let challenge = challenge_for(CHAIN_ID, registry, rp_id, &key, binding);
                let mut rendered = render_challenge(challenge);
                rendered["publicKey"] = json!(member.public_key);
                rendered
            })
            .collect();
        json_response(
            200,
            json!({
                "contentHash": format!("{content_hash:#x}"),
                "groupChallenge": render_challenge(group_challenge),
                "members": member_challenges,
            }),
        )
    }

    // ── Writes: validate at the edge, admit in the Durable Object ──────────

    async fn register(&self, mut req: Request) -> Result<Response> {
        let ip_hash = self.ip_hash(&req);
        let Some(bytes) = bounded_body(&mut req).await? else {
            return error_response(413, "request body too large");
        };
        let Ok(body) = serde_json::from_slice::<RegisterRequest>(&bytes) else {
            return error_response(400, "invalid JSON body");
        };
        // Edge pre-validation: the full proof check runs here, where CPU
        // scales horizontally, so an invalid request never reaches the
        // single-threaded Durable Object. The admission program inside the
        // object revalidates (same function — the messages cannot drift).
        if let Err(message) = validate_register(
            body.clone(),
            "edge-validate".into(),
            Date::now().as_millis(),
            CHAIN_ID,
            &self.chain.domain_registry_address(),
        ) {
            return render_admission(AdmissionOutcome::Invalid { message });
        }
        self.admit(AdmissionRequest::Register(body), ip_hash).await
    }

    async fn refer(&self, mut req: Request) -> Result<Response> {
        let ip_hash = self.ip_hash(&req);
        let Some(bytes) = bounded_body(&mut req).await? else {
            return error_response(413, "request body too large");
        };
        let Ok(body) = serde_json::from_slice::<ReferRequest>(&bytes) else {
            return error_response(400, "invalid JSON body");
        };

        // Fail-open rpId cross-check against the group's frozen record — a
        // mismatch can only revert on-chain, so reject it at the door. A
        // missing group passes (it may be racing through the pipeline); an
        // RPC failure passes.
        if let (Some(rp_id), Some(group_key)) =
            (body.rp_id.as_deref(), body.group_public_key.as_deref())
            && let Ok(group_key_bytes) = parse_hex_bytes(group_key)
            && let Ok(Some(unit)) = self.chain.unit_by_group_key(group_key_bytes).await
            && unit.rp_id != rp_id
        {
            return error_response(400, "rpId does not match the group's frozen record");
        }
        if let Err(message) = validate_refer(
            body.clone(),
            "edge-validate".into(),
            Date::now().as_millis(),
            CHAIN_ID,
            &self.chain.domain_registry_address(),
        ) {
            return render_admission(AdmissionOutcome::Invalid { message });
        }
        self.admit(AdmissionRequest::Refer(body), ip_hash).await
    }

    async fn admit(&self, request: AdmissionRequest, ip_hash: String) -> Result<Response> {
        match self
            .do_post::<AdmissionOutcome>("/admit", &AdmitCall { request, ip_hash })
            .await
        {
            Ok(outcome) => render_admission(outcome),
            Err(_) => error_response(503, "store temporarily unavailable, please retry"),
        }
    }

    async fn task_status(&self, id: &str) -> Result<Response> {
        match self
            .do_get::<TaskEnvelope>(&format!("/task?id={}", urlencode(id)))
            .await
        {
            Ok(TaskEnvelope { task: Some(task) }) => json_response(200, task_status_body(&task)),
            Ok(TaskEnvelope { task: None }) => error_response(404, "not found"),
            Err(_) => error_response(503, "store temporarily unavailable, please retry"),
        }
    }

    // ── Lookup: the registrar's program against KV + chain + the object ────

    async fn run_lookup(&self, req: &Request, endpoint: LookupEndpoint) -> Result<Response> {
        let ip_hash = self.ip_hash(req);
        let core: Core<LookupApp> = Core::new();
        let mut effects = core.process_event(LookupEvent::Start { endpoint });

        loop {
            let Some(effect) = effects.pop() else {
                break;
            };
            let LookupEffect::Work(mut request) = effect;
            let result = self.execute_lookup(&ip_hash, &request.operation).await;
            match core.resolve(&mut request, result) {
                Ok(next) => effects = next,
                Err(_) => return error_response(500, "internal error"),
            }
        }

        match core.view().outcome {
            Some(outcome) => render_lookup(outcome),
            None => error_response(500, "lookup never settled"),
        }
    }

    async fn execute_lookup(&self, ip_hash: &str, operation: &LookupOperation) -> LookupResult {
        match operation {
            LookupOperation::ReadCache { key } => {
                let stale_limit_ms = match key.ttl_class() {
                    TtlClass::Record => RECORD_STALE_LIMIT_MS,
                    TtlClass::Stats => STATS_STALE_LIMIT_MS,
                };
                match self.cache_get(&cache_key_string(key), stale_limit_ms).await {
                    Ok(read) => read,
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
                    self.cache_set(&key, None).await
                } else {
                    self.cache_set(&key, Some(value.clone())).await
                };
                match write {
                    Ok(()) => LookupResult::Persisted,
                    Err(_) => LookupResult::StoreUnavailable,
                }
            }
            // Fail-open by program design: StoreUnavailable lets the read
            // proceed.
            LookupOperation::AllowRead => {
                match self
                    .do_get::<AllowedEnvelope>(&format!("/allow-read?ip={ip_hash}"))
                    .await
                {
                    Ok(env) => LookupResult::Allowed {
                        allowed: env.allowed,
                    },
                    Err(_) => LookupResult::StoreUnavailable,
                }
            }
            LookupOperation::FetchChain { fetch } => self.execute_fetch(fetch).await,
            LookupOperation::FindTaskByKey { key_hash } => {
                match self
                    .do_get::<TaskEnvelope>(&format!("/find-by-key?key={}", urlencode(key_hash)))
                    .await
                {
                    Ok(env) => LookupResult::TaskFound { task: env.task },
                    Err(_) => LookupResult::StoreUnavailable,
                }
            }
        }
    }

    async fn execute_fetch(&self, fetch: &ChainFetch) -> LookupResult {
        match fetch {
            ChainFetch::EntriesByKey {
                public_key,
                offset,
                limit,
                descending,
            } => {
                let page = offset / limit + 1;
                match self
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
            ChainFetch::Entry { entry_id } => match self.chain.entry(*entry_id).await {
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
                match self
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
                match self
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
            ChainFetch::Totals => match self.chain.totals().await {
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
                match self.chain.rp_ids(page, *limit, *descending).await {
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
                match self
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

    // ── Response cache: the docker shell's Redis cache envelope, stored in
    // the platform Cache API (per-datacenter, zero-provisioning) ───────────

    async fn cache_get(&self, key: &str, stale_limit_ms: u64) -> Result<LookupResult> {
        #[derive(serde::Deserialize)]
        struct CacheEntry {
            value: Option<Value>,
            stored_at_ms: u64,
            fresh_until_ms: u64,
        }
        let Some(mut hit) = Cache::default().get(cache_url(key).as_str(), false).await? else {
            return Ok(LookupResult::CacheMiss);
        };
        let payload = hit.text().await?;
        let Ok(entry) = serde_json::from_str::<CacheEntry>(&payload) else {
            return Ok(LookupResult::CacheMiss);
        };
        let now = Date::now().as_millis();
        Ok(match entry.value {
            None if now <= entry.fresh_until_ms => LookupResult::CacheNegative,
            None => LookupResult::CacheMiss,
            Some(value) if now <= entry.fresh_until_ms => LookupResult::CacheFresh { value },
            Some(value) if now.saturating_sub(entry.stored_at_ms) <= stale_limit_ms => {
                LookupResult::CacheStale {
                    value,
                    age_ms: now.saturating_sub(entry.stored_at_ms),
                }
            }
            Some(_) => LookupResult::CacheMiss,
        })
    }

    async fn cache_set(&self, key: &str, value: Option<Value>) -> Result<()> {
        let negative = value.is_none();
        let stored_at_ms = Date::now().as_millis();
        let fresh_ttl_ms = if negative {
            CACHE_NEGATIVE_TTL_MS
        } else {
            CACHE_FRESH_TTL_MS
        };
        let payload = json!({
            "value": value,
            "stored_at_ms": stored_at_ms,
            "fresh_until_ms": stored_at_ms + fresh_ttl_ms,
        })
        .to_string();
        let retention_secs = if negative { 60 } else { CACHE_RETENTION_SECS };
        let mut envelope = Response::ok(payload)?;
        envelope
            .headers_mut()
            .set("cache-control", &format!("max-age={retention_secs}"))?;
        Cache::default().put(cache_url(key).as_str(), envelope).await
    }

    fn ip_hash(&self, req: &Request) -> String {
        let ip = req
            .headers()
            .get("cf-connecting-ip")
            .ok()
            .flatten()
            .unwrap_or_default();
        hash_ip(&derive_ip_salt(self.config.private_key.as_deref()), &ip)
    }
}

// ── Rendering (ported verbatim from the docker shell) ──────────────────────

fn render_admission(outcome: AdmissionOutcome) -> Result<Response> {
    match outcome {
        AdmissionOutcome::Invalid { message } => error_response(400, &message),
        AdmissionOutcome::RateLimited => {
            error_response(429, "rate limit exceeded, max 5 requests per minute")
        }
        AdmissionOutcome::Queued { id, status } => {
            let code = match status {
                TaskStatus::Done => 200,
                _ => 202,
            };
            json_response(code, json!({ "id": id, "status": status }))
        }
        AdmissionOutcome::AlreadyRegistered { content_hash } => json_response(
            200,
            json!({ "status": "done", "contentHash": content_hash }),
        ),
        AdmissionOutcome::ReferGroupMissing => error_response(
            404,
            "referenced group does not exist; if you just created it, retry shortly",
        ),
        AdmissionOutcome::Busy => error_response(503, "service is busy, please retry later"),
        AdmissionOutcome::DependencyUnavailable { dependency } => error_response(
            503,
            &format!("{dependency} temporarily unavailable, please retry"),
        ),
    }
}

fn render_lookup(outcome: LookupOutcome) -> Result<Response> {
    match outcome {
        LookupOutcome::CachedOk { value } => {
            let mut response = json_response(200, value)?;
            response
                .headers_mut()
                .set("cache-control", "public, max-age=3600")?;
            Ok(response)
        }
        LookupOutcome::Ok { value } | LookupOutcome::QueuePending { value } => {
            json_response(200, value)
        }
        LookupOutcome::StaleOk { value, age_ms } => {
            let mut body = value;
            if let Some(object) = body.as_object_mut() {
                object.insert("_stale".into(), Value::Bool(true));
                object.insert("_staleAgeMs".into(), json!(age_ms));
            }
            let mut response = json_response(200, body)?;
            response.headers_mut().set("cache-control", "no-cache")?;
            response.headers_mut().set("x-served-stale", "true")?;
            Ok(response)
        }
        LookupOutcome::Invalid { message } => error_response(400, &message),
        LookupOutcome::NotFound => error_response(404, "not found"),
        LookupOutcome::ReadLimited => {
            error_response(429, "rate limit exceeded, please retry later")
        }
        LookupOutcome::DependencyUnavailable { dependency } => error_response(
            503,
            &format!("{dependency} temporarily unavailable, please retry"),
        ),
    }
}

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

// ── Transport helpers ──────────────────────────────────────────────────────

fn root() -> Result<Response> {
    let mut response = Response::ok(
        "<!doctype html><html><head><title>WebAuthn P256 Public Key Registry</title></head><body><h1>WebAuthn P256 Public Key Registry</h1><p>See the REST API documentation in this service repository.</p></body></html>",
    )?;
    response
        .headers_mut()
        .set("content-type", "text/html; charset=utf-8")?;
    Ok(response)
}

/// `None` means "too large". Mirrors the docker shell's Content-Length +
/// bounded-read gate.
async fn bounded_body(req: &mut Request) -> Result<Option<Vec<u8>>> {
    if let Ok(Some(length)) = req.headers().get("content-length") {
        match length.parse::<usize>() {
            Ok(length) if length <= MAX_BODY_SIZE => {}
            _ => return Ok(None),
        }
    }
    let bytes = req.bytes().await?;
    if bytes.len() > MAX_BODY_SIZE {
        return Ok(None);
    }
    Ok(Some(bytes))
}

pub fn json_response(status: u16, body: Value) -> Result<Response> {
    Ok(Response::from_json(&body)?.with_status(status))
}

pub fn error_response(status: u16, message: &str) -> Result<Response> {
    json_response(status, json!({ "error": message }))
}

pub fn apply_cors(response: &mut Response) -> Result<()> {
    let headers = response.headers_mut();
    headers.set("access-control-allow-origin", "*")?;
    headers.set("access-control-allow-methods", "GET, POST, OPTIONS")?;
    headers.set("access-control-allow-headers", "content-type")?;
    headers.set("access-control-max-age", "86400")?;
    Ok(())
}

fn lookup_params(url: &Url) -> LookupParams {
    let mut params = LookupParams::default();
    for (key, value) in url.query_pairs() {
        let value = value.into_owned();
        match key.as_ref() {
            "publicKey" => params.public_key = Some(value),
            "entryId" => params.entry_id = Some(value),
            "unitId" => params.unit_id = Some(value),
            "groupPublicKey" => params.group_public_key = Some(value),
            "page" => params.page = value.parse().ok(),
            "pageSize" => params.page_size = value.parse().ok(),
            "order" => params.order = Some(value),
            _ => {}
        }
    }
    params
}

fn query_param(url: &Url, name: &str) -> Option<String> {
    url.query_pairs()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
}

fn urlencode(value: &str) -> String {
    // The values crossing to the object are hex strings and uuids; conservative
    // percent-encoding keeps the helper dependency-free.
    value
        .bytes()
        .flat_map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
                vec![byte as char]
            } else {
                format!("%{byte:02X}").chars().collect()
            }
        })
        .collect()
}

/// A synthetic, collision-free cache key URL; the host never resolves —
/// Cache API keys are opaque.
fn cache_url(key: &str) -> String {
    format!(
        "https://p256-index-cache.internal/{}",
        hex::encode(Sha256::digest(key.as_bytes()))
    )
}

pub fn hash_ip(salt: &str, ip: &str) -> String {
    hex::encode(Sha256::digest(format!("{salt}\0{ip}").as_bytes()))[..16].to_owned()
}

pub fn derive_ip_salt(secret: Option<&str>) -> String {
    hex::encode(Sha256::digest(
        format!("ip-salt\0{}", secret.unwrap_or("webauthnp256-index")).as_bytes(),
    ))
}

fn empty_proof() -> p256_registrar::task::Proof {
    p256_registrar::task::Proof {
        authenticator_data: String::new(),
        client_data_json: String::new(),
        challenge_index: 0,
        type_index: 0,
        r: String::new(),
        s: String::new(),
    }
}
