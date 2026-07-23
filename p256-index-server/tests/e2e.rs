//! End-to-end parity tests: prove the Rust service reproduces the HTTP + queue contract of the
//! retired Deno server and Cloudflare Worker, exercised against **real Redis and real Iggy**.
//!
//! These are gated behind `#[ignore]` and two environment variables so `cargo test` stays green
//! in CI (which has no infrastructure). Run them locally against the dev stack:
//!
//! ```sh
//! P256_INDEX_TEST_REDIS_URL='redis://127.0.0.1:6379/0' \
//! P256_INDEX_TEST_IGGY_URL='iggy+tcp://iggy:Secret123@127.0.0.1:5100' \
//!   cargo test --test e2e -- --ignored --nocapture
//! ```
//!
//! The full create -> chain -> confirmed path (real on-chain write, real gas) lives in a separate
//! `worker.rs` inline test gated by `P256_INDEX_E2E_CHAIN=1`.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy::primitives::B256;
use async_trait::async_trait;
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
    response::Response,
};
use iggy::prelude::{Client, Consumer, Identifier, IggyClient, MessageClient, PollingStrategy};
use p256::elliptic_curve::{Generate, sec1::ToSec1Point};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

use p256_index_server::{
    chain::{ChainError, ReadChain},
    config::Config,
    contract::build_wallet_ref,
    http::{AppState, router},
    queue::{CreateQueue, CreateTaskQueue, STREAM_NAME, TOPIC_NAME},
    store::{RedisStore, derive_ip_salt, hash_ip},
    types::{CreateTask, Page, Record, SiteItem, TaskStatus},
};

// ── Infrastructure gating ──────────────────────────────────────────────────

fn redis_url() -> String {
    std::env::var("P256_INDEX_TEST_REDIS_URL")
        .expect("P256_INDEX_TEST_REDIS_URL is required for the e2e suite")
}

fn iggy_url() -> String {
    std::env::var("P256_INDEX_TEST_IGGY_URL")
        .expect("P256_INDEX_TEST_IGGY_URL is required for the e2e suite")
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ── A configurable read-only chain double ──────────────────────────────────
//
// `down` flips every read to `Unavailable`, which lets a single test exercise both the fresh path
// (canned data) and the stale-serving / degraded path the Deno service guaranteed.

struct FakeChain {
    down: AtomicBool,
    total: u64,
}

impl FakeChain {
    fn new() -> Self {
        Self {
            down: AtomicBool::new(false),
            total: 4242,
        }
    }
    fn set_down(&self, value: bool) {
        self.down.store(value, Ordering::SeqCst);
    }
    fn is_down(&self) -> bool {
        self.down.load(Ordering::SeqCst)
    }
}

fn sample_record(rp_id: &str) -> Record {
    Record {
        rp_id: rp_id.to_owned(),
        credential_id: "sample-credential".to_owned(),
        wallet_ref: format!("0x{}", "0".repeat(64)),
        public_key: "04".to_owned() + &"ab".repeat(64),
        name: "Sample key".to_owned(),
        initial_credential_id: "sample-credential".to_owned(),
        metadata: "0x".to_owned(),
        created_at: 1_700_000_000_000,
    }
}

#[async_trait]
impl ReadChain for FakeChain {
    fn rpc_circuit_state(&self) -> &'static str {
        if self.is_down() { "open" } else { "closed" }
    }

    async fn get_record(&self, _: &str, _: &str) -> Result<Option<Record>, ChainError> {
        if self.is_down() {
            Err(ChainError::Unavailable)
        } else {
            Ok(None)
        }
    }

    async fn get_record_by_wallet_ref(&self, _: B256) -> Result<Option<Record>, ChainError> {
        if self.is_down() {
            Err(ChainError::Unavailable)
        } else {
            Ok(None)
        }
    }

    async fn total_credentials(&self) -> Result<u64, ChainError> {
        if self.is_down() {
            Err(ChainError::Unavailable)
        } else {
            Ok(self.total)
        }
    }

    async fn list_sites(
        &self,
        page: u64,
        page_size: u64,
        _descending: bool,
    ) -> Result<Page<SiteItem>, ChainError> {
        if self.is_down() {
            return Err(ChainError::Unavailable);
        }
        Ok(Page {
            total: 2,
            page,
            page_size,
            items: vec![
                SiteItem {
                    rp_id: "example.com".to_owned(),
                    public_key_count: 3,
                    created_at: 1_700_000_000_000,
                },
                SiteItem {
                    rp_id: "other.test".to_owned(),
                    public_key_count: 1,
                    created_at: 1_700_000_001_000,
                },
            ],
        })
    }

    async fn list_keys(
        &self,
        rp_id: &str,
        page: u64,
        page_size: u64,
        _descending: bool,
    ) -> Result<Page<Record>, ChainError> {
        if self.is_down() {
            return Err(ChainError::Unavailable);
        }
        Ok(Page {
            total: 1,
            page,
            page_size,
            items: vec![sample_record(rp_id)],
        })
    }
}

// ── Test config (never constructs a real Chain) ────────────────────────────

fn test_config(redis: &str, iggy: &str) -> Config {
    Config {
        listen_addr: "127.0.0.1:0".parse().expect("test listen addr"),
        // A run-unique salt isolates every rate-limit / IP-hash key across repeated runs against a
        // shared Redis. No real Chain is built from this value.
        private_key: Some(format!("e2e-ip-salt-{}", uuid::Uuid::new_v4())),
        commit_private_key: None,
        alchemy_api_key: None,
        iggy_url: iggy.to_owned(),
        iggy_consumer_url: iggy.to_owned(),
        iggy_provisioner_url: iggy.to_owned(),
        redis_url: redis.to_owned(),
        queue_worker_enabled: false,
        telegram_bot_token: Some("test-token".to_owned()),
        telegram_chat_id: Some("test-chat".to_owned()),
        global_write_limit: 10_000,
        iggy_enqueue_timeout: Duration::from_secs(5),
        iggy_consumer_group: format!("e2e-{}", uuid::Uuid::new_v4()),
    }
}

// ── HTTP helpers ───────────────────────────────────────────────────────────

async fn send(
    app: &Router,
    method: &str,
    uri: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Response {
    let mut builder = Request::builder().method(method).uri(uri);
    for (key, value) in headers {
        builder = builder.header(*key, *value);
    }
    app.clone()
        .oneshot(
            builder
                .body(Body::from(body.to_owned()))
                .expect("test request"),
        )
        .await
        .expect("router response")
}

async fn post_json(app: &Router, uri: &str, ip: Option<&str>, body: &str) -> Response {
    let mut headers = vec![("content-type", "application/json")];
    if let Some(ip) = ip {
        headers.push(("x-forwarded-for", ip));
    }
    send(app, "POST", uri, &headers, body).await
}

async fn body_json(response: Response) -> Value {
    let body = to_bytes(response.into_body(), 256 * 1024)
        .await
        .expect("response body");
    serde_json::from_slice(&body).expect("JSON response body")
}

fn valid_key_pair() -> (String, String) {
    let signing_key = p256::SecretKey::generate();
    let public_key = hex::encode(signing_key.public_key().to_sec1_point(false).as_bytes());
    let wallet_ref = build_wallet_ref(&public_key).expect("valid P-256 key");
    (public_key, wallet_ref)
}

async fn raw_redis(url: &str) -> redis::aio::MultiplexedConnection {
    redis::Client::open(url)
        .expect("redis client")
        .get_multiplexed_async_connection()
        .await
        .expect("redis connection")
}

/// The store hashes the full logical cache key with SHA-256 before namespacing it.
fn cache_redis_key(logical: &str) -> String {
    format!(
        "p256-index:cache:{}",
        hex::encode(Sha256::digest(logical.as_bytes()))
    )
}

// ── Test 1: the full HTTP contract over real Redis + real Iggy ──────────────

#[tokio::test]
#[ignore = "requires P256_INDEX_TEST_REDIS_URL and P256_INDEX_TEST_IGGY_URL"]
async fn http_contract_over_real_redis_and_iggy() {
    let redis = redis_url();
    let iggy = iggy_url();
    let config = test_config(&redis, &iggy);

    let store = RedisStore::connect(&redis).await.expect("Redis connect");
    // Connecting the real producer + provisioner and materialising the stream/topic proves the
    // Iggy integration end to end, not just against a fake queue.
    let queue = CreateQueue::connect(&iggy, &iggy, Duration::from_secs(5))
        .await
        .expect("Iggy connect");
    queue.ensure_topology().await.expect("Iggy topology");

    let initial_depth = store.queue_stats().await.expect("queue stats").depth;

    let chain = Arc::new(FakeChain::new());
    let state = AppState::with_clients(store.clone(), Arc::new(queue), chain.clone(), &config);
    let app = router(state);

    let mut created_ids: Vec<String> = Vec::new();

    // — CORS preflight echoes the requested headers and advertises the method set —
    let preflight = send(
        &app,
        "OPTIONS",
        "/api/create",
        &[("access-control-request-headers", "content-type, x-test")],
        "",
    )
    .await;
    assert_eq!(preflight.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        preflight
            .headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("*")
    );
    assert_eq!(
        preflight
            .headers()
            .get("access-control-allow-headers")
            .and_then(|v| v.to_str().ok()),
        Some("content-type, x-test")
    );

    // — Home page + request id + unknown route —
    let home = send(&app, "GET", "/", &[], "").await;
    assert_eq!(home.status(), StatusCode::OK);
    assert!(home.headers().get("x-request-id").is_some());
    assert!(
        home.headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.contains("text/html"))
    );

    let missing = send(&app, "GET", "/api/does-not-exist", &[], "").await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert_eq!(body_json(missing).await["error"], "not found");

    // — Challenge is a 43-char base64url of 32 random bytes —
    let challenge = send(&app, "GET", "/api/challenge", &[], "").await;
    assert_eq!(challenge.status(), StatusCode::OK);
    let challenge = body_json(challenge).await;
    assert!(challenge["challenge"].as_str().is_some_and(|value| {
        value.len() == 43
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    }));

    // — Health reflects real Redis queue stats + telegram configuration —
    let health = send(&app, "GET", "/api/health", &[], "").await;
    assert_eq!(health.status(), StatusCode::OK);
    let health = body_json(health).await;
    assert_eq!(health["service"], "webauthn-p256-publickey-index");
    assert_eq!(health["chainId"], 100);
    assert_eq!(health["telegramConfigured"], true);
    assert_eq!(health["rpcCircuit"], "closed");
    // Both are 200 responses; which one depends on leftover queue/DLQ depth in the shared Redis.
    assert!(matches!(
        health["status"].as_str(),
        Some("ok") | Some("degraded")
    ));
    assert!(health["queue"]["depth"].is_number());

    // — Create validation errors —
    assert_eq!(
        post_json(&app, "/api/create", None, "not-json")
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    let bad_len = send(
        &app,
        "POST",
        "/api/create",
        &[
            ("content-type", "application/json"),
            ("content-length", "not-a-number"),
        ],
        "{}",
    )
    .await;
    assert_eq!(bad_len.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let oversized = post_json(&app, "/api/create", None, &"x".repeat(33 * 1024)).await;
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        post_json(&app, "/api/create", None, "{}").await.status(),
        StatusCode::BAD_REQUEST
    );

    let (public_key, wallet_ref) = valid_key_pair();
    let suffix = uuid::Uuid::new_v4();
    let rp_id = format!("e2e-{suffix}.invalid");
    let credential_id = format!("cred-{suffix}");

    let bad_key = json!({
        "rpId": rp_id, "credentialId": credential_id,
        "publicKey": "04zz", "name": "bad key"
    })
    .to_string();
    assert_eq!(
        post_json(&app, "/api/create", None, &bad_key)
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );

    let mismatch = json!({
        "rpId": rp_id, "credentialId": credential_id, "publicKey": public_key,
        "name": "mismatch", "walletRef": format!("0x{}", "1".repeat(64))
    })
    .to_string();
    let mismatch = post_json(&app, "/api/create", None, &mismatch).await;
    assert_eq!(mismatch.status(), StatusCode::BAD_REQUEST);
    assert!(
        body_json(mismatch).await["error"]
            .as_str()
            .unwrap_or_default()
            .contains("walletRef")
    );

    // — A valid create is admitted (202) and appended to the real Iggy topic —
    let create_body = json!({
        "rpId": rp_id, "credentialId": credential_id,
        "publicKey": public_key, "name": "My passkey"
    })
    .to_string();
    let created = post_json(&app, "/api/create", None, &create_body).await;
    assert_eq!(created.status(), StatusCode::ACCEPTED);
    let created = body_json(created).await;
    assert_eq!(created["status"], "pending");
    let id = created["id"].as_str().expect("create id").to_owned();
    created_ids.push(id.clone());

    // — An identical retry is idempotent: same id, no second admission —
    let duplicate = post_json(&app, "/api/create", None, &create_body).await;
    assert_eq!(duplicate.status(), StatusCode::ACCEPTED);
    assert_eq!(body_json(duplicate).await["id"], id);

    // — Admission registers the task in the real active queue (Redis) exactly once —
    let depth_after_create = store.queue_stats().await.expect("queue stats").depth;
    assert!(
        depth_after_create > initial_depth,
        "an admitted create must raise the active queue depth"
    );

    // — Status is redacted for a non-done task (no credentialId / walletRef leak) —
    let status = send(&app, "GET", &format!("/api/create/{id}"), &[], "").await;
    assert_eq!(status.status(), StatusCode::OK);
    let status = body_json(status).await;
    assert_eq!(status["status"], "pending");
    assert_eq!(status["rpId"], rp_id);
    assert!(status.get("credentialId").is_none());
    assert!(status.get("walletRef").is_none());

    // — /api/create/ (empty id) and an unknown id —
    assert_eq!(
        send(&app, "GET", "/api/create/", &[], "").await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        send(
            &app,
            "GET",
            &format!("/api/create/{}", uuid::Uuid::new_v4()),
            &[],
            ""
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );

    // — Same key under a different credential is a walletRef conflict (409) —
    let conflict_body = json!({
        "rpId": format!("other-{suffix}.invalid"),
        "credentialId": format!("other-{suffix}"),
        "publicKey": public_key, "name": "conflicting key"
    })
    .to_string();
    let conflict = post_json(&app, "/api/create", None, &conflict_body).await;
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    let conflict = body_json(conflict).await;
    assert_eq!(conflict["walletRef"], wallet_ref);

    // — Query resolves the pending task through the queue fallback (chain returns None) —
    let record_query = send(
        &app,
        "GET",
        &format!("/api/query?rpId={rp_id}&credentialId={credential_id}"),
        &[],
        "",
    )
    .await;
    assert_eq!(record_query.status(), StatusCode::OK);
    let record_query = body_json(record_query).await;
    assert_eq!(record_query["_queue"]["id"], id);
    assert!(record_query.get("credentialId").is_none());

    let wallet_query = send(
        &app,
        "GET",
        &format!("/api/query?walletRef={wallet_ref}"),
        &[],
        "",
    )
    .await;
    assert_eq!(wallet_query.status(), StatusCode::OK);
    assert_eq!(body_json(wallet_query).await["_queue"]["id"], id);

    // — Query error surfaces —
    assert_eq!(
        send(&app, "GET", "/api/query", &[], "").await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        send(&app, "GET", "/api/query?walletRef=abc", &[], "")
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    let unknown_query = send(
        &app,
        "GET",
        &format!("/api/query?rpId=absent-{suffix}.invalid&credentialId=absent-{suffix}"),
        &[],
        "",
    )
    .await;
    assert_eq!(unknown_query.status(), StatusCode::NOT_FOUND);

    // — Stats: total, sites, keys, pagination clamp, page overflow short-circuit —
    let total = send(&app, "GET", "/api/stats/total", &[], "").await;
    assert_eq!(total.status(), StatusCode::OK);
    assert_eq!(
        total
            .headers()
            .get(axum::http::header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("public, max-age=3600")
    );
    assert_eq!(body_json(total).await["totalCredentials"], 4242);

    let sites = send(&app, "GET", "/api/stats/sites?page=1&pageSize=20", &[], "").await;
    assert_eq!(sites.status(), StatusCode::OK);
    let sites = body_json(sites).await;
    assert_eq!(sites["total"], 2);
    assert_eq!(sites["items"].as_array().map(Vec::len), Some(2));

    let clamped = send(
        &app,
        "GET",
        "/api/stats/sites?page=0&pageSize=101&order=asc",
        &[],
        "",
    )
    .await;
    let clamped = body_json(clamped).await;
    assert_eq!(clamped["page"], 1);
    assert_eq!(clamped["pageSize"], 100);

    let overflow = send(&app, "GET", "/api/stats/sites?page=10001", &[], "").await;
    let overflow = body_json(overflow).await;
    assert_eq!(overflow["total"], 0);
    assert_eq!(overflow["items"].as_array().map(Vec::len), Some(0));

    assert_eq!(
        send(&app, "GET", "/api/stats/keys", &[], "").await.status(),
        StatusCode::BAD_REQUEST
    );
    let keys = send(&app, "GET", "/api/stats/keys?rpId=example.com", &[], "").await;
    assert_eq!(keys.status(), StatusCode::OK);
    assert_eq!(body_json(keys).await["total"], 1);

    // — Stale-serving: a stale cache entry + a down chain returns 200 with stale markers —
    {
        let mut conn = raw_redis(&redis).await;
        let stored_at = now_ms().saturating_sub(120_000);
        let entry = json!({
            "value": { "totalCredentials": 999 },
            "stored_at_ms": stored_at,
            "fresh_until_ms": stored_at.saturating_add(1_000),
        })
        .to_string();
        let _: () = redis::cmd("SET")
            .arg(cache_redis_key("stats:totalCredentials"))
            .arg(entry)
            .arg("PX")
            .arg(3_600_000u64)
            .query_async(&mut conn)
            .await
            .expect("seed stale cache");
    }
    chain.set_down(true);
    let stale = send(&app, "GET", "/api/stats/total", &[], "").await;
    assert_eq!(stale.status(), StatusCode::OK);
    assert_eq!(
        stale
            .headers()
            .get("x-served-stale")
            .and_then(|v| v.to_str().ok()),
        Some("true")
    );
    let stale = body_json(stale).await;
    assert_eq!(stale["totalCredentials"], 999);
    assert_eq!(stale["_stale"], true);
    assert!(stale["_staleAgeMs"].is_number());
    chain.set_down(false);

    // — Read-limit: pre-seed a distinct IP to its ceiling, next uncached read is 429 —
    {
        let salt = derive_ip_salt(config.private_key.as_deref());
        let ip = "203.0.113.7";
        let key = format!("p256-index:rate:read:{}", hash_ip(&salt, ip));
        let mut conn = raw_redis(&redis).await;
        let _: () = redis::cmd("SET")
            .arg(&key)
            .arg(120u64)
            .arg("PX")
            .arg(60_000u64)
            .query_async(&mut conn)
            .await
            .expect("seed read-rate key");
        let limited = send(
            &app,
            "GET",
            &format!("/api/stats/sites?page={}&pageSize=5", uuid_page(suffix)),
            &[("x-forwarded-for", ip)],
            "",
        )
        .await;
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            limited
                .headers()
                .get(axum::http::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok()),
            Some("10")
        );
    }

    // — Per-IP create rate limit: the 6th create in a minute from one IP is 429 —
    let rl_ip = "198.51.100.9";
    for attempt in 1..=6 {
        let (pk, _) = valid_key_pair();
        let body = json!({
            "rpId": format!("rl-{suffix}-{attempt}.invalid"),
            "credentialId": format!("rl-{suffix}-{attempt}"),
            "publicKey": pk, "name": "rate limit probe"
        })
        .to_string();
        let response = post_json(&app, "/api/create", Some(rl_ip), &body).await;
        if attempt <= 5 {
            assert_eq!(response.status(), StatusCode::ACCEPTED, "attempt {attempt}");
            if let Some(id) = body_json(response).await["id"].as_str() {
                created_ids.push(id.to_owned());
            }
        } else {
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
            assert!(
                body_json(response).await["error"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("rate limit")
            );
        }
    }

    // — Tidy up: mark every admitted task done so it leaves the active set and can never be
    //   consumed as junk by the real worker. `mark_done` (not `mark_failed`) avoids growing the
    //   DLQ set, which would eventually flip the health probe to "degraded" across reruns. —
    for id in &created_ids {
        let _ = store.mark_done(id, None).await;
    }
}

/// A small, run-unique, in-range page (<= 10_000, so it reaches the read limiter rather than the
/// page-overflow short-circuit) that reliably misses the stats cache.
fn uuid_page(suffix: uuid::Uuid) -> u64 {
    1 + (suffix.as_u128() as u64 % 9_000)
}

// ── Test 2: the Iggy transport round-trips a task payload ───────────────────
//
// The task id is deliberately absent from Redis, so even if the real worker later drains this
// topic it loads `None` and skips the message — this test can never trigger an on-chain write.

#[tokio::test]
#[ignore = "requires P256_INDEX_TEST_IGGY_URL"]
async fn enqueued_task_is_durably_consumable_from_iggy() {
    let iggy = iggy_url();
    let queue = CreateQueue::connect(&iggy, &iggy, Duration::from_secs(5))
        .await
        .expect("Iggy connect");
    queue.ensure_topology().await.expect("Iggy topology");

    let marker = uuid::Uuid::new_v4().to_string();
    let (public_key, wallet_ref) = valid_key_pair();
    let task = CreateTask {
        id: format!("e2e-transport-{marker}"),
        status: TaskStatus::Pending,
        rp_id: format!("transport-{marker}.invalid"),
        credential_id: format!("transport-{marker}"),
        wallet_ref,
        public_key,
        name: "transport probe".to_owned(),
        initial_credential_id: format!("transport-{marker}"),
        metadata: "0x".to_owned(),
        tx_hash: None,
        error: None,
        retries: 0,
        created_at: now_ms() as i64,
        admitted: true,
    };
    queue.enqueue(&task).await.expect("enqueue to Iggy");

    // Consume it back with an independent individual consumer, scanning by absolute offset — the
    // same poll surface the worker uses, so this proves the message is durable and deserialisable.
    let client = IggyClient::from_connection_string(&iggy).expect("consumer client");
    client.connect().await.expect("consumer connect");
    let stream: Identifier = STREAM_NAME.try_into().expect("stream id");
    let topic: Identifier = TOPIC_NAME.try_into().expect("topic id");
    let consumer = Consumer::new(
        format!("e2e-probe-{marker}")
            .as_str()
            .try_into()
            .expect("consumer id"),
    );

    let mut cursor = 0u64;
    let mut found: Option<CreateTask> = None;
    for _ in 0..500 {
        let polled = client
            .poll_messages(
                &stream,
                &topic,
                None,
                &consumer,
                &PollingStrategy::offset(cursor),
                500,
                false,
            )
            .await
            .expect("poll Iggy");
        if polled.messages.is_empty() {
            break;
        }
        for message in &polled.messages {
            cursor = message.header.offset + 1;
            if let Ok(decoded) = serde_json::from_slice::<CreateTask>(&message.payload)
                && decoded.id == task.id
            {
                found = Some(decoded);
            }
        }
        if found.is_some() {
            break;
        }
    }

    let decoded = found.expect("enqueued task must be consumable from Iggy");
    assert_eq!(decoded.rp_id, task.rp_id);
    assert_eq!(decoded.credential_id, task.credential_id);
    assert_eq!(decoded.wallet_ref, task.wallet_ref);
    assert_eq!(decoded.public_key, task.public_key);
}
