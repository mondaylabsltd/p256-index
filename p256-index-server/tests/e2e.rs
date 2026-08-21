//! End-to-end contract tests: the HTTP + queue behaviour of the registry
//! service, exercised against **real Redis and real Iggy**.
//!
//! Gated behind `#[ignore]` and two environment variables so `cargo test`
//! stays green in CI (which has no infrastructure). Run them locally:
//!
//! ```sh
//! P256_INDEX_TEST_REDIS_URL='redis://127.0.0.1:6379/0' \
//! P256_INDEX_TEST_IGGY_URL='iggy+tcp://iggy:Secret123@127.0.0.1:5100' \
//!   cargo test --test e2e -- --ignored --nocapture
//! ```
//!
//! The full register -> chain -> confirmed path (real on-chain write, real
//! gas) lives in the `worker.rs` inline test gated by `P256_INDEX_E2E_CHAIN=1`.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use alloy::primitives::B256;
use async_trait::async_trait;
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{Request, StatusCode},
    response::Response,
};
use iggy::prelude::{Client, Consumer, Identifier, IggyClient, MessageClient, PollingStrategy};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::elliptic_curve::Generate;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

use p256_index_server::{
    chain::{ChainError, ReadChain},
    config::Config,
    http::{AppState, router},
    queue::{CreateQueue, DEFAULT_STREAM_NAME, DEFAULT_TOPIC_NAME},
    store::RedisStore,
};
use p256_registrar::{
    lookup::{Entry, Page, SiteItem, Unit},
    protocol::{challenge_for, content_hash_for, member_binding_for},
    task::RegisterTask,
    verify::base64url_32,
};

const REGISTRY: &str = "0x1111111111111111111111111111111111111111";

fn test_config(redis_url: &str, iggy_url: &str) -> Config {
    Config {
        listen_addr: "127.0.0.1:0".parse().expect("test address"),
        private_key: Some(format!("e2e-ip-salt-{}", uuid::Uuid::new_v4())),
        alchemy_api_key: None,
        iggy_url: iggy_url.to_owned(),
        iggy_consumer_url: iggy_url.to_owned(),
        iggy_provisioner_url: iggy_url.to_owned(),
        redis_url: redis_url.to_owned(),
        queue_worker_enabled: false,
        telegram_bot_token: None,
        telegram_chat_id: None,
        max_gas_price_wei: p256_registrar::gas::DEFAULT_MAX_FEE_WEI,
        global_write_limit: 10_000,
        iggy_enqueue_timeout: Duration::from_secs(5),
        iggy_consumer_group: format!("e2e-{}", uuid::Uuid::new_v4()),
        iggy_stream: DEFAULT_STREAM_NAME.into(),
        iggy_topic: DEFAULT_TOPIC_NAME.into(),
        contract_address: REGISTRY.into(),
    }
}

/// A chain that has nothing and fails all pre-checks fail-open.
struct FakeChain;

#[async_trait]
impl ReadChain for FakeChain {
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
    ) -> Result<Option<p256_index_server::chain::KeyProfile>, ChainError> {
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
    ) -> Result<Option<p256_index_server::chain::GroupDetail>, ChainError> {
        Ok(None)
    }

    async fn group_detail_by_id(
        &self,
        _: u64,
        _: u64,
        _: u64,
        _: bool,
    ) -> Result<Option<p256_index_server::chain::GroupDetail>, ChainError> {
        Ok(None)
    }

    async fn rp_ids(&self, _: u64, _: u64, _: bool) -> Result<Page<SiteItem>, ChainError> {
        Err(ChainError::Unavailable)
    }

    async fn totals(&self) -> Result<p256_index_server::chain::Totals, ChainError> {
        Err(ChainError::Unavailable)
    }

    async fn is_content_registered(&self, _: B256) -> Result<bool, ChainError> {
        Err(ChainError::Unavailable)
    }
}

async fn send(app: &Router, method: &str, uri: &str, body: &str) -> Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header("content-type", "application/json")
                .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 5000))))
                .body(Body::from(body.to_owned()))
                .expect("test request"),
        )
        .await
        .expect("router response")
}

async fn body_json(response: Response) -> Value {
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json body")
}

/// A fully-signed single-member unit (fresh group key + fresh passkey):
/// the member binds (groupKey, own attestation), the group key closes over
/// the content hash. Returns (register body, member pub hex).
fn signed_unit(rp_id: &str, metadata_hex: &str) -> (Value, String) {
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
        status: p256_registrar::task::TaskStatus::Pending,
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
            credential_id: String::new(),
            authenticator_attachment: String::new(),
            transports: String::new(),
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

    (
        json!({
            "rpId": rp_id,
            "metadata": metadata_hex,
            "groupPublicKey": group_public,
            "groupProof": group_proof,
            "members": [{ "publicKey": member_public, "proof": member_proof }],
        }),
        member_public,
    )
}

fn infra() -> Option<(String, String)> {
    let redis = std::env::var("P256_INDEX_TEST_REDIS_URL").ok()?;
    let iggy = std::env::var("P256_INDEX_TEST_IGGY_URL").ok()?;
    Some((redis, iggy))
}

// ── Test 1: the HTTP contract over real Redis + real Iggy ───────────────────

#[tokio::test]
#[ignore = "requires P256_INDEX_TEST_REDIS_URL and P256_INDEX_TEST_IGGY_URL"]
async fn http_contract_over_real_redis_and_iggy() {
    let Some((redis_url, iggy_url)) = infra() else {
        return;
    };
    let config = test_config(&redis_url, &iggy_url);
    let store = RedisStore::connect(&redis_url).await.expect("Redis");
    let queue = CreateQueue::connect(
        &config.iggy_url,
        &config.iggy_provisioner_url,
        &config.iggy_stream,
        &config.iggy_topic,
        config.iggy_enqueue_timeout,
    )
    .await
    .expect("Iggy");
    queue.ensure_topology().await.expect("Iggy topology");
    let queue = Arc::new(queue);
    let state = AppState::new(store.clone(), queue, Arc::new(FakeChain), &config);
    let app = router(state);

    // A fully-proven registration flows to 202, is idempotent by content
    // hash, and is visible pre-chain via task status and the key query.
    let rp_id = format!("e2e-{}.example", uuid::Uuid::new_v4());
    let (unit_body, public_key) = signed_unit(&rp_id, "0xe2e0");
    let body = unit_body.to_string();

    let created = send(&app, "POST", "/api/register", &body).await;
    assert_eq!(created.status(), StatusCode::ACCEPTED);
    let created = body_json(created).await;
    let id = created["id"].as_str().expect("task id").to_owned();

    let duplicate = send(&app, "POST", "/api/register", &body).await;
    assert_eq!(duplicate.status(), StatusCode::ACCEPTED);
    assert_eq!(body_json(duplicate).await["id"], id);

    let status = send(&app, "GET", &format!("/api/task/{id}"), "").await;
    assert_eq!(status.status(), StatusCode::OK);
    let status = body_json(status).await;
    assert_eq!(status["status"], "pending");
    assert_eq!(status["members"][0]["publicKey"], public_key);

    let pending = send(
        &app,
        "GET",
        &format!("/api/query?publicKey={public_key}"),
        "",
    )
    .await;
    assert_eq!(pending.status(), StatusCode::OK);
    assert_eq!(body_json(pending).await["_queue"]["id"], id);

    // The durable envelope is consumable from Iggy.
    let client = IggyClient::from_connection_string(&iggy_url).expect("iggy client");
    client.connect().await.expect("iggy connect");
    let stream: Identifier = DEFAULT_STREAM_NAME.try_into().unwrap();
    let topic: Identifier = DEFAULT_TOPIC_NAME.try_into().unwrap();
    let consumer = Consumer::default();
    let mut found = false;
    let mut offset = 0u64;
    for _ in 0..50 {
        let polled = client
            .poll_messages(
                &stream,
                &topic,
                Some(1),
                &consumer,
                &PollingStrategy::offset(offset),
                100,
                false,
            )
            .await
            .expect("poll");
        if polled.messages.is_empty() {
            break;
        }
        for message in &polled.messages {
            offset = message.header.offset + 1;
            if let Ok(task) = serde_json::from_slice::<RegisterTask>(&message.payload)
                && task.id == id
            {
                assert_eq!(task.members[0].public_key, public_key);
                found = true;
            }
        }
        if found {
            break;
        }
    }
    assert!(
        found,
        "the admitted task must be durably consumable from Iggy"
    );
}
