//! Live end-to-end probe of the running HTTP service against the deployed
//! registry: every endpoint, happy and unhappy, driven exactly like a real
//! client — challenges cross-checked against local computation, a register
//! and a refer pushed through the full queue → chain → done lifecycle.
//!
//! Requires the server on 127.0.0.1:11256 with Redis + Iggy + the funded
//! `.env` PRIVATE_KEY (the worker spends real gas).
//!
//! ```sh
//! cargo run -p p256-index-server --example live_api_probe
//! ```

use std::time::{Duration, Instant};

use alloy::primitives::{Address, B256};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::elliptic_curve::Generate as _;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use p256_registrar::{
    protocol::{challenge_for, content_hash_for, member_binding_for, reference_binding_for},
    task::{Member, Proof, RegisterTask, TaskKind, TaskStatus},
    verify::base64url_32,
};

const API: &str = "http://127.0.0.1:11256";

struct Keypair {
    signing: p256::ecdsa::SigningKey,
    public_hex: String,
}

impl Keypair {
    fn fresh() -> Self {
        let signing = p256::ecdsa::SigningKey::from(&p256::SecretKey::generate());
        let public_hex = hex::encode(signing.verifying_key().to_sec1_point(false).as_bytes());
        Self {
            signing,
            public_hex,
        }
    }

    fn bytes(&self) -> Vec<u8> {
        hex::decode(&self.public_hex).expect("own key hex")
    }
}

fn sign_proof(signing: &p256::ecdsa::SigningKey, challenge: B256, rp_id: &str) -> Proof {
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
    let signature: p256::ecdsa::Signature = signing.sign_prehash(&digest).expect("p256 sign");
    let bytes = signature.to_bytes();
    Proof {
        authenticator_data: hex::encode(auth_data),
        client_data_json: client_data,
        challenge_index: 23,
        type_index: 1,
        r: format!("0x{}", hex::encode(&bytes[..32])),
        s: format!("0x{}", hex::encode(&bytes[32..])),
    }
}

/// The signed register REQUEST BODY plus the group's local content hash.
fn register_body(
    chain_id: u64,
    registry: Address,
    rp_id: &str,
    metadata: &str,
    group: &Keypair,
    members: &[&Keypair],
) -> (Value, B256) {
    let mut task = RegisterTask {
        id: String::new(),
        status: TaskStatus::Pending,
        kind: TaskKind::Register,
        rp_id: rp_id.to_owned(),
        metadata: metadata.to_owned(),
        content_hash: String::new(),
        group_public_key: group.public_hex.clone(),
        group_proof: None,
        members: members
            .iter()
            .enumerate()
            .map(|(i, key)| {
                let binding = member_binding_for(&group.bytes(), &[]);
                let challenge = challenge_for(chain_id, registry, rp_id, &key.bytes(), binding);
                let (credential_id, attachment, transports) = member_hints(i);
                Member {
                    public_key: key.public_hex.clone(),
                    attestation: String::new(),
                    // Store-only WebAuthn signals — not part of any binding or
                    // the contentHash, so these values never alter a signature.
                    credential_id,
                    authenticator_attachment: attachment,
                    transports,
                    proof: sign_proof(&key.signing, challenge, rp_id),
                }
            })
            .collect(),
        tx_hash: None,
        on_chain_id: None,
        error: None,
        retries: 0,
        created_at: 0,
        admitted: false,
    };
    let content = content_hash_for(&task).expect("content hash");
    task.content_hash = format!("{content:#x}");
    let group_challenge = challenge_for(chain_id, registry, rp_id, &group.bytes(), content);
    let group_proof = sign_proof(&group.signing, group_challenge, rp_id);
    let body = json!({
        "rpId": rp_id,
        "metadata": metadata,
        "groupPublicKey": group.public_hex,
        "groupProof": serde_json::to_value(&group_proof).expect("proof json"),
        "members": task.members.iter().map(|member| json!({
            "publicKey": member.public_key,
            "credentialId": member.credential_id,
            "authenticatorAttachment": member.authenticator_attachment,
            "transports": member.transports,
            "proof": serde_json::to_value(&member.proof).expect("proof json"),
        })).collect::<Vec<_>>(),
    });
    (body, content)
}

/// Realistic, per-member WebAuthn display hints, mirroring what a browser's
/// `PublicKeyCredential` exposes: (credentialId hex, authenticatorAttachment,
/// transports). Distinct per member so the probe can prove they are stored
/// per-entry, not smeared across the group.
fn member_hints(index: usize) -> (String, String, String) {
    match index {
        0 => (
            "0x0102030405060708".to_owned(),
            "platform".to_owned(),
            "hybrid,internal".to_owned(),
        ),
        _ => (
            "0x0a0b0c0d".to_owned(),
            "cross-platform".to_owned(),
            "usb,nfc".to_owned(),
        ),
    }
}

/// The signed refer REQUEST BODY.
fn refer_body(
    chain_id: u64,
    registry: Address,
    group_public_hex: &str,
    group_rp_id: &str,
    metadata_bytes: &[u8],
    referrer: &Keypair,
) -> Value {
    let group_bytes = hex::decode(group_public_hex).expect("group hex");
    let binding = reference_binding_for(&group_bytes, &[], metadata_bytes);
    let challenge = challenge_for(chain_id, registry, group_rp_id, &referrer.bytes(), binding);
    json!({
        "rpId": group_rp_id,
        "groupPublicKey": group_public_hex,
        "metadata": format!("0x{}", hex::encode(metadata_bytes)),
        "member": {
            "publicKey": referrer.public_hex,
            "proof": serde_json::to_value(sign_proof(&referrer.signing, challenge, group_rp_id))
                .expect("proof json"),
        },
    })
}

struct Api {
    client: reqwest::Client,
    passed: u32,
    failed: u32,
}

impl Api {
    fn check(&mut self, name: &str, ok: bool, detail: String) {
        if ok {
            self.passed += 1;
            println!("  ✓ {name}");
        } else {
            self.failed += 1;
            println!("  ✗ {name} — {detail}");
        }
    }

    async fn get(&self, path: &str) -> (u16, Value, Option<String>) {
        let response = self
            .client
            .get(format!("{API}{path}"))
            .send()
            .await
            .expect("GET");
        let status = response.status().as_u16();
        let cache = response
            .headers()
            .get("cache-control")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let body = response.json::<Value>().await.unwrap_or(Value::Null);
        (status, body, cache)
    }

    async fn post(&self, path: &str, body: &Value) -> (u16, Value) {
        let response = self
            .client
            .post(format!("{API}{path}"))
            .json(body)
            .send()
            .await
            .expect("POST");
        (
            response.status().as_u16(),
            response.json::<Value>().await.unwrap_or(Value::Null),
        )
    }

    /// Poll the task until terminal; panics on timeout.
    async fn wait_done(&self, id: &str, timeout: Duration) -> Value {
        let started = Instant::now();
        loop {
            let (status, body, _) = self.get(&format!("/api/task/{id}")).await;
            assert_eq!(status, 200, "task status fetch");
            match body["status"].as_str() {
                Some("done") => return body,
                Some("failed") => panic!("task {id} failed: {body}"),
                _ => {}
            }
            assert!(
                started.elapsed() < timeout,
                "task {id} not done after {timeout:?}: {body}"
            );
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    }
}

#[tokio::main]
async fn main() {
    let mut api = Api {
        // No idle-connection reuse: a pooled keep-alive socket the server
        // has closed surfaces as a spurious "connection reset by peer".
        client: reqwest::Client::builder()
            .pool_max_idle_per_host(0)
            .build()
            .expect("http client"),
        passed: 0,
        failed: 0,
    };

    // ── Health names the deployed registry ─────────────────────────────────
    println!("[health]");
    let (status, health, _) = api.get("/api/health").await;
    let registry: Address = health["registry"]
        .as_str()
        .expect("registry in health")
        .parse()
        .expect("registry address");
    let chain_id = health["chainId"].as_u64().expect("chainId");
    api.check(
        "GET /api/health 200 ok with registry + chainId",
        status == 200 && health["status"] == "ok" && chain_id == 100,
        format!("{health}"),
    );

    let suffix = uuid::Uuid::new_v4().to_string()[..8].to_owned();
    let rp = format!("api-{suffix}.probe");
    let group = Keypair::fresh();
    let member_1 = Keypair::fresh();
    let member_2 = Keypair::fresh();
    let (body, local_content) = register_body(
        chain_id,
        registry,
        &rp,
        "0xa11a",
        &group,
        &[&member_1, &member_2],
    );

    // ── Challenge: three modes, cross-checked against local computation ────
    println!("[challenge]");
    let (status, derived) = api
        .post(
            "/api/challenge",
            &json!({ "rpId": rp, "groupPublicKey": group.public_hex, "publicKey": member_1.public_hex }),
        )
        .await;
    let local_member = challenge_for(
        chain_id,
        registry,
        &rp,
        &member_1.bytes(),
        member_binding_for(&group.bytes(), &[]),
    );
    api.check(
        "member mode returns exactly the locally-computed challenge",
        status == 200 && derived["challengeBase64url"] == base64url_32(&local_member),
        format!("{derived}"),
    );
    let (status, derived) = api
        .post(
            "/api/challenge",
            &json!({
                "rpId": rp, "metadata": "0xa11a", "groupPublicKey": group.public_hex,
                "members": [{ "publicKey": member_1.public_hex }, { "publicKey": member_2.public_hex }],
            }),
        )
        .await;
    api.check(
        "group mode returns the contract contentHash + group challenge",
        status == 200
            && derived["contentHash"] == format!("{local_content:#x}")
            && derived["groupChallenge"]["challengeBase64url"]
                == base64url_32(&challenge_for(
                    chain_id,
                    registry,
                    &rp,
                    &group.bytes(),
                    local_content,
                )),
        format!("{derived}"),
    );
    let referrer = Keypair::fresh();
    let (status, derived) = api
        .post(
            "/api/challenge",
            &json!({
                "rpId": rp, "groupPublicKey": group.public_hex,
                "publicKey": referrer.public_hex, "refer": true, "metadata": "0xcafe",
            }),
        )
        .await;
    let local_refer = challenge_for(
        chain_id,
        registry,
        &rp,
        &referrer.bytes(),
        reference_binding_for(&group.bytes(), &[], &[0xca, 0xfe]),
    );
    api.check(
        "reference mode (refer: true) binds the reference metadata",
        status == 200 && derived["challengeBase64url"] == base64url_32(&local_refer),
        format!("{derived}"),
    );
    let (status, _) = api
        .post(
            "/api/challenge",
            &json!({
                "rpId": rp, "groupPublicKey": group.public_hex, "refer": true,
                "members": [{ "publicKey": member_1.public_hex }],
            }),
        )
        .await;
    api.check(
        "refer + members is an ambiguous 400",
        status == 400,
        status.to_string(),
    );
    let (status, _) = api
        .post(
            "/api/challenge",
            &json!({ "rpId": rp, "groupPublicKey": group.public_hex, "publicKey": "0x0400" }),
        )
        .await;
    api.check(
        "malformed publicKey is a 400",
        status == 400,
        status.to_string(),
    );

    // ── Register: full lifecycle through queue and chain ───────────────────
    println!("[register]");
    let (status, created) = api.post("/api/register", &body).await;
    api.check(
        "POST /api/register 202 pending",
        status == 202 && created["status"] == "pending",
        format!("{status} {created}"),
    );
    let task_id = created["id"].as_str().expect("task id").to_owned();

    let (status, pending, _) = api
        .get(&format!("/api/query?publicKey={}", member_1.public_hex))
        .await;
    api.check(
        "pre-chain visibility: member key answers 200 with _queue (or already landed)",
        status == 200
            && (pending["_queue"]["id"] == task_id.as_str() || pending["entry"].is_object()),
        format!("{status} {pending}"),
    );
    let (status, group_pending, _) = api
        .get(&format!("/api/query?groupPublicKey={}", group.public_hex))
        .await;
    api.check(
        "pre-chain visibility: GROUP key answers 200 with _queue (or already landed)",
        status == 200
            && (group_pending["_queue"]["id"] == task_id.as_str()
                || group_pending["unit"].is_object()),
        format!("{status} {group_pending}"),
    );

    let (status, duplicate) = api.post("/api/register", &body).await;
    api.check(
        "identical resubmission maps to the SAME task (idempotency by contentHash)",
        status == 202 && duplicate["id"] == task_id.as_str(),
        format!("{status} {duplicate}"),
    );

    let done = api.wait_done(&task_id, Duration::from_secs(180)).await;
    let unit_id = done["onChainId"].as_u64().expect("onChainId");
    api.check(
        "task walks pending → done with txHash + onChainId",
        done["txHash"]
            .as_str()
            .is_some_and(|hash| hash.starts_with("0x")),
        format!("{done}"),
    );

    // ── Queries over the landed unit ───────────────────────────────────────
    println!("[query]");
    let (status, profile, _) = api
        .get(&format!("/api/query?publicKey={}", member_1.public_hex))
        .await;
    api.check(
        "?publicKey= serves the file + group ids",
        status == 200
            && profile["entry"]["publicKey"] == member_1.public_hex
            && profile["groups"]["total"] == 1
            && profile["groups"]["unitIds"][0] == unit_id,
        format!("{status} {profile}"),
    );
    // The three store-only WebAuthn signals must round-trip on member_1's entry:
    // credentialId comes back as bare hex (no 0x); the hints as their UTF-8 text.
    api.check(
        "member_1 entry carries credentialId + authenticatorAttachment + transports",
        profile["entry"]["credentialId"] == "0102030405060708"
            && profile["entry"]["authenticatorAttachment"] == "platform"
            && profile["entry"]["transports"] == "hybrid,internal",
        format!(
            "credentialId={} attachment={} transports={}",
            profile["entry"]["credentialId"],
            profile["entry"]["authenticatorAttachment"],
            profile["entry"]["transports"]
        ),
    );
    // member_2's entry must carry ITS OWN distinct signals (proving per-entry storage).
    let (_, profile_2, _) = api
        .get(&format!("/api/query?publicKey={}", member_2.public_hex))
        .await;
    api.check(
        "member_2 entry carries its OWN distinct signals",
        profile_2["entry"]["credentialId"] == "0a0b0c0d"
            && profile_2["entry"]["authenticatorAttachment"] == "cross-platform"
            && profile_2["entry"]["transports"] == "usb,nfc",
        format!("{profile_2}"),
    );
    let (_, _, cache) = api
        .get(&format!("/api/query?publicKey={}", member_1.public_hex))
        .await;
    api.check(
        "repeat query serves from cache (Cache-Control set)",
        cache
            .as_deref()
            .is_some_and(|value| value.contains("max-age")),
        format!("{cache:?}"),
    );
    let entry_id = profile["entry"]["entryId"].as_u64().expect("entryId");
    let (status, entry, _) = api.get(&format!("/api/query?entryId={entry_id}")).await;
    api.check(
        "?entryId= serves the single file",
        status == 200 && entry["publicKey"] == member_1.public_hex,
        format!("{status} {entry}"),
    );
    let (status, unit, _) = api.get(&format!("/api/query?unitId={unit_id}")).await;
    api.check(
        "?unitId= serves the group detail (record + members + references)",
        status == 200
            && unit["unit"]["groupPublicKey"] == group.public_hex
            && unit["unit"]["rpId"] == rp.as_str()
            && unit["members"]["total"] == 2
            && unit["references"]["total"] == 0,
        format!("{status} {unit}"),
    );
    let (status, by_group, _) = api
        .get(&format!("/api/query?groupPublicKey={}", group.public_hex))
        .await;
    api.check(
        "?groupPublicKey= serves the same group detail",
        status == 200
            && by_group["unit"]["unitId"] == unit_id
            && by_group["unit"]["metadata"] == "a11a"
            && by_group["members"]["items"]
                .as_array()
                .is_some_and(|items| items.len() == 2),
        format!("{status} {by_group}"),
    );

    // ── Refer: full lifecycle, then discovery ──────────────────────────────
    println!("[refer]");
    let refer_request = refer_body(
        chain_id,
        registry,
        &group.public_hex,
        &rp,
        &[0xca, 0xfe],
        &referrer,
    );
    let (status, accepted) = api.post("/api/refer", &refer_request).await;
    api.check(
        "POST /api/refer 202 pending",
        status == 202 && accepted["status"] == "pending",
        format!("{status} {accepted}"),
    );
    let refer_id = accepted["id"].as_str().expect("refer task id").to_owned();
    let refer_done = api.wait_done(&refer_id, Duration::from_secs(180)).await;
    api.check(
        "refer task walks pending → done with its referenceId",
        refer_done["kind"] == "refer" && refer_done["onChainId"].is_u64(),
        format!("{refer_done}"),
    );
    // A terminal task answers 200 with its outcome — not a make-believe 202.
    let (status, resubmitted) = api.post("/api/refer", &refer_request).await;
    api.check(
        "identical refer resubmission answers 200 with the SAME done task",
        status == 200 && resubmitted["id"] == refer_id.as_str() && resubmitted["status"] == "done",
        format!("{status} {resubmitted}"),
    );
    let (status, referrer_profile, _) = api
        .get(&format!("/api/query?publicKey={}", referrer.public_hex))
        .await;
    api.check(
        "the referrer's file shows the reference, no membership",
        status == 200
            && referrer_profile["references"]["total"] == 1
            && referrer_profile["groups"]["total"] == 0,
        format!("{status} {referrer_profile}"),
    );
    // The default page for this group was cached BEFORE the refer landed
    // and is still fresh — by-design read-through caching. A different
    // pageSize is a different cache key, so it reads through to the chain.
    let (status, group_cached, _) = api
        .get(&format!("/api/query?groupPublicKey={}", group.public_hex))
        .await;
    api.check(
        "the pre-refer cached group page is still served fresh (by design)",
        status == 200 && group_cached["references"]["total"] == 0,
        format!("{status} {group_cached}"),
    );
    let (status, group_after, _) = api
        .get(&format!(
            "/api/query?groupPublicKey={}&pageSize=19",
            group.public_hex
        ))
        .await;
    api.check(
        "a cache-missing page shows the reference in the group's inbox",
        status == 200 && group_after["references"]["total"] == 1,
        format!("{status} {group_after}"),
    );

    // ── Stats ──────────────────────────────────────────────────────────────
    println!("[stats]");
    let (status, totals, _) = api.get("/api/stats/total").await;
    api.check(
        "stats/total carries all four structural counters",
        status == 200
            && totals["totalEntries"]
                .as_u64()
                .is_some_and(|value| value >= 3)
            && totals["totalUnits"]
                .as_u64()
                .is_some_and(|value| value >= 1)
            && totals["totalReferences"]
                .as_u64()
                .is_some_and(|value| value >= 1)
            && totals["totalRpIds"]
                .as_u64()
                .is_some_and(|value| value >= 1),
        format!("{status} {totals}"),
    );
    let (status, keys, _) = api.get(&format!("/api/stats/keys?rpId={rp}")).await;
    api.check(
        "stats/keys?rpId= lists this run's group with its frozen record",
        status == 200 && keys["total"] == 1 && keys["items"][0]["unitId"] == unit_id,
        format!("{status} {keys}"),
    );
    let (status, sites, _) = api.get("/api/stats/sites?pageSize=100").await;
    api.check(
        "stats/sites carries this run's rpId",
        status == 200
            && sites["items"]
                .as_array()
                .is_some_and(|items| items.iter().any(|site| site["rpId"] == rp.as_str())),
        format!("{status}"),
    );

    // ── Unhappy paths ──────────────────────────────────────────────────────
    println!("[errors]");
    let mut tampered = body.clone();
    tampered["members"][0]["proof"]["r"] = json!(format!("0x{}", "11".repeat(32)));
    let (status, rejected) = api.post("/api/register", &tampered).await;
    api.check(
        "tampered proof never enters the queue (400)",
        status == 400,
        format!("{status} {rejected}"),
    );
    // NOTE: a refer to a group that does NOT exist is currently admitted
    // fail-open and then wedges the worker forever (GroupNotFound is
    // classified transient and the FIFO offset never advances). That is a
    // real availability finding, reported separately — the probe must not
    // enqueue such a poison pill, so it asserts the safe admission-level
    // rejections instead. The GroupNotFound revert itself is covered by the
    // direct-to-chain probe.
    let malformed_refer = json!({
        "rpId": rp,
        "groupPublicKey": group.public_hex,
        "metadata": "0x00",
        "member": { "publicKey": "0x0400", "proof": refer_request["member"]["proof"].clone() },
    });
    let (status, rejected) = api.post("/api/refer", &malformed_refer).await;
    api.check(
        "refer with a malformed member key is a 400 (never enqueued)",
        status == 400,
        format!("{status} {rejected}"),
    );
    let mut tampered_refer = refer_request.clone();
    tampered_refer["member"]["proof"]["s"] = json!(format!("0x{}", "22".repeat(32)));
    let (status, rejected) = api.post("/api/refer", &tampered_refer).await;
    api.check(
        "refer with a tampered proof is a 400 (never enqueued)",
        status == 400,
        format!("{status} {rejected}"),
    );
    let raw = api
        .client
        .post(format!("{API}/api/register"))
        .header("content-type", "application/json")
        .body("not-json")
        .send()
        .await
        .expect("POST");
    api.check(
        "malformed JSON is a 400",
        raw.status().as_u16() == 400,
        raw.status().to_string(),
    );
    let (status, _, _) = api.get("/api/task/no-such-task").await;
    api.check(
        "unknown task id is a 404",
        status == 404,
        status.to_string(),
    );
    let (status, _, _) = api.get("/api/query?publicKey=02ab").await;
    api.check(
        "query with a malformed key is a 400",
        status == 400,
        status.to_string(),
    );
    let (status, _, _) = api.get("/api/query?unitId=999999999").await;
    api.check(
        "query for a unit that does not exist is a 404",
        status == 404,
        status.to_string(),
    );
    let (status, _, _) = api.get("/api/query").await;
    api.check(
        "query without any dimension is a 400",
        status == 400,
        status.to_string(),
    );
    let oversized = json!({ "rpId": rp, "metadata": format!("0x{}", "aa".repeat(200_000)) });
    let (status, _) = api.post("/api/register", &oversized).await;
    api.check(
        "oversized body is refused with a 4xx",
        (400..500).contains(&status),
        status.to_string(),
    );

    println!("\n[result] {} passed, {} failed", api.passed, api.failed);
    if api.failed > 0 {
        std::process::exit(1);
    }
}
