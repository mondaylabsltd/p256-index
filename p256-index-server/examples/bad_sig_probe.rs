//! Adversarial probe: an INVALID WebAuthn signature can never create a wallet.
//!
//! Two properties, each checked two ways:
//!   1. a single-key register with a bad member signature is rejected;
//!   2. a MULTI-key register where just ONE of the founding members has a bad
//!      signature is rejected wholesale — register is all-or-nothing.
//!
//! Part A hits the DEPLOYED contract directly through free `eth_call`
//! simulation (no gas, no state change): a valid group simulates to success,
//! a tampered one reverts with `InvalidProof()`. Part B posts the same bodies
//! to the p256-index backend, which verifies every proof up front and must
//! answer 400 before anything is enqueued or any gas is spent.
//!
//! Run (backend must be up on :11256 for Part B):
//! ```sh
//! cargo run -p p256-index-server --example bad_sig_probe
//! ```

use alloy::primitives::{Address, B256, keccak256};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::elliptic_curve::Generate as _;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use p256_registrar::{
    protocol::{challenge_for, content_hash_for, member_binding_for, register_calldata},
    task::{Member, Proof, RegisterTask, TaskKind, TaskStatus},
    verify::base64url_32,
};

const RPC: &str = "https://rpc.gnosischain.com";
const API: &str = "http://127.0.0.1:11256";
const REGISTRY: &str = "0x5266DfF591B9F9EecfEdb8E7EfEf6c687854edaf";
const CHAIN_ID: u64 = 100;

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

/// A genuine WebAuthn-shaped P-256 assertion over `challenge`.
fn sign_proof(signing: &p256::ecdsa::SigningKey, challenge: B256, rp_id: &str) -> Proof {
    let client_data = format!(
        "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"https://{rp_id}\"}}",
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
    Proof {
        authenticator_data: hex::encode(&auth_data),
        client_data_json: client_data,
        challenge_index: 23,
        type_index: 1,
        r: format!("0x{}", hex::encode(&bytes[..32])),
        s: format!("0x{}", hex::encode(&bytes[32..])),
    }
}

/// A fully-signed register task: every member binds (groupKey, own attestation);
/// the group key closes over the content hash.
fn register_task(rp_id: &str, group: &Keypair, members: &[&Keypair]) -> RegisterTask {
    let registry: Address = REGISTRY.parse().unwrap();
    let mut task = RegisterTask {
        id: String::new(),
        status: TaskStatus::Pending,
        kind: TaskKind::Register,
        rp_id: rp_id.to_owned(),
        metadata: "0x".to_owned(),
        content_hash: String::new(),
        group_public_key: group.public_hex.clone(),
        group_proof: None,
        members: members
            .iter()
            .map(|key| {
                let binding = member_binding_for(&group.bytes(), &[]);
                let challenge = challenge_for(CHAIN_ID, registry, rp_id, &key.bytes(), binding);
                Member {
                    public_key: key.public_hex.clone(),
                    attestation: String::new(),
                    credential_id: String::new(),
                    authenticator_attachment: String::new(),
                    transports: String::new(),
                    proof: sign_proof(&key.signing, challenge, rp_id),
                }
            })
            .collect(),
        tx_hash: None,
        on_chain_id: None,
        error: None,
        retries: 0,
        created_at: 0,
        admitted: true,
    };
    let content = content_hash_for(&task).expect("content hash");
    task.content_hash = format!("{content:#x}");
    let group_challenge = challenge_for(CHAIN_ID, registry, rp_id, &group.bytes(), content);
    task.group_proof = Some(sign_proof(&group.signing, group_challenge, rp_id));
    task
}

/// The REST register body the backend expects.
fn register_body(task: &RegisterTask) -> Value {
    json!({
        "rpId": task.rp_id,
        "metadata": task.metadata,
        "groupPublicKey": task.group_public_key,
        "groupProof": serde_json::to_value(task.group_proof.as_ref().unwrap()).unwrap(),
        "members": task.members.iter().map(|m| json!({
            "publicKey": m.public_key,
            "proof": serde_json::to_value(&m.proof).unwrap(),
        })).collect::<Vec<_>>(),
    })
}

struct Probe {
    client: reqwest::Client,
    registry: Address,
    passed: u32,
    failed: u32,
}

impl Probe {
    fn check(&mut self, name: &str, ok: bool, detail: String) {
        if ok {
            self.passed += 1;
            println!("  \u{2713} {name}");
        } else {
            self.failed += 1;
            println!("  \u{2717} {name} \u{2014} {detail}");
        }
    }

    async fn eth_call(&self, data: Vec<u8>) -> Result<Vec<u8>, String> {
        let body = json!({
            "jsonrpc": "2.0", "id": 1, "method": "eth_call",
            "params": [{ "to": self.registry.to_string(), "data": format!("0x{}", hex::encode(data)) }, "latest"],
        });
        let response: Value = self
            .client
            .post(RPC)
            .json(&body)
            .send()
            .await
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())?;
        match response.get("result").and_then(Value::as_str) {
            Some(result) => hex::decode(result.trim_start_matches("0x")).map_err(|e| e.to_string()),
            None => Err(response
                .get("error")
                .map(|e| e.to_string())
                .unwrap_or_else(|| "no result, no error".into())),
        }
    }

    /// A valid register must SIMULATE to success (no revert) — the control that
    /// proves the harness produces accepting proofs.
    async fn expect_ok(&mut self, name: &str, data: Vec<u8>) {
        match self.eth_call(data).await {
            Ok(_) => self.check(name, true, String::new()),
            Err(error) => self.check(name, false, format!("expected success, reverted: {error}")),
        }
    }

    /// The calldata must revert, carrying the selector of `error_signature`.
    async fn expect_revert(&mut self, name: &str, data: Vec<u8>, error_signature: &str) {
        let selector = hex::encode(&keccak256(error_signature.as_bytes())[..4]);
        match self.eth_call(data).await {
            Ok(bytes) => self.check(
                name,
                false,
                format!(
                    "expected {error_signature}, call succeeded: 0x{}",
                    hex::encode(bytes)
                ),
            ),
            Err(error) => self.check(
                name,
                error.contains(&selector),
                format!("expected 0x{selector} ({error_signature}) in: {error}"),
            ),
        }
    }

    async fn post_status(&self, body: &Value) -> u16 {
        self.client
            .post(format!("{API}/api/register"))
            .json(body)
            .send()
            .await
            .map(|r| r.status().as_u16())
            .unwrap_or(0)
    }

    async fn expect_status(&mut self, name: &str, body: &Value, want: u16) {
        let got = self.post_status(body).await;
        self.check(name, got == want, format!("expected {want}, got {got}"));
    }
}

/// Replace one member's signature `s` with a bogus scalar — a definitively
/// invalid signature for that member's key, leaving every other member intact.
fn corrupt_member_signature(task: &mut RegisterTask, index: usize) {
    task.members[index].proof.s = format!("0x{}", "11".repeat(32));
}

#[tokio::main]
async fn main() {
    let mut probe = Probe {
        client: reqwest::Client::new(),
        registry: REGISTRY.parse().unwrap(),
        passed: 0,
        failed: 0,
    };

    // ── Part A: directly against the deployed contract (free eth_call) ──────
    println!("[contract] direct eth_call against {REGISTRY}");

    // A1 control — a single valid member registers cleanly.
    let g1 = Keypair::fresh();
    let m1 = Keypair::fresh();
    let single_ok = register_task("badsig.probe", &g1, &[&m1]);
    probe
        .expect_ok(
            "single-key, valid signature: register simulates to success",
            register_calldata(&single_ok).expect("calldata"),
        )
        .await;

    // A2 — the same single member with a tampered signature is rejected.
    let mut single_bad = single_ok.clone();
    corrupt_member_signature(&mut single_bad, 0);
    probe
        .expect_revert(
            "single-key, BAD signature: reverts InvalidProof()",
            register_calldata(&single_bad).expect("calldata"),
            "InvalidProof()",
        )
        .await;

    // A3 control — three valid members found one wallet.
    let g3 = Keypair::fresh();
    let (a, b, c) = (Keypair::fresh(), Keypair::fresh(), Keypair::fresh());
    let multi_ok = register_task("badsig.probe", &g3, &[&a, &b, &c]);
    probe
        .expect_ok(
            "multi-key (3 valid): register simulates to success",
            register_calldata(&multi_ok).expect("calldata"),
        )
        .await;

    // A4 — three members, only the SECOND one's signature is bad: the WHOLE
    // register must revert. One rotten proof fails the entire group.
    let mut multi_one_bad = multi_ok.clone();
    corrupt_member_signature(&mut multi_one_bad, 1);
    probe
        .expect_revert(
            "multi-key, ONE bad member signature: whole register reverts InvalidProof()",
            register_calldata(&multi_one_bad).expect("calldata"),
            "InvalidProof()",
        )
        .await;

    // ── Part B: through the p256-index backend (verified before enqueue) ────
    println!("\n[backend] POST /api/register to {API}");
    match probe.client.get(format!("{API}/api/health")).send().await {
        Ok(r) if r.status().is_success() => {
            probe
                .expect_status(
                    "single-key, BAD signature: 400 (never enqueued, no gas)",
                    &register_body(&single_bad),
                    400,
                )
                .await;
            probe
                .expect_status(
                    "multi-key, ONE bad member signature: 400 (whole request refused)",
                    &register_body(&multi_one_bad),
                    400,
                )
                .await;
        }
        _ => println!("  (skipped — backend not reachable on :11256)"),
    }

    println!(
        "\n[result] {} passed, {} failed",
        probe.passed, probe.failed
    );
    if probe.failed > 0 {
        std::process::exit(1);
    }
}
