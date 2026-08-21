//! Live on-chain probe of the deployed registry, driven directly against
//! the chain — no HTTP server, no queue. Builds a small world of real
//! possession-proven groups and references (spends real gas from the
//! `.env` PRIVATE_KEY), then checks every read function against it and
//! probes every revert path via free `eth_call` simulation.
//!
//! Run from the workspace root:
//!
//! ```sh
//! cargo run -p p256-index-server --example live_probe
//! ```

use std::time::Duration;

use alloy::{
    primitives::{Address, B256, keccak256},
    sol,
    sol_types::SolCall,
};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::elliptic_curve::Generate as _;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use p256_index_server::{
    chain::{Chain, ReceiptOutcome},
    config::Config,
};
use p256_registrar::{
    protocol::{
        challenge_for, content_hash_for, get_entry_calldata, get_reference_calldata,
        get_unit_calldata, member_binding_for, refer_calldata, reference_binding_for,
        register_calldata, write_calldata,
    },
    task::{Member, Proof, RegisterTask, TaskKind, TaskStatus},
    verify::base64url_32,
};

const RPC: &str = "https://rpc.gnosischain.com";

// Contract views the server's protocol mirror deliberately does not carry
// (pure helpers and total-counters the probe wants raw).
sol! {
    function VERSION() external view returns (uint256);
    function isMember(bytes groupPublicKey, bytes memberPublicKey) external view returns (bool);
    function hasEntry(bytes publicKey) external view returns (bool);
    function getUnitIdByContentHash(bytes32 contentHash) external view returns (bool exists, uint256 unitId);
    function getTotalGroupsOfKey(bytes publicKey) external view returns (uint256);
    function getTotalGroupMembers(uint256 unitId) external view returns (uint256);
    function getTotalReferencesOfKey(bytes publicKey) external view returns (uint256);
    function getTotalReferencesToGroup(bytes groupPublicKey) external view returns (uint256);
    function getTotalGroupsByRpId(string rpId) external view returns (uint256);
    function challengeFor(string rpId, bytes publicKey, bytes32 binding) external view returns (bytes32);
    function memberBindingFor(bytes groupPublicKey, bytes attestation) external pure returns (bytes32);
    function referenceBindingFor(bytes groupPublicKey, bytes attestation, bytes metadata) external pure returns (bytes32);
}

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

/// A fully-signed register task: every member binds (groupKey, own
/// attestation); the group key closes over the content hash.
fn register_task(
    chain_id: u64,
    registry: Address,
    rp_id: &str,
    metadata: &str,
    group: &Keypair,
    members: &[(&Keypair, &str)],
) -> RegisterTask {
    let mut task = RegisterTask {
        id: format!("probe-{}", uuid::Uuid::new_v4()),
        status: TaskStatus::Pending,
        kind: TaskKind::Register,
        rp_id: rp_id.to_owned(),
        metadata: metadata.to_owned(),
        content_hash: String::new(),
        group_public_key: group.public_hex.clone(),
        group_proof: None,
        members: members
            .iter()
            .map(|(key, attestation)| {
                let binding =
                    member_binding_for(&group.bytes(), &hex::decode(attestation).expect("att hex"));
                let challenge = challenge_for(chain_id, registry, rp_id, &key.bytes(), binding);
                Member {
                    public_key: key.public_hex.clone(),
                    attestation: (*attestation).to_owned(),
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
    let group_challenge = challenge_for(chain_id, registry, rp_id, &group.bytes(), content);
    task.group_proof = Some(sign_proof(&group.signing, group_challenge, rp_id));
    task
}

/// A fully-signed refer task: the referrer binds (groupKey, own
/// attestation, reference metadata); rp_id must be the GROUP's frozen rpId.
fn refer_task(
    chain_id: u64,
    registry: Address,
    group_public_hex: &str,
    group_rp_id: &str,
    metadata: &str,
    referrer: &Keypair,
    attestation: &str,
) -> RegisterTask {
    let group_bytes = hex::decode(group_public_hex).expect("group hex");
    let binding = reference_binding_for(
        &group_bytes,
        &hex::decode(attestation).expect("att hex"),
        &hex::decode(metadata.trim_start_matches("0x")).expect("metadata hex"),
    );
    let challenge = challenge_for(chain_id, registry, group_rp_id, &referrer.bytes(), binding);
    let mut task = RegisterTask {
        id: format!("probe-{}", uuid::Uuid::new_v4()),
        status: TaskStatus::Pending,
        kind: TaskKind::Refer,
        rp_id: group_rp_id.to_owned(),
        metadata: metadata.to_owned(),
        content_hash: String::new(),
        group_public_key: group_public_hex.to_owned(),
        group_proof: None,
        members: vec![Member {
            public_key: referrer.public_hex.clone(),
            attestation: attestation.to_owned(),
            proof: sign_proof(&referrer.signing, challenge, group_rp_id),
        }],
        tx_hash: None,
        on_chain_id: None,
        error: None,
        retries: 0,
        created_at: 0,
        admitted: true,
    };
    let content = content_hash_for(&task).expect("refer digest");
    task.content_hash = format!("{content:#x}");
    task
}

/// Recompute the content hash and the group key's closing proof after the
/// task's fields were edited — the way to probe validators that only run
/// once the group signature is genuine over the (bad) content.
fn resign_group(chain_id: u64, registry: Address, task: &mut RegisterTask, group: &Keypair) {
    let content = content_hash_for(task).expect("content hash");
    task.content_hash = format!("{content:#x}");
    let challenge = challenge_for(chain_id, registry, &task.rp_id, &group.bytes(), content);
    task.group_proof = Some(sign_proof(&group.signing, challenge, &task.rp_id));
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
            println!("  ✓ {name}");
        } else {
            self.failed += 1;
            println!("  ✗ {name} — {detail}");
        }
    }

    async fn eth_call(&self, data: Vec<u8>) -> Result<Vec<u8>, String> {
        let body = json!({
            "jsonrpc": "2.0", "id": 1, "method": "eth_call",
            "params": [{
                "to": self.registry.to_string(),
                "data": format!("0x{}", hex::encode(data)),
            }, "latest"],
        });
        let response: Value = self
            .client
            .post(RPC)
            .json(&body)
            .send()
            .await
            .map_err(|error| error.to_string())?
            .json()
            .await
            .map_err(|error| error.to_string())?;
        match response.get("result").and_then(Value::as_str) {
            Some(result) => {
                hex::decode(result.trim_start_matches("0x")).map_err(|error| error.to_string())
            }
            None => Err(response
                .get("error")
                .map(|error| error.to_string())
                .unwrap_or_else(|| "no result, no error".into())),
        }
    }

    /// The calldata must revert, and the revert data must carry the
    /// selector of `error_signature`.
    async fn expect_revert(&mut self, name: &str, data: Vec<u8>, error_signature: &str) {
        let selector = hex::encode(&keccak256(error_signature.as_bytes())[..4]);
        match self.eth_call(data).await {
            Ok(bytes) => self.check(
                name,
                false,
                format!(
                    "expected revert {error_signature}, call succeeded: 0x{}",
                    hex::encode(bytes)
                ),
            ),
            Err(error) => self.check(
                name,
                error.contains(&selector),
                format!("expected selector 0x{selector} ({error_signature}) in: {error}"),
            ),
        }
    }

    async fn call<C: SolCall>(&self, call: C) -> C::Return {
        let bytes = self
            .eth_call(call.abi_encode())
            .await
            .unwrap_or_else(|error| panic!("eth_call failed: {error}"));
        C::abi_decode_returns(&bytes).expect("decode return")
    }
}

async fn send(chain: &Chain, task: &RegisterTask) -> u64 {
    let nonce = chain
        .pending_nonce(p256_index_server::chain::WalletRole::Register)
        .await
        .expect("pending nonce");
    let broadcast = chain.register(task, nonce).await.expect("broadcast");
    match chain
        .wait_for_receipt(&broadcast.hash, Duration::from_secs(120))
        .await
        .expect("receipt")
    {
        ReceiptOutcome::Success { on_chain_id } => {
            let id = on_chain_id.expect("on-chain id in receipt");
            println!("  → tx {} confirmed, on-chain id {id}", broadcast.hash);
            id
        }
        ReceiptOutcome::Reverted => panic!("transaction reverted: {}", broadcast.hash),
    }
}

#[tokio::main]
async fn main() {
    dotenvy::from_path("p256-index-server/.env")
        .or_else(|_| dotenvy::from_path(".env").map(|_| ()))
        .expect(".env with PRIVATE_KEY and P256_INDEX_CONTRACT_ADDRESS");
    let config = Config::from_env().expect("config");
    let chain = Chain::new(&config).expect("chain");
    assert!(chain.has_signer(), "PRIVATE_KEY required");
    let registry: Address = config.contract_address.parse().expect("registry address");
    let chain_id = chain.chain_id();
    let mut probe = Probe {
        client: reqwest::Client::new(),
        registry,
        passed: 0,
        failed: 0,
    };

    let version = probe.call(VERSIONCall {}).await;
    println!("registry {registry} VERSION={version}");
    let before = chain.totals().await.expect("totals");

    // ── World: 4 groups, 3 references ─────────────────────────────────────
    let suffix = uuid::Uuid::new_v4().to_string()[..8].to_owned();
    let rp1 = format!("p1-{suffix}.probe");
    let rp2 = format!("p2-{suffix}.probe");
    let att3 = "01".to_owned() + &"ab".repeat(19); // 20 versioned bytes

    let m: Vec<Keypair> = (0..10).map(|_| Keypair::fresh()).collect();
    let ga = Keypair::fresh();
    let gb = Keypair::fresh();
    let gc = Keypair::fresh();
    let gd = Keypair::fresh();

    println!("\n[world] register A: 1 member, empty metadata, rpId {rp1}");
    let task_a = register_task(chain_id, registry, &rp1, "0x", &ga, &[(&m[0], "")]);
    let unit_a = send(&chain, &task_a).await;

    println!("[world] register B: 3 members (m0 reused across groups, m2 with attestation)");
    let task_b = register_task(
        chain_id,
        registry,
        &rp1,
        "0xb0b1",
        &gb,
        &[(&m[0], ""), (&m[1], ""), (&m[2], att3.as_str())],
    );
    let unit_b = send(&chain, &task_b).await;

    println!("[world] register C: 7 members (MAX_MEMBERS), rpId {rp2}");
    let members_c: Vec<(&Keypair, &str)> = m[3..10].iter().map(|key| (key, "")).collect();
    let task_c = register_task(chain_id, registry, &rp2, "0x", &gc, &members_c);
    let unit_c = send(&chain, &task_c).await;

    println!("[world] register D: the USED group key of A as a MEMBER (role namespaces)");
    let task_d = register_task(chain_id, registry, &rp2, "0xdd", &gd, &[(&ga, "")]);
    let unit_d = send(&chain, &task_d).await;

    println!("[world] refer R1: m1 → A with metadata");
    let refer_1 = refer_task(chain_id, registry, &ga.public_hex, &rp1, "0xaa", &m[1], "");
    let ref_1 = send(&chain, &refer_1).await;

    println!("[world] refer R2: the USED group key of B as a REFERRER → A (role namespaces)");
    let refer_2 = refer_task(chain_id, registry, &ga.public_hex, &rp1, "0x", &gb, "");
    let ref_2 = send(&chain, &refer_2).await;

    println!("[world] refer R3: m0 → C, empty metadata");
    let refer_3 = refer_task(chain_id, registry, &gc.public_hex, &rp2, "0x", &m[0], "");
    let ref_3 = send(&chain, &refer_3).await;

    // ── Reads against the world ────────────────────────────────────────────
    println!("\n[reads] totals");
    let after = chain.totals().await.expect("totals");
    // Entries: m0..m9 (10) + ga-as-member (1) + gb whose entry was created
    // by refer R2 — a brand-new referring key gets its global file on the
    // way.
    probe.check(
        "getTotalEntries +12 (incl. the referrer entry refer created)",
        after.entries == before.entries + 12,
        format!("{} → {}", before.entries, after.entries),
    );
    probe.check(
        "getTotalUnits +4",
        after.units == before.units + 4,
        format!("{} → {}", before.units, after.units),
    );
    probe.check(
        "getTotalReferences +3 (counted apart from groups)",
        after.references == before.references + 3,
        format!("{} → {}", before.references, after.references),
    );
    probe.check(
        "getTotalRpIds +2",
        after.rp_ids == before.rp_ids + 2,
        format!("{} → {}", before.rp_ids, after.rp_ids),
    );

    println!("[reads] entries");
    let has = probe
        .call(hasEntryCall {
            publicKey: m[0].bytes().into(),
        })
        .await;
    probe.check("hasEntry(m0)", has, String::new());
    let unknown = Keypair::fresh();
    let has_not = probe
        .call(hasEntryCall {
            publicKey: unknown.bytes().into(),
        })
        .await;
    probe.check("!hasEntry(fresh key)", !has_not, String::new());
    let profile = chain
        .key_profile(&m[0].public_hex, 1, 20, false)
        .await
        .expect("profile")
        .expect("m0 has a file");
    probe.check(
        "getEntryByKey(m0): key + empty attestation",
        profile.entry.public_key == m[0].public_hex && profile.entry.attestation.is_empty(),
        format!("{:?}", profile.entry),
    );
    let entry_by_id = chain
        .entry(profile.entry.entry_id)
        .await
        .expect("entry read")
        .expect("entry exists");
    probe.check(
        "getEntry(id) round-trips getEntryByKey",
        entry_by_id.public_key == m[0].public_hex,
        String::new(),
    );
    let m2_profile = chain
        .key_profile(&m[2].public_hex, 1, 20, false)
        .await
        .expect("profile")
        .expect("m2 has a file");
    probe.check(
        "attestation frozen at first sight (m2)",
        m2_profile.entry.attestation == att3,
        m2_profile.entry.attestation.clone(),
    );

    println!("[reads] membership");
    probe.check(
        "getGroupsOfKey(m0) = [A, B] ascending",
        profile.group_total == 2 && profile.group_ids == vec![unit_a, unit_b],
        format!("total {} ids {:?}", profile.group_total, profile.group_ids),
    );
    let desc_profile = chain
        .key_profile(&m[0].public_hex, 1, 1, true)
        .await
        .expect("profile")
        .expect("exists");
    probe.check(
        "getGroupsOfKey(m0) descending page 1/1 = [B]",
        desc_profile.group_ids == vec![unit_b],
        format!("{:?}", desc_profile.group_ids),
    );
    let total_groups = probe
        .call(getTotalGroupsOfKeyCall {
            publicKey: m[0].bytes().into(),
        })
        .await;
    probe.check(
        "getTotalGroupsOfKey(m0) = 2",
        total_groups == alloy::primitives::U256::from(2),
        total_groups.to_string(),
    );
    let is_member = probe
        .call(isMemberCall {
            groupPublicKey: ga.bytes().into(),
            memberPublicKey: m[0].bytes().into(),
        })
        .await;
    probe.check("isMember(A, m0)", is_member, String::new());
    let not_member = probe
        .call(isMemberCall {
            groupPublicKey: ga.bytes().into(),
            memberPublicKey: m[1].bytes().into(),
        })
        .await;
    probe.check(
        "!isMember(A, m1) — a reference is NOT membership",
        !not_member,
        String::new(),
    );

    println!("[reads] groups");
    let unit = chain
        .unit_by_group_key(ga.bytes())
        .await
        .expect("unit read")
        .expect("group A exists");
    probe.check(
        "getUnitByGroupKey(A): frozen record",
        unit.unit_id == unit_a
            && unit.rp_id == rp1
            && unit.metadata.is_empty()
            && unit.member_count == 1
            && unit.content_hash == task_a.content_hash,
        format!("{unit:?}"),
    );
    let (content_exists, content_unit) = {
        let ret = probe
            .call(getUnitIdByContentHashCall {
                contentHash: task_a.content_hash.parse().expect("content hash hex"),
            })
            .await;
        (ret.exists, ret.unitId)
    };
    probe.check(
        "getUnitIdByContentHash(local contentHashFor) = A — Rust/Solidity hash agreement",
        content_exists && content_unit == alloy::primitives::U256::from(unit_a),
        format!("exists {content_exists} unit {content_unit}"),
    );
    probe.check(
        "isContentRegistered(A)",
        chain
            .is_content_registered(task_a.content_hash.parse().expect("hash"))
            .await
            .expect("read"),
        String::new(),
    );
    probe.check(
        "!isContentRegistered(random)",
        !chain
            .is_content_registered(B256::from(keccak256(b"nothing like this")))
            .await
            .expect("read"),
        String::new(),
    );
    let detail_c = chain
        .group_detail_by_id(unit_c, 1, 3, false)
        .await
        .expect("detail")
        .expect("C exists");
    probe.check(
        "getGroupMembers(C) total 7, page 1(size 3) ascending = m3..m5",
        detail_c.member_total == 7
            && detail_c.members.len() == 3
            && detail_c.members[0].public_key == m[3].public_hex
            && detail_c.members[2].public_key == m[5].public_hex,
        format!(
            "total {} first-page {}",
            detail_c.member_total,
            detail_c.members.len()
        ),
    );
    let detail_c_last = chain
        .group_detail_by_id(unit_c, 3, 3, false)
        .await
        .expect("detail")
        .expect("C exists");
    probe.check(
        "getGroupMembers(C) page 3(size 3) = [m9]",
        detail_c_last.members.len() == 1 && detail_c_last.members[0].public_key == m[9].public_hex,
        format!("{}", detail_c_last.members.len()),
    );
    let total_members = probe
        .call(getTotalGroupMembersCall {
            unitId: alloy::primitives::U256::from(unit_c),
        })
        .await;
    probe.check(
        "getTotalGroupMembers(C) = 7",
        total_members == alloy::primitives::U256::from(7),
        total_members.to_string(),
    );
    let unit_d_read = chain.unit(unit_d).await.expect("read").expect("D exists");
    probe.check(
        "role namespaces: used group key A is a MEMBER of D",
        unit_d_read.member_count == 1
            && probe
                .call(isMemberCall {
                    groupPublicKey: gd.bytes().into(),
                    memberPublicKey: ga.bytes().into(),
                })
                .await,
        String::new(),
    );

    println!("[reads] references");
    probe.check(
        "isReferenced(A, m1)",
        chain
            .is_referenced(ga.bytes(), m[1].bytes())
            .await
            .expect("read"),
        String::new(),
    );
    probe.check(
        "!isReferenced(A, m0) — membership is NOT a reference",
        !chain
            .is_referenced(ga.bytes(), m[0].bytes())
            .await
            .expect("read"),
        String::new(),
    );
    let m1_profile = chain
        .key_profile(&m[1].public_hex, 1, 20, false)
        .await
        .expect("profile")
        .expect("m1 exists");
    probe.check(
        "getReferencesOfKey(m1) = [R1]",
        m1_profile.reference_total == 1 && m1_profile.reference_ids == vec![ref_1],
        format!("{:?}", m1_profile.reference_ids),
    );
    let detail_a = chain
        .group_detail_by_key(ga.bytes(), 1, 20, false)
        .await
        .expect("detail")
        .expect("A exists");
    probe.check(
        "getReferencesToGroup(A) = [R1, R2] (m1 and B's used group key)",
        detail_a.reference_total == 2 && detail_a.reference_ids == vec![ref_1, ref_2],
        format!("{:?}", detail_a.reference_ids),
    );
    let reference = probe
        .eth_call(get_reference_calldata(ref_1))
        .await
        .expect("getReference");
    let decoded = p256_registrar::protocol::decode_reference(ref_1, &reference).expect("decode");
    probe.check(
        "getReference(R1): entry=m1, unit=A, metadata aa",
        decoded.entry_id == m1_profile.entry.entry_id
            && decoded.unit_id == unit_a
            && decoded.metadata == "aa",
        format!("{decoded:?}"),
    );
    let gb_profile = chain
        .key_profile(&gb.public_hex, 1, 20, false)
        .await
        .expect("profile")
        .expect("gb has an entry (created by refer)");
    probe.check(
        "role namespaces: used group key B holds reference R2 and got a global entry",
        gb_profile.reference_ids == vec![ref_2] && gb_profile.group_total == 0,
        format!("{:?}", gb_profile.reference_ids),
    );
    let _ = ref_3;

    println!("[reads] rpId enumeration");
    let groups_rp1 = chain
        .groups_by_rp_id(&rp1, 1, 20, false)
        .await
        .expect("groups by rpId");
    probe.check(
        "getGroupsByRpId(rp1) = [A, B] with frozen records",
        groups_rp1.total == 2
            && groups_rp1.items.len() == 2
            && groups_rp1.items[0].unit_id == unit_a
            && groups_rp1.items[1].metadata == "b0b1",
        format!("total {}", groups_rp1.total),
    );
    let total_rp1 = probe
        .call(getTotalGroupsByRpIdCall { rpId: rp1.clone() })
        .await;
    probe.check(
        "getTotalGroupsByRpId(rp1) = 2",
        total_rp1 == alloy::primitives::U256::from(2),
        total_rp1.to_string(),
    );
    let sites = chain.rp_ids(1, 100, true).await.expect("rp ids");
    let rp1_row = sites.items.iter().find(|site| site.rp_id == rp1);
    let rp2_row = sites.items.iter().find(|site| site.rp_id == rp2);
    probe.check(
        "getRpIds carries both probe rpIds with group counts",
        rp1_row.is_some_and(|site| site.entry_count == 2)
            && rp2_row.is_some_and(|site| site.entry_count == 2),
        format!("rp1 {rp1_row:?} rp2 {rp2_row:?}"),
    );

    println!("[reads] pure helpers: on-chain vs local Rust");
    let onchain_binding = probe
        .call(memberBindingForCall {
            groupPublicKey: ga.bytes().into(),
            attestation: hex::decode(&att3).expect("att").into(),
        })
        .await;
    probe.check(
        "memberBindingFor matches Rust",
        onchain_binding == member_binding_for(&ga.bytes(), &hex::decode(&att3).expect("att")),
        format!("{onchain_binding:#x}"),
    );
    let onchain_ref_binding = probe
        .call(referenceBindingForCall {
            groupPublicKey: ga.bytes().into(),
            attestation: Vec::new().into(),
            metadata: vec![0xaa].into(),
        })
        .await;
    probe.check(
        "referenceBindingFor matches Rust",
        onchain_ref_binding == reference_binding_for(&ga.bytes(), &[], &[0xaa]),
        format!("{onchain_ref_binding:#x}"),
    );
    let onchain_challenge = probe
        .call(challengeForCall {
            rpId: rp1.clone(),
            publicKey: m[0].bytes().into(),
            binding: onchain_binding,
        })
        .await;
    probe.check(
        "challengeFor matches Rust (chainid + instance bound)",
        onchain_challenge
            == challenge_for(chain_id, registry, &rp1, &m[0].bytes(), onchain_binding),
        format!("{onchain_challenge:#x}"),
    );

    // ── Revert paths, free of charge via eth_call ──────────────────────────
    println!("\n[reverts] write guards");
    let reused_group = register_task(chain_id, registry, &rp1, "0x", &ga, &[(&unknown, "")]);
    probe
        .expect_revert(
            "register with a used group key",
            register_calldata(&reused_group).expect("calldata"),
            "GroupKeyAlreadyUsed(bytes32)",
        )
        .await;
    let dup = register_task(
        chain_id,
        registry,
        &rp1,
        "0x",
        &Keypair::fresh(),
        &[(&m[0], ""), (&m[0], "")],
    );
    probe
        .expect_revert(
            "register with a duplicated member",
            register_calldata(&dup).expect("calldata"),
            "DuplicateMemberKey(uint256)",
        )
        .await;
    let self_member_group = Keypair::fresh();
    let self_member = register_task(
        chain_id,
        registry,
        &rp1,
        "0x",
        &self_member_group,
        &[(&self_member_group, "")],
    );
    probe
        .expect_revert(
            "register with the group key as its own member",
            register_calldata(&self_member).expect("calldata"),
            "DuplicateMemberKey(uint256)",
        )
        .await;
    let mismatched = register_task(
        chain_id,
        registry,
        &rp1,
        "0x",
        &Keypair::fresh(),
        &[(&m[0], "02".repeat(20).as_str())],
    );
    probe
        .expect_revert(
            "register m0 again with a different attestation",
            register_calldata(&mismatched).expect("calldata"),
            "AttestationMismatch(uint256)",
        )
        .await;
    let mut tampered = register_task(
        chain_id,
        registry,
        &rp1,
        "0x",
        &Keypair::fresh(),
        &[(&Keypair::fresh(), "")],
    );
    tampered.members[0].proof.r = format!("0x{}", "11".repeat(32));
    probe
        .expect_revert(
            "register with a tampered member signature",
            register_calldata(&tampered).expect("calldata"),
            "InvalidProof()",
        )
        .await;
    let mut group_tampered = register_task(
        chain_id,
        registry,
        &rp1,
        "0x",
        &Keypair::fresh(),
        &[(&Keypair::fresh(), "")],
    );
    if let Some(proof) = group_tampered.group_proof.as_mut() {
        proof.s = format!("0x{}", "22".repeat(32));
    }
    probe
        .expect_revert(
            "register with a tampered group signature",
            register_calldata(&group_tampered).expect("calldata"),
            "InvalidProof()",
        )
        .await;
    let mut empty_members = register_task(
        chain_id,
        registry,
        &rp1,
        "0x",
        &Keypair::fresh(),
        &[(&Keypair::fresh(), "")],
    );
    empty_members.members.clear();
    probe
        .expect_revert(
            "register with 0 members",
            register_calldata(&empty_members).expect("calldata"),
            "InvalidMemberCount(uint256)",
        )
        .await;
    let eight: Vec<Keypair> = (0..8).map(|_| Keypair::fresh()).collect();
    let eight_refs: Vec<(&Keypair, &str)> = eight.iter().map(|key| (key, "")).collect();
    let over_cap = register_task(
        chain_id,
        registry,
        &rp1,
        "0x",
        &Keypair::fresh(),
        &eight_refs,
    );
    probe
        .expect_revert(
            "register with 8 members (MAX_MEMBERS is 7)",
            register_calldata(&over_cap).expect("calldata"),
            "InvalidMemberCount(uint256)",
        )
        .await;
    let fat = register_task(
        chain_id,
        registry,
        &rp1,
        &format!("0x{}", "cc".repeat(2049)),
        &Keypair::fresh(),
        &[(&Keypair::fresh(), "")],
    );
    probe
        .expect_revert(
            "register with 2049-byte metadata (max 2048)",
            register_calldata(&fat).expect("calldata"),
            "MetadataTooLong(uint256)",
        )
        .await;
    let no_rp = register_task(
        chain_id,
        registry,
        "",
        "0x",
        &Keypair::fresh(),
        &[(&Keypair::fresh(), "")],
    );
    probe
        .expect_revert(
            "register with an empty rpId",
            register_calldata(&no_rp).expect("calldata"),
            "EmptyRpId()",
        )
        .await;
    let long_rp = register_task(
        chain_id,
        registry,
        &"r".repeat(254),
        "0x",
        &Keypair::fresh(),
        &[(&Keypair::fresh(), "")],
    );
    probe
        .expect_revert(
            "register with a 254-char rpId (max 253)",
            register_calldata(&long_rp).expect("calldata"),
            "RpIdTooLong(uint256)",
        )
        .await;

    // The specific key validators only fire once the group signature is
    // genuine over the content that CONTAINS the bad key: tampering a
    // member key after signing just breaks the content binding and reverts
    // InvalidProof (probed separately above). So each case swaps the bad
    // key in and re-signs the group proof over it.
    println!("[reverts] key validation");
    let group_for_prefix = Keypair::fresh();
    let mut bad_prefix = register_task(
        chain_id,
        registry,
        &rp1,
        "0x",
        &group_for_prefix,
        &[(&Keypair::fresh(), "")],
    );
    bad_prefix.members[0].public_key = format!("02{}", &bad_prefix.members[0].public_key[2..]);
    resign_group(chain_id, registry, &mut bad_prefix, &group_for_prefix);
    probe
        .expect_revert(
            "member key with compressed prefix 02",
            register_calldata(&bad_prefix).expect("calldata"),
            "InvalidPublicKeyPrefix(bytes1)",
        )
        .await;
    let group_for_short = Keypair::fresh();
    let mut short_key = register_task(
        chain_id,
        registry,
        &rp1,
        "0x",
        &group_for_short,
        &[(&Keypair::fresh(), "")],
    );
    short_key.members[0].public_key = short_key.members[0].public_key[..128].to_owned();
    resign_group(chain_id, registry, &mut short_key, &group_for_short);
    probe
        .expect_revert(
            "member key of 64 bytes",
            register_calldata(&short_key).expect("calldata"),
            "InvalidPublicKeyLength(uint256)",
        )
        .await;
    let group_for_curve = Keypair::fresh();
    let mut off_curve = register_task(
        chain_id,
        registry,
        &rp1,
        "0x",
        &group_for_curve,
        &[(&Keypair::fresh(), "")],
    );
    off_curve.members[0].public_key = format!("04{:064x}{:064x}", 1u128, 2u128);
    resign_group(chain_id, registry, &mut off_curve, &group_for_curve);
    probe
        .expect_revert(
            "member key not on the P-256 curve",
            register_calldata(&off_curve).expect("calldata"),
            "InvalidPublicKeyPoint()",
        )
        .await;
    let group_for_coord = Keypair::fresh();
    let mut fat_coord = register_task(
        chain_id,
        registry,
        &rp1,
        "0x",
        &group_for_coord,
        &[(&Keypair::fresh(), "")],
    );
    fat_coord.members[0].public_key = format!(
        "04ffffffff00000001000000000000000000000000ffffffffffffffffffffffff{:064x}",
        2u128
    );
    resign_group(chain_id, registry, &mut fat_coord, &group_for_coord);
    probe
        .expect_revert(
            "member key with x >= field prime",
            register_calldata(&fat_coord).expect("calldata"),
            "InvalidPublicKeyCoordinate()",
        )
        .await;
    // A bad GROUP key is validated before its proof is even checked.
    let mut bad_group = register_task(
        chain_id,
        registry,
        &rp1,
        "0x",
        &Keypair::fresh(),
        &[(&Keypair::fresh(), "")],
    );
    bad_group.group_public_key = bad_group.group_public_key[..128].to_owned();
    probe
        .expect_revert(
            "group key of 64 bytes",
            register_calldata(&bad_group).expect("calldata"),
            "InvalidPublicKeyLength(uint256)",
        )
        .await;

    println!("[reverts] refer guards");
    let ghost_group = Keypair::fresh();
    let ghost = refer_task(
        chain_id,
        registry,
        &ghost_group.public_hex,
        &rp1,
        "0x",
        &Keypair::fresh(),
        "",
    );
    probe
        .expect_revert(
            "refer to a group that does not exist",
            refer_calldata(&ghost).expect("calldata"),
            "GroupNotFound(bytes32)",
        )
        .await;
    let duplicate_ref = refer_task(chain_id, registry, &ga.public_hex, &rp1, "0xaa", &m[1], "");
    probe
        .expect_revert(
            "refer the same (group, key) pair twice",
            refer_calldata(&duplicate_ref).expect("calldata"),
            "AlreadyReferenced(uint256)",
        )
        .await;
    let wrong_rp = refer_task(
        chain_id,
        registry,
        &ga.public_hex,
        &rp2,
        "0x",
        &Keypair::fresh(),
        "",
    );
    probe
        .expect_revert(
            "refer with a proof bound to the wrong rpId",
            refer_calldata(&wrong_rp).expect("calldata"),
            "RpIdMismatch()",
        )
        .await;
    let self_ref = refer_task(chain_id, registry, &ga.public_hex, &rp1, "0x", &ga, "");
    probe
        .expect_revert(
            "refer a group key to itself",
            refer_calldata(&self_ref).expect("calldata"),
            "DuplicateMemberKey(uint256)",
        )
        .await;
    let _ = write_calldata(&refer_1).expect("write_calldata dispatches refer");

    println!("[reverts] missing-id reads");
    probe
        .expect_revert(
            "getEntry(1e9)",
            get_entry_calldata(1_000_000_000),
            "EntryNotFound(uint256)",
        )
        .await;
    probe
        .expect_revert(
            "getUnit(1e9)",
            get_unit_calldata(1_000_000_000),
            "UnitNotFound(uint256)",
        )
        .await;
    probe
        .expect_revert(
            "getReference(1e9)",
            get_reference_calldata(1_000_000_000),
            "ReferenceNotFound(uint256)",
        )
        .await;

    println!(
        "\n[result] {} passed, {} failed (world: units {unit_a},{unit_b},{unit_c},{unit_d} refs {ref_1},{ref_2},{ref_3})",
        probe.passed, probe.failed
    );
    if probe.failed > 0 {
        std::process::exit(1);
    }
}
