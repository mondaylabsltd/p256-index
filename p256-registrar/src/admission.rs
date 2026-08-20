//! Registration admission: the decision half of the register endpoint.
//!
//! One [`AdmissionApp`] instance drives one request from a parsed
//! [`RegisterRequest`] to an [`AdmissionOutcome`]:
//!
//! - validation is TOTAL: shapes, bounds, and every member's possession
//!   proof are verified (pure P-256, mirroring the contract) before anything
//!   touches Redis — an invalid proof can never reach the chain or burn gas;
//! - the unitNonce is the idempotency key: a resubmission of the same unit
//!   returns its existing task, a different unit reusing an in-flight nonce
//!   is a 409;
//! - chain pre-checks are fail-open: content already registered answers
//!   "done" retroactively, a consumed nonce (with our content absent) is a
//!   terminal 409 — the proofs died with it, the client must re-enroll;
//! - write gates: active queue depth and the global create budget;
//! - the two-phase admission protocol: Redis admit → Iggy enqueue → mark
//!   admitted. A failed enqueue keeps the placeholder so a retry reuses the
//!   task id; the operation vocabulary has no "delete admission" at all.
//!
//! The shell owns transport (body limits, JSON, IP extraction — the raw IP
//! never crosses into this module), key naming, and executes each operation
//! against Redis / the chain / Iggy. Task identity, wall-clock time, chain id
//! and registry address enter through the Submit event so the program stays
//! deterministic.

use alloy::primitives::Address;
use crux_core::{App, Command, command::CommandContext, macros::effect};
use serde::{Deserialize, Serialize};

use crate::protocol::{challenge_for, content_hash_for, parse_b256, parse_hex_bytes};
use crate::task::{Member, Proof, RegisterTask, TaskStatus};
use crate::verify::verify_proof;

/// New registrations are rejected while the active queue is at least this deep.
pub const MAX_ACTIVE_QUEUE_DEPTH: u64 = 10_000;

/// Mirrors the contract's MAX_MEMBERS.
pub const MAX_MEMBERS: usize = 7;
/// Mirrors the contract's MAX_METADATA_LENGTH (bytes).
pub const MAX_METADATA_BYTES: usize = 1024;
/// Mirrors the contract's ATTESTATION_LENGTH / ATTESTATION_VERSION.
pub const ATTESTATION_BYTES: usize = 20;
pub const ATTESTATION_VERSION: u8 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofRequest {
    pub authenticator_data: Option<String>,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: Option<String>,
    pub challenge_index: Option<u64>,
    pub type_index: Option<u64>,
    pub r: Option<String>,
    pub s: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberRequest {
    pub public_key: Option<String>,
    pub attestation: Option<String>,
    pub proof: Option<ProofRequest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRequest {
    pub rp_id: Option<String>,
    pub metadata: Option<String>,
    pub unit_nonce: Option<String>,
    pub members: Option<Vec<MemberRequest>>,
}

// ── Shell protocol ─────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AdmissionOperation {
    /// May this client register right now? The shell resolves this against
    /// its salted per-IP counter; the raw IP never enters the Core.
    AllowIpCreate,
    /// The in-flight/terminal task holding this unitNonce, if any.
    FindTaskByNonce {
        unit_nonce: String,
    },
    /// isContentRegistered(contentHash) on the registry (fail-open).
    CheckContentRegistered {
        content_hash: String,
    },
    /// isNonceUsed(unitNonce) on the registry (fail-open).
    CheckNonceUsed {
        unit_nonce: String,
    },
    QueueDepth,
    AllowGlobalCreate,
    /// Phase one: the store's atomic admission keyed by the unitNonce.
    Admit {
        task: RegisterTask,
    },
    LoadTask {
        id: String,
    },
    /// Phase two: append to the durable queue.
    Enqueue {
        task: RegisterTask,
    },
    MarkAdmitted {
        id: String,
    },
}

impl crux_core::capability::Operation for AdmissionOperation {
    type Output = AdmissionResult;
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AdmitOutcome {
    New,
    Existing { id: String },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AdmissionResult {
    Allowed { allowed: bool },
    TaskFound { task: Option<RegisterTask> },
    ChainBool { value: bool },
    ChainReadFailed,
    Depth { depth: u64 },
    Admitted(AdmitOutcome),
    Enqueued,
    QueueUnavailable,
    Persisted,
    StoreUnavailable,
}

#[effect]
pub enum AdmissionEffect {
    Work(AdmissionOperation),
}

// ── App ────────────────────────────────────────────────────────────────────

/// The admission verdict. The shell renders these into HTTP responses.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AdmissionOutcome {
    /// 400 with the validation message.
    Invalid { message: String },
    /// 429, fixed message.
    RateLimited,
    /// 202 (or 200 for a terminal Done task) with the task's id and status.
    Queued { id: String, status: TaskStatus },
    /// 200: identical content is already on-chain.
    AlreadyRegistered { content_hash: String },
    /// 409: the unitNonce cannot be used.
    NonceConflict { message: String },
    /// 503 busy (depth or global rate gate).
    Busy,
    /// 503 retryable, naming the failed dependency ("redis" / "queue").
    DependencyUnavailable { dependency: String },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AdmissionEvent {
    /// The shell supplies task identity, wall-clock time and the chain
    /// context so the program stays deterministic.
    Submit {
        request: RegisterRequest,
        new_task_id: String,
        now_ms: u64,
        chain_id: u64,
        registry: String,
    },
    Settled(AdmissionOutcome),
}

#[derive(Default)]
pub struct AdmissionModel {
    outcome: Option<AdmissionOutcome>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdmissionViewModel {
    pub outcome: Option<AdmissionOutcome>,
}

#[derive(Default)]
pub struct AdmissionApp;

impl App for AdmissionApp {
    type Event = AdmissionEvent;
    type Model = AdmissionModel;
    type ViewModel = AdmissionViewModel;
    type Effect = AdmissionEffect;

    fn update(
        &self,
        event: Self::Event,
        model: &mut Self::Model,
    ) -> Command<Self::Effect, Self::Event> {
        match event {
            AdmissionEvent::Submit {
                request,
                new_task_id,
                now_ms,
                chain_id,
                registry,
            } => Command::new(|ctx| async move {
                let outcome =
                    match drive_admission(&ctx, request, new_task_id, now_ms, chain_id, &registry)
                        .await
                    {
                        Ok(outcome) | Err(outcome) => outcome,
                    };
                ctx.send_event(AdmissionEvent::Settled(outcome));
            }),
            AdmissionEvent::Settled(outcome) => {
                model.outcome = Some(outcome);
                Command::done()
            }
        }
    }

    fn view(&self, model: &Self::Model) -> Self::ViewModel {
        AdmissionViewModel {
            outcome: model.outcome.clone(),
        }
    }
}

// ── The admission program ──────────────────────────────────────────────────

type Ctx = CommandContext<AdmissionEffect, AdmissionEvent>;
type Flow<T> = Result<T, AdmissionOutcome>;

fn redis_down() -> AdmissionOutcome {
    AdmissionOutcome::DependencyUnavailable {
        dependency: "redis".to_owned(),
    }
}

pub const CONFLICT_NONCE_IN_FLIGHT: &str =
    "this unitNonce is already carrying a different unit; every unit needs a fresh nonce";
pub const CONFLICT_NONCE_CONSUMED: &str = "this unitNonce was already consumed on-chain; the proofs are void — re-enroll with a fresh nonce";

async fn request(ctx: &Ctx, operation: AdmissionOperation) -> AdmissionResult {
    ctx.request_from_shell(operation).await
}

async fn drive_admission(
    ctx: &Ctx,
    register: RegisterRequest,
    new_task_id: String,
    now_ms: u64,
    chain_id: u64,
    registry: &str,
) -> Flow<AdmissionOutcome> {
    let (task, content_hash) =
        match validate_register(register, new_task_id, now_ms, chain_id, registry) {
            Ok(valid) => valid,
            Err(message) => return Ok(AdmissionOutcome::Invalid { message }),
        };

    match request(ctx, AdmissionOperation::AllowIpCreate).await {
        AdmissionResult::Allowed { allowed: true } => {}
        AdmissionResult::Allowed { allowed: false } => return Ok(AdmissionOutcome::RateLimited),
        _ => return Err(redis_down()),
    }

    // Idempotency by unitNonce: the same unit resubmitted returns its task,
    // a different unit on an in-flight nonce is a conflict.
    match request(
        ctx,
        AdmissionOperation::FindTaskByNonce {
            unit_nonce: task.unit_nonce.clone(),
        },
    )
    .await
    {
        AdmissionResult::TaskFound {
            task: Some(existing),
        } => {
            let same_unit = crate::protocol::content_hash_for(&existing)
                .map(|hash| format!("{hash:#x}") == content_hash)
                .unwrap_or(false);
            if same_unit {
                return Ok(AdmissionOutcome::Queued {
                    id: existing.id,
                    status: existing.status,
                });
            }
            return Ok(AdmissionOutcome::NonceConflict {
                message: CONFLICT_NONCE_IN_FLIGHT.to_owned(),
            });
        }
        AdmissionResult::TaskFound { task: None } => {}
        _ => return Err(redis_down()),
    }

    // Chain pre-checks, fail-open: an RPC outage never blocks admission —
    // the worker reconciles against the chain anyway.
    match request(
        ctx,
        AdmissionOperation::CheckContentRegistered {
            content_hash: content_hash.clone(),
        },
    )
    .await
    {
        AdmissionResult::ChainBool { value: true } => {
            return Ok(AdmissionOutcome::AlreadyRegistered { content_hash });
        }
        AdmissionResult::ChainBool { value: false } | AdmissionResult::ChainReadFailed => {}
        _ => return Err(redis_down()),
    }
    match request(
        ctx,
        AdmissionOperation::CheckNonceUsed {
            unit_nonce: task.unit_nonce.clone(),
        },
    )
    .await
    {
        AdmissionResult::ChainBool { value: true } => {
            return Ok(AdmissionOutcome::NonceConflict {
                message: CONFLICT_NONCE_CONSUMED.to_owned(),
            });
        }
        AdmissionResult::ChainBool { value: false } | AdmissionResult::ChainReadFailed => {}
        _ => return Err(redis_down()),
    }

    // Write gates.
    match request(ctx, AdmissionOperation::QueueDepth).await {
        AdmissionResult::Depth { depth } if depth >= MAX_ACTIVE_QUEUE_DEPTH => {
            return Ok(AdmissionOutcome::Busy);
        }
        AdmissionResult::Depth { .. } => {}
        _ => return Err(redis_down()),
    }
    match request(ctx, AdmissionOperation::AllowGlobalCreate).await {
        AdmissionResult::Allowed { allowed: true } => {}
        AdmissionResult::Allowed { allowed: false } => return Ok(AdmissionOutcome::Busy),
        _ => return Err(redis_down()),
    }

    // Two-phase admission.
    match request(ctx, AdmissionOperation::Admit { task: task.clone() }).await {
        AdmissionResult::Admitted(AdmitOutcome::Existing { id }) => {
            match request(ctx, AdmissionOperation::LoadTask { id }).await {
                AdmissionResult::TaskFound {
                    task: Some(existing),
                } if existing.admitted => Ok(AdmissionOutcome::Queued {
                    id: existing.id,
                    status: existing.status,
                }),
                AdmissionResult::TaskFound {
                    task: Some(existing),
                } => enqueue(ctx, existing).await,
                _ => Err(redis_down()),
            }
        }
        AdmissionResult::Admitted(AdmitOutcome::New) => enqueue(ctx, task).await,
        _ => Err(redis_down()),
    }
}

/// Phase two of admission. On queue failure the Redis admission is kept — a
/// retry of the same request reuses the task id and the consumer is
/// idempotent. There is deliberately no operation that could delete it.
async fn enqueue(ctx: &Ctx, task: RegisterTask) -> Flow<AdmissionOutcome> {
    let id = task.id.clone();
    match request(ctx, AdmissionOperation::Enqueue { task }).await {
        AdmissionResult::Enqueued => {
            match request(ctx, AdmissionOperation::MarkAdmitted { id }).await {
                AdmissionResult::TaskFound { task: Some(task) } => Ok(AdmissionOutcome::Queued {
                    id: task.id,
                    status: task.status,
                }),
                _ => Err(redis_down()),
            }
        }
        AdmissionResult::QueueUnavailable => Err(AdmissionOutcome::DependencyUnavailable {
            dependency: "queue".to_owned(),
        }),
        _ => Err(redis_down()),
    }
}

// ── Validation ─────────────────────────────────────────────────────────────

/// Total validation: shapes, bounds and every member's possession proof.
/// Returns the canonical task plus the unit's content hash (0x-hex).
pub fn validate_register(
    request: RegisterRequest,
    new_task_id: String,
    now_ms: u64,
    chain_id: u64,
    registry: &str,
) -> Result<(RegisterTask, String), String> {
    let registry: Address = registry
        .parse()
        .map_err(|_| "service misconfigured: invalid registry address".to_owned())?;

    let Some(rp_id) = request.rp_id.filter(|value| !value.is_empty()) else {
        return Err("rpId is required".into());
    };
    if rp_id.len() > 253 {
        return Err("rpId exceeds max length (253)".into());
    }

    let Some(unit_nonce) = request.unit_nonce.as_deref() else {
        return Err("unitNonce is required (32-byte hex)".into());
    };
    let nonce = parse_b256(unit_nonce).map_err(|_| "unitNonce must be 32-byte hex".to_owned())?;
    let unit_nonce = format!("{nonce:#x}");

    let metadata = request.metadata.unwrap_or_default();
    let metadata_bytes =
        parse_hex_bytes(&metadata).map_err(|_| "metadata must be a valid hex string".to_owned())?;
    if metadata_bytes.len() > MAX_METADATA_BYTES {
        return Err(format!(
            "metadata exceeds max length ({MAX_METADATA_BYTES} bytes)"
        ));
    }
    let metadata = if metadata_bytes.is_empty() {
        String::new()
    } else {
        format!("0x{}", hex::encode(&metadata_bytes))
    };

    let Some(members) = request.members.filter(|members| !members.is_empty()) else {
        return Err("members is required (1 to 7 entries)".into());
    };
    if members.len() > MAX_MEMBERS {
        return Err(format!("members must contain 1 to {MAX_MEMBERS} entries"));
    }

    let mut parsed = Vec::with_capacity(members.len());
    for (index, member) in members.into_iter().enumerate() {
        parsed.push(
            validate_member(member, &rp_id, nonce, chain_id, registry)
                .map_err(|message| format!("members[{index}]: {message}"))?,
        );
    }

    let task = RegisterTask {
        id: new_task_id,
        status: TaskStatus::Pending,
        rp_id,
        metadata,
        unit_nonce,
        members: parsed,
        tx_hash: None,
        first_entry_id: None,
        error: None,
        retries: 0,
        created_at: now_ms as i64,
        admitted: false,
    };
    let content_hash = content_hash_for(&task).map_err(|error| error.to_string())?;
    Ok((task, format!("{content_hash:#x}")))
}

fn validate_member(
    member: MemberRequest,
    rp_id: &str,
    nonce: alloy::primitives::B256,
    chain_id: u64,
    registry: Address,
) -> Result<Member, String> {
    let Some(public_key) = member.public_key.as_deref() else {
        return Err("publicKey is required".into());
    };
    let raw = public_key.strip_prefix("0x").unwrap_or(public_key);
    if raw.len() != 130 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("publicKey must be an uncompressed P-256 point (04 + 128 hex chars)".into());
    }
    if !raw.starts_with("04") {
        return Err("publicKey must start with the uncompressed prefix 04".into());
    }
    let public_key = raw.to_ascii_lowercase();
    let key_bytes = hex::decode(&public_key).expect("validated hex");
    p256::PublicKey::from_sec1_bytes(&key_bytes)
        .map_err(|_| "publicKey must be a valid point on the P-256 curve".to_owned())?;

    let attestation = member.attestation.unwrap_or_default();
    let attestation_bytes = parse_hex_bytes(&attestation)
        .map_err(|_| "attestation must be a valid hex string".to_owned())?;
    if !attestation_bytes.is_empty() {
        if attestation_bytes.len() != ATTESTATION_BYTES {
            return Err(format!("attestation must be {ATTESTATION_BYTES} bytes"));
        }
        if attestation_bytes[0] != ATTESTATION_VERSION {
            return Err(format!(
                "attestation must start with version byte 0x{ATTESTATION_VERSION:02x}"
            ));
        }
    }
    let attestation = if attestation_bytes.is_empty() {
        String::new()
    } else {
        format!("0x{}", hex::encode(&attestation_bytes))
    };

    let Some(proof) = member.proof else {
        return Err("proof is required".into());
    };
    let proof = Proof {
        authenticator_data: proof
            .authenticator_data
            .ok_or("proof.authenticatorData is required")?,
        client_data_json: proof
            .client_data_json
            .ok_or("proof.clientDataJSON is required")?,
        challenge_index: proof
            .challenge_index
            .ok_or("proof.challengeIndex is required")?,
        type_index: proof.type_index.ok_or("proof.typeIndex is required")?,
        r: proof.r.ok_or("proof.r is required")?,
        s: proof.s.ok_or("proof.s is required")?,
    };

    // The pure mirror of the contract's verification: an invalid proof never
    // reaches the chain.
    let challenge = challenge_for(chain_id, registry, rp_id, &key_bytes, nonce);
    verify_proof(&proof, challenge, rp_id, &key_bytes)
        .map_err(|error| format!("proof rejected: {error}"))?;

    Ok(Member {
        public_key,
        attestation,
        proof,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use alloy::primitives::B256;
    use crux_core::{Core, Request};
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::verify::base64url_32;

    const CHAIN: u64 = 100;
    const REGISTRY: &str = "0x1111111111111111111111111111111111111111";

    fn keypair() -> (p256::ecdsa::SigningKey, String) {
        let secret = [
            0xba, 0xb2, 0x6f, 0x1a, 0xb9, 0x4e, 0x84, 0xa2, 0x31, 0x99, 0xc4, 0x6e, 0xc2, 0xdd,
            0x44, 0x89, 0x50, 0x7c, 0x27, 0x8d, 0xd3, 0xdd, 0xf2, 0xba, 0x0a, 0x47, 0xec, 0x20,
            0x12, 0x05, 0xfe, 0x7a,
        ];
        let key = p256::ecdsa::SigningKey::from_bytes((&secret).into()).unwrap();
        let public = hex::encode(key.verifying_key().to_sec1_point(false).as_bytes());
        (key, public)
    }

    fn nonce_hex() -> String {
        format!("0x{}", "11".repeat(32))
    }

    fn signed_member(rp_id: &str) -> MemberRequest {
        let (signing, public) = keypair();
        let nonce = B256::repeat_byte(0x11);
        let challenge = challenge_for(
            CHAIN,
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
        MemberRequest {
            public_key: Some(public),
            attestation: None,
            proof: Some(ProofRequest {
                authenticator_data: Some(hex::encode(auth_data)),
                client_data_json: Some(client_data),
                challenge_index: Some(23),
                type_index: Some(1),
                r: Some(format!("0x{}", hex::encode(&bytes[..32]))),
                s: Some(format!("0x{}", hex::encode(&bytes[32..]))),
            }),
        }
    }

    fn valid_request() -> RegisterRequest {
        RegisterRequest {
            rp_id: Some("example.com".into()),
            metadata: Some("0xaa".into()),
            unit_nonce: Some(nonce_hex()),
            members: Some(vec![signed_member("example.com")]),
        }
    }

    fn validated() -> (RegisterTask, String) {
        validate_register(valid_request(), "task-new".into(), 1_000, CHAIN, REGISTRY)
            .expect("valid request")
    }

    // ── Validation ─────────────────────────────────────────────────────────

    #[test]
    fn a_fully_proven_request_validates() {
        let (task, content_hash) = validated();
        assert_eq!(task.rp_id, "example.com");
        assert_eq!(task.metadata, "0xaa");
        assert_eq!(task.members.len(), 1);
        assert!(content_hash.starts_with("0x"));
    }

    #[test]
    fn a_bad_proof_is_rejected_before_any_io() {
        let mut request = valid_request();
        // Flip one signature byte.
        let member = &mut request.members.as_mut().unwrap()[0];
        let r = member.proof.as_mut().unwrap().r.as_mut().unwrap();
        let flipped = if r.ends_with('0') { "1" } else { "0" };
        r.truncate(r.len() - 1);
        r.push_str(flipped);
        let error = validate_register(request, "t".into(), 0, CHAIN, REGISTRY).unwrap_err();
        assert!(error.starts_with("members[0]: proof rejected"), "{error}");

        // And the driver settles Invalid without a single operation.
        let mut bad = valid_request();
        bad.members.as_mut().unwrap()[0]
            .proof
            .as_mut()
            .unwrap()
            .type_index = Some(2);
        let driver = Driver::submit(bad);
        match driver.core.view().outcome {
            Some(AdmissionOutcome::Invalid { message }) => {
                assert!(message.contains("webauthn.get"), "{message}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn validation_bounds() {
        let mut no_rp = valid_request();
        no_rp.rp_id = None;
        assert_eq!(
            validate_register(no_rp, "t".into(), 0, CHAIN, REGISTRY).unwrap_err(),
            "rpId is required"
        );

        let mut bad_nonce = valid_request();
        bad_nonce.unit_nonce = Some("0x1234".into());
        assert_eq!(
            validate_register(bad_nonce, "t".into(), 0, CHAIN, REGISTRY).unwrap_err(),
            "unitNonce must be 32-byte hex"
        );

        let mut fat_metadata = valid_request();
        fat_metadata.metadata = Some(format!("0x{}", "00".repeat(1025)));
        assert_eq!(
            validate_register(fat_metadata, "t".into(), 0, CHAIN, REGISTRY).unwrap_err(),
            "metadata exceeds max length (1024 bytes)"
        );

        let mut too_many = valid_request();
        too_many.members = Some(vec![signed_member("example.com"); 8]);
        assert_eq!(
            validate_register(too_many, "t".into(), 0, CHAIN, REGISTRY).unwrap_err(),
            "members must contain 1 to 7 entries"
        );

        let mut bad_attestation = valid_request();
        bad_attestation.members.as_mut().unwrap()[0].attestation = Some("0x00".into());
        assert!(
            validate_register(bad_attestation, "t".into(), 0, CHAIN, REGISTRY)
                .unwrap_err()
                .contains("attestation must be 20 bytes")
        );
    }

    // ── Driver ─────────────────────────────────────────────────────────────

    struct Driver {
        core: Core<AdmissionApp>,
        queue: VecDeque<Request<AdmissionOperation>>,
    }

    impl Driver {
        fn submit(request_body: RegisterRequest) -> Self {
            let core = Core::new();
            let effects = core.process_event(AdmissionEvent::Submit {
                request: request_body,
                new_task_id: "task-new".into(),
                now_ms: 1_000,
                chain_id: CHAIN,
                registry: REGISTRY.into(),
            });
            let mut driver = Self {
                core,
                queue: VecDeque::new(),
            };
            driver.absorb(effects);
            driver
        }

        fn absorb(&mut self, effects: Vec<AdmissionEffect>) {
            for effect in effects {
                let AdmissionEffect::Work(request) = effect;
                self.queue.push_back(request);
            }
            assert!(
                self.queue.len() <= 1,
                "the admission program must be strictly sequential"
            );
        }

        fn step(&mut self, expected: AdmissionOperation, result: AdmissionResult) {
            let mut request = self
                .queue
                .pop_front()
                .unwrap_or_else(|| panic!("no operation in flight; expected {expected:?}"));
            assert_eq!(request.operation, expected);
            let effects = self
                .core
                .resolve(&mut request, result)
                .expect("resolve must succeed");
            self.absorb(effects);
        }

        fn assert_settled(&self, expected: AdmissionOutcome) {
            assert!(self.queue.is_empty(), "no operation may remain in flight");
            assert_eq!(self.core.view().outcome, Some(expected));
        }
    }

    fn expected_task() -> RegisterTask {
        validated().0
    }

    fn expected_content_hash() -> String {
        validated().1
    }

    fn walk_clean_prechecks(driver: &mut Driver) {
        driver.step(
            AdmissionOperation::AllowIpCreate,
            AdmissionResult::Allowed { allowed: true },
        );
        driver.step(
            AdmissionOperation::FindTaskByNonce {
                unit_nonce: nonce_hex(),
            },
            AdmissionResult::TaskFound { task: None },
        );
        driver.step(
            AdmissionOperation::CheckContentRegistered {
                content_hash: expected_content_hash(),
            },
            AdmissionResult::ChainBool { value: false },
        );
        driver.step(
            AdmissionOperation::CheckNonceUsed {
                unit_nonce: nonce_hex(),
            },
            AdmissionResult::ChainBool { value: false },
        );
    }

    #[test]
    fn clean_walk_admits_enqueues_and_returns_queued() {
        let mut driver = Driver::submit(valid_request());
        walk_clean_prechecks(&mut driver);
        driver.step(
            AdmissionOperation::QueueDepth,
            AdmissionResult::Depth { depth: 0 },
        );
        driver.step(
            AdmissionOperation::AllowGlobalCreate,
            AdmissionResult::Allowed { allowed: true },
        );
        driver.step(
            AdmissionOperation::Admit {
                task: expected_task(),
            },
            AdmissionResult::Admitted(AdmitOutcome::New),
        );
        driver.step(
            AdmissionOperation::Enqueue {
                task: expected_task(),
            },
            AdmissionResult::Enqueued,
        );
        let mut admitted = expected_task();
        admitted.admitted = true;
        driver.step(
            AdmissionOperation::MarkAdmitted {
                id: "task-new".into(),
            },
            AdmissionResult::TaskFound {
                task: Some(admitted),
            },
        );
        driver.assert_settled(AdmissionOutcome::Queued {
            id: "task-new".into(),
            status: TaskStatus::Pending,
        });
    }

    #[test]
    fn ip_rate_limit_rejects_before_other_io() {
        let mut driver = Driver::submit(valid_request());
        driver.step(
            AdmissionOperation::AllowIpCreate,
            AdmissionResult::Allowed { allowed: false },
        );
        driver.assert_settled(AdmissionOutcome::RateLimited);
    }

    #[test]
    fn same_unit_resubmission_is_idempotent() {
        let mut driver = Driver::submit(valid_request());
        driver.step(
            AdmissionOperation::AllowIpCreate,
            AdmissionResult::Allowed { allowed: true },
        );
        let mut existing = expected_task();
        existing.id = "earlier".into();
        driver.step(
            AdmissionOperation::FindTaskByNonce {
                unit_nonce: nonce_hex(),
            },
            AdmissionResult::TaskFound {
                task: Some(existing),
            },
        );
        driver.assert_settled(AdmissionOutcome::Queued {
            id: "earlier".into(),
            status: TaskStatus::Pending,
        });
    }

    #[test]
    fn different_unit_on_an_in_flight_nonce_conflicts() {
        let mut driver = Driver::submit(valid_request());
        driver.step(
            AdmissionOperation::AllowIpCreate,
            AdmissionResult::Allowed { allowed: true },
        );
        let mut foreign = expected_task();
        foreign.id = "earlier".into();
        foreign.metadata = "0xbb".into(); // different content, same nonce
        driver.step(
            AdmissionOperation::FindTaskByNonce {
                unit_nonce: nonce_hex(),
            },
            AdmissionResult::TaskFound {
                task: Some(foreign),
            },
        );
        driver.assert_settled(AdmissionOutcome::NonceConflict {
            message: CONFLICT_NONCE_IN_FLIGHT.into(),
        });
    }

    #[test]
    fn content_already_on_chain_answers_done_retroactively() {
        let mut driver = Driver::submit(valid_request());
        driver.step(
            AdmissionOperation::AllowIpCreate,
            AdmissionResult::Allowed { allowed: true },
        );
        driver.step(
            AdmissionOperation::FindTaskByNonce {
                unit_nonce: nonce_hex(),
            },
            AdmissionResult::TaskFound { task: None },
        );
        driver.step(
            AdmissionOperation::CheckContentRegistered {
                content_hash: expected_content_hash(),
            },
            AdmissionResult::ChainBool { value: true },
        );
        driver.assert_settled(AdmissionOutcome::AlreadyRegistered {
            content_hash: expected_content_hash(),
        });
    }

    #[test]
    fn consumed_nonce_with_absent_content_is_terminal() {
        let mut driver = Driver::submit(valid_request());
        driver.step(
            AdmissionOperation::AllowIpCreate,
            AdmissionResult::Allowed { allowed: true },
        );
        driver.step(
            AdmissionOperation::FindTaskByNonce {
                unit_nonce: nonce_hex(),
            },
            AdmissionResult::TaskFound { task: None },
        );
        driver.step(
            AdmissionOperation::CheckContentRegistered {
                content_hash: expected_content_hash(),
            },
            AdmissionResult::ChainBool { value: false },
        );
        driver.step(
            AdmissionOperation::CheckNonceUsed {
                unit_nonce: nonce_hex(),
            },
            AdmissionResult::ChainBool { value: true },
        );
        driver.assert_settled(AdmissionOutcome::NonceConflict {
            message: CONFLICT_NONCE_CONSUMED.into(),
        });
    }

    #[test]
    fn chain_prechecks_fail_open_to_the_gates() {
        let mut driver = Driver::submit(valid_request());
        driver.step(
            AdmissionOperation::AllowIpCreate,
            AdmissionResult::Allowed { allowed: true },
        );
        driver.step(
            AdmissionOperation::FindTaskByNonce {
                unit_nonce: nonce_hex(),
            },
            AdmissionResult::TaskFound { task: None },
        );
        driver.step(
            AdmissionOperation::CheckContentRegistered {
                content_hash: expected_content_hash(),
            },
            AdmissionResult::ChainReadFailed,
        );
        driver.step(
            AdmissionOperation::CheckNonceUsed {
                unit_nonce: nonce_hex(),
            },
            AdmissionResult::ChainReadFailed,
        );
        driver.step(
            AdmissionOperation::QueueDepth,
            AdmissionResult::Depth { depth: 0 },
        );
        // Reaching the depth gate proves both fail-open arms.
    }

    #[test]
    fn queue_depth_gate_is_inclusive_at_the_limit() {
        let mut driver = Driver::submit(valid_request());
        walk_clean_prechecks(&mut driver);
        driver.step(
            AdmissionOperation::QueueDepth,
            AdmissionResult::Depth {
                depth: MAX_ACTIVE_QUEUE_DEPTH,
            },
        );
        driver.assert_settled(AdmissionOutcome::Busy);
    }

    #[test]
    fn existing_unadmitted_task_repairs_phase_two() {
        let mut driver = Driver::submit(valid_request());
        walk_clean_prechecks(&mut driver);
        driver.step(
            AdmissionOperation::QueueDepth,
            AdmissionResult::Depth { depth: 0 },
        );
        driver.step(
            AdmissionOperation::AllowGlobalCreate,
            AdmissionResult::Allowed { allowed: true },
        );
        driver.step(
            AdmissionOperation::Admit {
                task: expected_task(),
            },
            AdmissionResult::Admitted(AdmitOutcome::Existing {
                id: "earlier".into(),
            }),
        );
        let mut unadmitted = expected_task();
        unadmitted.id = "earlier".into();
        driver.step(
            AdmissionOperation::LoadTask {
                id: "earlier".into(),
            },
            AdmissionResult::TaskFound {
                task: Some(unadmitted.clone()),
            },
        );
        driver.step(
            AdmissionOperation::Enqueue {
                task: unadmitted.clone(),
            },
            AdmissionResult::Enqueued,
        );
        let mut admitted = unadmitted;
        admitted.admitted = true;
        driver.step(
            AdmissionOperation::MarkAdmitted {
                id: "earlier".into(),
            },
            AdmissionResult::TaskFound {
                task: Some(admitted),
            },
        );
        driver.assert_settled(AdmissionOutcome::Queued {
            id: "earlier".into(),
            status: TaskStatus::Pending,
        });
    }

    #[test]
    fn enqueue_failure_keeps_the_admission_and_reports_the_queue() {
        let mut driver = Driver::submit(valid_request());
        walk_clean_prechecks(&mut driver);
        driver.step(
            AdmissionOperation::QueueDepth,
            AdmissionResult::Depth { depth: 0 },
        );
        driver.step(
            AdmissionOperation::AllowGlobalCreate,
            AdmissionResult::Allowed { allowed: true },
        );
        driver.step(
            AdmissionOperation::Admit {
                task: expected_task(),
            },
            AdmissionResult::Admitted(AdmitOutcome::New),
        );
        driver.step(
            AdmissionOperation::Enqueue {
                task: expected_task(),
            },
            AdmissionResult::QueueUnavailable,
        );
        driver.assert_settled(AdmissionOutcome::DependencyUnavailable {
            dependency: "queue".into(),
        });
    }
}
