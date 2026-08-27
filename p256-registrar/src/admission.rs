//! Registration admission: the decision half of the register endpoint.
//!
//! One [`AdmissionApp`] instance drives one request from a parsed
//! [`RegisterRequest`] to an [`AdmissionOutcome`]:
//!
//! - validation is TOTAL: shapes, bounds, and every member's possession
//!   proof are verified (pure P-256, mirroring the contract) before anything
//!   touches Redis — an invalid proof can never reach the chain or burn gas.
//!   Every proof binds the unit's content hash, so a valid request is valid
//!   for exactly its own content;
//! - the content hash is the idempotency key: a resubmission of the same
//!   unit returns its existing task, and nothing else can collide with it;
//! - the chain pre-check is fail-open: content already registered answers
//!   "done" retroactively;
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

use alloy::primitives::{Address, keccak256};
use crux_core::{App, Command, command::CommandContext, macros::effect};
use serde::{Deserialize, Serialize};

use crate::protocol::{
    challenge_for, content_hash_for, member_binding_for, parse_hex_bytes, reference_binding_for,
};
use crate::task::{Member, Proof, RegisterTask, TaskKind, TaskStatus};
use crate::verify::verify_proof;

/// New registrations are rejected while the active queue is at least this deep.
pub const MAX_ACTIVE_QUEUE_DEPTH: u64 = 10_000;

/// How long a register's retry digest keeps coalescing look-alike
/// resubmissions (see [`register_retry_digest`]). Long enough to absorb any
/// client retry loop, short enough that a deliberate identical re-register
/// weeks later still passes.
pub const RETRY_COALESCE_TTL_SECS: u64 = 24 * 60 * 60;

/// Mirrors the contract's MAX_MEMBERS.
pub const MAX_MEMBERS: usize = 7;
/// Mirrors the contract's MAX_METADATA_LENGTH (bytes).
pub const MAX_METADATA_BYTES: usize = 2048;
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
    pub credential_id: Option<String>,
    pub authenticator_attachment: Option<String>,
    pub transports: Option<String>,
    pub proof: Option<ProofRequest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRequest {
    pub rp_id: Option<String>,
    pub metadata: Option<String>,
    pub group_public_key: Option<String>,
    pub group_proof: Option<ProofRequest>,
    pub members: Option<Vec<MemberRequest>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReferRequest {
    /// The target group's rpId — re-verified against the group's frozen
    /// record by the contract.
    pub rp_id: Option<String>,
    pub group_public_key: Option<String>,
    /// The reference's own opaque payload.
    pub metadata: Option<String>,
    pub member: Option<MemberRequest>,
}

/// One admitted write, dispatched by kind.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum AdmissionRequest {
    Register(RegisterRequest),
    Refer(ReferRequest),
}

// ── Shell protocol ─────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AdmissionOperation {
    /// May this client register right now? The shell resolves this against
    /// its salted per-IP counter; the raw IP never enters the Core.
    AllowIpCreate,
    /// The in-flight/terminal task holding this content hash, if any.
    FindTaskByContent {
        content_hash: String,
    },
    /// The task recorded under this group-key-agnostic retry digest, if any
    /// (see [`register_retry_digest`]); the shell answers from a TTL'd
    /// marker written by [`AdmissionOperation::RecordRetryDigest`].
    FindTaskByRetryDigest {
        digest: String,
    },
    /// Best-effort marker: this digest's identical resubmissions coalesce
    /// onto `task_id` for [`RETRY_COALESCE_TTL_SECS`]. A lost marker only
    /// weakens dedup; it must never fail an admission.
    RecordRetryDigest {
        digest: String,
        task_id: String,
    },
    /// isContentRegistered(contentHash) on the registry (fail-open).
    CheckContentRegistered {
        content_hash: String,
    },
    /// isReferenced(groupPublicKey, memberPublicKey) on the registry
    /// (fail-open).
    CheckReferenced {
        group_public_key: String,
        member_public_key: String,
    },
    /// Does the target group exist on-chain? getUnitByGroupKey(groupKey) —
    /// Refer only, fail-open. Answered by [`AdmissionResult::ChainBool`].
    CheckGroupExists {
        group_public_key: String,
    },
    /// The in-flight/terminal task holding this public key's placeholder, if
    /// any — used to tell a refer racing its own register (allowed) from a
    /// refer to a group that never existed (rejected).
    FindTaskByKey {
        key_hash: String,
    },
    QueueDepth,
    AllowGlobalCreate,
    /// Phase one: the store's atomic admission keyed by the content hash.
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

// In-process operation envelopes; the task-bearing variants dominate by
// design and boxing them would complicate every core/shell match.
#[allow(clippy::large_enum_variant)]
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
    /// 404: a refer names a group that is not on-chain and has no register
    /// in flight to create it — refusing it at the door keeps a would-be
    /// GroupNotFound poison pill out of the FIFO queue.
    ReferGroupMissing,
    /// 503 busy (depth or global rate gate).
    Busy,
    /// 503 retryable, naming the failed dependency ("redis" / "queue").
    DependencyUnavailable { dependency: String },
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AdmissionEvent {
    /// The shell supplies task identity, wall-clock time and the chain
    /// context so the program stays deterministic.
    Submit {
        request: AdmissionRequest,
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

async fn request(ctx: &Ctx, operation: AdmissionOperation) -> AdmissionResult {
    ctx.request_from_shell(operation).await
}

/// A register's identity MINUS its single-use group key: rpId, metadata and
/// the sorted member key set, each length-prefixed. The protocol makes the
/// group key part of the content hash, so a client that retries by
/// regenerating it mints a brand-new content hash and walks straight past
/// content idempotency — four identical units in 25 seconds, observed in
/// production. The server pays the gas, so it coalesces on this digest
/// instead. Byte-exact on purpose: any intentional difference (Vela's
/// metadata carries a creation timestamp) changes the digest and passes.
pub fn register_retry_digest(task: &RegisterTask) -> String {
    let mut member_keys: Vec<String> = task
        .members
        .iter()
        .map(|member| member.public_key.to_lowercase())
        .collect();
    member_keys.sort();
    let mut preimage = Vec::new();
    for part in std::iter::once(task.rp_id.as_str())
        .chain(std::iter::once(task.metadata.as_str()))
        .chain(member_keys.iter().map(String::as_str))
    {
        let bytes = part.as_bytes();
        preimage.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        preimage.extend_from_slice(bytes);
    }
    hex::encode(keccak256(preimage))
}

async fn drive_admission(
    ctx: &Ctx,
    submitted: AdmissionRequest,
    new_task_id: String,
    now_ms: u64,
    chain_id: u64,
    registry: &str,
) -> Flow<AdmissionOutcome> {
    let validated = match submitted {
        AdmissionRequest::Register(register) => {
            validate_register(register, new_task_id, now_ms, chain_id, registry)
        }
        AdmissionRequest::Refer(refer) => {
            validate_refer(refer, new_task_id, now_ms, chain_id, registry)
        }
    };
    let (task, content_hash) = match validated {
        Ok(valid) => valid,
        Err(message) => return Ok(AdmissionOutcome::Invalid { message }),
    };

    match request(ctx, AdmissionOperation::AllowIpCreate).await {
        AdmissionResult::Allowed { allowed: true } => {}
        AdmissionResult::Allowed { allowed: false } => return Ok(AdmissionOutcome::RateLimited),
        _ => return Err(redis_down()),
    }

    // Idempotency by content hash: the same unit resubmitted returns its
    // task — content-hash equality means it IS the same unit, so nothing
    // else can collide. A found-but-unadmitted task means an earlier
    // submission died between Redis admit and the queue append: repair
    // phase two here instead of reporting a task that will never run.
    match request(
        ctx,
        AdmissionOperation::FindTaskByContent {
            content_hash: content_hash.clone(),
        },
    )
    .await
    {
        AdmissionResult::TaskFound {
            task: Some(existing),
        } => {
            if existing.admitted || existing.status.is_terminal() {
                return Ok(AdmissionOutcome::Queued {
                    id: existing.id,
                    status: existing.status,
                });
            }
            return enqueue(ctx, existing).await;
        }
        AdmissionResult::TaskFound { task: None } => {}
        _ => return Err(redis_down()),
    }

    // Second idempotency net, register only: the same unit resubmitted with
    // a REGENERATED group key (a client retry loop) has a fresh content
    // hash but the same retry digest. Coalesce onto the live task — unless
    // it failed, in which case a fresh attempt with a fresh key is exactly
    // what should proceed.
    let retry_digest = (task.kind == TaskKind::Register).then(|| register_retry_digest(&task));
    if let Some(digest) = &retry_digest {
        match request(
            ctx,
            AdmissionOperation::FindTaskByRetryDigest {
                digest: digest.clone(),
            },
        )
        .await
        {
            AdmissionResult::TaskFound {
                task: Some(existing),
            } if existing.status != TaskStatus::Failed => {
                if existing.admitted || existing.status.is_terminal() {
                    return Ok(AdmissionOutcome::Queued {
                        id: existing.id,
                        status: existing.status,
                    });
                }
                return enqueue(ctx, existing).await;
            }
            AdmissionResult::TaskFound { .. } => {}
            _ => return Err(redis_down()),
        }
    }

    // Chain pre-check, fail-open: an RPC outage never blocks admission —
    // the worker reconciles against the chain anyway.
    let precheck = match task.kind {
        TaskKind::Register => AdmissionOperation::CheckContentRegistered {
            content_hash: content_hash.clone(),
        },
        TaskKind::Refer => AdmissionOperation::CheckReferenced {
            group_public_key: task.group_public_key.clone(),
            member_public_key: task.members[0].public_key.clone(),
        },
    };
    match request(ctx, precheck).await {
        AdmissionResult::ChainBool { value: true } => {
            return Ok(AdmissionOutcome::AlreadyRegistered { content_hash });
        }
        AdmissionResult::ChainBool { value: false } | AdmissionResult::ChainReadFailed => {}
        _ => return Err(redis_down()),
    }

    // A refer must target a group that already exists — or one whose
    // creating register is still in flight (the intended race). Refusing a
    // refer to a group that never existed keeps a permanent GroupNotFound
    // poison pill out of the FIFO queue, where it would wedge every write
    // behind it.
    if task.kind == TaskKind::Refer {
        refer_group_gate(ctx, &task).await?;
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
        AdmissionResult::Admitted(AdmitOutcome::New) => {
            if let Some(digest) = &retry_digest {
                // Best-effort by design: any shell answer is accepted — a
                // lost marker weakens dedup, never the admission itself.
                let _ = request(
                    ctx,
                    AdmissionOperation::RecordRetryDigest {
                        digest: digest.clone(),
                        task_id: task.id.clone(),
                    },
                )
                .await;
            }
            enqueue(ctx, task).await
        }
        _ => Err(redis_down()),
    }
}

/// The refer group-existence gate. The chain read is fail-open (an RPC
/// outage never blocks admission; the worker's GroupNotFound→transient
/// retry remains the backstop for the race). A Redis failure on the
/// task-lookup is a 503 like every other store failure. A definite "group
/// absent AND no register in flight for it" is the only rejection.
async fn refer_group_gate(ctx: &Ctx, task: &RegisterTask) -> Flow<()> {
    match request(
        ctx,
        AdmissionOperation::CheckGroupExists {
            group_public_key: task.group_public_key.clone(),
        },
    )
    .await
    {
        AdmissionResult::ChainBool { value: true } | AdmissionResult::ChainReadFailed => Ok(()),
        AdmissionResult::ChainBool { value: false } => {
            match request(
                ctx,
                AdmissionOperation::FindTaskByKey {
                    key_hash: task.group_public_key.clone(),
                },
            )
            .await
            {
                // Allowed only when a register that creates this exact group
                // is still working through the pipeline.
                AdmissionResult::TaskFound {
                    task: Some(pending),
                } if pending.kind == TaskKind::Register
                    && pending.group_public_key == task.group_public_key
                    && !pending.status.is_terminal() =>
                {
                    Ok(())
                }
                AdmissionResult::TaskFound { .. } => Err(AdmissionOutcome::ReferGroupMissing),
                _ => Err(redis_down()),
            }
        }
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

    // Structural parse first: the content hash covers the group key and
    // every member's key and attestation, so it must exist before any
    // proof can be checked.
    let group_public_key = parse_public_key(request.group_public_key.as_deref())
        .map_err(|message| format!("groupPublicKey: {message}"))?;
    let group_proof =
        parse_proof(request.group_proof).map_err(|message| format!("groupProof: {message}"))?;

    let mut parsed = Vec::with_capacity(members.len());
    for (index, member) in members.into_iter().enumerate() {
        let member =
            parse_member(member).map_err(|message| format!("members[{index}]: {message}"))?;
        if member.public_key == group_public_key {
            return Err(format!(
                "members[{index}]: the group key cannot also be a member"
            ));
        }
        if parsed
            .iter()
            .any(|earlier: &Member| earlier.public_key == member.public_key)
        {
            return Err(format!(
                "members[{index}]: duplicate public key within the unit"
            ));
        }
        parsed.push(member);
    }

    let mut task = RegisterTask {
        id: new_task_id,
        status: TaskStatus::Pending,
        kind: TaskKind::Register,
        rp_id,
        metadata,
        content_hash: String::new(),
        group_public_key,
        group_proof: Some(group_proof),
        members: parsed,
        tx_hash: None,
        on_chain_id: None,
        error: None,
        retries: 0,
        created_at: now_ms as i64,
        admitted: false,
    };
    let content_hash = content_hash_for(&task).map_err(|error| error.to_string())?;
    task.content_hash = format!("{content_hash:#x}");

    // The pure mirror of the contract's verification, so an invalid proof
    // never reaches the chain: the group proof binds the content hash...
    let group_key_bytes = hex::decode(&task.group_public_key).expect("validated hex");
    let group_challenge = challenge_for(
        chain_id,
        registry,
        &task.rp_id,
        &group_key_bytes,
        content_hash,
    );
    verify_proof(
        task.group_proof.as_ref().expect("register task has one"),
        group_challenge,
        &task.rp_id,
        &group_key_bytes,
    )
    .map_err(|error| format!("groupProof: proof rejected: {error}"))?;

    // ...and every member's proof binds (groupKey, own attestation).
    for (index, member) in task.members.iter().enumerate() {
        let key_bytes = hex::decode(&member.public_key).expect("validated hex");
        let attestation_bytes = parse_hex_bytes(&member.attestation).expect("validated hex");
        let binding = member_binding_for(&group_key_bytes, &attestation_bytes);
        let challenge = challenge_for(chain_id, registry, &task.rp_id, &key_bytes, binding);
        verify_proof(&member.proof, challenge, &task.rp_id, &key_bytes)
            .map_err(|error| format!("members[{index}]: proof rejected: {error}"))?;
    }

    let content_hash = task.content_hash.clone();
    Ok((task, content_hash))
}

/// Total validation for a Refer request: shapes, bounds and the referring
/// key's reference-bound possession proof.
pub fn validate_refer(
    request: ReferRequest,
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

    let group_public_key = parse_public_key(request.group_public_key.as_deref())
        .map_err(|message| format!("groupPublicKey: {message}"))?;

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

    let Some(member) = request.member else {
        return Err("member is required".into());
    };
    let member = parse_member(member).map_err(|message| format!("member: {message}"))?;
    if member.public_key == group_public_key {
        return Err("member: the group key cannot also be a member".into());
    }

    let mut task = RegisterTask {
        id: new_task_id,
        status: TaskStatus::Pending,
        kind: TaskKind::Refer,
        rp_id,
        metadata,
        content_hash: String::new(),
        group_public_key,
        group_proof: None,
        members: vec![member],
        tx_hash: None,
        on_chain_id: None,
        error: None,
        retries: 0,
        created_at: now_ms as i64,
        admitted: false,
    };
    let content_hash = content_hash_for(&task).map_err(|error| error.to_string())?;
    task.content_hash = format!("{content_hash:#x}");

    // The pure mirror of the contract's verification: the referring key
    // binds (groupKey, own attestation, reference metadata).
    let group_key_bytes = hex::decode(&task.group_public_key).expect("validated hex");
    let member_ref = &task.members[0];
    let key_bytes = hex::decode(&member_ref.public_key).expect("validated hex");
    let attestation_bytes = parse_hex_bytes(&member_ref.attestation).expect("validated hex");
    let metadata_bytes = parse_hex_bytes(&task.metadata).expect("validated hex");
    let binding = reference_binding_for(&group_key_bytes, &attestation_bytes, &metadata_bytes);
    let challenge = challenge_for(chain_id, registry, &task.rp_id, &key_bytes, binding);
    verify_proof(&member_ref.proof, challenge, &task.rp_id, &key_bytes)
        .map_err(|error| format!("member: proof rejected: {error}"))?;

    let content_hash = task.content_hash.clone();
    Ok((task, content_hash))
}

/// Key shape and curve membership for one hex-encoded key; returns the
/// normalized lowercase hex (no 0x). Public so the shell's challenge
/// endpoint enforces exactly what admission will.
pub fn validate_public_key_hex(value: &str) -> Result<String, String> {
    parse_public_key(Some(value))
}

/// Attestation shape (empty, or 20 versioned bytes); returns "" or 0x-hex.
/// Public for the same reason as [`validate_public_key_hex`].
pub fn validate_attestation_hex(value: &str) -> Result<String, String> {
    let attestation_bytes =
        parse_hex_bytes(value).map_err(|_| "attestation must be a valid hex string".to_owned())?;
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
    Ok(if attestation_bytes.is_empty() {
        String::new()
    } else {
        format!("0x{}", hex::encode(&attestation_bytes))
    })
}

/// Key shape and curve membership; returns the normalized lowercase hex.
fn parse_public_key(value: Option<&str>) -> Result<String, String> {
    let Some(public_key) = value else {
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
    Ok(public_key)
}

/// Field presence for a proof; verification happens once the challenge
/// exists.
fn parse_proof(proof: Option<ProofRequest>) -> Result<Proof, String> {
    let Some(proof) = proof else {
        return Err("proof is required".into());
    };
    Ok(Proof {
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
    })
}

/// Structural parse of one member: key shape and curve membership,
/// attestation shape, proof field presence. Proof VERIFICATION happens in
/// `validate_register` once the group key and content hash exist, because
/// every challenge binds them.
fn parse_member(member: MemberRequest) -> Result<Member, String> {
    let public_key = parse_public_key(member.public_key.as_deref())?;

    let attestation = validate_attestation_hex(&member.attestation.unwrap_or_default())?;

    let credential_id = normalize_credential_id(&member.credential_id.unwrap_or_default())?;

    let authenticator_attachment = normalize_hint(
        &member.authenticator_attachment.unwrap_or_default(),
        32,
        "authenticatorAttachment",
    )?;
    let transports = normalize_hint(&member.transports.unwrap_or_default(), 255, "transports")?;

    let proof = parse_proof(member.proof)?;

    Ok(Member {
        public_key,
        attestation,
        credential_id,
        authenticator_attachment,
        transports,
        proof,
    })
}

/// The credential id as stored: hex bytes, `0x`-normalized, bounded to the
/// contract's 1023-byte cap. Empty is allowed.
fn normalize_credential_id(value: &str) -> Result<String, String> {
    let bytes =
        parse_hex_bytes(value).map_err(|_| "credentialId must be a valid hex string".to_owned())?;
    if bytes.len() > 1023 {
        return Err("credentialId exceeds 1023 bytes".to_owned());
    }
    Ok(if bytes.is_empty() {
        String::new()
    } else {
        format!("0x{}", hex::encode(&bytes))
    })
}

/// A browser-reported display hint (authenticatorAttachment / transports):
/// an opaque UTF-8 token, trimmed and bounded to the contract's byte cap so
/// the calldata can never revert. Its truthfulness is the writer's claim.
fn normalize_hint(value: &str, max_bytes: usize, field: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.len() > max_bytes {
        return Err(format!("{field} exceeds {max_bytes} bytes"));
    }
    Ok(trimmed.to_owned())
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

    fn key_from(secret: [u8; 32]) -> (p256::ecdsa::SigningKey, String) {
        let key = p256::ecdsa::SigningKey::from_bytes((&secret).into()).unwrap();
        let public = hex::encode(key.verifying_key().to_sec1_point(false).as_bytes());
        (key, public)
    }

    fn keypair() -> (p256::ecdsa::SigningKey, String) {
        let mut secret = [0u8; 32];
        secret.copy_from_slice(
            &hex::decode("bab26f1ab94e84a23199c46ec2dd4489507c278dd3ddf2ba0a47ec201205fe7a")
                .unwrap(),
        );
        key_from(secret)
    }

    /// The unit's GROUP key (a client-side software key in production).
    fn group_keypair() -> (p256::ecdsa::SigningKey, String) {
        let mut secret = [0u8; 32];
        secret.copy_from_slice(
            &hex::decode("7e7b5b9fba4858c30377ef6a0f3d3d9079cf00d2291bf0d468789a5cb5705aef")
                .unwrap(),
        );
        key_from(secret)
    }

    /// A raw WebAuthn-shaped proof by `signing` over `challenge` for `rp_id`.
    fn proof_over(signing: &p256::ecdsa::SigningKey, challenge: B256, rp_id: &str) -> ProofRequest {
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
        ProofRequest {
            authenticator_data: Some(hex::encode(auth_data)),
            client_data_json: Some(client_data),
            challenge_index: Some(23),
            type_index: Some(1),
            r: Some(format!("0x{}", hex::encode(&bytes[..32]))),
            s: Some(format!("0x{}", hex::encode(&bytes[32..]))),
        }
    }

    /// The content hash of the canonical test unit: rpId, metadata "0xaa",
    /// the fixed group key, one member (the fixed keypair, no attestation)
    /// — mirroring exactly what validate_register computes.
    fn test_content_hash(rp_id: &str) -> B256 {
        let (_, public) = keypair();
        let (_, group_public) = group_keypair();
        let skeleton = RegisterTask {
            id: String::new(),
            status: TaskStatus::Pending,
            kind: TaskKind::Register,
            rp_id: rp_id.into(),
            metadata: "0xaa".into(),
            content_hash: String::new(),
            group_public_key: group_public,
            group_proof: Some(Proof {
                authenticator_data: String::new(),
                client_data_json: String::new(),
                challenge_index: 0,
                type_index: 0,
                r: String::new(),
                s: String::new(),
            }),
            members: vec![Member {
                public_key: public,
                attestation: String::new(),
                credential_id: String::new(),
                authenticator_attachment: String::new(),
                transports: String::new(),
                proof: Proof {
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
        content_hash_for(&skeleton).unwrap()
    }

    /// One member signing at creation time: binds (groupKey, own
    /// attestation) — independent of the metadata and of any sibling.
    fn signed_member(rp_id: &str) -> MemberRequest {
        let (signing, public) = keypair();
        let (_, group_public) = group_keypair();
        let binding = member_binding_for(&hex::decode(&group_public).unwrap(), &[]);
        let challenge = challenge_for(
            CHAIN,
            REGISTRY.parse().unwrap(),
            rp_id,
            &hex::decode(&public).unwrap(),
            binding,
        );
        MemberRequest {
            public_key: Some(public),
            attestation: None,
            credential_id: None,
            authenticator_attachment: None,
            transports: None,
            proof: Some(proof_over(&signing, challenge, rp_id)),
        }
    }

    /// The group key's silent closing proof over the finished unit content.
    fn signed_group_proof(rp_id: &str) -> ProofRequest {
        let (signing, group_public) = group_keypair();
        let challenge = challenge_for(
            CHAIN,
            REGISTRY.parse().unwrap(),
            rp_id,
            &hex::decode(&group_public).unwrap(),
            test_content_hash(rp_id),
        );
        proof_over(&signing, challenge, rp_id)
    }

    fn valid_request() -> RegisterRequest {
        RegisterRequest {
            rp_id: Some("example.com".into()),
            metadata: Some("0xaa".into()),
            group_public_key: Some(group_keypair().1),
            group_proof: Some(signed_group_proof("example.com")),
            members: Some(vec![signed_member("example.com")]),
        }
    }

    fn refer_binding() -> alloy::primitives::B256 {
        let (_, group_public) = group_keypair();
        reference_binding_for(&hex::decode(&group_public).unwrap(), &[], &[0xca, 0xfe])
    }

    /// A referring passkey's request: the fixed keypair pointing at the
    /// fixed group key with metadata 0xcafe.
    fn valid_refer_request() -> ReferRequest {
        let (signing, public) = keypair();
        let challenge = challenge_for(
            CHAIN,
            REGISTRY.parse().unwrap(),
            "example.com",
            &hex::decode(&public).unwrap(),
            refer_binding(),
        );
        ReferRequest {
            rp_id: Some("example.com".into()),
            group_public_key: Some(group_keypair().1),
            metadata: Some("0xcafe".into()),
            member: Some(MemberRequest {
                public_key: Some(public),
                attestation: None,
                credential_id: None,
                authenticator_attachment: None,
                transports: None,
                proof: Some(proof_over(&signing, challenge, "example.com")),
            }),
        }
    }

    fn validated_refer() -> (RegisterTask, String) {
        validate_refer(
            valid_refer_request(),
            "task-new".into(),
            1_000,
            CHAIN,
            REGISTRY,
        )
        .expect("valid refer request")
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

        let mut fat_metadata = valid_request();
        fat_metadata.metadata = Some(format!("0x{}", "00".repeat(2049)));
        assert_eq!(
            validate_register(fat_metadata, "t".into(), 0, CHAIN, REGISTRY).unwrap_err(),
            "metadata exceeds max length (2048 bytes)"
        );

        let mut duplicated = valid_request();
        duplicated.members = Some(vec![signed_member("example.com"); 2]);
        assert_eq!(
            validate_register(duplicated, "t".into(), 0, CHAIN, REGISTRY).unwrap_err(),
            "members[1]: duplicate public key within the unit"
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

    #[test]
    fn a_fully_proven_refer_validates() {
        let (task, content_hash) = validated_refer();
        assert_eq!(task.kind, TaskKind::Refer);
        assert_eq!(task.metadata, "0xcafe");
        assert_eq!(task.members.len(), 1);
        assert!(task.group_proof.is_none());
        assert!(content_hash.starts_with("0x"));
        // The idempotency digest is (group, key) ONLY — resubmitting the
        // same pair with different metadata maps to the SAME task.
        let mut replaced = valid_refer_request();
        replaced.metadata = Some("0xbeef".into());
        // (The proof no longer matches the new metadata, so recompute it.)
        let (signing, public) = keypair();
        let binding = reference_binding_for(
            &hex::decode(&group_keypair().1).unwrap(),
            &[],
            &[0xbe, 0xef],
        );
        let challenge = challenge_for(
            CHAIN,
            REGISTRY.parse().unwrap(),
            "example.com",
            &hex::decode(&public).unwrap(),
            binding,
        );
        replaced.member.as_mut().unwrap().proof =
            Some(proof_over(&signing, challenge, "example.com"));
        let (_, replaced_hash) =
            validate_refer(replaced, "t2".into(), 0, CHAIN, REGISTRY).expect("valid");
        assert_eq!(content_hash, replaced_hash);
    }

    #[test]
    fn refer_rejections() {
        let mut no_member = valid_refer_request();
        no_member.member = None;
        assert_eq!(
            validate_refer(no_member, "t".into(), 0, CHAIN, REGISTRY).unwrap_err(),
            "member is required"
        );

        let mut self_refer = valid_refer_request();
        self_refer.member.as_mut().unwrap().public_key = Some(group_keypair().1);
        assert_eq!(
            validate_refer(self_refer, "t".into(), 0, CHAIN, REGISTRY).unwrap_err(),
            "member: the group key cannot also be a member"
        );

        // A member-binding proof is not a reference proof.
        let mut wrong_binding = valid_refer_request();
        wrong_binding.member = Some(signed_member("example.com"));
        let error = validate_refer(wrong_binding, "t".into(), 0, CHAIN, REGISTRY).unwrap_err();
        assert!(error.starts_with("member: proof rejected"), "{error}");

        // Metadata tampering after signing dies too.
        let mut tampered = valid_refer_request();
        tampered.metadata = Some("0xbeef".into());
        let error = validate_refer(tampered, "t".into(), 0, CHAIN, REGISTRY).unwrap_err();
        assert!(error.starts_with("member: proof rejected"), "{error}");
    }

    #[test]
    fn refer_walks_check_referenced_and_admits() {
        let core: Core<AdmissionApp> = Core::new();
        let effects = core.process_event(AdmissionEvent::Submit {
            request: AdmissionRequest::Refer(valid_refer_request()),
            new_task_id: "task-new".into(),
            now_ms: 1_000,
            chain_id: CHAIN,
            registry: REGISTRY.into(),
        });
        let mut driver = Driver {
            core,
            queue: VecDeque::new(),
        };
        driver.absorb(effects);
        let (task, content_hash) = validated_refer();

        driver.step(
            AdmissionOperation::AllowIpCreate,
            AdmissionResult::Allowed { allowed: true },
        );
        driver.step(
            AdmissionOperation::FindTaskByContent {
                content_hash: content_hash.clone(),
            },
            AdmissionResult::TaskFound { task: None },
        );
        driver.step(
            AdmissionOperation::CheckReferenced {
                group_public_key: task.group_public_key.clone(),
                member_public_key: task.members[0].public_key.clone(),
            },
            AdmissionResult::ChainBool { value: false },
        );
        driver.step(
            AdmissionOperation::CheckGroupExists {
                group_public_key: task.group_public_key.clone(),
            },
            AdmissionResult::ChainBool { value: true },
        );
        driver.step(
            AdmissionOperation::QueueDepth,
            AdmissionResult::Depth { depth: 0 },
        );
        driver.step(
            AdmissionOperation::AllowGlobalCreate,
            AdmissionResult::Allowed { allowed: true },
        );
        driver.step(
            AdmissionOperation::Admit { task: task.clone() },
            AdmissionResult::Admitted(AdmitOutcome::New),
        );
        driver.step(
            AdmissionOperation::Enqueue { task: task.clone() },
            AdmissionResult::Enqueued,
        );
        let mut admitted = task;
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
    fn refer_already_on_chain_answers_done_retroactively() {
        let core: Core<AdmissionApp> = Core::new();
        let effects = core.process_event(AdmissionEvent::Submit {
            request: AdmissionRequest::Refer(valid_refer_request()),
            new_task_id: "task-new".into(),
            now_ms: 1_000,
            chain_id: CHAIN,
            registry: REGISTRY.into(),
        });
        let mut driver = Driver {
            core,
            queue: VecDeque::new(),
        };
        driver.absorb(effects);
        let (task, content_hash) = validated_refer();

        driver.step(
            AdmissionOperation::AllowIpCreate,
            AdmissionResult::Allowed { allowed: true },
        );
        driver.step(
            AdmissionOperation::FindTaskByContent {
                content_hash: content_hash.clone(),
            },
            AdmissionResult::TaskFound { task: None },
        );
        driver.step(
            AdmissionOperation::CheckReferenced {
                group_public_key: task.group_public_key.clone(),
                member_public_key: task.members[0].public_key.clone(),
            },
            AdmissionResult::ChainBool { value: true },
        );
        driver.assert_settled(AdmissionOutcome::AlreadyRegistered { content_hash });
    }

    /// Submit a refer and walk AllowIp + FindTaskByContent(none) +
    /// CheckReferenced(false), leaving CheckGroupExists in flight.
    fn refer_up_to_group_gate() -> (Driver, RegisterTask) {
        let core: Core<AdmissionApp> = Core::new();
        let effects = core.process_event(AdmissionEvent::Submit {
            request: AdmissionRequest::Refer(valid_refer_request()),
            new_task_id: "task-new".into(),
            now_ms: 1_000,
            chain_id: CHAIN,
            registry: REGISTRY.into(),
        });
        let mut driver = Driver {
            core,
            queue: VecDeque::new(),
        };
        driver.absorb(effects);
        let (task, content_hash) = validated_refer();
        driver.step(
            AdmissionOperation::AllowIpCreate,
            AdmissionResult::Allowed { allowed: true },
        );
        driver.step(
            AdmissionOperation::FindTaskByContent { content_hash },
            AdmissionResult::TaskFound { task: None },
        );
        driver.step(
            AdmissionOperation::CheckReferenced {
                group_public_key: task.group_public_key.clone(),
                member_public_key: task.members[0].public_key.clone(),
            },
            AdmissionResult::ChainBool { value: false },
        );
        (driver, task)
    }

    fn finish_refer_admit(driver: &mut Driver, task: &RegisterTask) {
        driver.step(
            AdmissionOperation::QueueDepth,
            AdmissionResult::Depth { depth: 0 },
        );
        driver.step(
            AdmissionOperation::AllowGlobalCreate,
            AdmissionResult::Allowed { allowed: true },
        );
        driver.step(
            AdmissionOperation::Admit { task: task.clone() },
            AdmissionResult::Admitted(AdmitOutcome::New),
        );
        driver.step(
            AdmissionOperation::Enqueue { task: task.clone() },
            AdmissionResult::Enqueued,
        );
        let mut admitted = task.clone();
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
    fn refer_to_a_missing_group_with_no_register_in_flight_is_refused() {
        let (mut driver, task) = refer_up_to_group_gate();
        driver.step(
            AdmissionOperation::CheckGroupExists {
                group_public_key: task.group_public_key.clone(),
            },
            AdmissionResult::ChainBool { value: false },
        );
        // No placeholder task holds the group key — a pure ghost.
        driver.step(
            AdmissionOperation::FindTaskByKey {
                key_hash: task.group_public_key.clone(),
            },
            AdmissionResult::TaskFound { task: None },
        );
        driver.assert_settled(AdmissionOutcome::ReferGroupMissing);
    }

    #[test]
    fn refer_racing_its_own_in_flight_register_is_admitted() {
        let (mut driver, task) = refer_up_to_group_gate();
        driver.step(
            AdmissionOperation::CheckGroupExists {
                group_public_key: task.group_public_key.clone(),
            },
            AdmissionResult::ChainBool { value: false },
        );
        // A register that creates this exact group is still in the pipeline.
        let mut register = task.clone();
        register.id = "register-in-flight".into();
        register.kind = TaskKind::Register;
        register.status = TaskStatus::Pending;
        driver.step(
            AdmissionOperation::FindTaskByKey {
                key_hash: task.group_public_key.clone(),
            },
            AdmissionResult::TaskFound {
                task: Some(register),
            },
        );
        finish_refer_admit(&mut driver, &task);
    }

    #[test]
    fn refer_to_a_missing_group_whose_register_already_finished_is_refused() {
        let (mut driver, task) = refer_up_to_group_gate();
        driver.step(
            AdmissionOperation::CheckGroupExists {
                group_public_key: task.group_public_key.clone(),
            },
            AdmissionResult::ChainBool { value: false },
        );
        // A terminal register is not "in flight": if the group is absent
        // on-chain the register did not create it (e.g. it was poisoned).
        let mut done_register = task.clone();
        done_register.id = "register-terminal".into();
        done_register.kind = TaskKind::Register;
        done_register.status = TaskStatus::Failed;
        driver.step(
            AdmissionOperation::FindTaskByKey {
                key_hash: task.group_public_key.clone(),
            },
            AdmissionResult::TaskFound {
                task: Some(done_register),
            },
        );
        driver.assert_settled(AdmissionOutcome::ReferGroupMissing);
    }

    #[test]
    fn refer_group_check_is_fail_open_on_rpc_outage() {
        let (mut driver, task) = refer_up_to_group_gate();
        // The chain read failed: admission never blocks on an RPC wobble,
        // so the refer proceeds (the worker's GroupNotFound→transient retry
        // is the backstop).
        driver.step(
            AdmissionOperation::CheckGroupExists {
                group_public_key: task.group_public_key.clone(),
            },
            AdmissionResult::ChainReadFailed,
        );
        finish_refer_admit(&mut driver, &task);
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
                request: AdmissionRequest::Register(request_body),
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

    fn expected_retry_digest() -> String {
        register_retry_digest(&expected_task())
    }

    fn walk_retry_digest_miss(driver: &mut Driver) {
        driver.step(
            AdmissionOperation::FindTaskByRetryDigest {
                digest: expected_retry_digest(),
            },
            AdmissionResult::TaskFound { task: None },
        );
    }

    fn walk_clean_prechecks(driver: &mut Driver) {
        driver.step(
            AdmissionOperation::AllowIpCreate,
            AdmissionResult::Allowed { allowed: true },
        );
        driver.step(
            AdmissionOperation::FindTaskByContent {
                content_hash: expected_content_hash(),
            },
            AdmissionResult::TaskFound { task: None },
        );
        walk_retry_digest_miss(driver);
        driver.step(
            AdmissionOperation::CheckContentRegistered {
                content_hash: expected_content_hash(),
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
            AdmissionOperation::RecordRetryDigest {
                digest: expected_retry_digest(),
                task_id: "task-new".into(),
            },
            AdmissionResult::Persisted,
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
        existing.admitted = true;
        driver.step(
            AdmissionOperation::FindTaskByContent {
                content_hash: expected_content_hash(),
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
    fn resubmission_repairs_a_stranded_unenqueued_task() {
        // An earlier submission died between Redis admit and the queue
        // append: the idempotency lookup finds the unadmitted task and
        // repairs phase two instead of reporting a task that never runs.
        let mut driver = Driver::submit(valid_request());
        driver.step(
            AdmissionOperation::AllowIpCreate,
            AdmissionResult::Allowed { allowed: true },
        );
        let mut stranded = expected_task();
        stranded.id = "earlier".into();
        stranded.admitted = false;
        driver.step(
            AdmissionOperation::FindTaskByContent {
                content_hash: expected_content_hash(),
            },
            AdmissionResult::TaskFound {
                task: Some(stranded.clone()),
            },
        );
        driver.step(
            AdmissionOperation::Enqueue {
                task: stranded.clone(),
            },
            AdmissionResult::Enqueued,
        );
        let mut admitted = stranded;
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
    fn content_already_on_chain_answers_done_retroactively() {
        let mut driver = Driver::submit(valid_request());
        driver.step(
            AdmissionOperation::AllowIpCreate,
            AdmissionResult::Allowed { allowed: true },
        );
        driver.step(
            AdmissionOperation::FindTaskByContent {
                content_hash: expected_content_hash(),
            },
            AdmissionResult::TaskFound { task: None },
        );
        walk_retry_digest_miss(&mut driver);
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
    fn chain_precheck_fails_open_to_the_gates() {
        let mut driver = Driver::submit(valid_request());
        driver.step(
            AdmissionOperation::AllowIpCreate,
            AdmissionResult::Allowed { allowed: true },
        );
        driver.step(
            AdmissionOperation::FindTaskByContent {
                content_hash: expected_content_hash(),
            },
            AdmissionResult::TaskFound { task: None },
        );
        walk_retry_digest_miss(&mut driver);
        driver.step(
            AdmissionOperation::CheckContentRegistered {
                content_hash: expected_content_hash(),
            },
            AdmissionResult::ChainReadFailed,
        );
        driver.step(
            AdmissionOperation::QueueDepth,
            AdmissionResult::Depth { depth: 0 },
        );
        // Reaching the depth gate proves the fail-open arm.
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
            AdmissionOperation::RecordRetryDigest {
                digest: expected_retry_digest(),
                task_id: "task-new".into(),
            },
            AdmissionResult::Persisted,
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

    /// The production incident: a client retry loop regenerated its
    /// single-use group key, so content idempotency missed — the retry
    /// digest (group-key-agnostic) coalesces the resubmission onto the
    /// live task instead of buying a second identical unit.
    #[test]
    fn fresh_group_key_retry_coalesces_onto_live_task() {
        let mut driver = Driver::submit(valid_request());
        driver.step(
            AdmissionOperation::AllowIpCreate,
            AdmissionResult::Allowed { allowed: true },
        );
        driver.step(
            AdmissionOperation::FindTaskByContent {
                content_hash: expected_content_hash(),
            },
            AdmissionResult::TaskFound { task: None },
        );
        let mut existing = expected_task();
        existing.id = "earlier".into();
        existing.admitted = true;
        driver.step(
            AdmissionOperation::FindTaskByRetryDigest {
                digest: expected_retry_digest(),
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

    /// A digest hit on a FAILED task must not coalesce: a fresh attempt
    /// with a fresh group key is exactly the retry that should proceed.
    #[test]
    fn retry_digest_hit_on_failed_task_does_not_coalesce() {
        let mut driver = Driver::submit(valid_request());
        driver.step(
            AdmissionOperation::AllowIpCreate,
            AdmissionResult::Allowed { allowed: true },
        );
        driver.step(
            AdmissionOperation::FindTaskByContent {
                content_hash: expected_content_hash(),
            },
            AdmissionResult::TaskFound { task: None },
        );
        let mut failed = expected_task();
        failed.id = "earlier".into();
        failed.admitted = true;
        failed.status = TaskStatus::Failed;
        driver.step(
            AdmissionOperation::FindTaskByRetryDigest {
                digest: expected_retry_digest(),
            },
            AdmissionResult::TaskFound { task: Some(failed) },
        );
        // The walk continues past the digest into a normal admission.
        driver.step(
            AdmissionOperation::CheckContentRegistered {
                content_hash: expected_content_hash(),
            },
            AdmissionResult::ChainBool { value: false },
        );
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
            AdmissionOperation::RecordRetryDigest {
                digest: expected_retry_digest(),
                task_id: "task-new".into(),
            },
            AdmissionResult::Persisted,
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
    fn retry_digest_ignores_group_key_and_member_order_but_not_metadata() {
        let base = expected_task();

        // A regenerated group key (and hence content hash) changes nothing.
        let mut rekeyed = base.clone();
        rekeyed.group_public_key = format!("{}00", rekeyed.group_public_key);
        rekeyed.content_hash = "0xrekeyed".into();
        assert_eq!(
            register_retry_digest(&base),
            register_retry_digest(&rekeyed)
        );

        // Member order is canonicalized away.
        let mut two = base.clone();
        let mut second = two.members[0].clone();
        second.public_key = format!("{}ff", second.public_key);
        two.members.push(second);
        let mut reversed = two.clone();
        reversed.members.reverse();
        assert_eq!(
            register_retry_digest(&two),
            register_retry_digest(&reversed)
        );
        assert_ne!(register_retry_digest(&base), register_retry_digest(&two));

        // Any metadata difference passes through (Vela metadata carries a
        // creation timestamp, so intentional new wallets never collide).
        let mut other_metadata = base.clone();
        other_metadata.metadata = format!("{}00", other_metadata.metadata);
        assert_ne!(
            register_retry_digest(&base),
            register_retry_digest(&other_metadata)
        );
    }
}
