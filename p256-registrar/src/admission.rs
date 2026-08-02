//! Registration admission: the decision half of the create endpoint.
//!
//! One [`AdmissionApp`] instance drives one create request from a parsed
//! [`CreateRequest`] to an [`AdmissionOutcome`]. Every rule the server's
//! `http.rs` used to interleave across ~12 awaits lives here as a pure
//! program over serializable [`AdmissionOperation`]s:
//!
//! - validation with defaults (initialCredentialId ← credentialId, metadata ←
//!   derived) and walletRef derivation/consistency;
//! - idempotent "already done" pre-checks: fresh record cache, then the
//!   chain, with chain prechecks deliberately fail-open (legacy behaviour);
//! - "a non-Failed in-flight task is a valid placeholder" — the rule finally
//!   has a named home, [`is_active_placeholder`];
//! - walletRef uniqueness across three sources (in-flight tasks, cache,
//!   chain), preserving each site's exact conflict message;
//! - write gates: active queue depth and the global create rate;
//! - the two-phase admission protocol: Redis admit (atomic three-way) →
//!   Iggy enqueue → mark admitted. A failed enqueue keeps the Redis
//!   placeholder so a retry reuses the task id — note that the operation
//!   vocabulary below contains no "delete admission" at all, so the
//!   "never roll back phase one" invariant is unrepresentable, not merely
//!   commented.
//!
//! The shell owns transport (body limits, JSON, IP extraction — the raw IP
//! never crosses into this module; the shell answers rate-limit questions
//! against its salted hash), key naming, and executes each operation against
//! Redis / the chain / Iggy. Task identity and time enter through the Submit
//! event so the program stays deterministic.

use crux_core::{App, Command, command::CommandContext, macros::effect};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::protocol::parse_b256;
use crate::task::{CreateTask, TaskStatus};
use crate::wallet::{build_wallet_ref, default_metadata};

/// New creates are rejected while the active queue is at least this deep.
pub const MAX_ACTIVE_QUEUE_DEPTH: u64 = 10_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRequest {
    pub rp_id: Option<String>,
    pub credential_id: Option<String>,
    pub wallet_ref: Option<String>,
    pub public_key: Option<String>,
    pub name: Option<String>,
    pub initial_credential_id: Option<String>,
    pub metadata: Option<String>,
}

/// "A non-Failed in-flight task is a valid placeholder." This rule used to be
/// copy-pasted five times across `http.rs`; admission uses it twice and the
/// lookup domain will adopt it for its queue-fallback checks.
pub fn is_active_placeholder(task: &CreateTask) -> bool {
    task.status != TaskStatus::Failed
}

// ── Shell protocol ─────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CacheScope {
    Record {
        rp_id: String,
        credential_id: String,
    },
    Wallet {
        wallet_ref: String,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AdmissionOperation {
    /// May this client create right now? The shell resolves this against its
    /// salted per-IP counter; the raw IP never enters the Core.
    AllowIpCreate,
    ReadCache {
        scope: CacheScope,
    },
    FetchChainRecord {
        rp_id: String,
        credential_id: String,
    },
    FetchChainRecordByWalletRef {
        wallet_ref: String,
    },
    /// Cache a record value. `best_effort` writes may fail silently (the
    /// original `let _ =` backfill); others surface a dependency error.
    StoreCache {
        scope: CacheScope,
        value: Value,
        best_effort: bool,
    },
    FindTaskByRecord {
        rp_id: String,
        credential_id: String,
    },
    FindTaskByWalletRef {
        wallet_ref: String,
    },
    QueueDepth,
    AllowGlobalCreate,
    /// Phase one: the store's atomic three-way admission.
    Admit {
        task: CreateTask,
    },
    LoadTask {
        id: String,
    },
    /// Phase two: append to the durable queue.
    Enqueue {
        task: CreateTask,
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
    WalletConflict,
}

// One result value exists per request at a time and lives microseconds;
// boxing the task-bearing variants would complicate the protocol for nothing.
#[expect(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AdmissionResult {
    Allowed {
        allowed: bool,
    },
    CacheHit {
        value: Value,
    },
    /// Negative, stale and missing cache entries are all "no usable hit" for
    /// admission purposes, exactly like the original `Ok(_) => {}` arm.
    CacheMiss,
    ChainRecord {
        value: Option<Value>,
    },
    ChainReadFailed,
    TaskFound {
        task: Option<CreateTask>,
    },
    Depth {
        depth: u64,
    },
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

/// The admission verdict. The shell renders these into the exact HTTP
/// responses the endpoint has always produced.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AdmissionOutcome {
    /// 400 with the validation message.
    Invalid { message: String },
    /// 429, fixed message.
    RateLimited,
    /// 201: the record already exists; `record` is the serialized record.
    AlreadyDone { record: Value },
    /// 202 with the task's id and current status.
    Queued { id: String, status: TaskStatus },
    /// 409 with the wallet ref and the originating site's exact message.
    WalletConflict { wallet_ref: String, message: String },
    /// 503 busy (depth or global rate gate).
    Busy,
    /// 503 retryable, naming the failed dependency ("redis" / "queue").
    DependencyUnavailable { dependency: String },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AdmissionEvent {
    /// The shell supplies task identity and wall-clock time so the program
    /// stays deterministic.
    Submit {
        request: CreateRequest,
        new_task_id: String,
        now_ms: u64,
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
            } => Command::new(|ctx| async move {
                let outcome = match drive_admission(&ctx, request, new_task_id, now_ms).await {
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
//
// `Flow` short-circuits to a terminal outcome exactly where the original
// handler returned a response. The step order matches `http.rs` line by line.

type Ctx = CommandContext<AdmissionEffect, AdmissionEvent>;
type Flow<T> = Result<T, AdmissionOutcome>;

fn redis_down() -> AdmissionOutcome {
    AdmissionOutcome::DependencyUnavailable {
        dependency: "redis".to_owned(),
    }
}

const CONFLICT_IN_FLIGHT: &str =
    "this publicKey is already being registered under a different credential (walletRef conflict)";
const CONFLICT_ON_CHAIN: &str =
    "this publicKey is already registered under a different credential (walletRef conflict)";

async fn request(ctx: &Ctx, operation: AdmissionOperation) -> AdmissionResult {
    ctx.request_from_shell(operation).await
}

async fn drive_admission(
    ctx: &Ctx,
    create: CreateRequest,
    new_task_id: String,
    now_ms: u64,
) -> Flow<AdmissionOutcome> {
    let input = match validate_create(create) {
        Ok(input) => input,
        Err(message) => return Ok(AdmissionOutcome::Invalid { message }),
    };

    match request(ctx, AdmissionOperation::AllowIpCreate).await {
        AdmissionResult::Allowed { allowed: true } => {}
        AdmissionResult::Allowed { allowed: false } => return Ok(AdmissionOutcome::RateLimited),
        _ => return Err(redis_down()),
    }

    // Idempotent pre-checks: a fresh cached record or an existing on-chain
    // record answers "done" without queueing anything.
    match request(
        ctx,
        AdmissionOperation::ReadCache {
            scope: CacheScope::Record {
                rp_id: input.rp_id.clone(),
                credential_id: input.credential_id.clone(),
            },
        },
    )
    .await
    {
        AdmissionResult::CacheHit { value } => {
            return Ok(AdmissionOutcome::AlreadyDone { record: value });
        }
        AdmissionResult::CacheMiss => {}
        _ => return Err(redis_down()),
    }
    match request(
        ctx,
        AdmissionOperation::FetchChainRecord {
            rp_id: input.rp_id.clone(),
            credential_id: input.credential_id.clone(),
        },
    )
    .await
    {
        AdmissionResult::ChainRecord { value: Some(value) } => {
            must_cache(
                ctx,
                CacheScope::Record {
                    rp_id: input.rp_id.clone(),
                    credential_id: input.credential_id.clone(),
                },
                value.clone(),
            )
            .await?;
            return Ok(AdmissionOutcome::AlreadyDone { record: value });
        }
        AdmissionResult::ChainRecord { value: None } => {}
        // Existing Deno behavior is fail-open for chain prechecks.
        AdmissionResult::ChainReadFailed => {}
        _ => return Err(redis_down()),
    }

    // In-flight placeholders and walletRef uniqueness, three sources deep.
    match request(
        ctx,
        AdmissionOperation::FindTaskByRecord {
            rp_id: input.rp_id.clone(),
            credential_id: input.credential_id.clone(),
        },
    )
    .await
    {
        AdmissionResult::TaskFound { task: Some(task) } if is_active_placeholder(&task) => {
            return Ok(AdmissionOutcome::Queued {
                id: task.id,
                status: task.status,
            });
        }
        AdmissionResult::TaskFound { .. } => {}
        _ => return Err(redis_down()),
    }
    match request(
        ctx,
        AdmissionOperation::FindTaskByWalletRef {
            wallet_ref: input.wallet_ref.clone(),
        },
    )
    .await
    {
        AdmissionResult::TaskFound { task: Some(task) }
            if is_active_placeholder(&task)
                && (task.rp_id != input.rp_id || task.credential_id != input.credential_id) =>
        {
            return Ok(AdmissionOutcome::WalletConflict {
                wallet_ref: input.wallet_ref,
                message: CONFLICT_IN_FLIGHT.to_owned(),
            });
        }
        AdmissionResult::TaskFound { .. } => {}
        _ => return Err(redis_down()),
    }
    match request(
        ctx,
        AdmissionOperation::ReadCache {
            scope: CacheScope::Wallet {
                wallet_ref: input.wallet_ref.clone(),
            },
        },
    )
    .await
    {
        AdmissionResult::CacheHit { value } => {
            if same_record(&value, &input.rp_id, &input.credential_id) {
                return Ok(AdmissionOutcome::AlreadyDone { record: value });
            }
            return Ok(AdmissionOutcome::WalletConflict {
                wallet_ref: input.wallet_ref,
                message: CONFLICT_ON_CHAIN.to_owned(),
            });
        }
        AdmissionResult::CacheMiss => {}
        _ => return Err(redis_down()),
    }
    match request(
        ctx,
        AdmissionOperation::FetchChainRecordByWalletRef {
            wallet_ref: input.wallet_ref.clone(),
        },
    )
    .await
    {
        AdmissionResult::ChainRecord { value: Some(value) } => {
            must_cache(
                ctx,
                CacheScope::Wallet {
                    wallet_ref: input.wallet_ref.clone(),
                },
                value.clone(),
            )
            .await?;
            if same_record(&value, &input.rp_id, &input.credential_id) {
                // Best-effort backfill of the record-keyed cache entry.
                let _ = request(
                    ctx,
                    AdmissionOperation::StoreCache {
                        scope: CacheScope::Record {
                            rp_id: input.rp_id.clone(),
                            credential_id: input.credential_id.clone(),
                        },
                        value: value.clone(),
                        best_effort: true,
                    },
                )
                .await;
                return Ok(AdmissionOutcome::AlreadyDone { record: value });
            }
            return Ok(AdmissionOutcome::WalletConflict {
                wallet_ref: input.wallet_ref,
                message: CONFLICT_ON_CHAIN.to_owned(),
            });
        }
        AdmissionResult::ChainRecord { value: None } => {}
        AdmissionResult::ChainReadFailed => {}
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
    let task = CreateTask {
        id: new_task_id,
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
        created_at: now_ms as i64,
        admitted: false,
    };
    match request(ctx, AdmissionOperation::Admit { task: task.clone() }).await {
        AdmissionResult::Admitted(AdmitOutcome::WalletConflict) => {
            Ok(AdmissionOutcome::WalletConflict {
                wallet_ref: task.wallet_ref,
                message: CONFLICT_IN_FLIGHT.to_owned(),
            })
        }
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
async fn enqueue(ctx: &Ctx, task: CreateTask) -> Flow<AdmissionOutcome> {
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

/// A cache write that must succeed; failure is a Redis dependency error, as
/// in the original handler.
async fn must_cache(ctx: &Ctx, scope: CacheScope, value: Value) -> Flow<()> {
    match request(
        ctx,
        AdmissionOperation::StoreCache {
            scope,
            value,
            best_effort: false,
        },
    )
    .await
    {
        AdmissionResult::Persisted => Ok(()),
        _ => Err(redis_down()),
    }
}

fn same_record(value: &Value, rp_id: &str, credential_id: &str) -> bool {
    value.get("rpId").and_then(Value::as_str) == Some(rp_id)
        && value.get("credentialId").and_then(Value::as_str) == Some(credential_id)
}

// ── Validation ─────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct ValidCreate {
    pub rp_id: String,
    pub credential_id: String,
    pub wallet_ref: String,
    pub public_key: String,
    pub name: String,
    pub initial_credential_id: String,
    pub metadata: String,
}

pub fn validate_create(request: CreateRequest) -> Result<ValidCreate, String> {
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

pub fn validate_strings(values: &[(&str, &str, usize)]) -> Result<(), String> {
    for (name, value, maximum) in values {
        if value.len() > *maximum {
            return Err(format!("{name} exceeds max length ({maximum})"));
        }
    }
    Ok(())
}

pub fn validate_wallet_ref(value: &str) -> Result<(), String> {
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

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use crux_core::{Core, Request};
    use serde_json::json;

    use super::*;

    // A valid uncompressed P-256 generator point, as used by the wallet tests.
    const KEY: &str = "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";

    // ── Test driver (same shape as commit_reveal's) ────────────────────────

    struct Driver {
        core: Core<AdmissionApp>,
        queue: VecDeque<Request<AdmissionOperation>>,
    }

    impl Driver {
        fn submit(request_body: CreateRequest) -> Self {
            let core = Core::new();
            let effects = core.process_event(AdmissionEvent::Submit {
                request: request_body,
                new_task_id: "task-new".into(),
                now_ms: 1_000,
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

    fn valid_request() -> CreateRequest {
        CreateRequest {
            rp_id: Some("example.com".into()),
            credential_id: Some("cred-1".into()),
            wallet_ref: None,
            public_key: Some(KEY.into()),
            name: Some("n".into()),
            initial_credential_id: None,
            metadata: None,
        }
    }

    fn derived_wallet_ref() -> String {
        build_wallet_ref(KEY).unwrap()
    }

    fn record_scope() -> CacheScope {
        CacheScope::Record {
            rp_id: "example.com".into(),
            credential_id: "cred-1".into(),
        }
    }

    fn wallet_scope() -> CacheScope {
        CacheScope::Wallet {
            wallet_ref: derived_wallet_ref(),
        }
    }

    fn record_value() -> Value {
        json!({ "rpId": "example.com", "credentialId": "cred-1", "name": "n" })
    }

    fn other_record_value() -> Value {
        json!({ "rpId": "other.example", "credentialId": "cred-x" })
    }

    fn in_flight(id: &str, status: TaskStatus) -> CreateTask {
        CreateTask {
            id: id.to_owned(),
            status,
            rp_id: "example.com".into(),
            credential_id: "cred-1".into(),
            wallet_ref: derived_wallet_ref(),
            public_key: KEY.into(),
            name: "n".into(),
            initial_credential_id: "cred-1".into(),
            metadata: "0x00".into(),
            tx_hash: None,
            error: None,
            retries: 0,
            created_at: 0,
            admitted: true,
        }
    }

    /// Walk the request up to (and including) the pre-checks that find
    /// nothing: rate limit ok, cache miss, chain empty, no in-flight tasks,
    /// wallet cache miss, wallet chain empty.
    fn walk_clean_prechecks(driver: &mut Driver) {
        driver.step(
            AdmissionOperation::AllowIpCreate,
            AdmissionResult::Allowed { allowed: true },
        );
        driver.step(
            AdmissionOperation::ReadCache {
                scope: record_scope(),
            },
            AdmissionResult::CacheMiss,
        );
        driver.step(
            AdmissionOperation::FetchChainRecord {
                rp_id: "example.com".into(),
                credential_id: "cred-1".into(),
            },
            AdmissionResult::ChainRecord { value: None },
        );
        driver.step(
            AdmissionOperation::FindTaskByRecord {
                rp_id: "example.com".into(),
                credential_id: "cred-1".into(),
            },
            AdmissionResult::TaskFound { task: None },
        );
        driver.step(
            AdmissionOperation::FindTaskByWalletRef {
                wallet_ref: derived_wallet_ref(),
            },
            AdmissionResult::TaskFound { task: None },
        );
        driver.step(
            AdmissionOperation::ReadCache {
                scope: wallet_scope(),
            },
            AdmissionResult::CacheMiss,
        );
        driver.step(
            AdmissionOperation::FetchChainRecordByWalletRef {
                wallet_ref: derived_wallet_ref(),
            },
            AdmissionResult::ChainRecord { value: None },
        );
    }

    fn expected_new_task() -> CreateTask {
        CreateTask {
            id: "task-new".into(),
            status: TaskStatus::Pending,
            rp_id: "example.com".into(),
            credential_id: "cred-1".into(),
            wallet_ref: derived_wallet_ref(),
            public_key: KEY.into(),
            name: "n".into(),
            initial_credential_id: "cred-1".into(),
            metadata: default_metadata(KEY).unwrap(),
            tx_hash: None,
            error: None,
            retries: 0,
            created_at: 1_000,
            admitted: false,
        }
    }

    // ── Validation ─────────────────────────────────────────────────────────

    #[test]
    fn validation_derives_wallet_ref_and_metadata() {
        let input = validate_create(valid_request()).expect("valid");
        assert_eq!(input.wallet_ref, derived_wallet_ref());
        assert_eq!(input.initial_credential_id, "cred-1");
        assert_eq!(input.metadata, default_metadata(KEY).unwrap());
    }

    #[test]
    fn validation_rejects_missing_empty_and_mismatched_inputs() {
        let missing = CreateRequest {
            rp_id: None,
            ..valid_request()
        };
        assert_eq!(
            validate_create(missing).unwrap_err(),
            "rpId, credentialId, publicKey, and name are required"
        );
        let empty = CreateRequest {
            name: Some(String::new()),
            ..valid_request()
        };
        assert_eq!(
            validate_create(empty).unwrap_err(),
            "rpId, credentialId, publicKey, and name are required"
        );
        // A 0x-prefixed key is 132 chars: the length gate fires before the
        // point check, exactly like the original ordering.
        let prefixed = CreateRequest {
            public_key: Some(format!("0x{KEY}")),
            ..valid_request()
        };
        assert_eq!(
            validate_create(prefixed).unwrap_err(),
            "publicKey exceeds max length (130)"
        );
        let not_a_point = CreateRequest {
            public_key: Some("04".repeat(65)),
            ..valid_request()
        };
        assert_eq!(
            validate_create(not_a_point).unwrap_err(),
            "publicKey must be a valid point on the P-256 curve"
        );
        let mismatched = CreateRequest {
            wallet_ref: Some(
                "0x00000000000000000000000000000000000000000000000000000000000000ff".into(),
            ),
            ..valid_request()
        };
        assert_eq!(
            validate_create(mismatched).unwrap_err(),
            "walletRef does not match publicKey"
        );
        // A supplied wallet ref matches case-insensitively.
        let uppercase = CreateRequest {
            wallet_ref: Some(derived_wallet_ref().to_uppercase().replace("0X", "0x")),
            ..valid_request()
        };
        assert!(validate_create(uppercase).is_ok());
        let odd_metadata = CreateRequest {
            metadata: Some("0x123".into()),
            ..valid_request()
        };
        assert_eq!(
            validate_create(odd_metadata).unwrap_err(),
            "metadata must be byte-aligned hex (even number of hex chars)"
        );
    }

    #[test]
    fn invalid_request_settles_without_any_operation() {
        let driver = Driver::submit(CreateRequest {
            rp_id: None,
            ..valid_request()
        });
        driver.assert_settled(AdmissionOutcome::Invalid {
            message: "rpId, credentialId, publicKey, and name are required".into(),
        });
    }

    // ── Gates and pre-checks ───────────────────────────────────────────────

    #[test]
    fn ip_rate_limit_rejects_before_any_other_io() {
        let mut driver = Driver::submit(valid_request());
        driver.step(
            AdmissionOperation::AllowIpCreate,
            AdmissionResult::Allowed { allowed: false },
        );
        driver.assert_settled(AdmissionOutcome::RateLimited);
    }

    #[test]
    fn rate_limit_store_failure_is_a_redis_dependency_error() {
        let mut driver = Driver::submit(valid_request());
        driver.step(
            AdmissionOperation::AllowIpCreate,
            AdmissionResult::StoreUnavailable,
        );
        driver.assert_settled(AdmissionOutcome::DependencyUnavailable {
            dependency: "redis".into(),
        });
    }

    #[test]
    fn fresh_record_cache_answers_done_immediately() {
        let mut driver = Driver::submit(valid_request());
        driver.step(
            AdmissionOperation::AllowIpCreate,
            AdmissionResult::Allowed { allowed: true },
        );
        driver.step(
            AdmissionOperation::ReadCache {
                scope: record_scope(),
            },
            AdmissionResult::CacheHit {
                value: record_value(),
            },
        );
        driver.assert_settled(AdmissionOutcome::AlreadyDone {
            record: record_value(),
        });
    }

    #[test]
    fn chain_record_hit_backfills_cache_then_answers_done() {
        let mut driver = Driver::submit(valid_request());
        driver.step(
            AdmissionOperation::AllowIpCreate,
            AdmissionResult::Allowed { allowed: true },
        );
        driver.step(
            AdmissionOperation::ReadCache {
                scope: record_scope(),
            },
            AdmissionResult::CacheMiss,
        );
        driver.step(
            AdmissionOperation::FetchChainRecord {
                rp_id: "example.com".into(),
                credential_id: "cred-1".into(),
            },
            AdmissionResult::ChainRecord {
                value: Some(record_value()),
            },
        );
        // This cache write must succeed (not best-effort).
        driver.step(
            AdmissionOperation::StoreCache {
                scope: record_scope(),
                value: record_value(),
                best_effort: false,
            },
            AdmissionResult::Persisted,
        );
        driver.assert_settled(AdmissionOutcome::AlreadyDone {
            record: record_value(),
        });
    }

    #[test]
    fn record_cache_write_failure_is_a_dependency_error() {
        let mut driver = Driver::submit(valid_request());
        driver.step(
            AdmissionOperation::AllowIpCreate,
            AdmissionResult::Allowed { allowed: true },
        );
        driver.step(
            AdmissionOperation::ReadCache {
                scope: record_scope(),
            },
            AdmissionResult::CacheMiss,
        );
        driver.step(
            AdmissionOperation::FetchChainRecord {
                rp_id: "example.com".into(),
                credential_id: "cred-1".into(),
            },
            AdmissionResult::ChainRecord {
                value: Some(record_value()),
            },
        );
        driver.step(
            AdmissionOperation::StoreCache {
                scope: record_scope(),
                value: record_value(),
                best_effort: false,
            },
            AdmissionResult::StoreUnavailable,
        );
        driver.assert_settled(AdmissionOutcome::DependencyUnavailable {
            dependency: "redis".into(),
        });
    }

    #[test]
    fn in_flight_placeholder_returns_its_id_as_queued() {
        let mut driver = Driver::submit(valid_request());
        driver.step(
            AdmissionOperation::AllowIpCreate,
            AdmissionResult::Allowed { allowed: true },
        );
        driver.step(
            AdmissionOperation::ReadCache {
                scope: record_scope(),
            },
            AdmissionResult::CacheMiss,
        );
        driver.step(
            AdmissionOperation::FetchChainRecord {
                rp_id: "example.com".into(),
                credential_id: "cred-1".into(),
            },
            AdmissionResult::ChainRecord { value: None },
        );
        driver.step(
            AdmissionOperation::FindTaskByRecord {
                rp_id: "example.com".into(),
                credential_id: "cred-1".into(),
            },
            AdmissionResult::TaskFound {
                task: Some(in_flight("existing", TaskStatus::Committed)),
            },
        );
        driver.assert_settled(AdmissionOutcome::Queued {
            id: "existing".into(),
            status: TaskStatus::Committed,
        });
    }

    #[test]
    fn failed_in_flight_task_is_not_a_placeholder() {
        // A Failed task must not block re-registration: the flow continues
        // past both task lookups.
        let mut driver = Driver::submit(valid_request());
        driver.step(
            AdmissionOperation::AllowIpCreate,
            AdmissionResult::Allowed { allowed: true },
        );
        driver.step(
            AdmissionOperation::ReadCache {
                scope: record_scope(),
            },
            AdmissionResult::CacheMiss,
        );
        driver.step(
            AdmissionOperation::FetchChainRecord {
                rp_id: "example.com".into(),
                credential_id: "cred-1".into(),
            },
            AdmissionResult::ChainRecord { value: None },
        );
        driver.step(
            AdmissionOperation::FindTaskByRecord {
                rp_id: "example.com".into(),
                credential_id: "cred-1".into(),
            },
            AdmissionResult::TaskFound {
                task: Some(in_flight("failed", TaskStatus::Failed)),
            },
        );
        // Continues to the wallet lookup instead of returning Queued.
        driver.step(
            AdmissionOperation::FindTaskByWalletRef {
                wallet_ref: derived_wallet_ref(),
            },
            AdmissionResult::TaskFound { task: None },
        );
        driver.step(
            AdmissionOperation::ReadCache {
                scope: wallet_scope(),
            },
            AdmissionResult::CacheMiss,
        );
        driver.step(
            AdmissionOperation::FetchChainRecordByWalletRef {
                wallet_ref: derived_wallet_ref(),
            },
            AdmissionResult::ChainRecord { value: None },
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
                task: expected_new_task(),
            },
            AdmissionResult::Admitted(AdmitOutcome::New),
        );
        driver.step(
            AdmissionOperation::Enqueue {
                task: expected_new_task(),
            },
            AdmissionResult::Enqueued,
        );
        let mut admitted = expected_new_task();
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
    fn wallet_task_conflict_uses_the_in_flight_message() {
        let mut driver = Driver::submit(valid_request());
        driver.step(
            AdmissionOperation::AllowIpCreate,
            AdmissionResult::Allowed { allowed: true },
        );
        driver.step(
            AdmissionOperation::ReadCache {
                scope: record_scope(),
            },
            AdmissionResult::CacheMiss,
        );
        driver.step(
            AdmissionOperation::FetchChainRecord {
                rp_id: "example.com".into(),
                credential_id: "cred-1".into(),
            },
            AdmissionResult::ChainRecord { value: None },
        );
        driver.step(
            AdmissionOperation::FindTaskByRecord {
                rp_id: "example.com".into(),
                credential_id: "cred-1".into(),
            },
            AdmissionResult::TaskFound { task: None },
        );
        let mut other = in_flight("other", TaskStatus::Pending);
        other.credential_id = "cred-other".into();
        driver.step(
            AdmissionOperation::FindTaskByWalletRef {
                wallet_ref: derived_wallet_ref(),
            },
            AdmissionResult::TaskFound { task: Some(other) },
        );
        driver.assert_settled(AdmissionOutcome::WalletConflict {
            wallet_ref: derived_wallet_ref(),
            message: CONFLICT_IN_FLIGHT.into(),
        });
    }

    #[test]
    fn wallet_task_for_the_same_credential_is_not_a_conflict() {
        // Same rp_id + credential_id under the wallet index: fall through.
        let mut driver = Driver::submit(valid_request());
        driver.step(
            AdmissionOperation::AllowIpCreate,
            AdmissionResult::Allowed { allowed: true },
        );
        driver.step(
            AdmissionOperation::ReadCache {
                scope: record_scope(),
            },
            AdmissionResult::CacheMiss,
        );
        driver.step(
            AdmissionOperation::FetchChainRecord {
                rp_id: "example.com".into(),
                credential_id: "cred-1".into(),
            },
            AdmissionResult::ChainRecord { value: None },
        );
        driver.step(
            AdmissionOperation::FindTaskByRecord {
                rp_id: "example.com".into(),
                credential_id: "cred-1".into(),
            },
            AdmissionResult::TaskFound { task: None },
        );
        driver.step(
            AdmissionOperation::FindTaskByWalletRef {
                wallet_ref: derived_wallet_ref(),
            },
            AdmissionResult::TaskFound {
                task: Some(in_flight("same", TaskStatus::Pending)),
            },
        );
        driver.step(
            AdmissionOperation::ReadCache {
                scope: wallet_scope(),
            },
            AdmissionResult::CacheMiss,
        );
        // Reaching the wallet-cache read proves the conflict arm was skipped.
    }

    #[test]
    fn wallet_cache_hit_splits_on_same_record() {
        let mut driver = Driver::submit(valid_request());
        driver.step(
            AdmissionOperation::AllowIpCreate,
            AdmissionResult::Allowed { allowed: true },
        );
        driver.step(
            AdmissionOperation::ReadCache {
                scope: record_scope(),
            },
            AdmissionResult::CacheMiss,
        );
        driver.step(
            AdmissionOperation::FetchChainRecord {
                rp_id: "example.com".into(),
                credential_id: "cred-1".into(),
            },
            AdmissionResult::ChainRecord { value: None },
        );
        driver.step(
            AdmissionOperation::FindTaskByRecord {
                rp_id: "example.com".into(),
                credential_id: "cred-1".into(),
            },
            AdmissionResult::TaskFound { task: None },
        );
        driver.step(
            AdmissionOperation::FindTaskByWalletRef {
                wallet_ref: derived_wallet_ref(),
            },
            AdmissionResult::TaskFound { task: None },
        );
        driver.step(
            AdmissionOperation::ReadCache {
                scope: wallet_scope(),
            },
            AdmissionResult::CacheHit {
                value: other_record_value(),
            },
        );
        driver.assert_settled(AdmissionOutcome::WalletConflict {
            wallet_ref: derived_wallet_ref(),
            message: CONFLICT_ON_CHAIN.into(),
        });
    }

    #[test]
    fn wallet_chain_hit_same_record_backfills_best_effort_and_answers_done() {
        let mut driver = Driver::submit(valid_request());
        driver.step(
            AdmissionOperation::AllowIpCreate,
            AdmissionResult::Allowed { allowed: true },
        );
        driver.step(
            AdmissionOperation::ReadCache {
                scope: record_scope(),
            },
            AdmissionResult::CacheMiss,
        );
        driver.step(
            AdmissionOperation::FetchChainRecord {
                rp_id: "example.com".into(),
                credential_id: "cred-1".into(),
            },
            AdmissionResult::ChainRecord { value: None },
        );
        driver.step(
            AdmissionOperation::FindTaskByRecord {
                rp_id: "example.com".into(),
                credential_id: "cred-1".into(),
            },
            AdmissionResult::TaskFound { task: None },
        );
        driver.step(
            AdmissionOperation::FindTaskByWalletRef {
                wallet_ref: derived_wallet_ref(),
            },
            AdmissionResult::TaskFound { task: None },
        );
        driver.step(
            AdmissionOperation::ReadCache {
                scope: wallet_scope(),
            },
            AdmissionResult::CacheMiss,
        );
        driver.step(
            AdmissionOperation::FetchChainRecordByWalletRef {
                wallet_ref: derived_wallet_ref(),
            },
            AdmissionResult::ChainRecord {
                value: Some(record_value()),
            },
        );
        // The wallet-cache write must succeed…
        driver.step(
            AdmissionOperation::StoreCache {
                scope: wallet_scope(),
                value: record_value(),
                best_effort: false,
            },
            AdmissionResult::Persisted,
        );
        // …while the record-cache backfill is best-effort: its failure must
        // not change the outcome.
        driver.step(
            AdmissionOperation::StoreCache {
                scope: record_scope(),
                value: record_value(),
                best_effort: true,
            },
            AdmissionResult::StoreUnavailable,
        );
        driver.assert_settled(AdmissionOutcome::AlreadyDone {
            record: record_value(),
        });
    }

    #[test]
    fn chain_prechecks_fail_open_all_the_way_to_admission() {
        // Both chain prechecks fail; the request still reaches the gates.
        let mut driver = Driver::submit(valid_request());
        driver.step(
            AdmissionOperation::AllowIpCreate,
            AdmissionResult::Allowed { allowed: true },
        );
        driver.step(
            AdmissionOperation::ReadCache {
                scope: record_scope(),
            },
            AdmissionResult::CacheMiss,
        );
        driver.step(
            AdmissionOperation::FetchChainRecord {
                rp_id: "example.com".into(),
                credential_id: "cred-1".into(),
            },
            AdmissionResult::ChainReadFailed,
        );
        driver.step(
            AdmissionOperation::FindTaskByRecord {
                rp_id: "example.com".into(),
                credential_id: "cred-1".into(),
            },
            AdmissionResult::TaskFound { task: None },
        );
        driver.step(
            AdmissionOperation::FindTaskByWalletRef {
                wallet_ref: derived_wallet_ref(),
            },
            AdmissionResult::TaskFound { task: None },
        );
        driver.step(
            AdmissionOperation::ReadCache {
                scope: wallet_scope(),
            },
            AdmissionResult::CacheMiss,
        );
        driver.step(
            AdmissionOperation::FetchChainRecordByWalletRef {
                wallet_ref: derived_wallet_ref(),
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
    fn queue_depth_below_the_limit_passes() {
        let mut driver = Driver::submit(valid_request());
        walk_clean_prechecks(&mut driver);
        driver.step(
            AdmissionOperation::QueueDepth,
            AdmissionResult::Depth {
                depth: MAX_ACTIVE_QUEUE_DEPTH - 1,
            },
        );
        driver.step(
            AdmissionOperation::AllowGlobalCreate,
            AdmissionResult::Allowed { allowed: false },
        );
        driver.assert_settled(AdmissionOutcome::Busy);
    }

    // ── Two-phase admission ────────────────────────────────────────────────

    #[test]
    fn new_admission_enqueues_marks_and_returns_queued() {
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
        // The task the Core builds is fully pinned: shell-supplied id and
        // time, derived wallet ref and metadata, admitted=false.
        driver.step(
            AdmissionOperation::Admit {
                task: expected_new_task(),
            },
            AdmissionResult::Admitted(AdmitOutcome::New),
        );
        driver.step(
            AdmissionOperation::Enqueue {
                task: expected_new_task(),
            },
            AdmissionResult::Enqueued,
        );
        let mut admitted = expected_new_task();
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
    fn enqueue_failure_keeps_the_admission_and_reports_the_queue() {
        // Phase two fails: the outcome names the queue, and no operation to
        // delete the Redis admission is ever issued (none exists).
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
                task: expected_new_task(),
            },
            AdmissionResult::Admitted(AdmitOutcome::New),
        );
        driver.step(
            AdmissionOperation::Enqueue {
                task: expected_new_task(),
            },
            AdmissionResult::QueueUnavailable,
        );
        driver.assert_settled(AdmissionOutcome::DependencyUnavailable {
            dependency: "queue".into(),
        });
    }

    #[test]
    fn existing_admitted_task_returns_queued_without_re_enqueueing() {
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
                task: expected_new_task(),
            },
            AdmissionResult::Admitted(AdmitOutcome::Existing {
                id: "earlier".into(),
            }),
        );
        driver.step(
            AdmissionOperation::LoadTask {
                id: "earlier".into(),
            },
            AdmissionResult::TaskFound {
                task: Some(in_flight("earlier", TaskStatus::Pending)),
            },
        );
        driver.assert_settled(AdmissionOutcome::Queued {
            id: "earlier".into(),
            status: TaskStatus::Pending,
        });
    }

    #[test]
    fn existing_unadmitted_task_repairs_phase_two() {
        // The earlier request lost its enqueue: this request re-enqueues the
        // same task id and completes the mark, never creating a second task.
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
                task: expected_new_task(),
            },
            AdmissionResult::Admitted(AdmitOutcome::Existing {
                id: "earlier".into(),
            }),
        );
        let mut unadmitted = in_flight("earlier", TaskStatus::Pending);
        unadmitted.admitted = false;
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
        let mut repaired = unadmitted;
        repaired.admitted = true;
        driver.step(
            AdmissionOperation::MarkAdmitted {
                id: "earlier".into(),
            },
            AdmissionResult::TaskFound {
                task: Some(repaired),
            },
        );
        driver.assert_settled(AdmissionOutcome::Queued {
            id: "earlier".into(),
            status: TaskStatus::Pending,
        });
    }

    #[test]
    fn admission_wallet_conflict_uses_the_in_flight_message() {
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
                task: expected_new_task(),
            },
            AdmissionResult::Admitted(AdmitOutcome::WalletConflict),
        );
        driver.assert_settled(AdmissionOutcome::WalletConflict {
            wallet_ref: derived_wallet_ref(),
            message: CONFLICT_IN_FLIGHT.into(),
        });
    }

    #[test]
    fn mark_admitted_losing_the_task_is_a_redis_dependency_error() {
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
                task: expected_new_task(),
            },
            AdmissionResult::Admitted(AdmitOutcome::New),
        );
        driver.step(
            AdmissionOperation::Enqueue {
                task: expected_new_task(),
            },
            AdmissionResult::Enqueued,
        );
        driver.step(
            AdmissionOperation::MarkAdmitted {
                id: "task-new".into(),
            },
            AdmissionResult::TaskFound { task: None },
        );
        driver.assert_settled(AdmissionOutcome::DependencyUnavailable {
            dependency: "redis".into(),
        });
    }

    // ── Mutation-killing coverage ──────────────────────────────────────────
    //
    // Each test below pins a branch a mutation-testing pass found unguarded.

    #[test]
    fn conflict_messages_are_pinned_literally() {
        // The two 409 messages are a published API surface; the scenario
        // tests assert which constant each site uses, this one asserts what
        // the constants actually say.
        assert_eq!(
            CONFLICT_IN_FLIGHT,
            "this publicKey is already being registered under a different credential (walletRef conflict)"
        );
        assert_eq!(
            CONFLICT_ON_CHAIN,
            "this publicKey is already registered under a different credential (walletRef conflict)"
        );
    }

    #[test]
    fn same_rp_with_other_credential_is_still_a_wallet_conflict() {
        // same_record must compare BOTH fields: a record under the same rpId
        // but another credential is a conflict, not an AlreadyDone.
        let mut driver = Driver::submit(valid_request());
        driver.step(
            AdmissionOperation::AllowIpCreate,
            AdmissionResult::Allowed { allowed: true },
        );
        driver.step(
            AdmissionOperation::ReadCache {
                scope: record_scope(),
            },
            AdmissionResult::CacheMiss,
        );
        driver.step(
            AdmissionOperation::FetchChainRecord {
                rp_id: "example.com".into(),
                credential_id: "cred-1".into(),
            },
            AdmissionResult::ChainRecord { value: None },
        );
        driver.step(
            AdmissionOperation::FindTaskByRecord {
                rp_id: "example.com".into(),
                credential_id: "cred-1".into(),
            },
            AdmissionResult::TaskFound { task: None },
        );
        driver.step(
            AdmissionOperation::FindTaskByWalletRef {
                wallet_ref: derived_wallet_ref(),
            },
            AdmissionResult::TaskFound { task: None },
        );
        driver.step(
            AdmissionOperation::ReadCache {
                scope: wallet_scope(),
            },
            AdmissionResult::CacheHit {
                value: json!({ "rpId": "example.com", "credentialId": "cred-x" }),
            },
        );
        driver.assert_settled(AdmissionOutcome::WalletConflict {
            wallet_ref: derived_wallet_ref(),
            message: CONFLICT_ON_CHAIN.into(),
        });
    }

    #[test]
    fn existing_task_vanishing_before_load_is_a_redis_dependency_error() {
        // Admit said Existing but the task cannot be loaded (expiry race):
        // the request must fail retryably, never mint a second task id.
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
                task: expected_new_task(),
            },
            AdmissionResult::Admitted(AdmitOutcome::Existing {
                id: "earlier".into(),
            }),
        );
        driver.step(
            AdmissionOperation::LoadTask {
                id: "earlier".into(),
            },
            AdmissionResult::TaskFound { task: None },
        );
        driver.assert_settled(AdmissionOutcome::DependencyUnavailable {
            dependency: "redis".into(),
        });
    }

    #[test]
    fn length_gate_fires_before_the_point_check_for_doubly_invalid_keys() {
        // 140 hex chars fail both the length gate (140 > 130) and the P-256
        // point check; the reported message must be the length one, pinning
        // the validation order.
        let doubly_invalid = CreateRequest {
            public_key: Some("ab".repeat(70)),
            ..valid_request()
        };
        assert_eq!(
            validate_create(doubly_invalid).unwrap_err(),
            "publicKey exceeds max length (130)"
        );
    }

    #[test]
    fn failed_task_at_the_wallet_index_is_not_a_placeholder_either() {
        // The is_active_placeholder guard applies at BOTH task lookups: a
        // Failed task under another credential must not 409 the request.
        let mut driver = Driver::submit(valid_request());
        driver.step(
            AdmissionOperation::AllowIpCreate,
            AdmissionResult::Allowed { allowed: true },
        );
        driver.step(
            AdmissionOperation::ReadCache {
                scope: record_scope(),
            },
            AdmissionResult::CacheMiss,
        );
        driver.step(
            AdmissionOperation::FetchChainRecord {
                rp_id: "example.com".into(),
                credential_id: "cred-1".into(),
            },
            AdmissionResult::ChainRecord { value: None },
        );
        driver.step(
            AdmissionOperation::FindTaskByRecord {
                rp_id: "example.com".into(),
                credential_id: "cred-1".into(),
            },
            AdmissionResult::TaskFound { task: None },
        );
        let mut failed_other = in_flight("failed-other", TaskStatus::Failed);
        failed_other.credential_id = "cred-other".into();
        driver.step(
            AdmissionOperation::FindTaskByWalletRef {
                wallet_ref: derived_wallet_ref(),
            },
            AdmissionResult::TaskFound {
                task: Some(failed_other),
            },
        );
        // Reaching the wallet-cache read proves the conflict arm was skipped.
        driver.step(
            AdmissionOperation::ReadCache {
                scope: wallet_scope(),
            },
            AdmissionResult::CacheMiss,
        );
    }

    #[test]
    fn queued_status_echoes_the_marked_task_not_a_constant() {
        // If the consumer already advanced the task between enqueue and
        // mark_admitted, the 202 must echo the real status.
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
                task: expected_new_task(),
            },
            AdmissionResult::Admitted(AdmitOutcome::New),
        );
        driver.step(
            AdmissionOperation::Enqueue {
                task: expected_new_task(),
            },
            AdmissionResult::Enqueued,
        );
        let mut advanced = expected_new_task();
        advanced.admitted = true;
        advanced.status = TaskStatus::Committed;
        driver.step(
            AdmissionOperation::MarkAdmitted {
                id: "task-new".into(),
            },
            AdmissionResult::TaskFound {
                task: Some(advanced),
            },
        );
        driver.assert_settled(AdmissionOutcome::Queued {
            id: "task-new".into(),
            status: TaskStatus::Committed,
        });
    }
}
