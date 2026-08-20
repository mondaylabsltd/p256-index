//! The submission task lifecycle: the decision half of the queue worker.
//!
//! One [`SubmissionApp`] instance drives one polled batch of queue envelopes
//! from "ids arrived" to a [`BatchVerdict`]: advance the consumer offset, or
//! retry the whole batch without advancing. The rules:
//!
//! - the queue message is only an envelope; the store record is
//!   authoritative, and terminal tasks are skipped;
//! - reconciliation first: a unit whose content hash is already on-chain
//!   marks its task done and is never re-sent ("见链即完成") — this also
//!   absorbs lost receipts and producer duplicates;
//! - ONE UNIT, ONE TRANSACTION: each task gets its own `register` tx, so a
//!   failure attributes directly to its task. A reverted receipt carries no
//!   reason, so the task reconciles then resends ONCE — the resend's gas
//!   estimation surfaces the actual revert for classification;
//! - chain-write errors classify via [`classify_chain_error`]:
//!   content-registered → done, nonce-used → reconcile then terminal
//!   CONFLICT (the proofs died with the nonce), transient → retry counter,
//!   else POISON;
//! - any transient condition settles the batch as Retry so the shell does
//!   not advance the consumer offset.
//!
//! The shell executes operations sequentially (the program awaits each one),
//! owns nonce management, the pending-tx ledger and receipt waiting, and maps
//! their outcomes into [`TxOutcome`] — including parsing the confirmed
//! receipt's UnitRegistered log for the unit's first entry id.

use crux_core::{App, Command, command::CommandContext, macros::effect};
use serde::{Deserialize, Serialize};

use crate::protocol::{
    ChainError, ErrorClass, classify_chain_error, content_hash_for, is_transient,
};
use crate::task::RegisterTask;

// ── Shell protocol ─────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SubmissionOperation {
    /// Load the authoritative task records for a list of envelope ids.
    LoadTasks {
        ids: Vec<String>,
    },
    /// isContentRegistered(contentHash) on the registry.
    CheckContentRegistered {
        content_hash: String,
    },
    /// One register() transaction: send + receipt wait + nonce/ledger
    /// bookkeeping happen shell-side; the outcome comes back as [`TxOutcome`].
    SubmitRegister {
        task: RegisterTask,
    },
    MarkDone {
        task_id: String,
        tx_hash: Option<String>,
        first_entry_id: Option<u64>,
    },
    MarkFailed {
        task_id: String,
        kind: FailureKind,
        message: String,
    },
    RecordTransientFailure {
        task_id: String,
        message: String,
    },
}

impl crux_core::capability::Operation for SubmissionOperation {
    type Output = SubmissionResult;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    Poison,
    Conflict,
}

impl FailureKind {
    /// The store's failure-class prefix.
    pub fn as_store_class(&self) -> &'static str {
        match self {
            Self::Poison => "POISON",
            Self::Conflict => "CONFLICT",
        }
    }
}

/// How a chain write ended, as observed by the shell.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TxOutcome {
    Confirmed {
        tx_hash: String,
        /// Parsed from the receipt's UnitRegistered log when present.
        first_entry_id: Option<u64>,
    },
    Reverted {
        tx_hash: String,
    },
    /// The tx was broadcast but its receipt never became definite (timeout or
    /// RPC failure). The shell keeps the ledger row for the unstick sweep.
    ReceiptUncertain {
        error: ChainError,
    },
    SendFailed {
        error: ChainError,
    },
    /// The shell could not obtain a nonce; nothing was broadcast.
    NoncePoolUnavailable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SubmissionResult {
    TasksLoaded { tasks: Vec<Option<RegisterTask>> },
    ContentChecked { registered: bool },
    Tx(TxOutcome),
    Persisted,
    StoreUnavailable,
    ChainReadFailed,
}

#[effect]
pub enum SubmissionEffect {
    Work(SubmissionOperation),
}

// ── App ────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BatchVerdict {
    /// Every task settled; the shell may advance the consumer offset.
    Advance,
    /// A transient condition was hit; do not advance the offset, retry the
    /// batch after backoff.
    Retry { reason: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SubmissionEvent {
    Start { envelope_ids: Vec<String> },
    Settled(BatchVerdict),
}

#[derive(Default)]
pub struct SubmissionModel {
    outcome: Option<BatchVerdict>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmissionViewModel {
    pub outcome: Option<BatchVerdict>,
}

#[derive(Default)]
pub struct SubmissionApp;

impl App for SubmissionApp {
    type Event = SubmissionEvent;
    type Model = SubmissionModel;
    type ViewModel = SubmissionViewModel;
    type Effect = SubmissionEffect;

    fn update(
        &self,
        event: Self::Event,
        model: &mut Self::Model,
    ) -> Command<Self::Effect, Self::Event> {
        match event {
            SubmissionEvent::Start { envelope_ids } => Command::new(|ctx| async move {
                let verdict = match drive_batch(&ctx, envelope_ids).await {
                    Ok(verdict) | Err(verdict) => verdict,
                };
                ctx.send_event(SubmissionEvent::Settled(verdict));
            }),
            SubmissionEvent::Settled(verdict) => {
                model.outcome = Some(verdict);
                Command::done()
            }
        }
    }

    fn view(&self, model: &Self::Model) -> Self::ViewModel {
        SubmissionViewModel {
            outcome: model.outcome.clone(),
        }
    }
}

// ── The batch program ──────────────────────────────────────────────────────

type Ctx = CommandContext<SubmissionEffect, SubmissionEvent>;
type Flow<T> = Result<T, BatchVerdict>;

fn retry(reason: &str) -> BatchVerdict {
    BatchVerdict::Retry {
        reason: reason.to_owned(),
    }
}

async fn request(ctx: &Ctx, operation: SubmissionOperation) -> SubmissionResult {
    ctx.request_from_shell(operation).await
}

/// Issue a persistence operation; a store failure settles the batch with the
/// call site's reason.
async fn persist(ctx: &Ctx, operation: SubmissionOperation, fail_reason: &str) -> Flow<()> {
    match request(ctx, operation).await {
        SubmissionResult::Persisted => Ok(()),
        SubmissionResult::StoreUnavailable => Err(retry(fail_reason)),
        _ => Err(retry("unexpected shell result for a persistence operation")),
    }
}

async fn drive_batch(ctx: &Ctx, envelope_ids: Vec<String>) -> Flow<BatchVerdict> {
    if envelope_ids.is_empty() {
        return Ok(BatchVerdict::Advance);
    }

    // The queue message is only an envelope: load the authoritative records,
    // drop terminal and unknown tasks, process each id at most once.
    let loaded = match request(
        ctx,
        SubmissionOperation::LoadTasks {
            ids: envelope_ids.clone(),
        },
    )
    .await
    {
        SubmissionResult::TasksLoaded { tasks } => tasks,
        SubmissionResult::StoreUnavailable => {
            return Err(retry("could not load Redis register task"));
        }
        _ => return Err(retry("unexpected shell result for LoadTasks")),
    };
    let mut canonical: Vec<RegisterTask> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for task in loaded.into_iter().flatten() {
        if !task.status.is_terminal() && seen.insert(task.id.clone()) {
            canonical.push(task);
        }
    }

    for task in canonical {
        // Reconciliation first: content already on-chain is retroactive
        // success (covers lost receipts and producer duplicates).
        match check_content(ctx, &task).await? {
            ContentState::Registered => {
                mark_done(ctx, &task, task.tx_hash.clone(), None).await?;
                continue;
            }
            ContentState::Absent => {}
            ContentState::Unencodable => {
                persist(
                    ctx,
                    SubmissionOperation::MarkFailed {
                        task_id: task.id.clone(),
                        kind: FailureKind::Poison,
                        message: "stored register task cannot be encoded".to_owned(),
                    },
                    "could not persist poison task",
                )
                .await?;
                continue;
            }
        }
        submit_stage(ctx, &task).await?;
    }
    Ok(BatchVerdict::Advance)
}

enum ContentState {
    Registered,
    Absent,
    Unencodable,
}

/// isContentRegistered with the worker's failure handling: a read failure
/// records a transient retry on the task, then fails the whole batch.
async fn check_content(ctx: &Ctx, task: &RegisterTask) -> Flow<ContentState> {
    let Ok(content_hash) = content_hash_for(task) else {
        return Ok(ContentState::Unencodable);
    };
    match request(
        ctx,
        SubmissionOperation::CheckContentRegistered {
            content_hash: format!("{content_hash:#x}"),
        },
    )
    .await
    {
        SubmissionResult::ContentChecked { registered: true } => Ok(ContentState::Registered),
        SubmissionResult::ContentChecked { registered: false } => Ok(ContentState::Absent),
        SubmissionResult::ChainReadFailed => {
            persist(
                ctx,
                SubmissionOperation::RecordTransientFailure {
                    task_id: task.id.clone(),
                    message: "isContentRegistered RPC temporarily unavailable".to_owned(),
                },
                "could not persist task retry",
            )
            .await?;
            Err(retry("chain reconciliation failed"))
        }
        _ => Err(retry("unexpected shell result for CheckContentRegistered")),
    }
}

async fn mark_done(
    ctx: &Ctx,
    task: &RegisterTask,
    tx_hash: Option<String>,
    first_entry_id: Option<u64>,
) -> Flow<()> {
    persist(
        ctx,
        SubmissionOperation::MarkDone {
            task_id: task.id.clone(),
            tx_hash,
            first_entry_id,
        },
        "could not persist done task",
    )
    .await
}

async fn submit(ctx: &Ctx, task: &RegisterTask) -> Flow<TxOutcome> {
    match request(
        ctx,
        SubmissionOperation::SubmitRegister { task: task.clone() },
    )
    .await
    {
        SubmissionResult::Tx(outcome) => match outcome {
            TxOutcome::NoncePoolUnavailable => Err(retry("could not acquire pending chain nonce")),
            other => Ok(other),
        },
        _ => Err(retry("unexpected shell result for a chain write")),
    }
}

/// One register transaction for one task, with the revert-recovery resend.
async fn submit_stage(ctx: &Ctx, task: &RegisterTask) -> Flow<()> {
    match submit(ctx, task).await? {
        TxOutcome::Confirmed {
            tx_hash,
            first_entry_id,
        } => mark_done(ctx, task, Some(tx_hash), first_entry_id).await,
        TxOutcome::Reverted { .. } => register_reverted(ctx, task).await,
        TxOutcome::ReceiptUncertain { error } => {
            classify_task(ctx, task, &error).await?;
            Err(retry("register receipt wait failed"))
        }
        TxOutcome::SendFailed { error } => {
            classify_task(ctx, task, &error).await?;
            if is_transient(&error) {
                return Err(retry("register temporarily failed"));
            }
            Ok(())
        }
        TxOutcome::NoncePoolUnavailable => unreachable!("filtered by submit"),
    }
}

/// The register reverted on-chain: a revert receipt carries no reason, so
/// reconcile (the unit may have landed in a race) and resend ONCE — the
/// resend's gas estimation surfaces the actual revert for classification.
async fn register_reverted(ctx: &Ctx, task: &RegisterTask) -> Flow<()> {
    match check_content(ctx, task).await? {
        ContentState::Registered => return mark_done(ctx, task, task.tx_hash.clone(), None).await,
        ContentState::Absent => {}
        ContentState::Unencodable => unreachable!("encodability was checked before submitting"),
    }
    match submit(ctx, task).await? {
        TxOutcome::Confirmed {
            tx_hash,
            first_entry_id,
        } => mark_done(ctx, task, Some(tx_hash), first_entry_id).await,
        TxOutcome::Reverted { .. } => {
            persist(
                ctx,
                SubmissionOperation::MarkFailed {
                    task_id: task.id.clone(),
                    kind: FailureKind::Poison,
                    message: "register transaction reverted".to_owned(),
                },
                "could not persist failed task",
            )
            .await
        }
        TxOutcome::ReceiptUncertain { error } => {
            classify_task(ctx, task, &error).await?;
            Err(retry("register receipt wait failed"))
        }
        TxOutcome::SendFailed { error } => {
            classify_task(ctx, task, &error).await?;
            if is_transient(&error) {
                return Err(retry("register temporarily failed"));
            }
            Ok(())
        }
        TxOutcome::NoncePoolUnavailable => unreachable!("filtered by submit"),
    }
}

/// Classify a failed chain write for one task. Message formatting uses the
/// error's Display.
async fn classify_task(ctx: &Ctx, task: &RegisterTask, error: &ChainError) -> Flow<()> {
    let message = format!("register: {error}");
    match classify_chain_error(error) {
        ErrorClass::ContentRegistered => mark_done(ctx, task, task.tx_hash.clone(), None).await,
        // The nonce was consumed. If our content is on-chain the consumer
        // was our own lost-receipt transaction (done); otherwise a third
        // party consumed it — the proofs are void, terminal CONFLICT.
        ErrorClass::NonceUsed => match check_content(ctx, task).await? {
            ContentState::Registered => mark_done(ctx, task, task.tx_hash.clone(), None).await,
            ContentState::Absent | ContentState::Unencodable => {
                persist(
                    ctx,
                    SubmissionOperation::MarkFailed {
                        task_id: task.id.clone(),
                        kind: FailureKind::Conflict,
                        message,
                    },
                    "could not persist conflict task",
                )
                .await
            }
        },
        ErrorClass::Transient => {
            persist(
                ctx,
                SubmissionOperation::RecordTransientFailure {
                    task_id: task.id.clone(),
                    message,
                },
                "could not persist task retry",
            )
            .await
        }
        ErrorClass::Poison => {
            persist(
                ctx,
                SubmissionOperation::MarkFailed {
                    task_id: task.id.clone(),
                    kind: FailureKind::Poison,
                    message,
                },
                "could not persist poison task",
            )
            .await
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use crux_core::{Core, Request};

    use super::*;
    use crate::task::{Member, Proof, TaskStatus};

    struct Driver {
        core: Core<SubmissionApp>,
        queue: VecDeque<Request<SubmissionOperation>>,
    }

    impl Driver {
        fn start(envelope_ids: &[&str]) -> Self {
            let core = Core::new();
            let effects = core.process_event(SubmissionEvent::Start {
                envelope_ids: envelope_ids.iter().map(|id| (*id).to_owned()).collect(),
            });
            let mut driver = Self {
                core,
                queue: VecDeque::new(),
            };
            driver.absorb(effects);
            driver
        }

        fn absorb(&mut self, effects: Vec<SubmissionEffect>) {
            for effect in effects {
                let SubmissionEffect::Work(request) = effect;
                self.queue.push_back(request);
            }
            assert!(
                self.queue.len() <= 1,
                "the batch program must be strictly sequential"
            );
        }

        fn step(&mut self, expected: SubmissionOperation, result: SubmissionResult) {
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

        fn assert_settled(&self, expected: BatchVerdict) {
            assert!(self.queue.is_empty(), "no operation may remain in flight");
            assert_eq!(self.core.view().outcome, Some(expected));
        }
    }

    const PK: &str = "041a8cc55e2d14a61c8f3f1bcf6f8e7e40fe09cc624a6b77f0539d5eebfafa7bc7880184f26b47cfc67b445168c34355416c93c73cb9b896b82be84486adf88ca0";

    fn task(id: &str, status: TaskStatus) -> RegisterTask {
        RegisterTask {
            id: id.to_owned(),
            status,
            rp_id: format!("{id}.example"),
            metadata: "0xaa".into(),
            unit_nonce: format!("0x{}", "11".repeat(32)),
            members: vec![Member {
                public_key: PK.into(),
                attestation: String::new(),
                proof: Proof {
                    authenticator_data: "00".repeat(37),
                    client_data_json: "{}".into(),
                    challenge_index: 23,
                    type_index: 1,
                    r: format!("0x{}", "22".repeat(32)),
                    s: format!("0x{}", "33".repeat(32)),
                },
            }],
            tx_hash: None,
            first_entry_id: None,
            error: None,
            retries: 0,
            created_at: 0,
            admitted: true,
        }
    }

    fn content_hash(task: &RegisterTask) -> String {
        format!("{:#x}", content_hash_for(task).unwrap())
    }

    fn load(ids: &[&str]) -> SubmissionOperation {
        SubmissionOperation::LoadTasks {
            ids: ids.iter().map(|id| (*id).to_owned()).collect(),
        }
    }

    fn loaded(tasks: &[&RegisterTask]) -> SubmissionResult {
        SubmissionResult::TasksLoaded {
            tasks: tasks.iter().map(|task| Some((*task).clone())).collect(),
        }
    }

    fn check(task: &RegisterTask) -> SubmissionOperation {
        SubmissionOperation::CheckContentRegistered {
            content_hash: content_hash(task),
        }
    }

    fn registered(value: bool) -> SubmissionResult {
        SubmissionResult::ContentChecked { registered: value }
    }

    fn advance() -> BatchVerdict {
        BatchVerdict::Advance
    }

    fn retry_verdict(reason: &str) -> BatchVerdict {
        BatchVerdict::Retry {
            reason: reason.to_owned(),
        }
    }

    #[test]
    fn empty_batch_advances_without_loading() {
        let driver = Driver::start(&[]);
        driver.assert_settled(advance());
    }

    #[test]
    fn terminal_and_unknown_envelopes_advance_without_chain_traffic() {
        let done = task("a", TaskStatus::Done);
        let mut driver = Driver::start(&["a", "ghost"]);
        driver.step(
            load(&["a", "ghost"]),
            SubmissionResult::TasksLoaded {
                tasks: vec![Some(done), None],
            },
        );
        driver.assert_settled(advance());
    }

    #[test]
    fn duplicate_envelopes_are_processed_once() {
        let pending = task("a", TaskStatus::Pending);
        let mut driver = Driver::start(&["a", "a"]);
        driver.step(load(&["a", "a"]), loaded(&[&pending, &pending]));
        // Exactly one content check for the duplicated id.
        driver.step(check(&pending), registered(true));
        driver.step(
            SubmissionOperation::MarkDone {
                task_id: "a".into(),
                tx_hash: None,
                first_entry_id: None,
            },
            SubmissionResult::Persisted,
        );
        driver.assert_settled(advance());
    }

    #[test]
    fn store_outage_on_load_retries_the_batch() {
        let mut driver = Driver::start(&["a"]);
        driver.step(load(&["a"]), SubmissionResult::StoreUnavailable);
        driver.assert_settled(retry_verdict("could not load Redis register task"));
    }

    #[test]
    fn pending_task_registers_to_done_with_entry_id() {
        let pending = task("a", TaskStatus::Pending);
        let mut driver = Driver::start(&["a"]);
        driver.step(load(&["a"]), loaded(&[&pending]));
        driver.step(check(&pending), registered(false));
        driver.step(
            SubmissionOperation::SubmitRegister {
                task: pending.clone(),
            },
            SubmissionResult::Tx(TxOutcome::Confirmed {
                tx_hash: "0xabc".into(),
                first_entry_id: Some(42),
            }),
        );
        driver.step(
            SubmissionOperation::MarkDone {
                task_id: "a".into(),
                tx_hash: Some("0xabc".into()),
                first_entry_id: Some(42),
            },
            SubmissionResult::Persisted,
        );
        driver.assert_settled(advance());
    }

    #[test]
    fn content_already_on_chain_reconciles_to_done() {
        let mut with_hash = task("a", TaskStatus::Pending);
        with_hash.tx_hash = Some("0xprev".into());
        let mut driver = Driver::start(&["a"]);
        driver.step(load(&["a"]), loaded(&[&with_hash]));
        driver.step(check(&with_hash), registered(true));
        driver.step(
            SubmissionOperation::MarkDone {
                task_id: "a".into(),
                tx_hash: Some("0xprev".into()),
                first_entry_id: None,
            },
            SubmissionResult::Persisted,
        );
        driver.assert_settled(advance());
    }

    #[test]
    fn reconcile_read_failure_records_a_retry_and_fails_the_batch() {
        let pending = task("a", TaskStatus::Pending);
        let mut driver = Driver::start(&["a"]);
        driver.step(load(&["a"]), loaded(&[&pending]));
        driver.step(check(&pending), SubmissionResult::ChainReadFailed);
        driver.step(
            SubmissionOperation::RecordTransientFailure {
                task_id: "a".into(),
                message: "isContentRegistered RPC temporarily unavailable".into(),
            },
            SubmissionResult::Persisted,
        );
        driver.assert_settled(retry_verdict("chain reconciliation failed"));
    }

    #[test]
    fn reverted_register_reconciles_then_resends_once_then_poisons() {
        let pending = task("a", TaskStatus::Pending);
        let mut driver = Driver::start(&["a"]);
        driver.step(load(&["a"]), loaded(&[&pending]));
        driver.step(check(&pending), registered(false));
        driver.step(
            SubmissionOperation::SubmitRegister {
                task: pending.clone(),
            },
            SubmissionResult::Tx(TxOutcome::Reverted {
                tx_hash: "0xdead".into(),
            }),
        );
        driver.step(check(&pending), registered(false));
        driver.step(
            SubmissionOperation::SubmitRegister {
                task: pending.clone(),
            },
            SubmissionResult::Tx(TxOutcome::Reverted {
                tx_hash: "0xdead2".into(),
            }),
        );
        driver.step(
            SubmissionOperation::MarkFailed {
                task_id: "a".into(),
                kind: FailureKind::Poison,
                message: "register transaction reverted".into(),
            },
            SubmissionResult::Persisted,
        );
        driver.assert_settled(advance());
    }

    #[test]
    fn reverted_register_that_landed_in_a_race_reconciles_to_done() {
        let pending = task("a", TaskStatus::Pending);
        let mut driver = Driver::start(&["a"]);
        driver.step(load(&["a"]), loaded(&[&pending]));
        driver.step(check(&pending), registered(false));
        driver.step(
            SubmissionOperation::SubmitRegister {
                task: pending.clone(),
            },
            SubmissionResult::Tx(TxOutcome::Reverted {
                tx_hash: "0xdead".into(),
            }),
        );
        driver.step(check(&pending), registered(true));
        driver.step(
            SubmissionOperation::MarkDone {
                task_id: "a".into(),
                tx_hash: None,
                first_entry_id: None,
            },
            SubmissionResult::Persisted,
        );
        driver.assert_settled(advance());
    }

    #[test]
    fn content_registered_send_failure_is_retroactive_success() {
        let pending = task("a", TaskStatus::Pending);
        let mut driver = Driver::start(&["a"]);
        driver.step(load(&["a"]), loaded(&[&pending]));
        driver.step(check(&pending), registered(false));
        driver.step(
            SubmissionOperation::SubmitRegister {
                task: pending.clone(),
            },
            SubmissionResult::Tx(TxOutcome::SendFailed {
                error: ChainError::Rejected("UnitAlreadyRegistered".into()),
            }),
        );
        driver.step(
            SubmissionOperation::MarkDone {
                task_id: "a".into(),
                tx_hash: None,
                first_entry_id: None,
            },
            SubmissionResult::Persisted,
        );
        driver.assert_settled(advance());
    }

    #[test]
    fn nonce_used_reconciles_content_before_the_conflict_verdict() {
        // Our own earlier transaction consumed the nonce with a lost receipt:
        // content present → done.
        let pending = task("a", TaskStatus::Pending);
        let mut driver = Driver::start(&["a"]);
        driver.step(load(&["a"]), loaded(&[&pending]));
        driver.step(check(&pending), registered(false));
        driver.step(
            SubmissionOperation::SubmitRegister {
                task: pending.clone(),
            },
            SubmissionResult::Tx(TxOutcome::SendFailed {
                error: ChainError::Rejected("NonceAlreadyUsed".into()),
            }),
        );
        driver.step(check(&pending), registered(true));
        driver.step(
            SubmissionOperation::MarkDone {
                task_id: "a".into(),
                tx_hash: None,
                first_entry_id: None,
            },
            SubmissionResult::Persisted,
        );
        driver.assert_settled(advance());
    }

    #[test]
    fn nonce_used_with_absent_content_is_a_terminal_conflict() {
        let pending = task("a", TaskStatus::Pending);
        let mut driver = Driver::start(&["a"]);
        driver.step(load(&["a"]), loaded(&[&pending]));
        driver.step(check(&pending), registered(false));
        driver.step(
            SubmissionOperation::SubmitRegister {
                task: pending.clone(),
            },
            SubmissionResult::Tx(TxOutcome::SendFailed {
                error: ChainError::Rejected("NonceAlreadyUsed".into()),
            }),
        );
        driver.step(check(&pending), registered(false));
        driver.step(
            SubmissionOperation::MarkFailed {
                task_id: "a".into(),
                kind: FailureKind::Conflict,
                message: "register: chain RPC rejected the request".into(),
            },
            SubmissionResult::Persisted,
        );
        driver.assert_settled(advance());
    }

    #[test]
    fn receipt_uncertainty_classifies_then_always_retries() {
        let pending = task("a", TaskStatus::Pending);
        let mut driver = Driver::start(&["a"]);
        driver.step(load(&["a"]), loaded(&[&pending]));
        driver.step(check(&pending), registered(false));
        driver.step(
            SubmissionOperation::SubmitRegister {
                task: pending.clone(),
            },
            SubmissionResult::Tx(TxOutcome::ReceiptUncertain {
                error: ChainError::Unavailable,
            }),
        );
        driver.step(
            SubmissionOperation::RecordTransientFailure {
                task_id: "a".into(),
                message: "register: chain RPC temporarily unavailable".into(),
            },
            SubmissionResult::Persisted,
        );
        // The tx may still land, and advancing would strand the envelope.
        driver.assert_settled(retry_verdict("register receipt wait failed"));
    }

    #[test]
    fn transient_send_failure_marks_and_retries() {
        let pending = task("a", TaskStatus::Pending);
        let mut driver = Driver::start(&["a"]);
        driver.step(load(&["a"]), loaded(&[&pending]));
        driver.step(check(&pending), registered(false));
        driver.step(
            SubmissionOperation::SubmitRegister {
                task: pending.clone(),
            },
            SubmissionResult::Tx(TxOutcome::SendFailed {
                error: ChainError::Unavailable,
            }),
        );
        driver.step(
            SubmissionOperation::RecordTransientFailure {
                task_id: "a".into(),
                message: "register: chain RPC temporarily unavailable".into(),
            },
            SubmissionResult::Persisted,
        );
        driver.assert_settled(retry_verdict("register temporarily failed"));
    }

    #[test]
    fn a_terminal_classification_continues_with_the_rest_of_the_batch() {
        let one = task("t1", TaskStatus::Pending);
        let two = task("t2", TaskStatus::Pending);
        let mut driver = Driver::start(&["t1", "t2"]);
        driver.step(load(&["t1", "t2"]), loaded(&[&one, &two]));
        driver.step(check(&one), registered(false));
        driver.step(
            SubmissionOperation::SubmitRegister { task: one.clone() },
            SubmissionResult::Tx(TxOutcome::SendFailed {
                error: ChainError::Reverted("InvalidProof".into()),
            }),
        );
        driver.step(
            SubmissionOperation::MarkFailed {
                task_id: "t1".into(),
                kind: FailureKind::Poison,
                message: "register: EVM execution reverted".into(),
            },
            SubmissionResult::Persisted,
        );
        // Non-transient → t2 still runs.
        driver.step(check(&two), registered(false));
        driver.step(
            SubmissionOperation::SubmitRegister { task: two.clone() },
            SubmissionResult::Tx(TxOutcome::Confirmed {
                tx_hash: "0xok".into(),
                first_entry_id: Some(7),
            }),
        );
        driver.step(
            SubmissionOperation::MarkDone {
                task_id: "t2".into(),
                tx_hash: Some("0xok".into()),
                first_entry_id: Some(7),
            },
            SubmissionResult::Persisted,
        );
        driver.assert_settled(advance());
    }

    #[test]
    fn nonce_pool_outage_retries_without_touching_any_task() {
        let pending = task("a", TaskStatus::Pending);
        let mut driver = Driver::start(&["a"]);
        driver.step(load(&["a"]), loaded(&[&pending]));
        driver.step(check(&pending), registered(false));
        driver.step(
            SubmissionOperation::SubmitRegister {
                task: pending.clone(),
            },
            SubmissionResult::Tx(TxOutcome::NoncePoolUnavailable),
        );
        driver.assert_settled(retry_verdict("could not acquire pending chain nonce"));
    }

    #[test]
    fn store_failure_while_marking_settles_with_that_call_sites_reason() {
        let pending = task("a", TaskStatus::Pending);
        let mut driver = Driver::start(&["a"]);
        driver.step(load(&["a"]), loaded(&[&pending]));
        driver.step(check(&pending), registered(true));
        driver.step(
            SubmissionOperation::MarkDone {
                task_id: "a".into(),
                tx_hash: None,
                first_entry_id: None,
            },
            SubmissionResult::StoreUnavailable,
        );
        driver.assert_settled(retry_verdict("could not persist done task"));
    }
}
