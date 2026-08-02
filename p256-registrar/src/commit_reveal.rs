//! The commit-reveal task lifecycle: the decision half of the queue worker.
//!
//! One [`CommitRevealApp`] instance drives one polled batch of queue
//! envelopes from "ids arrived" to a [`BatchVerdict`]: advance the consumer
//! offset, or retry the whole batch without advancing. Every rule the server's
//! `worker.rs` used to interleave with I/O lives here as a pure program over
//! serializable [`CommitRevealOperation`]s:
//!
//! - the queue message is only an envelope; the store record is authoritative,
//!   and terminal tasks are skipped;
//! - reconciliation first: a record already on chain marks its task done and
//!   is never re-created ("见链即完成" — previously duplicated five times);
//! - Pending tasks are committed, Committed tasks skip straight to the reveal
//!   wait; the reveal rule is `current_block >= commit_block + 1`;
//! - a reverted batch isolates tasks one by one so a single deterministically
//!   failing task is quarantined as POISON instead of poisoning its batch
//!   (still two deliberately mirrored flows, matching the original worker's
//!   isolate_commit/isolate_create pair — unifying them is future work);
//! - chain-write errors classify via [`classify_chain_error`]: exists → done,
//!   conflict → terminal CONFLICT, transient → retry counter, else POISON;
//! - any transient condition settles the batch as Retry so the shell does not
//!   advance the consumer offset.
//!
//! The shell executes operations sequentially (the program awaits each one),
//! owns nonce management, the pending-tx ledger and receipt waiting, and maps
//! their outcomes into [`TxOutcome`]. Control flow mirrors the original
//! `worker.rs` line by line on purpose: this module was extracted for
//! testability, not redesigned. Reason strings are kept identical for log
//! continuity.

use crux_core::{App, Command, command::CommandContext, macros::effect};
use serde::{Deserialize, Serialize};

use crate::protocol::{
    ChainError, ErrorClass, build_commitment, classify_chain_error, is_transient,
};
use crate::task::{CreateTask, TaskStatus};

/// createRecord calls go out in sub-batches of this size.
pub const CREATE_SUB_BATCH_SIZE: usize = 10;
/// Total time budget for the reveal wait, measured on the shell's clock.
pub const REVEAL_TIMEOUT_MS: u64 = 75_000;
/// Pause between reveal-wait polling passes.
pub const REVEAL_POLL_MS: u64 = 2_000;

// ── Shell protocol ─────────────────────────────────────────────────────────

/// Operations are complete, self-contained intents: they carry the tasks they
/// act on, so the shell needs no side-channel state to execute them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CommitRevealOperation {
    /// Load the authoritative task records for a list of envelope ids.
    LoadTasks {
        ids: Vec<String>,
    },
    /// Does the on-chain index already hold this credential?
    CheckRecord {
        rp_id: String,
        credential_id: String,
    },
    /// Block height at which a commitment was recorded (0 = not present).
    GetCommitBlock {
        commitment: String,
    },
    GetCurrentBlock,
    Sleep {
        ms: u64,
    },
    /// batchCommit for these tasks: send + receipt wait + nonce/ledger
    /// bookkeeping happen shell-side; the outcome comes back as [`TxOutcome`].
    SubmitCommit {
        tasks: Vec<CreateTask>,
    },
    /// batchCreateRecord, same contract as [`Self::SubmitCommit`].
    SubmitCreate {
        tasks: Vec<CreateTask>,
    },
    MarkCommitted {
        task_id: String,
    },
    MarkDone {
        task_id: String,
        tx_hash: Option<String>,
    },
    MarkPendingAgain {
        task_id: String,
        reason: String,
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

impl crux_core::capability::Operation for CommitRevealOperation {
    type Output = CommitRevealResult;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    Poison,
    Conflict,
}

impl FailureKind {
    /// The store's failure-class prefix, unchanged from the original strings.
    pub fn as_store_class(&self) -> &'static str {
        match self {
            Self::Poison => "POISON",
            Self::Conflict => "CONFLICT",
        }
    }
}

/// How a chain write ended, as observed by the shell. The nonce/ledger rules
/// (release on failure, keep the ledger row on receipt timeout for the
/// unstick sweep) are executed shell-side; the Core only decides what the
/// outcome means for the tasks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TxOutcome {
    Confirmed {
        tx_hash: String,
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
pub enum CommitRevealResult {
    TasksLoaded { tasks: Vec<Option<CreateTask>> },
    RecordChecked { exists: bool },
    CommitBlock { block: u64, now_ms: u64 },
    CurrentBlock { block: u64, now_ms: u64 },
    Slept { now_ms: u64 },
    Tx(TxOutcome),
    Persisted,
    StoreUnavailable,
    ChainReadFailed,
}

#[effect]
pub enum CommitRevealEffect {
    Work(CommitRevealOperation),
}

// ── App ────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BatchVerdict {
    /// Every task settled; the shell may advance the consumer offset.
    Advance,
    /// A transient condition was hit; do not advance the offset, retry the
    /// batch after backoff. The reason strings match the original worker's.
    Retry { reason: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CommitRevealEvent {
    Start { envelope_ids: Vec<String> },
    Settled(BatchVerdict),
}

#[derive(Default)]
pub struct CommitRevealModel {
    outcome: Option<BatchVerdict>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitRevealViewModel {
    pub outcome: Option<BatchVerdict>,
}

#[derive(Default)]
pub struct CommitRevealApp;

impl App for CommitRevealApp {
    type Event = CommitRevealEvent;
    type Model = CommitRevealModel;
    type ViewModel = CommitRevealViewModel;
    type Effect = CommitRevealEffect;

    fn update(
        &self,
        event: Self::Event,
        model: &mut Self::Model,
    ) -> Command<Self::Effect, Self::Event> {
        match event {
            CommitRevealEvent::Start { envelope_ids } => Command::new(|ctx| async move {
                let verdict = match drive_batch(&ctx, envelope_ids).await {
                    Ok(verdict) | Err(verdict) => verdict,
                };
                ctx.send_event(CommitRevealEvent::Settled(verdict));
            }),
            CommitRevealEvent::Settled(verdict) => {
                model.outcome = Some(verdict);
                Command::done()
            }
        }
    }

    fn view(&self, model: &Self::Model) -> Self::ViewModel {
        CommitRevealViewModel {
            outcome: model.outcome.clone(),
        }
    }
}

// ── The batch program ──────────────────────────────────────────────────────
//
// `Flow` short-circuits to a Retry verdict exactly where the original worker
// returned `Err(WorkerError(...))`. `Ok(Advance)` is the fall-through end.

type Ctx = CommandContext<CommitRevealEffect, CommitRevealEvent>;
type Flow<T> = Result<T, BatchVerdict>;

fn retry(reason: &str) -> BatchVerdict {
    BatchVerdict::Retry {
        reason: reason.to_owned(),
    }
}

async fn request(ctx: &Ctx, operation: CommitRevealOperation) -> CommitRevealResult {
    ctx.request_from_shell(operation).await
}

/// Issue a persistence operation; a store failure settles the batch with the
/// same reason string the original worker used at that call site.
async fn persist(ctx: &Ctx, operation: CommitRevealOperation, fail_reason: &str) -> Flow<()> {
    match request(ctx, operation).await {
        CommitRevealResult::Persisted => Ok(()),
        CommitRevealResult::StoreUnavailable => Err(retry(fail_reason)),
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
        CommitRevealOperation::LoadTasks {
            ids: envelope_ids.clone(),
        },
    )
    .await
    {
        CommitRevealResult::TasksLoaded { tasks } => tasks,
        CommitRevealResult::StoreUnavailable => {
            return Err(retry("could not load Redis create task"));
        }
        _ => return Err(retry("unexpected shell result for LoadTasks")),
    };
    let mut canonical: Vec<CreateTask> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for task in loaded.into_iter().flatten() {
        if !task.status.is_terminal() && seen.insert(task.id.clone()) {
            canonical.push(task);
        }
    }
    if canonical.is_empty() {
        return Ok(BatchVerdict::Advance);
    }

    // Reconciliation comes first. It covers receipt-timeout and producer
    // duplicate cases without ever replaying a successful on-chain create.
    let mut pending = Vec::new();
    let mut committed = Vec::new();
    for task in canonical {
        match check_record(ctx, &task).await? {
            true => {
                persist(
                    ctx,
                    CommitRevealOperation::MarkDone {
                        task_id: task.id.clone(),
                        tx_hash: task.tx_hash.clone(),
                    },
                    "could not persist reconciled task",
                )
                .await?;
            }
            false if task.status == TaskStatus::Pending => pending.push(task),
            false if task.status == TaskStatus::Committed => committed.push(task),
            false => {}
        }
    }

    if !pending.is_empty() {
        commit_stage(ctx, &pending).await?;
        // Reload what the store now says, exactly as the worker did: only
        // tasks that actually reached Committed advance to the reveal wait.
        let reloaded = match request(
            ctx,
            CommitRevealOperation::LoadTasks {
                ids: pending.iter().map(|task| task.id.clone()).collect(),
            },
        )
        .await
        {
            CommitRevealResult::TasksLoaded { tasks } => tasks,
            CommitRevealResult::StoreUnavailable => {
                return Err(retry("could not reload committed task"));
            }
            _ => return Err(retry("unexpected shell result for LoadTasks")),
        };
        for task in reloaded.into_iter().flatten() {
            if task.status == TaskStatus::Committed {
                committed.push(task);
            }
        }
    }
    if committed.is_empty() {
        return Ok(BatchVerdict::Advance);
    }

    wait_for_reveal(ctx, &committed).await?;

    let mut missing = Vec::new();
    for task in committed {
        match check_record(ctx, &task).await? {
            true => {
                persist(
                    ctx,
                    CommitRevealOperation::MarkDone {
                        task_id: task.id.clone(),
                        tx_hash: task.tx_hash.clone(),
                    },
                    "could not persist completed task",
                )
                .await?;
            }
            false => missing.push(task),
        }
    }
    for chunk in missing.chunks(CREATE_SUB_BATCH_SIZE) {
        create_stage(ctx, chunk).await?;
    }
    Ok(BatchVerdict::Advance)
}

/// hasRecord with the worker's exact failure handling: a read failure records
/// a transient retry on the task, then fails the whole batch.
async fn check_record(ctx: &Ctx, task: &CreateTask) -> Flow<bool> {
    match request(
        ctx,
        CommitRevealOperation::CheckRecord {
            rp_id: task.rp_id.clone(),
            credential_id: task.credential_id.clone(),
        },
    )
    .await
    {
        CommitRevealResult::RecordChecked { exists } => Ok(exists),
        CommitRevealResult::ChainReadFailed => {
            persist(
                ctx,
                CommitRevealOperation::RecordTransientFailure {
                    task_id: task.id.clone(),
                    message: "hasRecord RPC temporarily unavailable".to_owned(),
                },
                "could not persist task retry",
            )
            .await?;
            Err(retry("chain reconciliation failed"))
        }
        _ => Err(retry("unexpected shell result for CheckRecord")),
    }
}

async fn submit(ctx: &Ctx, operation: CommitRevealOperation) -> Flow<TxOutcome> {
    match request(ctx, operation).await {
        CommitRevealResult::Tx(outcome) => match outcome {
            TxOutcome::NoncePoolUnavailable => Err(retry("could not acquire pending chain nonce")),
            other => Ok(other),
        },
        _ => Err(retry("unexpected shell result for a chain write")),
    }
}

async fn commit_stage(ctx: &Ctx, tasks: &[CreateTask]) -> Flow<()> {
    match submit(
        ctx,
        CommitRevealOperation::SubmitCommit {
            tasks: tasks.to_vec(),
        },
    )
    .await?
    {
        TxOutcome::Confirmed { .. } => {
            for task in tasks {
                persist(
                    ctx,
                    CommitRevealOperation::MarkCommitted {
                        task_id: task.id.clone(),
                    },
                    "could not persist committed task",
                )
                .await?;
            }
            Ok(())
        }
        // Isolate the single culprit commitment instead of poisoning the
        // whole batch, so innocent items still make forward progress.
        TxOutcome::Reverted { .. } => isolate_commit(ctx, tasks).await,
        // Receipt timeout or send failure: classify per task; a transient
        // error retries the batch, anything terminal lets the flow continue.
        TxOutcome::ReceiptUncertain { error } | TxOutcome::SendFailed { error } => {
            classify_batch(ctx, tasks, &error, "batchCommit").await
        }
        TxOutcome::NoncePoolUnavailable => unreachable!("filtered by submit"),
    }
}

/// Poison isolation for batchCommit (mirror of [`isolate_create`], exactly as
/// the original worker kept two mirrored copies): re-commit each task
/// individually so a single deterministically-reverting commitment is
/// quarantined while the rest advance. An already-recorded commitment is
/// reconciled to `committed`.
async fn isolate_commit(ctx: &Ctx, tasks: &[CreateTask]) -> Flow<()> {
    for task in tasks {
        // Shortcut: the commitment may already be on chain. Any failure along
        // this probe (encoding, RPC) just falls through to a single re-commit,
        // exactly like the worker's `if let Ok(..) && .. && block > 0` chain.
        if let Ok(commitment) = build_commitment(task) {
            let probed = request(
                ctx,
                CommitRevealOperation::GetCommitBlock {
                    commitment: commitment.to_string(),
                },
            )
            .await;
            if let CommitRevealResult::CommitBlock { block, .. } = probed
                && block > 0
            {
                persist(
                    ctx,
                    CommitRevealOperation::MarkCommitted {
                        task_id: task.id.clone(),
                    },
                    "could not persist committed task",
                )
                .await?;
                continue;
            }
        }
        match submit(
            ctx,
            CommitRevealOperation::SubmitCommit {
                tasks: vec![task.clone()],
            },
        )
        .await?
        {
            TxOutcome::Confirmed { .. } => {
                persist(
                    ctx,
                    CommitRevealOperation::MarkCommitted {
                        task_id: task.id.clone(),
                    },
                    "could not persist committed task",
                )
                .await?;
            }
            TxOutcome::Reverted { .. } => {
                persist(
                    ctx,
                    CommitRevealOperation::MarkFailed {
                        task_id: task.id.clone(),
                        kind: FailureKind::Poison,
                        message: "batchCommit transaction reverted".to_owned(),
                    },
                    "could not persist failed task",
                )
                .await?;
            }
            TxOutcome::ReceiptUncertain { error } => {
                classify_task(ctx, task, &error, "batchCommit").await?;
                return Err(retry("isolated commit receipt wait failed"));
            }
            TxOutcome::SendFailed { error } => {
                classify_task(ctx, task, &error, "batchCommit").await?;
                if is_transient(&error) {
                    return Err(retry("isolated commit temporarily failed"));
                }
            }
            TxOutcome::NoncePoolUnavailable => unreachable!("filtered by submit"),
        }
    }
    Ok(())
}

async fn wait_for_reveal(ctx: &Ctx, tasks: &[CreateTask]) -> Flow<()> {
    // Deadline semantics ported from the worker's Instant-based check: the
    // timeout is evaluated after each full polling pass using the freshest
    // timestamp the shell reported during that pass, so slow per-task RPC
    // rounds count against the 75s budget just as wall-clock time did. Two
    // bounded drifts from the original, neither accumulating across rounds:
    // the anchor is the first block read's completion time rather than
    // function entry (budget starts up to one RPC later), and the last
    // task's vanish-branch tail (CheckRecord + MarkDone) lands after this
    // round's newest timestamp, deferring — not losing — that time to the
    // next round's check.
    let mut deadline_base: Option<u64> = None;
    loop {
        let (block, mut pass_now_ms) =
            match request(ctx, CommitRevealOperation::GetCurrentBlock).await {
                CommitRevealResult::CurrentBlock { block, now_ms } => {
                    deadline_base.get_or_insert(now_ms);
                    (block, now_ms)
                }
                CommitRevealResult::ChainReadFailed => {
                    return Err(retry("could not read current block"));
                }
                _ => return Err(retry("unexpected shell result for GetCurrentBlock")),
            };
        let mut all_ready = true;
        for task in tasks {
            let commitment = build_commitment(task)
                .map_err(|_| retry("stored create task cannot be encoded"))?;
            let commit_block = match request(
                ctx,
                CommitRevealOperation::GetCommitBlock {
                    commitment: commitment.to_string(),
                },
            )
            .await
            {
                CommitRevealResult::CommitBlock { block, now_ms } => {
                    pass_now_ms = now_ms;
                    block
                }
                _ => return Err(retry("could not read commit block")),
            };
            if commit_block == 0 {
                // The commitment vanished: either the record made it on chain
                // (done), or the commit was lost and the task must re-commit.
                match request(
                    ctx,
                    CommitRevealOperation::CheckRecord {
                        rp_id: task.rp_id.clone(),
                        credential_id: task.credential_id.clone(),
                    },
                )
                .await
                {
                    CommitRevealResult::RecordChecked { exists: true } => {
                        persist(
                            ctx,
                            CommitRevealOperation::MarkDone {
                                task_id: task.id.clone(),
                                tx_hash: task.tx_hash.clone(),
                            },
                            "could not persist reconciled task",
                        )
                        .await?;
                    }
                    CommitRevealResult::RecordChecked { exists: false } => {
                        persist(
                            ctx,
                            CommitRevealOperation::MarkPendingAgain {
                                task_id: task.id.clone(),
                                reason: "commitment missing; re-committing".to_owned(),
                            },
                            "could not reschedule task",
                        )
                        .await?;
                        return Err(retry("commitment was not found"));
                    }
                    _ => return Err(retry("could not reconcile missing commitment")),
                }
            } else if block >= commit_block.saturating_add(1) {
                // Ready: at least one block has passed since the commit.
            } else {
                all_ready = false;
            }
        }
        if all_ready {
            return Ok(());
        }
        if pass_now_ms.saturating_sub(deadline_base.unwrap_or(pass_now_ms)) >= REVEAL_TIMEOUT_MS {
            return Err(retry("commit reveal delay exceeded timeout"));
        }
        request(ctx, CommitRevealOperation::Sleep { ms: REVEAL_POLL_MS }).await;
    }
}

async fn create_stage(ctx: &Ctx, tasks: &[CreateTask]) -> Flow<()> {
    match submit(
        ctx,
        CommitRevealOperation::SubmitCreate {
            tasks: tasks.to_vec(),
        },
    )
    .await?
    {
        TxOutcome::Confirmed { tx_hash } => {
            for task in tasks {
                persist(
                    ctx,
                    CommitRevealOperation::MarkDone {
                        task_id: task.id.clone(),
                        tx_hash: Some(tx_hash.clone()),
                    },
                    "could not persist done task",
                )
                .await?;
            }
            Ok(())
        }
        TxOutcome::Reverted { .. } => isolate_create(ctx, tasks).await,
        TxOutcome::ReceiptUncertain { error } => {
            classify_batch(ctx, tasks, &error, "batchCreateRecord").await
        }
        // Deliberate asymmetry inherited from the worker: a non-transient
        // send failure on create goes straight to isolation, while commit
        // always classified batch-wide.
        TxOutcome::SendFailed { error } => {
            if is_transient(&error) {
                classify_batch(ctx, tasks, &error, "batchCreateRecord").await
            } else {
                isolate_create(ctx, tasks).await
            }
        }
        TxOutcome::NoncePoolUnavailable => unreachable!("filtered by submit"),
    }
}

async fn isolate_create(ctx: &Ctx, tasks: &[CreateTask]) -> Flow<()> {
    for task in tasks {
        match request(
            ctx,
            CommitRevealOperation::CheckRecord {
                rp_id: task.rp_id.clone(),
                credential_id: task.credential_id.clone(),
            },
        )
        .await
        {
            CommitRevealResult::RecordChecked { exists: true } => {
                persist(
                    ctx,
                    CommitRevealOperation::MarkDone {
                        task_id: task.id.clone(),
                        tx_hash: task.tx_hash.clone(),
                    },
                    "could not persist reconciled task",
                )
                .await?;
                continue;
            }
            CommitRevealResult::RecordChecked { exists: false } => {}
            _ => return Err(retry("could not reconcile isolated task")),
        }
        match submit(
            ctx,
            CommitRevealOperation::SubmitCreate {
                tasks: vec![task.clone()],
            },
        )
        .await?
        {
            TxOutcome::Confirmed { tx_hash } => {
                persist(
                    ctx,
                    CommitRevealOperation::MarkDone {
                        task_id: task.id.clone(),
                        tx_hash: Some(tx_hash),
                    },
                    "could not persist isolated task",
                )
                .await?;
            }
            TxOutcome::Reverted { .. } => {
                persist(
                    ctx,
                    CommitRevealOperation::MarkFailed {
                        task_id: task.id.clone(),
                        kind: FailureKind::Poison,
                        message: "createRecord transaction reverted".to_owned(),
                    },
                    "could not persist failed task",
                )
                .await?;
            }
            TxOutcome::ReceiptUncertain { error } => {
                classify_task(ctx, task, &error, "createRecord").await?;
                return Err(retry("isolated create receipt wait failed"));
            }
            TxOutcome::SendFailed { error } => {
                classify_task(ctx, task, &error, "createRecord").await?;
                if is_transient(&error) {
                    return Err(retry("isolated create temporarily failed"));
                }
            }
            TxOutcome::NoncePoolUnavailable => unreachable!("filtered by submit"),
        }
    }
    Ok(())
}

/// The worker's handle_batch_error: classify every task, then let a transient
/// error retry the batch while terminal classifications let the flow continue.
async fn classify_batch(
    ctx: &Ctx,
    tasks: &[CreateTask],
    error: &ChainError,
    operation: &str,
) -> Flow<()> {
    for task in tasks {
        classify_task(ctx, task, error, operation).await?;
    }
    if is_transient(error) {
        Err(retry("chain write temporarily failed"))
    } else {
        Ok(())
    }
}

/// The worker's handle_task_error, now routed through the typed
/// [`classify_chain_error`]. Message formatting uses the error's Display,
/// exactly as before.
async fn classify_task(
    ctx: &Ctx,
    task: &CreateTask,
    error: &ChainError,
    operation: &str,
) -> Flow<()> {
    let message = format!("{operation}: {error}");
    match classify_chain_error(error) {
        ErrorClass::RecordExists => {
            persist(
                ctx,
                CommitRevealOperation::MarkDone {
                    task_id: task.id.clone(),
                    tx_hash: task.tx_hash.clone(),
                },
                "could not persist reconciled task",
            )
            .await
        }
        ErrorClass::WalletConflict => {
            persist(
                ctx,
                CommitRevealOperation::MarkFailed {
                    task_id: task.id.clone(),
                    kind: FailureKind::Conflict,
                    message,
                },
                "could not persist conflict task",
            )
            .await
        }
        ErrorClass::Transient => {
            persist(
                ctx,
                CommitRevealOperation::RecordTransientFailure {
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
                CommitRevealOperation::MarkFailed {
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
    use crate::protocol::ChainError;

    // ── Test driver ────────────────────────────────────────────────────────
    //
    // The program is strictly sequential: at most one operation is ever in
    // flight. The driver asserts that invariant on every step.

    struct Driver {
        core: Core<CommitRevealApp>,
        queue: VecDeque<Request<CommitRevealOperation>>,
    }

    impl Driver {
        fn start(envelope_ids: &[&str]) -> Self {
            let core = Core::new();
            let effects = core.process_event(CommitRevealEvent::Start {
                envelope_ids: envelope_ids.iter().map(|id| (*id).to_owned()).collect(),
            });
            let mut driver = Self {
                core,
                queue: VecDeque::new(),
            };
            driver.absorb(effects);
            driver
        }

        fn absorb(&mut self, effects: Vec<CommitRevealEffect>) {
            for effect in effects {
                let CommitRevealEffect::Work(request) = effect;
                self.queue.push_back(request);
            }
            assert!(
                self.queue.len() <= 1,
                "the batch program must be strictly sequential"
            );
        }

        /// Assert the next operation matches, then resolve it with `result`.
        fn step(&mut self, expected: CommitRevealOperation, result: CommitRevealResult) {
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

        fn outcome(&self) -> Option<BatchVerdict> {
            self.core.view().outcome
        }

        fn assert_settled(&self, expected: BatchVerdict) {
            assert!(self.queue.is_empty(), "no operation may remain in flight");
            assert_eq!(self.outcome(), Some(expected));
        }
    }

    fn task(id: &str, status: TaskStatus) -> CreateTask {
        CreateTask {
            id: id.to_owned(),
            status,
            rp_id: format!("{id}.example"),
            credential_id: format!("cred-{id}"),
            wallet_ref: "0x0000000000000000000000000000000000000000000000000000000000000001"
                .to_owned(),
            public_key: "04".repeat(65),
            name: "n".to_owned(),
            initial_credential_id: format!("cred-{id}"),
            metadata: "0x00".to_owned(),
            tx_hash: None,
            error: None,
            retries: 0,
            created_at: 0,
            admitted: true,
        }
    }

    fn load(ids: &[&str]) -> CommitRevealOperation {
        CommitRevealOperation::LoadTasks {
            ids: ids.iter().map(|id| (*id).to_owned()).collect(),
        }
    }

    fn loaded(tasks: &[&CreateTask]) -> CommitRevealResult {
        CommitRevealResult::TasksLoaded {
            tasks: tasks.iter().map(|task| Some((*task).clone())).collect(),
        }
    }

    fn check(task: &CreateTask) -> CommitRevealOperation {
        CommitRevealOperation::CheckRecord {
            rp_id: task.rp_id.clone(),
            credential_id: task.credential_id.clone(),
        }
    }

    fn exists(value: bool) -> CommitRevealResult {
        CommitRevealResult::RecordChecked { exists: value }
    }

    fn commitment_hex(task: &CreateTask) -> String {
        build_commitment(task)
            .expect("test task encodes")
            .to_string()
    }

    fn probe(task: &CreateTask) -> CommitRevealOperation {
        CommitRevealOperation::GetCommitBlock {
            commitment: commitment_hex(task),
        }
    }

    fn commit_block(block: u64, now_ms: u64) -> CommitRevealResult {
        CommitRevealResult::CommitBlock { block, now_ms }
    }

    fn advance() -> BatchVerdict {
        BatchVerdict::Advance
    }

    fn retry_verdict(reason: &str) -> BatchVerdict {
        BatchVerdict::Retry {
            reason: reason.to_owned(),
        }
    }

    // ── Envelope handling ──────────────────────────────────────────────────

    #[test]
    fn terminal_and_unknown_envelopes_advance_without_any_chain_traffic() {
        let done = task("a", TaskStatus::Done);
        let mut driver = Driver::start(&["a", "ghost"]);
        driver.step(
            load(&["a", "ghost"]),
            CommitRevealResult::TasksLoaded {
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
        // Exactly one CheckRecord for the duplicated id.
        driver.step(check(&pending), exists(true));
        driver.step(
            CommitRevealOperation::MarkDone {
                task_id: "a".into(),
                tx_hash: None,
            },
            CommitRevealResult::Persisted,
        );
        driver.assert_settled(advance());
    }

    #[test]
    fn store_outage_on_load_retries_the_batch() {
        let mut driver = Driver::start(&["a"]);
        driver.step(load(&["a"]), CommitRevealResult::StoreUnavailable);
        driver.assert_settled(retry_verdict("could not load Redis create task"));
    }

    // ── Reconciliation ─────────────────────────────────────────────────────

    #[test]
    fn record_already_on_chain_reconciles_to_done_without_submitting() {
        let committed = task("a", TaskStatus::Committed);
        let mut driver = Driver::start(&["a"]);
        driver.step(load(&["a"]), loaded(&[&committed]));
        driver.step(check(&committed), exists(true));
        driver.step(
            CommitRevealOperation::MarkDone {
                task_id: "a".into(),
                tx_hash: None,
            },
            CommitRevealResult::Persisted,
        );
        driver.assert_settled(advance());
    }

    #[test]
    fn reconcile_read_failure_records_a_retry_and_fails_the_batch() {
        let pending = task("a", TaskStatus::Pending);
        let mut driver = Driver::start(&["a"]);
        driver.step(load(&["a"]), loaded(&[&pending]));
        driver.step(check(&pending), CommitRevealResult::ChainReadFailed);
        driver.step(
            CommitRevealOperation::RecordTransientFailure {
                task_id: "a".into(),
                message: "hasRecord RPC temporarily unavailable".into(),
            },
            CommitRevealResult::Persisted,
        );
        driver.assert_settled(retry_verdict("chain reconciliation failed"));
    }

    // ── Happy path ─────────────────────────────────────────────────────────

    #[test]
    fn pending_task_walks_commit_reveal_create_to_done() {
        let pending = task("a", TaskStatus::Pending);
        let mut committed = pending.clone();
        committed.status = TaskStatus::Committed;

        let mut driver = Driver::start(&["a"]);
        driver.step(load(&["a"]), loaded(&[&pending]));
        driver.step(check(&pending), exists(false));

        // Commit stage.
        driver.step(
            CommitRevealOperation::SubmitCommit {
                tasks: vec![pending.clone()],
            },
            CommitRevealResult::Tx(TxOutcome::Confirmed {
                tx_hash: "0xc0".into(),
            }),
        );
        driver.step(
            CommitRevealOperation::MarkCommitted {
                task_id: "a".into(),
            },
            CommitRevealResult::Persisted,
        );
        driver.step(load(&["a"]), loaded(&[&committed]));

        // Reveal: commit landed at block 3, current block 5 ≥ 3 + 1.
        driver.step(
            CommitRevealOperation::GetCurrentBlock,
            CommitRevealResult::CurrentBlock {
                block: 5,
                now_ms: 1_000,
            },
        );
        driver.step(
            CommitRevealOperation::GetCommitBlock {
                commitment: commitment_hex(&committed),
            },
            commit_block(3, 1_100),
        );

        // Post-reveal reconcile: not yet on chain → create.
        driver.step(check(&committed), exists(false));
        driver.step(
            CommitRevealOperation::SubmitCreate {
                tasks: vec![committed.clone()],
            },
            CommitRevealResult::Tx(TxOutcome::Confirmed {
                tx_hash: "0xabc".into(),
            }),
        );
        driver.step(
            CommitRevealOperation::MarkDone {
                task_id: "a".into(),
                tx_hash: Some("0xabc".into()),
            },
            CommitRevealResult::Persisted,
        );
        driver.assert_settled(advance());
    }

    // ── Commit-stage failures ──────────────────────────────────────────────

    #[test]
    fn reverted_commit_isolates_replays_and_quarantines_the_poison_task() {
        let good = task("good", TaskStatus::Pending);
        let bad = task("bad", TaskStatus::Pending);
        let mut good_committed = good.clone();
        good_committed.status = TaskStatus::Committed;

        let mut driver = Driver::start(&["good", "bad"]);
        driver.step(load(&["good", "bad"]), loaded(&[&good, &bad]));
        driver.step(check(&good), exists(false));
        driver.step(check(&bad), exists(false));

        driver.step(
            CommitRevealOperation::SubmitCommit {
                tasks: vec![good.clone(), bad.clone()],
            },
            CommitRevealResult::Tx(TxOutcome::Reverted {
                tx_hash: "0xdead".into(),
            }),
        );

        // Isolation: `good`'s commitment already landed on chain.
        driver.step(
            CommitRevealOperation::GetCommitBlock {
                commitment: commitment_hex(&good),
            },
            commit_block(7, 500),
        );
        driver.step(
            CommitRevealOperation::MarkCommitted {
                task_id: "good".into(),
            },
            CommitRevealResult::Persisted,
        );
        // `bad` has no commitment on chain; its lone replay reverts → POISON.
        driver.step(
            CommitRevealOperation::GetCommitBlock {
                commitment: commitment_hex(&bad),
            },
            commit_block(0, 600),
        );
        driver.step(
            CommitRevealOperation::SubmitCommit {
                tasks: vec![bad.clone()],
            },
            CommitRevealResult::Tx(TxOutcome::Reverted {
                tx_hash: "0xdead2".into(),
            }),
        );
        driver.step(
            CommitRevealOperation::MarkFailed {
                task_id: "bad".into(),
                kind: FailureKind::Poison,
                message: "batchCommit transaction reverted".into(),
            },
            CommitRevealResult::Persisted,
        );

        // Reload: only `good` reached Committed; `bad` is terminal.
        let mut bad_failed = bad.clone();
        bad_failed.status = TaskStatus::Failed;
        driver.step(
            load(&["good", "bad"]),
            loaded(&[&good_committed, &bad_failed]),
        );

        // Reveal + post-reveal reconcile for `good` only.
        driver.step(
            CommitRevealOperation::GetCurrentBlock,
            CommitRevealResult::CurrentBlock {
                block: 9,
                now_ms: 1_000,
            },
        );
        driver.step(
            CommitRevealOperation::GetCommitBlock {
                commitment: commitment_hex(&good_committed),
            },
            commit_block(7, 1_100),
        );
        driver.step(check(&good_committed), exists(true));
        driver.step(
            CommitRevealOperation::MarkDone {
                task_id: "good".into(),
                tx_hash: None,
            },
            CommitRevealResult::Persisted,
        );
        driver.assert_settled(advance());
    }

    #[test]
    fn receipt_uncertainty_on_commit_marks_retries_and_fails_the_batch() {
        let pending = task("a", TaskStatus::Pending);
        let mut driver = Driver::start(&["a"]);
        driver.step(load(&["a"]), loaded(&[&pending]));
        driver.step(check(&pending), exists(false));
        driver.step(
            CommitRevealOperation::SubmitCommit {
                tasks: vec![pending.clone()],
            },
            CommitRevealResult::Tx(TxOutcome::ReceiptUncertain {
                error: ChainError::Unavailable,
            }),
        );
        // Message uses the error's Display, exactly as the worker formatted it.
        driver.step(
            CommitRevealOperation::RecordTransientFailure {
                task_id: "a".into(),
                message: "batchCommit: chain RPC temporarily unavailable".into(),
            },
            CommitRevealResult::Persisted,
        );
        driver.assert_settled(retry_verdict("chain write temporarily failed"));
    }

    #[test]
    fn wallet_conflict_on_commit_is_terminal_and_still_advances() {
        let pending = task("a", TaskStatus::Pending);
        let mut driver = Driver::start(&["a"]);
        driver.step(load(&["a"]), loaded(&[&pending]));
        driver.step(check(&pending), exists(false));
        driver.step(
            CommitRevealOperation::SubmitCommit {
                tasks: vec![pending.clone()],
            },
            CommitRevealResult::Tx(TxOutcome::SendFailed {
                error: ChainError::Rejected("WalletRefAlreadyExists".into()),
            }),
        );
        driver.step(
            CommitRevealOperation::MarkFailed {
                task_id: "a".into(),
                kind: FailureKind::Conflict,
                message: "batchCommit: chain RPC rejected the request".into(),
            },
            CommitRevealResult::Persisted,
        );
        // Non-transient → commit stage completes; reload finds the task
        // terminal, nothing reaches the reveal wait.
        let mut failed = pending.clone();
        failed.status = TaskStatus::Failed;
        driver.step(load(&["a"]), loaded(&[&failed]));
        driver.assert_settled(advance());
    }

    #[test]
    fn nonce_pool_outage_retries_without_touching_any_task() {
        let pending = task("a", TaskStatus::Pending);
        let mut driver = Driver::start(&["a"]);
        driver.step(load(&["a"]), loaded(&[&pending]));
        driver.step(check(&pending), exists(false));
        driver.step(
            CommitRevealOperation::SubmitCommit {
                tasks: vec![pending.clone()],
            },
            CommitRevealResult::Tx(TxOutcome::NoncePoolUnavailable),
        );
        driver.assert_settled(retry_verdict("could not acquire pending chain nonce"));
    }

    // ── Reveal wait ────────────────────────────────────────────────────────

    #[test]
    fn missing_commitment_without_record_requeues_the_task() {
        let committed = task("a", TaskStatus::Committed);
        let mut driver = Driver::start(&["a"]);
        driver.step(load(&["a"]), loaded(&[&committed]));
        driver.step(check(&committed), exists(false));
        driver.step(
            CommitRevealOperation::GetCurrentBlock,
            CommitRevealResult::CurrentBlock {
                block: 5,
                now_ms: 1_000,
            },
        );
        driver.step(
            CommitRevealOperation::GetCommitBlock {
                commitment: commitment_hex(&committed),
            },
            commit_block(0, 1_100),
        );
        driver.step(check(&committed), exists(false));
        driver.step(
            CommitRevealOperation::MarkPendingAgain {
                task_id: "a".into(),
                reason: "commitment missing; re-committing".into(),
            },
            CommitRevealResult::Persisted,
        );
        driver.assert_settled(retry_verdict("commitment was not found"));
    }

    #[test]
    fn reveal_wait_times_out_on_the_shell_clock() {
        let committed = task("a", TaskStatus::Committed);
        let mut driver = Driver::start(&["a"]);
        driver.step(load(&["a"]), loaded(&[&committed]));
        driver.step(check(&committed), exists(false));

        // Pass 1: commit block not deep enough yet → sleep.
        driver.step(
            CommitRevealOperation::GetCurrentBlock,
            CommitRevealResult::CurrentBlock {
                block: 5,
                now_ms: 10_000,
            },
        );
        driver.step(
            CommitRevealOperation::GetCommitBlock {
                commitment: commitment_hex(&committed),
            },
            commit_block(5, 11_000),
        );
        driver.step(
            CommitRevealOperation::Sleep { ms: REVEAL_POLL_MS },
            CommitRevealResult::Slept { now_ms: 12_000 },
        );
        // Pass 2: still not ready and 75s elapsed since the first block read.
        driver.step(
            CommitRevealOperation::GetCurrentBlock,
            CommitRevealResult::CurrentBlock {
                block: 5,
                now_ms: 86_000,
            },
        );
        driver.step(
            CommitRevealOperation::GetCommitBlock {
                commitment: commitment_hex(&committed),
            },
            commit_block(5, 86_500),
        );
        driver.assert_settled(retry_verdict("commit reveal delay exceeded timeout"));
    }

    // ── Create-stage failures ──────────────────────────────────────────────

    #[test]
    fn non_transient_create_send_failure_goes_to_isolation_and_reconciles() {
        // The deliberate asymmetry: commit would classify batch-wide, create
        // isolates. Here isolation discovers the record actually exists.
        let committed = task("a", TaskStatus::Committed);
        let mut driver = Driver::start(&["a"]);
        driver.step(load(&["a"]), loaded(&[&committed]));
        driver.step(check(&committed), exists(false));
        driver.step(
            CommitRevealOperation::GetCurrentBlock,
            CommitRevealResult::CurrentBlock {
                block: 9,
                now_ms: 1_000,
            },
        );
        driver.step(
            CommitRevealOperation::GetCommitBlock {
                commitment: commitment_hex(&committed),
            },
            commit_block(3, 1_100),
        );
        driver.step(check(&committed), exists(false));
        driver.step(
            CommitRevealOperation::SubmitCreate {
                tasks: vec![committed.clone()],
            },
            CommitRevealResult::Tx(TxOutcome::SendFailed {
                error: ChainError::Rejected("RecordAlreadyExists".into()),
            }),
        );
        // Isolation begins with reconciliation, which now finds the record.
        driver.step(check(&committed), exists(true));
        driver.step(
            CommitRevealOperation::MarkDone {
                task_id: "a".into(),
                tx_hash: None,
            },
            CommitRevealResult::Persisted,
        );
        driver.assert_settled(advance());
    }

    #[test]
    fn reverted_create_quarantines_only_the_poison_task() {
        let good = task("good", TaskStatus::Committed);
        let bad = task("bad", TaskStatus::Committed);
        let mut driver = Driver::start(&["good", "bad"]);
        driver.step(load(&["good", "bad"]), loaded(&[&good, &bad]));
        driver.step(check(&good), exists(false));
        driver.step(check(&bad), exists(false));

        // Reveal: both ready immediately.
        driver.step(
            CommitRevealOperation::GetCurrentBlock,
            CommitRevealResult::CurrentBlock {
                block: 9,
                now_ms: 1_000,
            },
        );
        driver.step(
            CommitRevealOperation::GetCommitBlock {
                commitment: commitment_hex(&good),
            },
            commit_block(3, 1_100),
        );
        driver.step(
            CommitRevealOperation::GetCommitBlock {
                commitment: commitment_hex(&bad),
            },
            commit_block(3, 1_200),
        );
        driver.step(check(&good), exists(false));
        driver.step(check(&bad), exists(false));

        driver.step(
            CommitRevealOperation::SubmitCreate {
                tasks: vec![good.clone(), bad.clone()],
            },
            CommitRevealResult::Tx(TxOutcome::Reverted {
                tx_hash: "0xdead".into(),
            }),
        );
        // Isolation: good re-creates cleanly, bad reverts alone → POISON.
        driver.step(check(&good), exists(false));
        driver.step(
            CommitRevealOperation::SubmitCreate {
                tasks: vec![good.clone()],
            },
            CommitRevealResult::Tx(TxOutcome::Confirmed {
                tx_hash: "0xok".into(),
            }),
        );
        driver.step(
            CommitRevealOperation::MarkDone {
                task_id: "good".into(),
                tx_hash: Some("0xok".into()),
            },
            CommitRevealResult::Persisted,
        );
        driver.step(check(&bad), exists(false));
        driver.step(
            CommitRevealOperation::SubmitCreate {
                tasks: vec![bad.clone()],
            },
            CommitRevealResult::Tx(TxOutcome::Reverted {
                tx_hash: "0xdead2".into(),
            }),
        );
        driver.step(
            CommitRevealOperation::MarkFailed {
                task_id: "bad".into(),
                kind: FailureKind::Poison,
                message: "createRecord transaction reverted".into(),
            },
            CommitRevealResult::Persisted,
        );
        driver.assert_settled(advance());
    }

    #[test]
    fn store_failure_while_marking_settles_with_that_call_sites_reason() {
        let pending = task("a", TaskStatus::Pending);
        let mut driver = Driver::start(&["a"]);
        driver.step(load(&["a"]), loaded(&[&pending]));
        driver.step(check(&pending), exists(false));
        driver.step(
            CommitRevealOperation::SubmitCommit {
                tasks: vec![pending.clone()],
            },
            CommitRevealResult::Tx(TxOutcome::Confirmed {
                tx_hash: "0xc0".into(),
            }),
        );
        driver.step(
            CommitRevealOperation::MarkCommitted {
                task_id: "a".into(),
            },
            CommitRevealResult::StoreUnavailable,
        );
        driver.assert_settled(retry_verdict("could not persist committed task"));
    }

    #[test]
    fn create_sub_batches_are_chunked_by_ten() {
        let tasks: Vec<CreateTask> = (0..12)
            .map(|index| task(&format!("t{index:02}"), TaskStatus::Committed))
            .collect();
        let ids: Vec<&str> = tasks.iter().map(|task| task.id.as_str()).collect();

        let mut driver = Driver::start(&ids);
        driver.step(
            load(&ids),
            CommitRevealResult::TasksLoaded {
                tasks: tasks.iter().map(|task| Some(task.clone())).collect(),
            },
        );
        for task in &tasks {
            driver.step(check(task), exists(false));
        }
        driver.step(
            CommitRevealOperation::GetCurrentBlock,
            CommitRevealResult::CurrentBlock {
                block: 9,
                now_ms: 1_000,
            },
        );
        for task in &tasks {
            driver.step(
                CommitRevealOperation::GetCommitBlock {
                    commitment: commitment_hex(task),
                },
                commit_block(3, 1_100),
            );
        }
        for task in &tasks {
            driver.step(check(task), exists(false));
        }

        // First chunk: ten tasks; second chunk: the remaining two.
        driver.step(
            CommitRevealOperation::SubmitCreate {
                tasks: tasks[..10].to_vec(),
            },
            CommitRevealResult::Tx(TxOutcome::Confirmed {
                tx_hash: "0x1".into(),
            }),
        );
        for task in &tasks[..10] {
            driver.step(
                CommitRevealOperation::MarkDone {
                    task_id: task.id.clone(),
                    tx_hash: Some("0x1".into()),
                },
                CommitRevealResult::Persisted,
            );
        }
        driver.step(
            CommitRevealOperation::SubmitCreate {
                tasks: tasks[10..].to_vec(),
            },
            CommitRevealResult::Tx(TxOutcome::Confirmed {
                tx_hash: "0x2".into(),
            }),
        );
        for task in &tasks[10..] {
            driver.step(
                CommitRevealOperation::MarkDone {
                    task_id: task.id.clone(),
                    tx_hash: Some("0x2".into()),
                },
                CommitRevealResult::Persisted,
            );
        }
        driver.assert_settled(advance());
    }

    // ── Mutation-killing coverage ──────────────────────────────────────────
    //
    // Each test below was written against a specific mutation that survived
    // the first review round; together they pin the branches the original
    // sixteen scenarios missed.

    #[test]
    fn empty_envelope_batch_advances_without_loading() {
        let driver = Driver::start(&[]);
        driver.assert_settled(advance());
    }

    #[test]
    fn mixed_pending_and_committed_batch_merges_for_reveal() {
        // A receipt-timeout retry naturally mixes directly-Committed tasks
        // with Pending ones. The directly-Committed task must survive the
        // post-commit reload merge (append, never overwrite).
        let pending = task("p", TaskStatus::Pending);
        let direct = task("c", TaskStatus::Committed);
        let mut pending_committed = pending.clone();
        pending_committed.status = TaskStatus::Committed;

        let mut driver = Driver::start(&["p", "c"]);
        driver.step(load(&["p", "c"]), loaded(&[&pending, &direct]));
        driver.step(check(&pending), exists(false));
        driver.step(check(&direct), exists(false));

        driver.step(
            CommitRevealOperation::SubmitCommit {
                tasks: vec![pending.clone()],
            },
            CommitRevealResult::Tx(TxOutcome::Confirmed {
                tx_hash: "0xc0".into(),
            }),
        );
        driver.step(
            CommitRevealOperation::MarkCommitted {
                task_id: "p".into(),
            },
            CommitRevealResult::Persisted,
        );
        driver.step(load(&["p"]), loaded(&[&pending_committed]));

        // Reveal must poll the directly-Committed task first, then the
        // reloaded one — the merge order is reconcile-first, reload-appended.
        driver.step(
            CommitRevealOperation::GetCurrentBlock,
            CommitRevealResult::CurrentBlock {
                block: 9,
                now_ms: 1_000,
            },
        );
        driver.step(probe(&direct), commit_block(3, 1_050));
        driver.step(probe(&pending_committed), commit_block(3, 1_100));
        driver.step(check(&direct), exists(false));
        driver.step(check(&pending_committed), exists(false));

        // Both tasks must reach the create batch, in merge order.
        driver.step(
            CommitRevealOperation::SubmitCreate {
                tasks: vec![direct.clone(), pending_committed.clone()],
            },
            CommitRevealResult::Tx(TxOutcome::Confirmed {
                tx_hash: "0xok".into(),
            }),
        );
        driver.step(
            CommitRevealOperation::MarkDone {
                task_id: "c".into(),
                tx_hash: Some("0xok".into()),
            },
            CommitRevealResult::Persisted,
        );
        driver.step(
            CommitRevealOperation::MarkDone {
                task_id: "p".into(),
                tx_hash: Some("0xok".into()),
            },
            CommitRevealResult::Persisted,
        );
        driver.assert_settled(advance());
    }

    #[test]
    fn record_exists_error_during_commit_reconciles_to_done() {
        // classify_task's RecordExists arm: the write failed because the
        // record is already on chain — that is retroactive success, MarkDone.
        let pending = task("a", TaskStatus::Pending);
        let mut driver = Driver::start(&["a"]);
        driver.step(load(&["a"]), loaded(&[&pending]));
        driver.step(check(&pending), exists(false));
        driver.step(
            CommitRevealOperation::SubmitCommit {
                tasks: vec![pending.clone()],
            },
            CommitRevealResult::Tx(TxOutcome::SendFailed {
                error: ChainError::Rejected("RecordAlreadyExists".into()),
            }),
        );
        driver.step(
            CommitRevealOperation::MarkDone {
                task_id: "a".into(),
                tx_hash: None,
            },
            CommitRevealResult::Persisted,
        );
        // The name marker makes the rejection non-transient → the commit
        // stage completes; the reload finds the task terminal and the batch
        // advances.
        let mut done = pending.clone();
        done.status = TaskStatus::Done;
        driver.step(load(&["a"]), loaded(&[&done]));
        driver.assert_settled(advance());
    }

    #[test]
    fn selector_only_record_exists_marks_done_but_still_retries_the_batch() {
        // Inherited predicate overlap, deliberately preserved: an error text
        // carrying only the selector 0x46a08bc5 classifies as RecordExists
        // (selectors count there) yet still counts as transient in
        // classify_batch's final gate (is_transient checks name markers and
        // revert phrasing, not selectors). The original worker behaved the
        // same way: the task is reconciled to done AND the batch retries —
        // harmless, because the next round's reconciliation skips the
        // now-terminal task. This test exists to break any refactor that
        // "simplifies" the two checks into one.
        let pending = task("a", TaskStatus::Pending);
        let mut driver = Driver::start(&["a"]);
        driver.step(load(&["a"]), loaded(&[&pending]));
        driver.step(check(&pending), exists(false));
        driver.step(
            CommitRevealOperation::SubmitCommit {
                tasks: vec![pending.clone()],
            },
            CommitRevealResult::Tx(TxOutcome::SendFailed {
                error: ChainError::Rejected("data: 0x46a08bc5".into()),
            }),
        );
        driver.step(
            CommitRevealOperation::MarkDone {
                task_id: "a".into(),
                tx_hash: None,
            },
            CommitRevealResult::Persisted,
        );
        driver.assert_settled(retry_verdict("chain write temporarily failed"));
    }

    #[test]
    fn poison_receipt_uncertainty_classifies_terminal_and_continues() {
        // A Reverted-flavoured receipt error is Poison (never transient):
        // classify_task must MarkFailed{Poison} with the Display message and
        // the batch must then continue (non-transient), not retry.
        let pending = task("a", TaskStatus::Pending);
        let mut driver = Driver::start(&["a"]);
        driver.step(load(&["a"]), loaded(&[&pending]));
        driver.step(check(&pending), exists(false));
        driver.step(
            CommitRevealOperation::SubmitCommit {
                tasks: vec![pending.clone()],
            },
            CommitRevealResult::Tx(TxOutcome::ReceiptUncertain {
                error: ChainError::Reverted("assert failed".into()),
            }),
        );
        driver.step(
            CommitRevealOperation::MarkFailed {
                task_id: "a".into(),
                kind: FailureKind::Poison,
                message: "batchCommit: EVM execution reverted".into(),
            },
            CommitRevealResult::Persisted,
        );
        let mut failed = pending.clone();
        failed.status = TaskStatus::Failed;
        driver.step(load(&["a"]), loaded(&[&failed]));
        driver.assert_settled(advance());
    }

    #[test]
    fn isolated_commit_single_resubmit_success_reaches_committed_not_done() {
        // The isolation recovery path: a lone re-commit that confirms must
        // mark the task Committed (it still needs reveal + create), never
        // Done.
        let pending = task("a", TaskStatus::Pending);
        let mut committed = pending.clone();
        committed.status = TaskStatus::Committed;

        let mut driver = Driver::start(&["a"]);
        driver.step(load(&["a"]), loaded(&[&pending]));
        driver.step(check(&pending), exists(false));
        driver.step(
            CommitRevealOperation::SubmitCommit {
                tasks: vec![pending.clone()],
            },
            CommitRevealResult::Tx(TxOutcome::Reverted {
                tx_hash: "0xdead".into(),
            }),
        );
        // Probe finds no commitment on chain → single re-commit confirms.
        driver.step(probe(&pending), commit_block(0, 500));
        driver.step(
            CommitRevealOperation::SubmitCommit {
                tasks: vec![pending.clone()],
            },
            CommitRevealResult::Tx(TxOutcome::Confirmed {
                tx_hash: "0xretry".into(),
            }),
        );
        driver.step(
            CommitRevealOperation::MarkCommitted {
                task_id: "a".into(),
            },
            CommitRevealResult::Persisted,
        );
        driver.step(load(&["a"]), loaded(&[&committed]));

        driver.step(
            CommitRevealOperation::GetCurrentBlock,
            CommitRevealResult::CurrentBlock {
                block: 9,
                now_ms: 1_000,
            },
        );
        driver.step(probe(&committed), commit_block(3, 1_100));
        driver.step(check(&committed), exists(true));
        driver.step(
            CommitRevealOperation::MarkDone {
                task_id: "a".into(),
                tx_hash: None,
            },
            CommitRevealResult::Persisted,
        );
        driver.assert_settled(advance());
    }

    #[test]
    fn isolated_commit_probe_read_failure_falls_through_to_single_recommit() {
        // The worker's `if let Ok(..) && .. && block > 0` chain: a failed
        // probe is not an error, it just skips the shortcut.
        let pending = task("a", TaskStatus::Pending);
        let mut committed = pending.clone();
        committed.status = TaskStatus::Committed;

        let mut driver = Driver::start(&["a"]);
        driver.step(load(&["a"]), loaded(&[&pending]));
        driver.step(check(&pending), exists(false));
        driver.step(
            CommitRevealOperation::SubmitCommit {
                tasks: vec![pending.clone()],
            },
            CommitRevealResult::Tx(TxOutcome::Reverted {
                tx_hash: "0xdead".into(),
            }),
        );
        driver.step(probe(&pending), CommitRevealResult::ChainReadFailed);
        driver.step(
            CommitRevealOperation::SubmitCommit {
                tasks: vec![pending.clone()],
            },
            CommitRevealResult::Tx(TxOutcome::Confirmed {
                tx_hash: "0xretry".into(),
            }),
        );
        driver.step(
            CommitRevealOperation::MarkCommitted {
                task_id: "a".into(),
            },
            CommitRevealResult::Persisted,
        );
        driver.step(load(&["a"]), loaded(&[&committed]));
        driver.step(
            CommitRevealOperation::GetCurrentBlock,
            CommitRevealResult::CurrentBlock {
                block: 9,
                now_ms: 1_000,
            },
        );
        driver.step(probe(&committed), commit_block(3, 1_100));
        driver.step(check(&committed), exists(true));
        driver.step(
            CommitRevealOperation::MarkDone {
                task_id: "a".into(),
                tx_hash: None,
            },
            CommitRevealResult::Persisted,
        );
        driver.assert_settled(advance());
    }

    #[test]
    fn isolated_commit_receipt_uncertainty_aborts_the_batch() {
        let pending = task("a", TaskStatus::Pending);
        let mut driver = Driver::start(&["a"]);
        driver.step(load(&["a"]), loaded(&[&pending]));
        driver.step(check(&pending), exists(false));
        driver.step(
            CommitRevealOperation::SubmitCommit {
                tasks: vec![pending.clone()],
            },
            CommitRevealResult::Tx(TxOutcome::Reverted {
                tx_hash: "0xdead".into(),
            }),
        );
        driver.step(probe(&pending), commit_block(0, 500));
        driver.step(
            CommitRevealOperation::SubmitCommit {
                tasks: vec![pending.clone()],
            },
            CommitRevealResult::Tx(TxOutcome::ReceiptUncertain {
                error: ChainError::Unavailable,
            }),
        );
        driver.step(
            CommitRevealOperation::RecordTransientFailure {
                task_id: "a".into(),
                message: "batchCommit: chain RPC temporarily unavailable".into(),
            },
            CommitRevealResult::Persisted,
        );
        driver.assert_settled(retry_verdict("isolated commit receipt wait failed"));
    }

    #[test]
    fn isolation_continues_past_a_non_transient_conflict() {
        // A terminal classification in the isolation loop must not abort the
        // remaining tasks: t1 hits a wallet conflict, t2 still re-commits.
        let one = task("t1", TaskStatus::Pending);
        let two = task("t2", TaskStatus::Pending);
        let mut two_committed = two.clone();
        two_committed.status = TaskStatus::Committed;

        let mut driver = Driver::start(&["t1", "t2"]);
        driver.step(load(&["t1", "t2"]), loaded(&[&one, &two]));
        driver.step(check(&one), exists(false));
        driver.step(check(&two), exists(false));
        driver.step(
            CommitRevealOperation::SubmitCommit {
                tasks: vec![one.clone(), two.clone()],
            },
            CommitRevealResult::Tx(TxOutcome::Reverted {
                tx_hash: "0xdead".into(),
            }),
        );
        // t1: no shortcut, single re-commit is rejected with a conflict.
        driver.step(probe(&one), commit_block(0, 500));
        driver.step(
            CommitRevealOperation::SubmitCommit {
                tasks: vec![one.clone()],
            },
            CommitRevealResult::Tx(TxOutcome::SendFailed {
                error: ChainError::Rejected("WalletRefAlreadyExists".into()),
            }),
        );
        driver.step(
            CommitRevealOperation::MarkFailed {
                task_id: "t1".into(),
                kind: FailureKind::Conflict,
                message: "batchCommit: chain RPC rejected the request".into(),
            },
            CommitRevealResult::Persisted,
        );
        // Non-transient → continue with t2.
        driver.step(probe(&two), commit_block(0, 600));
        driver.step(
            CommitRevealOperation::SubmitCommit {
                tasks: vec![two.clone()],
            },
            CommitRevealResult::Tx(TxOutcome::Confirmed {
                tx_hash: "0xok".into(),
            }),
        );
        driver.step(
            CommitRevealOperation::MarkCommitted {
                task_id: "t2".into(),
            },
            CommitRevealResult::Persisted,
        );
        let mut one_failed = one.clone();
        one_failed.status = TaskStatus::Failed;
        driver.step(load(&["t1", "t2"]), loaded(&[&one_failed, &two_committed]));
        driver.step(
            CommitRevealOperation::GetCurrentBlock,
            CommitRevealResult::CurrentBlock {
                block: 9,
                now_ms: 1_000,
            },
        );
        driver.step(probe(&two_committed), commit_block(3, 1_100));
        driver.step(check(&two_committed), exists(true));
        driver.step(
            CommitRevealOperation::MarkDone {
                task_id: "t2".into(),
                tx_hash: None,
            },
            CommitRevealResult::Persisted,
        );
        driver.assert_settled(advance());
    }

    #[test]
    fn isolated_create_continues_past_a_non_transient_conflict() {
        // Mirror of isolation_continues_past_a_non_transient_conflict on the
        // create side: a terminal classification in the isolation loop must
        // not abort the remaining tasks.
        let one = task("t1", TaskStatus::Committed);
        let two = task("t2", TaskStatus::Committed);
        let mut driver = Driver::start(&["t1", "t2"]);
        driver.step(load(&["t1", "t2"]), loaded(&[&one, &two]));
        driver.step(check(&one), exists(false));
        driver.step(check(&two), exists(false));
        driver.step(
            CommitRevealOperation::GetCurrentBlock,
            CommitRevealResult::CurrentBlock {
                block: 9,
                now_ms: 1_000,
            },
        );
        driver.step(probe(&one), commit_block(3, 1_050));
        driver.step(probe(&two), commit_block(3, 1_100));
        driver.step(check(&one), exists(false));
        driver.step(check(&two), exists(false));
        driver.step(
            CommitRevealOperation::SubmitCreate {
                tasks: vec![one.clone(), two.clone()],
            },
            CommitRevealResult::Tx(TxOutcome::Reverted {
                tx_hash: "0xdead".into(),
            }),
        );
        // t1: single create rejected with a conflict → terminal, continue.
        driver.step(check(&one), exists(false));
        driver.step(
            CommitRevealOperation::SubmitCreate {
                tasks: vec![one.clone()],
            },
            CommitRevealResult::Tx(TxOutcome::SendFailed {
                error: ChainError::Rejected("WalletRefAlreadyExists".into()),
            }),
        );
        driver.step(
            CommitRevealOperation::MarkFailed {
                task_id: "t1".into(),
                kind: FailureKind::Conflict,
                message: "createRecord: chain RPC rejected the request".into(),
            },
            CommitRevealResult::Persisted,
        );
        // t2 must still be processed.
        driver.step(check(&two), exists(false));
        driver.step(
            CommitRevealOperation::SubmitCreate {
                tasks: vec![two.clone()],
            },
            CommitRevealResult::Tx(TxOutcome::Confirmed {
                tx_hash: "0xok".into(),
            }),
        );
        driver.step(
            CommitRevealOperation::MarkDone {
                task_id: "t2".into(),
                tx_hash: Some("0xok".into()),
            },
            CommitRevealResult::Persisted,
        );
        driver.assert_settled(advance());
    }

    #[test]
    fn create_receipt_uncertainty_classifies_batch_wide_not_isolating() {
        // The deliberate asymmetry pinned from the other side: a create
        // receipt error must classify batch-wide (no CheckRecord-first
        // isolation probing) and a transient error retries the batch.
        let committed = task("a", TaskStatus::Committed);
        let mut driver = Driver::start(&["a"]);
        driver.step(load(&["a"]), loaded(&[&committed]));
        driver.step(check(&committed), exists(false));
        driver.step(
            CommitRevealOperation::GetCurrentBlock,
            CommitRevealResult::CurrentBlock {
                block: 9,
                now_ms: 1_000,
            },
        );
        driver.step(probe(&committed), commit_block(3, 1_100));
        driver.step(check(&committed), exists(false));
        driver.step(
            CommitRevealOperation::SubmitCreate {
                tasks: vec![committed.clone()],
            },
            CommitRevealResult::Tx(TxOutcome::ReceiptUncertain {
                error: ChainError::Unavailable,
            }),
        );
        driver.step(
            CommitRevealOperation::RecordTransientFailure {
                task_id: "a".into(),
                message: "batchCreateRecord: chain RPC temporarily unavailable".into(),
            },
            CommitRevealResult::Persisted,
        );
        driver.assert_settled(retry_verdict("chain write temporarily failed"));
    }

    #[test]
    fn isolated_create_receipt_uncertainty_aborts_the_batch() {
        let committed = task("a", TaskStatus::Committed);
        let mut driver = Driver::start(&["a"]);
        driver.step(load(&["a"]), loaded(&[&committed]));
        driver.step(check(&committed), exists(false));
        driver.step(
            CommitRevealOperation::GetCurrentBlock,
            CommitRevealResult::CurrentBlock {
                block: 9,
                now_ms: 1_000,
            },
        );
        driver.step(probe(&committed), commit_block(3, 1_100));
        driver.step(check(&committed), exists(false));
        driver.step(
            CommitRevealOperation::SubmitCreate {
                tasks: vec![committed.clone()],
            },
            CommitRevealResult::Tx(TxOutcome::Reverted {
                tx_hash: "0xdead".into(),
            }),
        );
        driver.step(check(&committed), exists(false));
        driver.step(
            CommitRevealOperation::SubmitCreate {
                tasks: vec![committed.clone()],
            },
            CommitRevealResult::Tx(TxOutcome::ReceiptUncertain {
                error: ChainError::Unavailable,
            }),
        );
        driver.step(
            CommitRevealOperation::RecordTransientFailure {
                task_id: "a".into(),
                message: "createRecord: chain RPC temporarily unavailable".into(),
            },
            CommitRevealResult::Persisted,
        );
        driver.assert_settled(retry_verdict("isolated create receipt wait failed"));
    }

    #[test]
    fn isolated_create_transient_send_failure_aborts_after_marking() {
        let committed = task("a", TaskStatus::Committed);
        let mut driver = Driver::start(&["a"]);
        driver.step(load(&["a"]), loaded(&[&committed]));
        driver.step(check(&committed), exists(false));
        driver.step(
            CommitRevealOperation::GetCurrentBlock,
            CommitRevealResult::CurrentBlock {
                block: 9,
                now_ms: 1_000,
            },
        );
        driver.step(probe(&committed), commit_block(3, 1_100));
        driver.step(check(&committed), exists(false));
        driver.step(
            CommitRevealOperation::SubmitCreate {
                tasks: vec![committed.clone()],
            },
            CommitRevealResult::Tx(TxOutcome::Reverted {
                tx_hash: "0xdead".into(),
            }),
        );
        driver.step(check(&committed), exists(false));
        driver.step(
            CommitRevealOperation::SubmitCreate {
                tasks: vec![committed.clone()],
            },
            CommitRevealResult::Tx(TxOutcome::SendFailed {
                error: ChainError::Unavailable,
            }),
        );
        driver.step(
            CommitRevealOperation::RecordTransientFailure {
                task_id: "a".into(),
                message: "createRecord: chain RPC temporarily unavailable".into(),
            },
            CommitRevealResult::Persisted,
        );
        driver.assert_settled(retry_verdict("isolated create temporarily failed"));
    }

    #[test]
    fn reveal_becomes_ready_after_a_sleep_and_exactly_one_block_deep() {
        // Liveness: poll → not ready at current == commit → sleep → ready at
        // exactly current == commit + 1 → the flow proceeds to create. Pins
        // the +1 boundary in both directions.
        let committed = task("a", TaskStatus::Committed);
        let mut driver = Driver::start(&["a"]);
        driver.step(load(&["a"]), loaded(&[&committed]));
        driver.step(check(&committed), exists(false));

        driver.step(
            CommitRevealOperation::GetCurrentBlock,
            CommitRevealResult::CurrentBlock {
                block: 5,
                now_ms: 1_000,
            },
        );
        driver.step(probe(&committed), commit_block(5, 1_500));
        driver.step(
            CommitRevealOperation::Sleep { ms: REVEAL_POLL_MS },
            CommitRevealResult::Slept { now_ms: 3_500 },
        );
        driver.step(
            CommitRevealOperation::GetCurrentBlock,
            CommitRevealResult::CurrentBlock {
                block: 6,
                now_ms: 3_600,
            },
        );
        driver.step(probe(&committed), commit_block(5, 3_700));
        driver.step(check(&committed), exists(false));
        driver.step(
            CommitRevealOperation::SubmitCreate {
                tasks: vec![committed.clone()],
            },
            CommitRevealResult::Tx(TxOutcome::Confirmed {
                tx_hash: "0xok".into(),
            }),
        );
        driver.step(
            CommitRevealOperation::MarkDone {
                task_id: "a".into(),
                tx_hash: Some("0xok".into()),
            },
            CommitRevealResult::Persisted,
        );
        driver.assert_settled(advance());
    }

    #[test]
    fn vanished_commitment_with_record_preserves_the_original_tx_hash() {
        let mut committed = task("a", TaskStatus::Committed);
        committed.tx_hash = Some("0xprev".into());
        let mut driver = Driver::start(&["a"]);
        driver.step(load(&["a"]), loaded(&[&committed]));
        driver.step(check(&committed), exists(false));
        driver.step(
            CommitRevealOperation::GetCurrentBlock,
            CommitRevealResult::CurrentBlock {
                block: 5,
                now_ms: 1_000,
            },
        );
        driver.step(probe(&committed), commit_block(0, 1_100));
        driver.step(check(&committed), exists(true));
        driver.step(
            CommitRevealOperation::MarkDone {
                task_id: "a".into(),
                tx_hash: Some("0xprev".into()),
            },
            CommitRevealResult::Persisted,
        );
        // The vanish branch does not unset readiness; the pass ends ready and
        // post-reveal reconciliation sees the record again.
        driver.step(check(&committed), exists(true));
        driver.step(
            CommitRevealOperation::MarkDone {
                task_id: "a".into(),
                tx_hash: Some("0xprev".into()),
            },
            CommitRevealResult::Persisted,
        );
        driver.assert_settled(advance());
    }

    #[test]
    fn current_block_read_failure_uses_its_own_reason() {
        let committed = task("a", TaskStatus::Committed);
        let mut driver = Driver::start(&["a"]);
        driver.step(load(&["a"]), loaded(&[&committed]));
        driver.step(check(&committed), exists(false));
        driver.step(
            CommitRevealOperation::GetCurrentBlock,
            CommitRevealResult::ChainReadFailed,
        );
        driver.assert_settled(retry_verdict("could not read current block"));
    }

    #[test]
    fn commit_block_read_failure_uses_its_own_reason() {
        let committed = task("a", TaskStatus::Committed);
        let mut driver = Driver::start(&["a"]);
        driver.step(load(&["a"]), loaded(&[&committed]));
        driver.step(check(&committed), exists(false));
        driver.step(
            CommitRevealOperation::GetCurrentBlock,
            CommitRevealResult::CurrentBlock {
                block: 9,
                now_ms: 1_000,
            },
        );
        driver.step(probe(&committed), CommitRevealResult::ChainReadFailed);
        driver.assert_settled(retry_verdict("could not read commit block"));
    }

    #[test]
    fn reschedule_persist_failure_uses_could_not_reschedule_task() {
        let committed = task("a", TaskStatus::Committed);
        let mut driver = Driver::start(&["a"]);
        driver.step(load(&["a"]), loaded(&[&committed]));
        driver.step(check(&committed), exists(false));
        driver.step(
            CommitRevealOperation::GetCurrentBlock,
            CommitRevealResult::CurrentBlock {
                block: 5,
                now_ms: 1_000,
            },
        );
        driver.step(probe(&committed), commit_block(0, 1_100));
        driver.step(check(&committed), exists(false));
        driver.step(
            CommitRevealOperation::MarkPendingAgain {
                task_id: "a".into(),
                reason: "commitment missing; re-committing".into(),
            },
            CommitRevealResult::StoreUnavailable,
        );
        driver.assert_settled(retry_verdict("could not reschedule task"));
    }

    #[test]
    fn reload_store_outage_uses_could_not_reload_committed_task() {
        let pending = task("a", TaskStatus::Pending);
        let mut driver = Driver::start(&["a"]);
        driver.step(load(&["a"]), loaded(&[&pending]));
        driver.step(check(&pending), exists(false));
        driver.step(
            CommitRevealOperation::SubmitCommit {
                tasks: vec![pending.clone()],
            },
            CommitRevealResult::Tx(TxOutcome::Confirmed {
                tx_hash: "0xc0".into(),
            }),
        );
        driver.step(
            CommitRevealOperation::MarkCommitted {
                task_id: "a".into(),
            },
            CommitRevealResult::Persisted,
        );
        driver.step(load(&["a"]), CommitRevealResult::StoreUnavailable);
        driver.assert_settled(retry_verdict("could not reload committed task"));
    }
}
