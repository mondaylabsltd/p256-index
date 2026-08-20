//! The `CreateTask` lifecycle vocabulary.
//!
//! A task is the unit of work that carries one credential from an accepted
//! create request to an on-chain record. Its status walks Pending → Committed
//! → Done/Failed; the transition rules currently live in the server's worker
//! and store and will migrate here as the `commit_reveal` domain.

use serde::{Deserialize, Serialize};

/// One member of a multi-key wallet task, mirroring the contract's
/// `WalletMember` struct (credential + key in derivation order).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletMember {
    pub credential_id: String,
    pub public_key: String,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTask {
    pub id: String,
    pub status: TaskStatus,
    pub rp_id: String,
    pub credential_id: String,
    pub wallet_ref: String,
    pub public_key: String,
    pub name: String,
    pub initial_credential_id: String,
    pub metadata: String,
    /// Non-empty marks a multi-key WALLET task: the reveal is one atomic
    /// `createWallet(rpId, walletRef, members)` call. The flat fields above
    /// mirror `members[0]` so every single-record code path (placeholders,
    /// reconciliation via the first member, disclosure) keeps working.
    /// Empty (the serde default) is a plain single-key `createRecord` task,
    /// keeping old queue/store payloads byte-compatible.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<WalletMember>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub retries: u32,
    pub created_at: i64,
    pub admitted: bool,
}

impl CreateTask {
    /// True for a multi-key wallet task (atomic `createWallet` reveal).
    pub fn is_wallet(&self) -> bool {
        !self.members.is_empty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TaskStatus {
    Pending,
    Committed,
    Done,
    Failed,
}

impl TaskStatus {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Done | Self::Failed)
    }
}
