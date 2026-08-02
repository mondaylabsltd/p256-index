//! The `CreateTask` lifecycle vocabulary.
//!
//! A task is the unit of work that carries one credential from an accepted
//! create request to an on-chain record. Its status walks Pending → Committed
//! → Done/Failed; the transition rules currently live in the server's worker
//! and store and will migrate here as the `commit_reveal` domain.

use serde::{Deserialize, Serialize};

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub retries: u32,
    pub created_at: i64,
    pub admitted: bool,
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
