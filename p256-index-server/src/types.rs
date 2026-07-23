use serde::{Deserialize, Serialize};

pub const CONTRACT_ADDRESS: &str = "0xdd93420BD49baaBdFF4A363DdD300622Ae87E9c3";
pub const BATCH_HELPER_ADDRESS: &str = "0xc7B0db5d4974abA3EA25780f40Bf369CC013a16E";
pub const CHAIN_ID: u64 = 100;

#[derive(Clone, Debug, Deserialize)]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Record {
    pub rp_id: String,
    pub credential_id: String,
    pub wallet_ref: String,
    pub public_key: String,
    pub name: String,
    pub initial_credential_id: String,
    pub metadata: String,
    pub created_at: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteItem {
    pub rp_id: String,
    pub public_key_count: u64,
    pub created_at: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Page<T> {
    pub total: u64,
    pub page: u64,
    pub page_size: u64,
    pub items: Vec<T>,
}
