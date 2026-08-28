//! The edge ↔ Durable Object wire vocabulary. Everything else on the wire
//! is a registrar type serialized as-is.

use serde::{Deserialize, Serialize};

use p256_registrar::{admission::AdmissionRequest, task::RegisterTask};

/// One admission, forwarded by the edge after transport validation. The raw
/// IP never crosses this boundary — only its salted hash.
#[derive(Serialize, Deserialize)]
pub struct AdmitCall {
    pub request: AdmissionRequest,
    pub ip_hash: String,
}

#[derive(Serialize, Deserialize)]
pub struct TaskEnvelope {
    pub task: Option<RegisterTask>,
}

#[derive(Serialize, Deserialize)]
pub struct AllowedEnvelope {
    pub allowed: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatsEnvelope {
    pub depth: u64,
    pub dlq: u64,
    pub oldest_job_age_ms: u64,
    pub worker_stalled: bool,
}
