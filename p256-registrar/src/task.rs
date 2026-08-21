//! The task lifecycle vocabulary shared by both write operations.
//!
//! A task carries one chain write from an accepted request to its on-chain
//! outcome. Two kinds exist, mirroring the contract's two writes:
//!
//! - `Register`: one frozen group — a single-use group key plus 1..7
//!   possession-proven member passkeys sharing an rpId and an opaque
//!   metadata payload. The group proof binds the group's content hash;
//!   every member proof binds (groupKey, own attestation).
//! - `Refer`: one passkey pointing at an existing group. Exactly one
//!   member whose proof binds (groupKey, own attestation, reference
//!   metadata).
//!
//! Status walks Pending → Done/Failed with no intermediate state. The
//! task's `content_hash` is its identity and the service's idempotency
//! key: the contract contentHash for Register, a service-side digest of
//! (groupKey, member, metadata) for Refer.

use serde::{Deserialize, Serialize};

/// The WebAuthn-formatted possession proof, mirroring the registry's
/// `Proof` struct: `(r, s)` signs
/// `sha256(authenticatorData || sha256(clientDataJSON))`, and clientDataJSON
/// carries base64url(the signer's storage-authorization challenge) at
/// `challenge_index`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Proof {
    /// Hex (0x optional): rpIdHash(32) || flags(1) || counter(4) [|| ...].
    pub authenticator_data: String,
    /// The raw JSON string, exactly as signed.
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    pub challenge_index: u64,
    pub type_index: u64,
    /// Hex 32-byte scalars.
    pub r: String,
    pub s: String,
}

/// One member passkey, mirroring the registry's `Member`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Member {
    /// Uncompressed P-256 point: 04 || x || y, hex (0x optional).
    pub public_key: String,
    /// Empty, or 20 versioned bytes of registration-time WebAuthn signals.
    #[serde(default)]
    pub attestation: String,
    pub proof: Proof,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TaskKind {
    Register,
    Refer,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterTask {
    pub id: String,
    pub status: TaskStatus,
    pub kind: TaskKind,
    /// The group's rpId. For Refer it is client-supplied and re-verified
    /// against the group's frozen record by the contract.
    pub rp_id: String,
    /// Register: the group's opaque payload. Refer: the reference's opaque
    /// payload. Hex, may be empty.
    pub metadata: String,
    /// The task's identity and idempotency key (0x-hex): the contract
    /// contentHash for Register, a service-side digest for Refer. Set once
    /// at validation.
    pub content_hash: String,
    /// The group key: uncompressed P-256 point hex. Single-use and
    /// client-held for Register; the target group's identity for Refer.
    pub group_public_key: String,
    /// The group key's content-bound closing proof — Register only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_proof: Option<Proof>,
    /// Register: 1..=7 members. Refer: exactly one (the referring key).
    pub members: Vec<Member>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
    /// The confirmed on-chain id once Done: the unitId for Register, the
    /// referenceId for Refer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_chain_id: Option<u64>,
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
    Done,
    Failed,
}

impl TaskStatus {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Done | Self::Failed)
    }
}
