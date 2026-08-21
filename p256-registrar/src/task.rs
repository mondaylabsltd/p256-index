//! The `RegisterTask` lifecycle vocabulary.
//!
//! A task carries one registration unit — a group key plus 1..7
//! possession-proven member passkeys sharing an rpId and an opaque metadata
//! payload; the group proof binds the unit's content hash and every member
//! proof binds (groupKey, own attestation) — from an accepted request to
//! on-chain entries. Its status walks Pending → Done/Failed with no
//! intermediate state. The content hash is the unit's identity and the
//! service's idempotency key.

use serde::{Deserialize, Serialize};

/// The WebAuthn-formatted possession proof for one member, mirroring the
/// registry's `Proof` struct: `(r, s)` signs
/// `sha256(authenticatorData || sha256(clientDataJSON))`, and clientDataJSON
/// carries base64url(the member's storage-authorization challenge) at
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

/// One member of a registration unit, mirroring the registry's `Member`.
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterTask {
    pub id: String,
    pub status: TaskStatus,
    pub rp_id: String,
    /// The unit's shared opaque payload, hex, may be empty. Credential ids,
    /// display names, wallet derivation preimages — all caller-defined.
    pub metadata: String,
    /// The unit's content hash (0x-hex), keccak over (rpId, metadata,
    /// groupPublicKey, member hashes) exactly as the contract computes it:
    /// the unit's stable identity, the service's idempotency key, and the
    /// value the group key's challenge binds. Set once at validation.
    pub content_hash: String,
    /// The unit's group key: an uncompressed P-256 point (hex), client-held
    /// software key. Every unit has exactly one; members bind it.
    pub group_public_key: String,
    /// The group key's content-bound closing proof over the whole unit.
    pub group_proof: Proof,
    /// 1..=7 members, registered atomically in one `register` transaction.
    pub members: Vec<Member>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
    /// The unit's first on-chain entry id once Done; members occupy
    /// `first_entry_id .. first_entry_id + members.len()` contiguously.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_entry_id: Option<u64>,
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
