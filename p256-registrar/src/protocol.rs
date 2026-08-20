//! The on-chain registry protocol: calldata encoding, response decoding,
//! challenge construction, and the single home for chain-error
//! classification.
//!
//! The registry (`WebAuthnP256PublicKeyRegistry`) is an append-only log of
//! possession-proven P-256 public keys. There is one write —
//! `register(rpId, metadata, unitNonce, members)` — and read views joined as
//! `EntryView`. No commit-reveal exists: a registration is one transaction.

use alloy::{
    primitives::{Address, B256, U256, keccak256},
    sol,
    sol_types::{SolCall, SolValue},
};
use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};

use crate::lookup::Entry;
use crate::task::RegisterTask;

pub const CHAIN_ID: u64 = 100;

/// Revert selectors of the registry's terminal classifications.
pub const SELECTOR_NONCE_ALREADY_USED: &str = "0x8c242285";
pub const SELECTOR_UNIT_ALREADY_REGISTERED: &str = "0x3cd13628";
pub const SELECTOR_INVALID_PROOF: &str = "0x09bde339";

/// keccak("UnitRegistered(uint256,bytes32,uint256,uint256)") — the receipt
/// log the shell parses to learn a confirmed unit's ids.
pub const UNIT_REGISTERED_TOPIC: &str =
    "0xb98a5d6ba38178d12f1bddae50c0268ec87d36ee974b0e7ac85d2f8ae5c9e856";

sol! {
    struct EntryViewSol {
        uint256 entryId;
        uint256 unitId;
        bytes publicKey;
        bytes attestation;
        string rpId;
        bytes metadata;
        uint64 firstEntryId;
        uint32 memberCount;
        uint256 createdAt;
    }

    struct ProofSol {
        bytes authenticatorData;
        string clientDataJSON;
        uint256 challengeIndex;
        uint256 typeIndex;
        uint256 r;
        uint256 s;
    }

    struct MemberSol {
        bytes publicKey;
        bytes attestation;
        ProofSol proof;
    }

    interface WebAuthnP256PublicKeyRegistry {
        function register(string calldata rpId, bytes calldata metadata, bytes32 unitNonce, MemberSol[] calldata members) external;
        function getTotalUnits() external view returns (uint256);
        function getTotalEntries() external view returns (uint256);
        function getEntry(uint256 entryId) external view returns (EntryViewSol memory);
        function hasEntries(bytes calldata publicKey) external view returns (bool);
        function getEntriesByKey(bytes calldata publicKey, uint256 offset, uint256 limit, bool desc)
            external view returns (uint256 total, EntryViewSol[] memory records);
        function getEntriesByRpId(string calldata rpId, uint256 offset, uint256 limit, bool desc)
            external view returns (uint256 total, EntryViewSol[] memory records);
        function getTotalRpIds() external view returns (uint256);
        function getRpIds(uint256 offset, uint256 limit, bool desc)
            external view returns (uint256 total, string[] memory rpIds, uint256[] memory counts, uint256[] memory createdAts);
        function isNonceUsed(bytes32 unitNonce) external view returns (bool);
        function isContentRegistered(bytes32 contentHash) external view returns (bool);
    }
}

// ── Chain-error vocabulary ─────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "message", rename_all = "snake_case")]
pub enum ChainError {
    Unavailable,
    Reverted(String),
    InvalidResponse,
    MissingSigner,
    Rejected(String),
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable => formatter.write_str("chain RPC temporarily unavailable"),
            Self::Reverted(_) => formatter.write_str("EVM execution reverted"),
            Self::InvalidResponse => formatter.write_str("chain RPC returned an invalid response"),
            Self::MissingSigner => formatter.write_str("PRIVATE_KEY is required for chain writes"),
            Self::Rejected(_) => formatter.write_str("chain RPC rejected the request"),
        }
    }
}

impl std::error::Error for ChainError {}

/// Whether an RPC error text describes an EVM revert. Matches the generic
/// revert phrasing plus the registry's terminal custom-error selectors.
pub fn is_revert(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    value.contains("execution reverted")
        || value.contains("revert")
        || value.contains(SELECTOR_NONCE_ALREADY_USED)
        || value.contains(SELECTOR_UNIT_ALREADY_REGISTERED)
}

/// The unit's nonce was already consumed on-chain. Either our own earlier
/// transaction landed with a lost receipt (reconcile via the content hash),
/// or a third party consumed it — a terminal conflict either way once
/// content reconciliation says the unit is absent.
pub fn is_nonce_used_error(error: &ChainError) -> bool {
    matches!(error, ChainError::Reverted(value) | ChainError::Rejected(value)
        if value.contains("NonceAlreadyUsed") || value.contains(SELECTOR_NONCE_ALREADY_USED))
}

/// Identical unit content already exists on-chain — retroactive success.
pub fn is_content_registered_error(error: &ChainError) -> bool {
    matches!(error, ChainError::Reverted(value) | ChainError::Rejected(value)
        if value.contains("UnitAlreadyRegistered") || value.contains(SELECTOR_UNIT_ALREADY_REGISTERED))
}

/// Whether the node saw a same-nonce replacement and refused it on price.
///
/// This is the *only* evidence that a bid actually reached the mempool and was
/// judged too low. The unstick sweep may raise its recorded bid on this and
/// nothing else: ratcheting on a transport failure records a price the node
/// never saw, and after enough retries the recorded bid reaches the cap and the
/// nonce becomes permanently unrescuable even though the real stuck transaction
/// is cheap to replace.
pub fn is_replacement_underpriced(error: &ChainError) -> bool {
    matches!(error, ChainError::Rejected(value) | ChainError::Reverted(value) if {
        let value = value.to_ascii_lowercase();
        value.contains("underpriced")
            || value.contains("replacement transaction")
            || value.contains("already known")
    })
}

/// Whether the error is worth retrying. Unavailable/InvalidResponse always
/// are; Rejected only when it carries none of the terminal markers and does
/// not read as an EVM revert.
pub fn is_transient(error: &ChainError) -> bool {
    match error {
        ChainError::Unavailable | ChainError::InvalidResponse => true,
        ChainError::Rejected(value) => {
            !is_revert(value)
                && !value.contains("NonceAlreadyUsed")
                && !value.contains("UnitAlreadyRegistered")
                && !value.contains("InvalidProof")
        }
        ChainError::Reverted(_) | ChainError::MissingSigner => false,
    }
}

/// The four-way verdict for a failed chain write, in precedence order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorClass {
    /// Identical content already on-chain: retroactive success.
    ContentRegistered,
    /// The unit nonce was consumed (by us with a lost receipt, or by a
    /// third party) — reconcile content, then treat as terminal conflict.
    NonceUsed,
    Transient,
    Poison,
}

pub fn classify_chain_error(error: &ChainError) -> ErrorClass {
    if is_content_registered_error(error) {
        ErrorClass::ContentRegistered
    } else if is_nonce_used_error(error) {
        ErrorClass::NonceUsed
    } else if is_transient(error) {
        ErrorClass::Transient
    } else {
        ErrorClass::Poison
    }
}

// ── Hex plumbing ───────────────────────────────────────────────────────────

pub fn parse_hex_bytes(value: &str) -> Result<Vec<u8>> {
    let raw = value.strip_prefix("0x").unwrap_or(value);
    if !raw.len().is_multiple_of(2) {
        bail!("invalid hex");
    }
    hex::decode(raw).map_err(Into::into)
}

pub fn parse_b256(value: &str) -> Result<B256> {
    let bytes = parse_hex_bytes(value)?;
    if bytes.len() != 32 {
        bail!("expected 32 bytes");
    }
    Ok(B256::from_slice(&bytes))
}

// ── Challenge and content hash ─────────────────────────────────────────────

/// The storage-authorization challenge one member's key signs, mirroring the
/// contract: keccak256(abi.encode(chainid, registry, rpId, publicKey, nonce)).
pub fn challenge_for(
    chain_id: u64,
    registry: Address,
    rp_id: &str,
    public_key: &[u8],
    unit_nonce: B256,
) -> B256 {
    keccak256(
        (
            U256::from(chain_id),
            registry,
            rp_id.to_owned(),
            alloy::primitives::Bytes::from(public_key.to_vec()),
            unit_nonce,
        )
            .abi_encode(),
    )
}

/// The duplicate-suppression content hash, mirroring the contract's
/// `contentHashFor`: keccak256(abi.encode(rpId, metadata, memberHashes)).
pub fn content_hash_for(task: &RegisterTask) -> Result<B256> {
    let mut member_hashes = Vec::with_capacity(task.members.len());
    for member in &task.members {
        let public_key: alloy::primitives::Bytes = parse_hex_bytes(&member.public_key)?.into();
        let attestation: alloy::primitives::Bytes = parse_hex_bytes(&member.attestation)?.into();
        member_hashes.push(keccak256((public_key, attestation).abi_encode()));
    }
    let metadata: alloy::primitives::Bytes = parse_hex_bytes(&task.metadata)?.into();
    Ok(keccak256(
        (task.rp_id.clone(), metadata, member_hashes).abi_encode(),
    ))
}

// ── Calldata builders ──────────────────────────────────────────────────────

fn member_sol(member: &crate::task::Member) -> Result<MemberSol> {
    Ok(MemberSol {
        publicKey: parse_hex_bytes(&member.public_key)?.into(),
        attestation: parse_hex_bytes(&member.attestation)?.into(),
        proof: ProofSol {
            authenticatorData: parse_hex_bytes(&member.proof.authenticator_data)?.into(),
            clientDataJSON: member.proof.client_data_json.clone(),
            challengeIndex: U256::from(member.proof.challenge_index),
            typeIndex: U256::from(member.proof.type_index),
            r: U256::from_be_bytes(parse_b256(&member.proof.r)?.0),
            s: U256::from_be_bytes(parse_b256(&member.proof.s)?.0),
        },
    })
}

/// One register() transaction for one task.
pub fn register_calldata(task: &RegisterTask) -> Result<Vec<u8>> {
    let members = task
        .members
        .iter()
        .map(member_sol)
        .collect::<Result<Vec<_>>>()?;
    Ok(WebAuthnP256PublicKeyRegistry::registerCall {
        rpId: task.rp_id.clone(),
        metadata: parse_hex_bytes(&task.metadata)?.into(),
        unitNonce: parse_b256(&task.unit_nonce)?,
        members,
    }
    .abi_encode())
}

// ── Read calldata ──────────────────────────────────────────────────────────

pub fn total_units_calldata() -> Vec<u8> {
    WebAuthnP256PublicKeyRegistry::getTotalUnitsCall {}.abi_encode()
}

pub fn total_entries_calldata() -> Vec<u8> {
    WebAuthnP256PublicKeyRegistry::getTotalEntriesCall {}.abi_encode()
}

pub fn get_entry_calldata(entry_id: u64) -> Vec<u8> {
    WebAuthnP256PublicKeyRegistry::getEntryCall {
        entryId: U256::from(entry_id),
    }
    .abi_encode()
}

pub fn has_entries_calldata(public_key: Vec<u8>) -> Vec<u8> {
    WebAuthnP256PublicKeyRegistry::hasEntriesCall {
        publicKey: public_key.into(),
    }
    .abi_encode()
}

pub fn entries_by_key_calldata(
    public_key: Vec<u8>,
    offset: u64,
    limit: u64,
    desc: bool,
) -> Vec<u8> {
    WebAuthnP256PublicKeyRegistry::getEntriesByKeyCall {
        publicKey: public_key.into(),
        offset: U256::from(offset),
        limit: U256::from(limit),
        desc,
    }
    .abi_encode()
}

pub fn entries_by_rp_id_calldata(rp_id: String, offset: u64, limit: u64, desc: bool) -> Vec<u8> {
    WebAuthnP256PublicKeyRegistry::getEntriesByRpIdCall {
        rpId: rp_id,
        offset: U256::from(offset),
        limit: U256::from(limit),
        desc,
    }
    .abi_encode()
}

pub fn total_rp_ids_calldata() -> Vec<u8> {
    WebAuthnP256PublicKeyRegistry::getTotalRpIdsCall {}.abi_encode()
}

pub fn rp_ids_calldata(offset: u64, limit: u64, desc: bool) -> Vec<u8> {
    WebAuthnP256PublicKeyRegistry::getRpIdsCall {
        offset: U256::from(offset),
        limit: U256::from(limit),
        desc,
    }
    .abi_encode()
}

pub fn is_nonce_used_calldata(unit_nonce: B256) -> Vec<u8> {
    WebAuthnP256PublicKeyRegistry::isNonceUsedCall {
        unitNonce: unit_nonce,
    }
    .abi_encode()
}

pub fn is_content_registered_calldata(content_hash: B256) -> Vec<u8> {
    WebAuthnP256PublicKeyRegistry::isContentRegisteredCall {
        contentHash: content_hash,
    }
    .abi_encode()
}

// ── Response decoders ──────────────────────────────────────────────────────

pub type SiteEntry = (String, u64, u64);

fn entry_from_sol(value: EntryViewSol) -> Result<Entry> {
    Ok(Entry {
        entry_id: u64::try_from(value.entryId).map_err(|_| anyhow!("entry id exceeds u64"))?,
        unit_id: u64::try_from(value.unitId).map_err(|_| anyhow!("unit id exceeds u64"))?,
        public_key: hex::encode(value.publicKey),
        attestation: hex::encode(value.attestation),
        rp_id: value.rpId,
        metadata: hex::encode(value.metadata),
        first_entry_id: value.firstEntryId,
        member_count: value.memberCount,
        created_at: u64::try_from(value.createdAt)
            .map_err(|_| anyhow!("timestamp exceeds u64"))?
            .saturating_mul(1000),
    })
}

pub fn decode_entry(bytes: &[u8]) -> Result<Entry> {
    let value = WebAuthnP256PublicKeyRegistry::getEntryCall::abi_decode_returns(bytes)
        .map_err(|_| anyhow!("invalid getEntry response"))?;
    entry_from_sol(value)
}

pub fn decode_entries_page(bytes: &[u8]) -> Result<(u64, Vec<Entry>)> {
    let value = WebAuthnP256PublicKeyRegistry::getEntriesByKeyCall::abi_decode_returns(bytes)
        .map_err(|_| anyhow!("invalid entries page response"))?;
    Ok((
        u64::try_from(value.total).map_err(|_| anyhow!("total exceeds u64"))?,
        value
            .records
            .into_iter()
            .map(entry_from_sol)
            .collect::<Result<Vec<_>>>()?,
    ))
}

pub fn decode_has_entries(bytes: &[u8]) -> Result<bool> {
    WebAuthnP256PublicKeyRegistry::hasEntriesCall::abi_decode_returns(bytes)
        .map_err(|_| anyhow!("invalid hasEntries response"))
}

pub fn decode_bool(bytes: &[u8]) -> Result<bool> {
    WebAuthnP256PublicKeyRegistry::isNonceUsedCall::abi_decode_returns(bytes)
        .map_err(|_| anyhow!("invalid bool response"))
}

pub fn decode_total(bytes: &[u8]) -> Result<u64> {
    let value = WebAuthnP256PublicKeyRegistry::getTotalEntriesCall::abi_decode_returns(bytes)
        .map_err(|_| anyhow!("invalid total response"))?;
    u64::try_from(value).map_err(|_| anyhow!("total exceeds u64"))
}

pub fn decode_rp_ids(bytes: &[u8]) -> Result<(u64, Vec<SiteEntry>)> {
    let value = WebAuthnP256PublicKeyRegistry::getRpIdsCall::abi_decode_returns(bytes)
        .map_err(|_| anyhow!("invalid getRpIds response"))?;
    let total = u64::try_from(value.total).map_err(|_| anyhow!("total exceeds u64"))?;
    let mut sites = Vec::with_capacity(value.rpIds.len());
    for ((rp_id, count), created_at) in value
        .rpIds
        .into_iter()
        .zip(value.counts)
        .zip(value.createdAts)
    {
        sites.push((
            rp_id,
            u64::try_from(count).map_err(|_| anyhow!("count exceeds u64"))?,
            u64::try_from(created_at)
                .map_err(|_| anyhow!("timestamp exceeds u64"))?
                .saturating_mul(1000),
        ));
    }
    Ok((total, sites))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task::{Member, Proof, RegisterTask, TaskStatus};

    const PK: &str = "041a8cc55e2d14a61c8f3f1bcf6f8e7e40fe09cc624a6b77f0539d5eebfafa7bc7880184f26b47cfc67b445168c34355416c93c73cb9b896b82be84486adf88ca0";

    fn task() -> RegisterTask {
        RegisterTask {
            id: "t1".into(),
            status: TaskStatus::Pending,
            rp_id: "example.com".into(),
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

    #[test]
    fn register_calldata_uses_the_register_selector() {
        let data = register_calldata(&task()).unwrap();
        assert_eq!(
            &data[..4],
            WebAuthnP256PublicKeyRegistry::registerCall::SELECTOR
        );
    }

    #[test]
    fn classification_precedence_matches_the_contract_vocabulary() {
        assert_eq!(
            classify_chain_error(&ChainError::Rejected("UnitAlreadyRegistered".into())),
            ErrorClass::ContentRegistered
        );
        assert_eq!(
            classify_chain_error(&ChainError::Reverted(format!(
                "data: {SELECTOR_UNIT_ALREADY_REGISTERED}"
            ))),
            ErrorClass::ContentRegistered
        );
        assert_eq!(
            classify_chain_error(&ChainError::Rejected("NonceAlreadyUsed".into())),
            ErrorClass::NonceUsed
        );
        assert_eq!(
            classify_chain_error(&ChainError::Reverted(format!(
                "data: {SELECTOR_NONCE_ALREADY_USED}"
            ))),
            ErrorClass::NonceUsed
        );
        assert_eq!(
            classify_chain_error(&ChainError::Unavailable),
            ErrorClass::Transient
        );
        assert_eq!(
            classify_chain_error(&ChainError::Rejected("rate limited".into())),
            ErrorClass::Transient
        );
        assert_eq!(
            classify_chain_error(&ChainError::Reverted("InvalidProof".into())),
            ErrorClass::Poison
        );
        assert_eq!(
            classify_chain_error(&ChainError::MissingSigner),
            ErrorClass::Poison
        );
    }

    #[test]
    fn transiency_respects_revert_markers() {
        assert!(is_transient(&ChainError::Rejected("timeout".into())));
        assert!(!is_transient(&ChainError::Rejected(
            "execution reverted".into()
        )));
        assert!(!is_transient(&ChainError::Rejected(
            "InvalidProof()".into()
        )));
        assert!(!is_transient(&ChainError::Reverted("anything".into())));
    }

    #[test]
    fn challenge_and_content_hash_are_deterministic() {
        use std::str::FromStr;
        let registry = Address::from_str("0x1111111111111111111111111111111111111111").unwrap();
        let nonce = parse_b256(&format!("0x{}", "11".repeat(32))).unwrap();
        let pk = parse_hex_bytes(PK).unwrap();
        let a = challenge_for(100, registry, "example.com", &pk, nonce);
        let b = challenge_for(100, registry, "example.com", &pk, nonce);
        assert_eq!(a, b);
        // Any component changes the challenge.
        assert_ne!(a, challenge_for(1, registry, "example.com", &pk, nonce));
        assert_ne!(a, challenge_for(100, registry, "other.com", &pk, nonce));

        let hash_one = content_hash_for(&task()).unwrap();
        let mut altered = task();
        altered.metadata = "0xbb".into();
        assert_ne!(hash_one, content_hash_for(&altered).unwrap());
        // The nonce is NOT part of the content hash.
        let mut renonced = task();
        renonced.unit_nonce = format!("0x{}", "44".repeat(32));
        assert_eq!(hash_one, content_hash_for(&renonced).unwrap());
    }
}
