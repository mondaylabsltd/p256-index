//! The on-chain registry protocol: calldata encoding, response decoding,
//! challenge construction, and the single home for chain-error
//! classification.
//!
//! The registry (`WebAuthnP256PublicKeyRegistry`) is an append-only store
//! of possession-proven P-256 public keys with two writes:
//! `register(rpId, metadata, groupPublicKey, groupProof, members)` creates
//! a frozen group (plus global entries for new keys), and
//! `refer(groupPublicKey, metadata, member)` points one passkey at an
//! existing group in the separate reference table. The group key's
//! challenge binds the group's content hash, a member's binds (groupKey,
//! own attestation), a referrer's binds (groupKey, own attestation,
//! reference metadata) — everything is signature-covered and idempotent;
//! nothing is consumable.

use alloy::{
    primitives::{Address, B256, U256, keccak256},
    sol,
    sol_types::{SolCall, SolValue},
};
use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};

use crate::lookup::{Entry, ReferenceRecord, Unit};
use crate::task::RegisterTask;

pub const CHAIN_ID: u64 = 100;

/// Revert selectors of the registry's terminal classifications.
pub const SELECTOR_GROUP_KEY_ALREADY_USED: &str = "0x10eafb1a";
pub const SELECTOR_ALREADY_REFERENCED: &str = "0x40709c5d";
pub const SELECTOR_GROUP_NOT_FOUND: &str = "0xdec308b4";
pub const SELECTOR_INVALID_PROOF: &str = "0x09bde339";

/// keccak("GroupCreated(uint256,bytes32,bytes32,bytes,uint256)") — the
/// receipt log the shell parses to learn a confirmed group's unit id.
pub const GROUP_CREATED_TOPIC: &str =
    "0xec8fb064abac351ab712c446266da8b3539b1c844ef0651babfc85a96f4f8186";
/// keccak("ReferenceCreated(uint256,uint256,uint256,bytes32,bytes32)").
pub const REFERENCE_CREATED_TOPIC: &str =
    "0xac974b7eb67da8eca98f625293e583be13beee67950dcea8c78710b4964b118a";

sol! {
    struct EntrySol {
        bytes publicKey;
        bytes attestation;
        uint256 createdAt;
    }

    struct UnitSol {
        string rpId;
        bytes metadata;
        bytes groupPublicKey;
        bytes32 contentHash;
        uint32 memberCount;
        uint256 createdAt;
    }

    struct ReferenceSol {
        uint256 entryId;
        uint256 unitId;
        bytes metadata;
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
        function register(string calldata rpId, bytes calldata metadata, bytes calldata groupPublicKey, ProofSol calldata groupProof, MemberSol[] calldata members) external;
        function refer(bytes calldata groupPublicKey, bytes calldata metadata, MemberSol calldata member) external;
        function getTotalEntries() external view returns (uint256);
        function getEntry(uint256 entryId) external view returns (EntrySol memory);
        function hasEntry(bytes calldata publicKey) external view returns (bool);
        function getEntryByKey(bytes calldata publicKey) external view returns (bool exists, uint256 entryId, EntrySol memory entry);
        function getTotalGroupsOfKey(bytes calldata publicKey) external view returns (uint256);
        function getGroupsOfKey(bytes calldata publicKey, uint256 offset, uint256 limit, bool desc)
            external view returns (uint256 total, uint256[] memory unitIds);
        function getTotalUnits() external view returns (uint256);
        function getUnit(uint256 unitId) external view returns (UnitSol memory);
        function getUnitByGroupKey(bytes calldata publicKey) external view returns (bool exists, uint256 unitId, UnitSol memory unit);
        function getUnitIdByContentHash(bytes32 contentHash) external view returns (bool exists, uint256 unitId);
        function isContentRegistered(bytes32 contentHash) external view returns (bool);
        function isMember(bytes calldata groupPublicKey, bytes calldata memberPublicKey) external view returns (bool);
        function getTotalGroupMembers(uint256 unitId) external view returns (uint256);
        function getGroupMembers(uint256 unitId, uint256 offset, uint256 limit, bool desc)
            external view returns (uint256 total, uint256[] memory entryIds, EntrySol[] memory entries);
        function getTotalReferences() external view returns (uint256);
        function getReference(uint256 referenceId) external view returns (ReferenceSol memory);
        function isReferenced(bytes calldata groupPublicKey, bytes calldata memberPublicKey) external view returns (bool);
        function getTotalReferencesOfKey(bytes calldata publicKey) external view returns (uint256);
        function getReferencesOfKey(bytes calldata publicKey, uint256 offset, uint256 limit, bool desc)
            external view returns (uint256 total, uint256[] memory referenceIds);
        function getTotalRpIds() external view returns (uint256);
        function getTotalGroupsByRpId(string calldata rpId) external view returns (uint256);
        function getGroupsByRpId(string calldata rpId, uint256 offset, uint256 limit, bool desc)
            external view returns (uint256 total, uint256[] memory unitIds);
        function getRpIds(uint256 offset, uint256 limit, bool desc)
            external view returns (uint256 total, string[] memory rpIds, uint256[] memory counts, uint256[] memory createdAts);
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
        || value.contains(SELECTOR_GROUP_KEY_ALREADY_USED)
        || value.contains(SELECTOR_ALREADY_REFERENCED)
        || value.contains(SELECTOR_INVALID_PROOF)
}

/// The refer's target group is not (yet) on-chain: a refer can race its
/// own group's registration through the pipeline, so this must retry, not
/// poison.
pub fn is_group_not_found_error(error: &ChainError) -> bool {
    matches!(error, ChainError::Reverted(value) | ChainError::Rejected(value)
        if value.contains("GroupNotFound") || value.contains(SELECTOR_GROUP_NOT_FOUND))
}

/// The write's target may already exist on-chain (a used group key, an
/// existing reference): reconcile against the chain, then done or poison.
pub fn is_already_exists_error(error: &ChainError) -> bool {
    matches!(error, ChainError::Reverted(value) | ChainError::Rejected(value)
        if value.contains("GroupKeyAlreadyUsed")
            || value.contains(SELECTOR_GROUP_KEY_ALREADY_USED)
            || value.contains("AlreadyReferenced")
            || value.contains(SELECTOR_ALREADY_REFERENCED))
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
                && !value.contains("GroupKeyAlreadyUsed")
                && !value.contains("AlreadyReferenced")
                && !value.contains("InvalidProof")
        }
        ChainError::Reverted(_) | ChainError::MissingSigner => false,
    }
}

/// The three-way verdict for a failed chain write, in precedence order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorClass {
    /// The target may already exist on-chain: reconcile, then done/poison.
    AlreadyExists,
    Transient,
    Poison,
}

pub fn classify_chain_error(error: &ChainError) -> ErrorClass {
    if is_already_exists_error(error) {
        ErrorClass::AlreadyExists
    } else if is_group_not_found_error(error) || is_transient(error) {
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

/// The storage-authorization challenge one key signs, mirroring the
/// contract: keccak256(abi.encode(chainid, registry, rpId, publicKey,
/// binding)) — the content hash for the group key, member_binding_for for
/// member passkeys. Nothing to consume, nothing to front-run.
pub fn challenge_for(
    chain_id: u64,
    registry: Address,
    rp_id: &str,
    public_key: &[u8],
    binding: B256,
) -> B256 {
    // abi_encode_params, NOT abi_encode: the contract hashes the parameter
    // sequence of abi.encode(...), which alloy calls "params" encoding —
    // plain .abi_encode() on a tuple prepends a 0x20 offset word and every
    // hash diverges from the chain. Pinned by
    // `pinned_vectors_match_the_contract`.
    keccak256(
        (
            U256::from(chain_id),
            registry,
            rp_id.to_owned(),
            alloy::primitives::Bytes::from(public_key.to_vec()),
            binding,
        )
            .abi_encode_params(),
    )
}

/// The binding a MEMBER passkey signs into its challenge, mirroring the
/// contract's `memberBindingFor`: keccak256(abi.encode(groupPublicKey,
/// attestation)) — both known the moment the member's key is created.
pub fn member_binding_for(group_public_key: &[u8], attestation: &[u8]) -> B256 {
    keccak256(
        (
            alloy::primitives::Bytes::from(group_public_key.to_vec()),
            alloy::primitives::Bytes::from(attestation.to_vec()),
        )
            .abi_encode_params(),
    )
}

/// The binding a REFERRING passkey signs, mirroring the contract's
/// `referenceBindingFor`: keccak256(abi.encode(groupPublicKey, attestation,
/// metadata)) — all known the moment the key is created.
pub fn reference_binding_for(group_public_key: &[u8], attestation: &[u8], metadata: &[u8]) -> B256 {
    keccak256(
        (
            alloy::primitives::Bytes::from(group_public_key.to_vec()),
            alloy::primitives::Bytes::from(attestation.to_vec()),
            alloy::primitives::Bytes::from(metadata.to_vec()),
        )
            .abi_encode_params(),
    )
}

/// The task's identity digest, mirroring the contract where one exists:
/// for Register it is the contract's `contentHashFor` (rpId, metadata,
/// groupPublicKey, memberHashes); for Refer it is a service-side
/// idempotency digest over (groupPublicKey, memberHash, metadata) — the
/// chain's own uniqueness is the (group, key) pair.
pub fn content_hash_for(task: &RegisterTask) -> Result<B256> {
    let group: alloy::primitives::Bytes = parse_hex_bytes(&task.group_public_key)?.into();
    let metadata: alloy::primitives::Bytes = parse_hex_bytes(&task.metadata)?.into();
    let mut member_hashes = Vec::with_capacity(task.members.len());
    for member in &task.members {
        let public_key: alloy::primitives::Bytes = parse_hex_bytes(&member.public_key)?.into();
        let attestation: alloy::primitives::Bytes = parse_hex_bytes(&member.attestation)?.into();
        member_hashes.push(keccak256((public_key, attestation).abi_encode_params()));
    }
    match task.kind {
        crate::task::TaskKind::Register => Ok(keccak256(
            (task.rp_id.clone(), metadata, group, member_hashes).abi_encode_params(),
        )),
        crate::task::TaskKind::Refer => {
            // Deliberately (group, key) ONLY — the chain's own uniqueness.
            // A resubmission with different reference metadata maps to the
            // SAME task, so the caller sees the record that actually
            // exists instead of a doomed duplicate reported as done.
            let member = task
                .members
                .first()
                .ok_or_else(|| anyhow!("refer task has no member"))?;
            let member_key: alloy::primitives::Bytes = parse_hex_bytes(&member.public_key)?.into();
            let _ = (metadata, member_hashes);
            Ok(keccak256((group, member_key).abi_encode_params()))
        }
    }
}

// ── Calldata builders ──────────────────────────────────────────────────────

fn proof_sol(proof: &crate::task::Proof) -> Result<ProofSol> {
    Ok(ProofSol {
        authenticatorData: parse_hex_bytes(&proof.authenticator_data)?.into(),
        clientDataJSON: proof.client_data_json.clone(),
        challengeIndex: U256::from(proof.challenge_index),
        typeIndex: U256::from(proof.type_index),
        r: U256::from_be_bytes(parse_b256(&proof.r)?.0),
        s: U256::from_be_bytes(parse_b256(&proof.s)?.0),
    })
}

fn member_sol(member: &crate::task::Member) -> Result<MemberSol> {
    Ok(MemberSol {
        publicKey: parse_hex_bytes(&member.public_key)?.into(),
        attestation: parse_hex_bytes(&member.attestation)?.into(),
        proof: proof_sol(&member.proof)?,
    })
}

/// One register() transaction for one Register task.
pub fn register_calldata(task: &RegisterTask) -> Result<Vec<u8>> {
    let members = task
        .members
        .iter()
        .map(member_sol)
        .collect::<Result<Vec<_>>>()?;
    let group_proof = task
        .group_proof
        .as_ref()
        .ok_or_else(|| anyhow!("register task has no group proof"))?;
    Ok(WebAuthnP256PublicKeyRegistry::registerCall {
        rpId: task.rp_id.clone(),
        metadata: parse_hex_bytes(&task.metadata)?.into(),
        groupPublicKey: parse_hex_bytes(&task.group_public_key)?.into(),
        groupProof: proof_sol(group_proof)?,
        members,
    }
    .abi_encode())
}

/// One refer() transaction for one Refer task.
pub fn refer_calldata(task: &RegisterTask) -> Result<Vec<u8>> {
    let member = task
        .members
        .first()
        .ok_or_else(|| anyhow!("refer task has no member"))?;
    Ok(WebAuthnP256PublicKeyRegistry::referCall {
        groupPublicKey: parse_hex_bytes(&task.group_public_key)?.into(),
        metadata: parse_hex_bytes(&task.metadata)?.into(),
        member: member_sol(member)?,
    }
    .abi_encode())
}

/// The right write calldata for the task's kind.
pub fn write_calldata(task: &RegisterTask) -> Result<Vec<u8>> {
    match task.kind {
        crate::task::TaskKind::Register => register_calldata(task),
        crate::task::TaskKind::Refer => refer_calldata(task),
    }
}

// ── Read calldata ──────────────────────────────────────────────────────────

pub fn total_entries_calldata() -> Vec<u8> {
    WebAuthnP256PublicKeyRegistry::getTotalEntriesCall {}.abi_encode()
}

pub fn total_units_calldata() -> Vec<u8> {
    WebAuthnP256PublicKeyRegistry::getTotalUnitsCall {}.abi_encode()
}

pub fn total_references_calldata() -> Vec<u8> {
    WebAuthnP256PublicKeyRegistry::getTotalReferencesCall {}.abi_encode()
}

pub fn total_rp_ids_calldata() -> Vec<u8> {
    WebAuthnP256PublicKeyRegistry::getTotalRpIdsCall {}.abi_encode()
}

pub fn get_entry_calldata(entry_id: u64) -> Vec<u8> {
    WebAuthnP256PublicKeyRegistry::getEntryCall {
        entryId: U256::from(entry_id),
    }
    .abi_encode()
}

pub fn get_entry_by_key_calldata(public_key: Vec<u8>) -> Vec<u8> {
    WebAuthnP256PublicKeyRegistry::getEntryByKeyCall {
        publicKey: public_key.into(),
    }
    .abi_encode()
}

pub fn has_entry_calldata(public_key: Vec<u8>) -> Vec<u8> {
    WebAuthnP256PublicKeyRegistry::hasEntryCall {
        publicKey: public_key.into(),
    }
    .abi_encode()
}

pub fn groups_of_key_calldata(public_key: Vec<u8>, offset: u64, limit: u64, desc: bool) -> Vec<u8> {
    WebAuthnP256PublicKeyRegistry::getGroupsOfKeyCall {
        publicKey: public_key.into(),
        offset: U256::from(offset),
        limit: U256::from(limit),
        desc,
    }
    .abi_encode()
}

pub fn references_of_key_calldata(
    public_key: Vec<u8>,
    offset: u64,
    limit: u64,
    desc: bool,
) -> Vec<u8> {
    WebAuthnP256PublicKeyRegistry::getReferencesOfKeyCall {
        publicKey: public_key.into(),
        offset: U256::from(offset),
        limit: U256::from(limit),
        desc,
    }
    .abi_encode()
}

pub fn get_unit_by_group_key_calldata(public_key: Vec<u8>) -> Vec<u8> {
    WebAuthnP256PublicKeyRegistry::getUnitByGroupKeyCall {
        publicKey: public_key.into(),
    }
    .abi_encode()
}

pub fn get_unit_calldata(unit_id: u64) -> Vec<u8> {
    WebAuthnP256PublicKeyRegistry::getUnitCall {
        unitId: U256::from(unit_id),
    }
    .abi_encode()
}

pub fn get_reference_calldata(reference_id: u64) -> Vec<u8> {
    WebAuthnP256PublicKeyRegistry::getReferenceCall {
        referenceId: U256::from(reference_id),
    }
    .abi_encode()
}

pub fn get_group_members_calldata(unit_id: u64, offset: u64, limit: u64, desc: bool) -> Vec<u8> {
    WebAuthnP256PublicKeyRegistry::getGroupMembersCall {
        unitId: U256::from(unit_id),
        offset: U256::from(offset),
        limit: U256::from(limit),
        desc,
    }
    .abi_encode()
}

pub fn groups_by_rp_id_calldata(rp_id: String, offset: u64, limit: u64, desc: bool) -> Vec<u8> {
    WebAuthnP256PublicKeyRegistry::getGroupsByRpIdCall {
        rpId: rp_id,
        offset: U256::from(offset),
        limit: U256::from(limit),
        desc,
    }
    .abi_encode()
}

pub fn rp_ids_calldata(offset: u64, limit: u64, desc: bool) -> Vec<u8> {
    WebAuthnP256PublicKeyRegistry::getRpIdsCall {
        offset: U256::from(offset),
        limit: U256::from(limit),
        desc,
    }
    .abi_encode()
}

pub fn is_content_registered_calldata(content_hash: B256) -> Vec<u8> {
    WebAuthnP256PublicKeyRegistry::isContentRegisteredCall {
        contentHash: content_hash,
    }
    .abi_encode()
}

pub fn is_referenced_calldata(group_public_key: Vec<u8>, member_public_key: Vec<u8>) -> Vec<u8> {
    WebAuthnP256PublicKeyRegistry::isReferencedCall {
        groupPublicKey: group_public_key.into(),
        memberPublicKey: member_public_key.into(),
    }
    .abi_encode()
}

// ── Response decoders ──────────────────────────────────────────────────────

pub type SiteEntry = (String, u64, u64);

fn entry_from_sol(entry_id: u64, value: EntrySol) -> Entry {
    Entry {
        entry_id,
        public_key: hex::encode(value.publicKey),
        attestation: hex::encode(value.attestation),
        created_at: u64::try_from(value.createdAt)
            .unwrap_or(u64::MAX)
            .saturating_mul(1000),
    }
}

fn unit_from_sol(unit_id: u64, value: UnitSol) -> Unit {
    Unit {
        unit_id,
        rp_id: value.rpId,
        metadata: hex::encode(value.metadata),
        group_public_key: hex::encode(value.groupPublicKey),
        content_hash: format!("{:#x}", value.contentHash),
        member_count: value.memberCount,
        created_at: u64::try_from(value.createdAt)
            .unwrap_or(u64::MAX)
            .saturating_mul(1000),
    }
}

pub fn decode_entry(entry_id: u64, bytes: &[u8]) -> Result<Entry> {
    let value = WebAuthnP256PublicKeyRegistry::getEntryCall::abi_decode_returns(bytes)
        .map_err(|_| anyhow!("invalid getEntry response"))?;
    Ok(entry_from_sol(entry_id, value))
}

/// (exists, entryId, entry)
pub fn decode_entry_by_key(bytes: &[u8]) -> Result<Option<Entry>> {
    let value = WebAuthnP256PublicKeyRegistry::getEntryByKeyCall::abi_decode_returns(bytes)
        .map_err(|_| anyhow!("invalid getEntryByKey response"))?;
    if !value.exists {
        return Ok(None);
    }
    let entry_id = u64::try_from(value.entryId).map_err(|_| anyhow!("entry id exceeds u64"))?;
    Ok(Some(entry_from_sol(entry_id, value.entry)))
}

pub fn decode_unit_by_group_key(bytes: &[u8]) -> Result<Option<Unit>> {
    let value = WebAuthnP256PublicKeyRegistry::getUnitByGroupKeyCall::abi_decode_returns(bytes)
        .map_err(|_| anyhow!("invalid getUnitByGroupKey response"))?;
    if !value.exists {
        return Ok(None);
    }
    let unit_id = u64::try_from(value.unitId).map_err(|_| anyhow!("unit id exceeds u64"))?;
    Ok(Some(unit_from_sol(unit_id, value.unit)))
}

pub fn decode_unit(unit_id: u64, bytes: &[u8]) -> Result<Unit> {
    let value = WebAuthnP256PublicKeyRegistry::getUnitCall::abi_decode_returns(bytes)
        .map_err(|_| anyhow!("invalid getUnit response"))?;
    Ok(unit_from_sol(unit_id, value))
}

pub fn decode_reference(reference_id: u64, bytes: &[u8]) -> Result<ReferenceRecord> {
    let value = WebAuthnP256PublicKeyRegistry::getReferenceCall::abi_decode_returns(bytes)
        .map_err(|_| anyhow!("invalid getReference response"))?;
    Ok(ReferenceRecord {
        reference_id,
        entry_id: u64::try_from(value.entryId).map_err(|_| anyhow!("entry id exceeds u64"))?,
        unit_id: u64::try_from(value.unitId).map_err(|_| anyhow!("unit id exceeds u64"))?,
        metadata: hex::encode(value.metadata),
        created_at: u64::try_from(value.createdAt)
            .unwrap_or(u64::MAX)
            .saturating_mul(1000),
    })
}

/// (total, ids) — shared by getGroupsOfKey / getReferencesOfKey /
/// getGroupsByRpId, whose return shapes are identical.
pub fn decode_id_page(bytes: &[u8]) -> Result<(u64, Vec<u64>)> {
    let value = WebAuthnP256PublicKeyRegistry::getGroupsOfKeyCall::abi_decode_returns(bytes)
        .map_err(|_| anyhow!("invalid id-page response"))?;
    let ids = value
        .unitIds
        .into_iter()
        .map(|id| u64::try_from(id).map_err(|_| anyhow!("id exceeds u64")))
        .collect::<Result<Vec<_>>>()?;
    Ok((
        u64::try_from(value.total).map_err(|_| anyhow!("total exceeds u64"))?,
        ids,
    ))
}

/// (total, entryIds, entries) from getGroupMembers.
pub fn decode_group_members(bytes: &[u8]) -> Result<(u64, Vec<Entry>)> {
    let value = WebAuthnP256PublicKeyRegistry::getGroupMembersCall::abi_decode_returns(bytes)
        .map_err(|_| anyhow!("invalid getGroupMembers response"))?;
    let mut entries = Vec::with_capacity(value.entries.len());
    for (id, entry) in value.entryIds.into_iter().zip(value.entries) {
        entries.push(entry_from_sol(
            u64::try_from(id).map_err(|_| anyhow!("entry id exceeds u64"))?,
            entry,
        ));
    }
    Ok((
        u64::try_from(value.total).map_err(|_| anyhow!("total exceeds u64"))?,
        entries,
    ))
}

pub fn decode_has_entry(bytes: &[u8]) -> Result<bool> {
    WebAuthnP256PublicKeyRegistry::hasEntryCall::abi_decode_returns(bytes)
        .map_err(|_| anyhow!("invalid hasEntry response"))
}

pub fn decode_bool(bytes: &[u8]) -> Result<bool> {
    WebAuthnP256PublicKeyRegistry::isContentRegisteredCall::abi_decode_returns(bytes)
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
    Ok((
        u64::try_from(value.total).map_err(|_| anyhow!("total exceeds u64"))?,
        sites,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task::{Member, Proof, RegisterTask, TaskKind, TaskStatus};

    const PK: &str = "041a8cc55e2d14a61c8f3f1bcf6f8e7e40fe09cc624a6b77f0539d5eebfafa7bc7880184f26b47cfc67b445168c34355416c93c73cb9b896b82be84486adf88ca0";
    const GROUP_PK: &str = "049e666db13bc6d0a76ec6801fbe24864030f15eca3b2d07ebcaf824bb2dc4f0aea8221dc27980b7c133a00d910c39723eb1523e88ad050a7303bba8bde07367fa";

    fn task() -> RegisterTask {
        RegisterTask {
            id: "t1".into(),
            status: TaskStatus::Pending,
            kind: TaskKind::Register,
            rp_id: "example.com".into(),
            metadata: "0xaa".into(),
            content_hash: String::new(),
            group_public_key: GROUP_PK.into(),
            group_proof: Some(Proof {
                authenticator_data: "00".repeat(37),
                client_data_json: "{}".into(),
                challenge_index: 23,
                type_index: 1,
                r: format!("0x{}", "44".repeat(32)),
                s: format!("0x{}", "55".repeat(32)),
            }),
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
            on_chain_id: None,
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
            classify_chain_error(&ChainError::Rejected("GroupKeyAlreadyUsed".into())),
            ErrorClass::AlreadyExists
        );
        assert_eq!(
            classify_chain_error(&ChainError::Reverted(format!(
                "data: {SELECTOR_GROUP_KEY_ALREADY_USED}"
            ))),
            ErrorClass::AlreadyExists
        );
        assert_eq!(
            classify_chain_error(&ChainError::Rejected("AlreadyReferenced".into())),
            ErrorClass::AlreadyExists
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
        let content = content_hash_for(&task()).unwrap();
        let pk = parse_hex_bytes(PK).unwrap();
        let a = challenge_for(100, registry, "example.com", &pk, content);
        let b = challenge_for(100, registry, "example.com", &pk, content);
        assert_eq!(a, b);
        // Any component changes the challenge — including the content hash,
        // which is what makes the group signature front-run-proof.
        assert_ne!(a, challenge_for(1, registry, "example.com", &pk, content));
        assert_ne!(a, challenge_for(100, registry, "other.com", &pk, content));
        let mut altered = task();
        altered.metadata = "0xbb".into();
        let altered_content = content_hash_for(&altered).unwrap();
        assert_ne!(content, altered_content);
        // The group key is part of the content.
        let mut regrouped = task();
        regrouped.group_public_key = PK.into();
        assert_ne!(content, content_hash_for(&regrouped).unwrap());
        // Member bindings move with the group key and the attestation.
        let group = parse_hex_bytes(GROUP_PK).unwrap();
        let binding = member_binding_for(&group, &[]);
        assert_ne!(binding, member_binding_for(&pk, &[]));
        assert_ne!(binding, member_binding_for(&group, &[0x01]));
    }

    /// Pinned with cast, independently of alloy AND of the contract; the
    /// same constants are asserted in the Solidity suite
    /// (test_pinnedVectors_matchIndependentEncoding). Any encoding drift on
    /// either side of the Rust/Solidity boundary breaks one of the two.
    #[test]
    fn pinned_vectors_match_the_contract() {
        use std::str::FromStr;
        let group = parse_hex_bytes(GROUP_PK).unwrap();
        let pk = parse_hex_bytes(PK).unwrap();

        assert_eq!(
            format!("{:#x}", member_binding_for(&group, &[])),
            "0x75a5d4ac7bfd9ba67dd55f90f5063062d6899090a46608ac1b10e9a51e359bc6"
        );
        assert_eq!(
            format!("{:#x}", reference_binding_for(&group, &[], &[0xaa])),
            "0xd5213d11b1f268a3098df33fa192e334e92788516ca70f286167a1e89457c2a3"
        );
        let content = content_hash_for(&task()).unwrap();
        assert_eq!(
            format!("{content:#x}"),
            "0x1d7f01eb5c0170f9196956c4d7b56484cc335ba23757431f60fb4aeb626f78eb"
        );
        let registry = Address::from_str("0x1111111111111111111111111111111111111111").unwrap();
        assert_eq!(
            format!(
                "{:#x}",
                challenge_for(100, registry, "example.com", &pk, content)
            ),
            "0xd17270edef23ad83ebbf91a0d4f50caf64ef9b64bb85bec51192e36f311082ce"
        );
    }

    /// The hardcoded protocol constants derive from their signatures.
    #[test]
    fn hardcoded_constants_derive_from_signatures() {
        assert_eq!(
            format!(
                "{:#x}",
                keccak256("GroupCreated(uint256,bytes32,bytes32,bytes,uint256)")
            ),
            GROUP_CREATED_TOPIC
        );
        assert_eq!(
            format!(
                "{:#x}",
                keccak256("ReferenceCreated(uint256,uint256,uint256,bytes32,bytes32)")
            ),
            REFERENCE_CREATED_TOPIC
        );
        assert_eq!(
            format!(
                "0x{}",
                hex::encode(&keccak256("GroupKeyAlreadyUsed(bytes32)")[..4])
            ),
            SELECTOR_GROUP_KEY_ALREADY_USED
        );
        assert_eq!(
            format!(
                "0x{}",
                hex::encode(&keccak256("AlreadyReferenced(uint256)")[..4])
            ),
            SELECTOR_ALREADY_REFERENCED
        );
        assert_eq!(
            format!("0x{}", hex::encode(&keccak256("InvalidProof()")[..4])),
            SELECTOR_INVALID_PROOF
        );
    }
}
