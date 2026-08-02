//! The on-chain index protocol: contract addresses, calldata encoding,
//! response decoding, commit-reveal commitment construction, and chain-error
//! classification.
//!
//! This module is the single home for the protocol's error vocabulary. The
//! four classification predicates below used to live in the server's
//! `chain.rs` as overlapping string matches (`is_revert` and `is_transient`
//! are deliberate near-inverses); they are kept byte-for-byte compatible and
//! locked in by the truth-table tests at the bottom.

use std::str::FromStr;

use alloy::{
    primitives::{Address, B256, Bytes, U256, keccak256},
    sol,
    sol_types::{SolCall, SolValue},
};
use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};

use crate::{lookup::Record, task::CreateTask};

pub const CONTRACT_ADDRESS: &str = "0xdd93420BD49baaBdFF4A363DdD300622Ae87E9c3";
pub const BATCH_HELPER_ADDRESS: &str = "0xc7B0db5d4974abA3EA25780f40Bf369CC013a16E";
pub const CHAIN_ID: u64 = 100;

pub type SiteEntry = (String, u64, u64);

sol! {
    struct PublicKeyRecord {
        string rpId;
        string credentialId;
        bytes32 walletRef;
        bytes publicKey;
        string name;
        string initialCredentialId;
        bytes metadata;
        uint256 createdAt;
    }

    struct CreateParams {
        string rpId;
        string credentialId;
        bytes32 walletRef;
        bytes publicKey;
        string name;
        string initialCredentialId;
        bytes metadata;
    }

    interface WebAuthnP256PublicKeyIndex {
        function getRecord(string calldata rpId, string calldata credentialId)
            external view returns (PublicKeyRecord memory);
        function getRecordByWalletRef(bytes32 walletRef)
            external view returns (PublicKeyRecord memory);
        function hasRecord(string calldata rpId, string calldata credentialId)
            external view returns (bool);
        function getCommitBlock(bytes32 commitment) external view returns (uint256);
        function getTotalCredentials() external view returns (uint256);
        function getRpIds(uint256 offset, uint256 limit, bool desc)
            external view returns (uint256 total, string[] memory rpIds, uint256[] memory counts, uint256[] memory createdAts);
        function getKeysByRpId(string calldata rpId, uint256 offset, uint256 limit, bool desc)
            external view returns (uint256 total, PublicKeyRecord[] memory records);
    }

    interface WebAuthnP256BatchHelper {
        function batchCommit(address index, bytes32[] calldata commitments) external;
        function batchCreateRecord(address index, CreateParams[] calldata params) external;
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
/// revert phrasing plus the two custom-error selectors this protocol can
/// throw (RecordAlreadyExists, WalletRefAlreadyExists). Case-insensitive.
pub fn is_revert(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    value.contains("execution reverted")
        || value.contains("revert")
        || value.contains("0x46a08bc5")
        || value.contains("0xc9af4506")
}

/// The record for this (rpId, credentialId) already exists on chain — a
/// terminal success for the task that tried to create it.
pub fn is_record_exists_error(error: &ChainError) -> bool {
    matches!(error, ChainError::Reverted(value) | ChainError::Rejected(value)
        if value.contains("RecordAlreadyExists") || value.contains("0x46a08bc5"))
}

/// The wallet ref is already bound to a different credential — a terminal
/// failure (business conflict) for the task.
pub fn is_wallet_conflict_error(error: &ChainError) -> bool {
    matches!(error, ChainError::Reverted(value) | ChainError::Rejected(value)
        if value.contains("WalletRefAlreadyExists") || value.contains("0xc9af4506"))
}

/// Whether the error is worth retrying. Unavailable/InvalidResponse always
/// are; Rejected only when it carries none of the terminal markers above and
/// no revert phrasing. Reverted and MissingSigner are never transient.
pub fn is_transient(error: &ChainError) -> bool {
    matches!(error, ChainError::Unavailable | ChainError::InvalidResponse)
        || matches!(error, ChainError::Rejected(value)
            if !value.contains("RecordAlreadyExists") && !value.contains("WalletRefAlreadyExists")
                && !value.contains("execution reverted") && !value.contains("revert"))
}

/// What a chain write error means for the task that caused it. This is the
/// four-way decision `worker.rs` used to spell out as an if/else chain in
/// `handle_task_error`; the precedence (exists > conflict > transient >
/// poison) is part of the contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorClass {
    /// The record already exists on chain: the task is retroactively done.
    RecordExists,
    /// The wallet ref belongs to another credential: terminal business failure.
    WalletConflict,
    /// Worth retrying later.
    Transient,
    /// Deterministic failure: quarantine the task so it cannot block others.
    Poison,
}

pub fn classify_chain_error(error: &ChainError) -> ErrorClass {
    if is_record_exists_error(error) {
        ErrorClass::RecordExists
    } else if is_wallet_conflict_error(error) {
        ErrorClass::WalletConflict
    } else if is_transient(error) {
        ErrorClass::Transient
    } else {
        ErrorClass::Poison
    }
}

// ── Calldata builders ──────────────────────────────────────────────────────

pub fn index_get_record_calldata(rp_id: String, credential_id: String) -> Vec<u8> {
    WebAuthnP256PublicKeyIndex::getRecordCall {
        rpId: rp_id,
        credentialId: credential_id,
    }
    .abi_encode()
}

pub fn index_get_record_by_wallet_ref_calldata(wallet_ref: B256) -> Vec<u8> {
    WebAuthnP256PublicKeyIndex::getRecordByWalletRefCall {
        walletRef: wallet_ref,
    }
    .abi_encode()
}

pub fn index_has_record_calldata(rp_id: String, credential_id: String) -> Vec<u8> {
    WebAuthnP256PublicKeyIndex::hasRecordCall {
        rpId: rp_id,
        credentialId: credential_id,
    }
    .abi_encode()
}

pub fn index_get_commit_block_calldata(commitment: B256) -> Vec<u8> {
    WebAuthnP256PublicKeyIndex::getCommitBlockCall { commitment }.abi_encode()
}

pub fn index_total_calldata() -> Vec<u8> {
    WebAuthnP256PublicKeyIndex::getTotalCredentialsCall {}.abi_encode()
}

pub fn index_sites_calldata(offset: u64, limit: u64, descending: bool) -> Vec<u8> {
    WebAuthnP256PublicKeyIndex::getRpIdsCall {
        offset: U256::from(offset),
        limit: U256::from(limit),
        desc: descending,
    }
    .abi_encode()
}

pub fn index_keys_calldata(rp_id: String, offset: u64, limit: u64, descending: bool) -> Vec<u8> {
    WebAuthnP256PublicKeyIndex::getKeysByRpIdCall {
        rpId: rp_id,
        offset: U256::from(offset),
        limit: U256::from(limit),
        desc: descending,
    }
    .abi_encode()
}

pub fn batch_commit_calldata(index: Address, commitments: Vec<B256>) -> Vec<u8> {
    WebAuthnP256BatchHelper::batchCommitCall { index, commitments }.abi_encode()
}

pub fn batch_create_calldata(index: Address, tasks: &[CreateTask]) -> Result<Vec<u8>> {
    let params = tasks
        .iter()
        .map(|task| {
            Ok(CreateParams {
                rpId: task.rp_id.clone(),
                credentialId: task.credential_id.clone(),
                walletRef: parse_b256(&task.wallet_ref)?,
                publicKey: parse_hex_bytes(&task.public_key)?.into(),
                name: task.name.clone(),
                initialCredentialId: task.initial_credential_id.clone(),
                metadata: parse_hex_bytes(&task.metadata)?.into(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(WebAuthnP256BatchHelper::batchCreateRecordCall { index, params }.abi_encode())
}

// ── Response decoders ──────────────────────────────────────────────────────

pub fn decode_record(bytes: &[u8]) -> Result<Record> {
    let value = WebAuthnP256PublicKeyIndex::getRecordCall::abi_decode_returns(bytes)
        .map_err(|_| anyhow!("invalid getRecord response"))?;
    record_from_sol(value)
}

pub fn decode_record_by_wallet_ref(bytes: &[u8]) -> Result<Record> {
    let value = WebAuthnP256PublicKeyIndex::getRecordByWalletRefCall::abi_decode_returns(bytes)
        .map_err(|_| anyhow!("invalid getRecordByWalletRef response"))?;
    record_from_sol(value)
}

pub fn decode_has_record(bytes: &[u8]) -> Result<bool> {
    WebAuthnP256PublicKeyIndex::hasRecordCall::abi_decode_returns(bytes)
        .map_err(|_| anyhow!("invalid hasRecord response"))
}

pub fn decode_commit_block(bytes: &[u8]) -> Result<u64> {
    let value = WebAuthnP256PublicKeyIndex::getCommitBlockCall::abi_decode_returns(bytes)
        .map_err(|_| anyhow!("invalid getCommitBlock response"))?;
    u64::try_from(value).map_err(|_| anyhow!("commit block exceeds u64"))
}

pub fn decode_total(bytes: &[u8]) -> Result<u64> {
    let value = WebAuthnP256PublicKeyIndex::getTotalCredentialsCall::abi_decode_returns(bytes)
        .map_err(|_| anyhow!("invalid getTotalCredentials response"))?;
    u64::try_from(value).map_err(|_| anyhow!("total exceeds u64"))
}

pub fn decode_sites(bytes: &[u8], page: u64, page_size: u64) -> Result<(u64, Vec<SiteEntry>)> {
    let response = WebAuthnP256PublicKeyIndex::getRpIdsCall::abi_decode_returns(bytes)
        .map_err(|_| anyhow!("invalid getRpIds response"))?;
    let total = u64::try_from(response.total).map_err(|_| anyhow!("total exceeds u64"))?;
    let mut items = Vec::with_capacity(response.rpIds.len());
    for ((rp_id, count), created_at) in response
        .rpIds
        .into_iter()
        .zip(response.counts)
        .zip(response.createdAts)
    {
        items.push((
            rp_id,
            u64::try_from(count).map_err(|_| anyhow!("count exceeds u64"))?,
            u64::try_from(created_at).map_err(|_| anyhow!("timestamp exceeds u64"))? * 1000,
        ));
    }
    let _ = (page, page_size);
    Ok((total, items))
}

pub fn decode_keys(bytes: &[u8]) -> Result<(u64, Vec<Record>)> {
    let response = WebAuthnP256PublicKeyIndex::getKeysByRpIdCall::abi_decode_returns(bytes)
        .map_err(|_| anyhow!("invalid getKeysByRpId response"))?;
    Ok((
        u64::try_from(response.total).map_err(|_| anyhow!("total exceeds u64"))?,
        response
            .records
            .into_iter()
            .map(record_from_sol)
            .collect::<Result<Vec<_>>>()?,
    ))
}

pub fn record_from_sol(value: PublicKeyRecord) -> Result<Record> {
    Ok(Record {
        rp_id: value.rpId,
        credential_id: value.credentialId,
        wallet_ref: value.walletRef.to_string().to_lowercase(),
        public_key: hex::encode(value.publicKey),
        name: value.name,
        initial_credential_id: value.initialCredentialId,
        metadata: hex::encode(value.metadata),
        created_at: u64::try_from(value.createdAt)
            .map_err(|_| anyhow!("record timestamp exceeds u64"))?
            .saturating_mul(1000),
    })
}

// ── Commit-reveal commitment ───────────────────────────────────────────────

pub fn build_commitment(task: &CreateTask) -> Result<B256> {
    let wallet_ref = parse_b256(&task.wallet_ref)?;
    let public_key: Bytes = parse_hex_bytes(&task.public_key)?.into();
    let metadata: Bytes = parse_hex_bytes(&task.metadata)?.into();
    Ok(keccak256(
        (
            task.rp_id.clone(),
            task.credential_id.clone(),
            wallet_ref,
            public_key,
            task.name.clone(),
            task.initial_credential_id.clone(),
            metadata,
        )
            .abi_encode_params(),
    ))
}

// ── Hex parsing helpers ────────────────────────────────────────────────────

pub fn parse_b256(value: &str) -> Result<B256> {
    B256::from_str(value).map_err(|_| anyhow!("invalid bytes32 hex"))
}

pub fn parse_hex_bytes(value: &str) -> Result<Vec<u8>> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if !value.len().is_multiple_of(2) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("invalid hex");
    }
    hex::decode(value).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::{
        ChainError, is_record_exists_error, is_revert, is_transient, is_wallet_conflict_error,
    };

    // These tests are the truth table for the four classification predicates.
    // They lock in the behaviour that used to be spread over `chain.rs` so the
    // upcoming commit_reveal state machine can rely on it.

    #[test]
    fn revert_detection_is_case_insensitive_and_knows_both_selectors() {
        assert!(is_revert("EXECUTION REVERTED"));
        assert!(is_revert("Revert: something"));
        assert!(is_revert("data 0x46A08BC5"));
        assert!(is_revert("data 0xc9af4506"));
        assert!(!is_revert("rate limited"));
    }

    #[test]
    fn record_exists_matches_name_or_selector_on_reverted_and_rejected() {
        for wrap in [ChainError::Reverted, ChainError::Rejected] {
            assert!(is_record_exists_error(&wrap("RecordAlreadyExists".into())));
            assert!(is_record_exists_error(&wrap("data: 0x46a08bc5".into())));
            assert!(!is_record_exists_error(&wrap(
                "WalletRefAlreadyExists".into()
            )));
        }
        assert!(!is_record_exists_error(&ChainError::Unavailable));
    }

    #[test]
    fn wallet_conflict_matches_name_or_selector_on_reverted_and_rejected() {
        for wrap in [ChainError::Reverted, ChainError::Rejected] {
            assert!(is_wallet_conflict_error(&wrap(
                "WalletRefAlreadyExists".into()
            )));
            assert!(is_wallet_conflict_error(&wrap("data: 0xc9af4506".into())));
            assert!(!is_wallet_conflict_error(&wrap(
                "RecordAlreadyExists".into()
            )));
        }
        assert!(!is_wallet_conflict_error(&ChainError::Unavailable));
    }

    #[test]
    fn transient_covers_infrastructure_errors_and_neutral_rejections_only() {
        assert!(is_transient(&ChainError::Unavailable));
        assert!(is_transient(&ChainError::InvalidResponse));
        assert!(is_transient(&ChainError::Rejected("rate limited".into())));

        // Terminal markers make a rejection non-transient.
        assert!(!is_transient(&ChainError::Rejected(
            "RecordAlreadyExists".into()
        )));
        assert!(!is_transient(&ChainError::Rejected(
            "WalletRefAlreadyExists".into()
        )));
        assert!(!is_transient(&ChainError::Rejected(
            "execution reverted".into()
        )));
        assert!(!is_transient(&ChainError::Rejected("revert".into())));

        // Reverted and MissingSigner are never transient.
        assert!(!is_transient(&ChainError::Reverted("anything".into())));
        assert!(!is_transient(&ChainError::MissingSigner));
    }

    #[test]
    fn transient_rejection_matching_is_case_sensitive_like_the_original() {
        // The predicates match exact case, as the original chain.rs code did.
        // A lowercase marker therefore still counts as transient — this test
        // documents (not endorses) that behaviour.
        assert!(is_transient(&ChainError::Rejected(
            "recordalreadyexists".into()
        )));
    }

    #[test]
    fn commitment_construction_matches_the_golden_value() {
        // Golden value: keccak256(abi.encode(rpId, credentialId, walletRef,
        // publicKey, name, initialCredentialId, metadata)) for the fixed task
        // below. Pins field order and encoding against silent regressions —
        // the commit_reveal tests derive expectations from this same
        // function, so without this anchor they would drift with it.
        use crate::task::{CreateTask, TaskStatus};

        let task = CreateTask {
            id: "golden".into(),
            status: TaskStatus::Pending,
            rp_id: "example.com".into(),
            credential_id: "cred-1".into(),
            wallet_ref: "0x0000000000000000000000000000000000000000000000000000000000000001".into(),
            public_key: "04".repeat(65),
            name: "n".into(),
            initial_credential_id: "cred-1".into(),
            metadata: "0x00".into(),
            tx_hash: None,
            error: None,
            retries: 0,
            created_at: 0,
            admitted: true,
        };
        assert_eq!(
            super::build_commitment(&task).unwrap().to_string(),
            "0xe7bec4938ed5410d3ede4770a739064cabd7110b918140690eb944208cfa3ff9"
        );
    }

    #[test]
    fn classification_precedence_matches_the_original_if_else_chain() {
        use super::{ErrorClass, classify_chain_error};

        assert_eq!(
            classify_chain_error(&ChainError::Rejected("RecordAlreadyExists".into())),
            ErrorClass::RecordExists
        );
        assert_eq!(
            classify_chain_error(&ChainError::Reverted("WalletRefAlreadyExists".into())),
            ErrorClass::WalletConflict
        );
        // An error carrying both markers resolves to RecordExists: exists is
        // checked first, exactly as handle_task_error did.
        assert_eq!(
            classify_chain_error(&ChainError::Reverted(
                "RecordAlreadyExists WalletRefAlreadyExists".into()
            )),
            ErrorClass::RecordExists
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
            classify_chain_error(&ChainError::Reverted("some assert".into())),
            ErrorClass::Poison
        );
        assert_eq!(
            classify_chain_error(&ChainError::MissingSigner),
            ErrorClass::Poison
        );
    }
}
