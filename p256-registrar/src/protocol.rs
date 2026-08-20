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

/// Default active index. Override with P256_INDEX_CONTRACT_ADDRESS to point at
/// the V3 deployment at cutover (V3 reads fall back to V2 on-chain, so the
/// server needs no dual-address read logic of its own).
pub const CONTRACT_ADDRESS: &str = "0xdd93420BD49baaBdFF4A363DdD300622Ae87E9c3";
/// The frozen V2 index — same value V3 embeds as its V2_ADDRESS fallback.
/// Admission probes it directly to detect cross-version walletRef conflicts.
pub const V2_CONTRACT_ADDRESS: &str = "0xdd93420BD49baaBdFF4A363DdD300622Ae87E9c3";
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

    struct WalletMemberSol {
        string credentialId;
        bytes publicKey;
        string name;
    }

    interface WebAuthnP256PublicKeyIndex {
        function createWallet(string calldata rpId, bytes32 walletRef, WalletMemberSol[] calldata members) external;
        function getRecord(string calldata rpId, string calldata credentialId)
            external view returns (PublicKeyRecord memory);
        function getRecordByWalletRef(bytes32 walletRef)
            external view returns (PublicKeyRecord memory);
        function hasRecord(string calldata rpId, string calldata credentialId)
            external view returns (bool);
        function getCommitBlock(bytes32 commitment) external view returns (uint256);
        function getTotalCredentials() external view returns (uint256);
        function getTotalWallets() external view returns (uint256);
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

pub fn index_total_wallets_calldata() -> Vec<u8> {
    WebAuthnP256PublicKeyIndex::getTotalWalletsCall {}.abi_encode()
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
    if tasks.iter().any(CreateTask::is_wallet) {
        bail!("wallet tasks must be revealed alone via createWallet");
    }
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

pub fn decode_total_wallets(bytes: &[u8]) -> Result<u64> {
    let value = WebAuthnP256PublicKeyIndex::getTotalWalletsCall::abi_decode_returns(bytes)
        .map_err(|_| anyhow!("invalid getTotalWallets response"))?;
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

/// The V3 contract's WALLET_COMMIT_TAG: bytes32("V3.createWallet"), the
/// domain separator that keeps wallet commitments disjoint from record ones.
pub fn wallet_commit_tag() -> B256 {
    let mut tag = [0u8; 32];
    tag[..15].copy_from_slice(b"V3.createWallet");
    B256::from(tag)
}

fn sol_members(members: &[crate::task::WalletMember]) -> Result<Vec<WalletMemberSol>> {
    members
        .iter()
        .map(|member| {
            Ok(WalletMemberSol {
                credentialId: member.credential_id.clone(),
                publicKey: parse_hex_bytes(&member.public_key)?.into(),
                name: member.name.clone(),
            })
        })
        .collect()
}

pub fn build_commitment(task: &CreateTask) -> Result<B256> {
    if task.is_wallet() {
        return build_wallet_commitment(task);
    }
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

/// One commitment covers the whole wallet bundle:
/// keccak256(abi.encode(WALLET_COMMIT_TAG, rpId, walletRef, members)).
pub fn build_wallet_commitment(task: &CreateTask) -> Result<B256> {
    Ok(keccak256(
        (
            wallet_commit_tag(),
            task.rp_id.clone(),
            parse_b256(&task.wallet_ref)?,
            sol_members(&task.members)?,
        )
            .abi_encode_params(),
    ))
}

/// Calldata for a wallet task's atomic reveal. Unlike batchCreateRecord this
/// targets the INDEX contract directly, so a wallet task must go out alone.
pub fn wallet_create_calldata(task: &CreateTask) -> Result<Vec<u8>> {
    Ok(WebAuthnP256PublicKeyIndex::createWalletCall {
        rpId: task.rp_id.clone(),
        walletRef: parse_b256(&task.wallet_ref)?,
        members: sol_members(&task.members)?,
    }
    .abi_encode())
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
            members: Vec::new(),
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
    fn wallet_commitment_matches_the_contract_golden_value() {
        // Pinned against the Solidity side (test_walletCommitment_goldenValue)
        // and an independent `cast abi-encode | cast keccak` computation.
        use crate::task::{CreateTask, TaskStatus, WalletMember};

        const PK1: &str = "045ff257819a8927dc548d62eeb90a7a61a8e90afd70c9f774e7ed78d0c5bbbc0e8ed0f6a55f675f162b2e8450f79cd0e6766e56f10f762430ec15d2a4388f19fb";
        const PK2: &str = "04550f471003f3df97c3df506ac797f6721fb1a1fb7b8f6f83d224498a65c88e24136093d7012e509a73715cbd0b00a3cc0ff4b5c01b3ffa196ab1fb327036b8e6";
        let task = CreateTask {
            id: "wallet-golden".into(),
            status: TaskStatus::Pending,
            rp_id: "rp1".into(),
            credential_id: "cred-1".into(),
            wallet_ref: "0x0000000000000000000000000000000000000000000000000000000000000042".into(),
            public_key: PK1.into(),
            name: "A".into(),
            initial_credential_id: "cred-1".into(),
            metadata: "0x00".into(),
            members: vec![
                WalletMember {
                    credential_id: "cred-1".into(),
                    public_key: PK1.into(),
                    name: "A".into(),
                },
                WalletMember {
                    credential_id: "cred-2".into(),
                    public_key: PK2.into(),
                    name: "B".into(),
                },
            ],
            tx_hash: None,
            error: None,
            retries: 0,
            created_at: 0,
            admitted: true,
        };
        assert_eq!(
            super::build_commitment(&task).unwrap().to_string(),
            "0x0bcf64f774f9f6721c25a0e2a2da9288add57fbf8c3625b1c72357f3c54383f2"
        );

        // The reveal calldata targets createWallet, and the batch encoder
        // refuses to mix a wallet task into a batchCreateRecord.
        let data = super::wallet_create_calldata(&task).unwrap();
        use alloy::sol_types::SolCall;
        assert_eq!(
            &data[..4],
            super::WebAuthnP256PublicKeyIndex::createWalletCall::SELECTOR
        );
        assert!(
            super::batch_create_calldata(
                alloy::primitives::Address::ZERO,
                std::slice::from_ref(&task)
            )
            .is_err()
        );

        // Altering any member changes the commitment.
        let mut altered = task.clone();
        altered.members[1].credential_id = "cred-CHANGED".into();
        assert_ne!(
            super::build_commitment(&altered).unwrap(),
            super::build_commitment(&task).unwrap()
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
