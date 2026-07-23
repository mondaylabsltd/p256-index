use std::str::FromStr;

use alloy::{
    primitives::{Address, B256, Bytes, U256, keccak256},
    sol,
    sol_types::{SolCall, SolValue},
};
use anyhow::{Result, anyhow, bail};

use crate::types::{CreateTask, Record};

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

const SAFE_PROXY_FACTORY: &str = "0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67";
const SAFE_SINGLETON: &str = "0x29fcB43b46531BcA003ddC8FCB67FFE91900C762";
const SAFE_4337_MODULE: &str = "0x75cf11467937ce3F2f357CE24ffc3DBF8fD5c226";
const SAFE_MODULE_SETUP: &str = "0x2dd68b007B46fBe91B9A7c3EDa5A7a1063cB5b47";
const WEBAUTHN_SIGNER: &str = "0x94a4F6affBd8975951142c3999aEAB7ecee555c2";
const MULTI_SEND: &str = "0x38869bf66a61cF6bDB996A6aE40D5853Fd43B526";
const PROXY_CREATION_CODE: &str = "608060405234801561001057600080fd5b506040516101e63803806101e68339818101604052602081101561003357600080fd5b8101908080519060200190929190505050600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff1614156100ca576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260228152602001806101c46022913960400191505060405180910390fd5b806000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505060ab806101196000396000f3fe608060405273ffffffffffffffffffffffffffffffffffffffff600054167fa619486e0000000000000000000000000000000000000000000000000000000060003514156050578060005260206000f35b3660008037600080366000845af43d6000803e60008114156070573d6000fd5b3d6000f3fea264697066735822122003d1488ee65e08fa41e58e888a9865554c535f2c77126a82cb4c0f917f31441364736f6c63430007060033496e76616c69642073696e676c65746f6e20616464726573732070726f7669646564";

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

pub fn default_metadata(public_key: &str) -> Result<String> {
    let public_key: Bytes = parse_hex_bytes(public_key)?.into();
    Ok(format!(
        "0x{}",
        hex::encode(("VelaWalletV1".to_owned(), public_key).abi_encode_params())
    ))
}

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

pub fn build_wallet_ref(public_key: &str) -> Result<String> {
    let public_key = parse_hex_bytes(public_key)?;
    if public_key.len() != 65 || public_key[0] != 4 {
        bail!("publicKey must be an uncompressed P-256 key (04 + 128 hex chars)");
    }

    // Reject points that meet the byte-shape rule but cannot ever be accepted by the contract.
    p256::PublicKey::from_sec1_bytes(&public_key)
        .map_err(|_| anyhow!("publicKey must be a valid point on the P-256 curve"))?;

    let x = B256::from_slice(&public_key[1..33]);
    let y = B256::from_slice(&public_key[33..65]);
    let safe_proxy_factory = address(SAFE_PROXY_FACTORY)?;
    let safe_singleton = address(SAFE_SINGLETON)?;
    let safe_4337_module = address(SAFE_4337_MODULE)?;
    let safe_module_setup = address(SAFE_MODULE_SETUP)?;
    let webauthn_signer = address(WEBAUTHN_SIGNER)?;
    let multi_send = address(MULTI_SEND)?;

    let salt_nonce = keccak256((x, y).abi_encode_params());

    let enable_modules_data = with_selector(
        "enableModules(address[])",
        (vec![safe_4337_module],).abi_encode_params(),
    );
    let configure_data = with_selector(
        "configure((uint256,uint256,uint176))",
        ((
            U256::from_be_bytes(x.0),
            U256::from_be_bytes(y.0),
            U256::from(0x100u64),
        ),)
            .abi_encode_params(),
    );
    let tx1 = encode_multisend_tx(safe_module_setup, &enable_modules_data, 1);
    let tx2 = encode_multisend_tx(webauthn_signer, &configure_data, 1);
    let mut packed = tx1;
    packed.extend(tx2);

    let multi_send_data = with_selector(
        "multiSend(bytes)",
        (Bytes::from(packed),).abi_encode_params(),
    );
    let setup_data = with_selector(
        "setup(address[],uint256,address,bytes,address,address,uint256,address)",
        (
            vec![webauthn_signer],
            U256::from(1u64),
            multi_send,
            Bytes::from(multi_send_data),
            safe_4337_module,
            Address::ZERO,
            U256::ZERO,
            Address::ZERO,
        )
            .abi_encode_params(),
    );

    let mut deployment_code = hex::decode(PROXY_CREATION_CODE)?;
    deployment_code.extend((safe_singleton,).abi_encode());
    let init_code_hash = keccak256(deployment_code);
    let initializer_hash = keccak256(setup_data);
    let salt = keccak256((initializer_hash, salt_nonce).abi_encode_params());

    let mut preimage = vec![0xff];
    preimage.extend(safe_proxy_factory.as_slice());
    preimage.extend(salt.0);
    preimage.extend(init_code_hash.0);
    let address_hash = keccak256(preimage);
    Ok(format!(
        "0x{}{}",
        "0".repeat(24),
        hex::encode(&address_hash.as_slice()[12..])
    ))
}

fn address(value: &str) -> Result<Address> {
    Address::from_str(value).map_err(|_| anyhow!("invalid embedded address"))
}

fn with_selector(signature: &str, arguments: Vec<u8>) -> Vec<u8> {
    let mut output = keccak256(signature.as_bytes()).as_slice()[..4].to_vec();
    output.extend(arguments);
    output
}

fn encode_multisend_tx(to: Address, data: &[u8], operation: u8) -> Vec<u8> {
    let mut output = Vec::with_capacity(1 + 20 + 32 + 32 + data.len());
    output.push(operation);
    output.extend(to.as_slice());
    output.extend([0u8; 32]);
    output.extend(U256::from(data.len()).to_be_bytes::<32>());
    output.extend(data);
    output
}

#[cfg(test)]
mod tests {
    use super::{build_wallet_ref, default_metadata, parse_hex_bytes};

    const GENERATOR: &str = "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";

    #[test]
    fn derives_the_existing_safe_wallet_reference() {
        assert_eq!(
            build_wallet_ref(GENERATOR).unwrap(),
            "0x000000000000000000000000d602f36e97fa37801565e3dc02f78ee0769d8fd6"
        );
        assert_eq!(
            build_wallet_ref(&format!("0x{GENERATOR}")).unwrap(),
            build_wallet_ref(GENERATOR).unwrap()
        );
    }

    #[test]
    fn encodes_the_documented_default_metadata() {
        assert!(default_metadata(GENERATOR).unwrap().starts_with("0x"));
        assert_eq!(parse_hex_bytes("0x00ff").unwrap(), vec![0, 255]);
    }
}
