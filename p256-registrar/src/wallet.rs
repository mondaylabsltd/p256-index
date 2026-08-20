//! Safe counterfactual wallet-reference derivation.
//!
//! A wallet ref is the CREATE2 address of the Safe that a P-256 passkey would
//! deploy, derived without touching the chain. This module owns the deployment
//! constants, the derivation itself, and the default `VelaWalletV1` metadata
//! scheme. It evolves with the Safe deployment scheme, not with the index
//! contract — which is why it is a separate domain from [`crate::protocol`].

use alloy::{
    primitives::{Address, B256, Bytes, U256, keccak256},
    sol_types::SolValue,
};
use anyhow::{Result, anyhow, bail};
use std::str::FromStr;

use crate::protocol::parse_hex_bytes;

const SAFE_PROXY_FACTORY: &str = "0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67";
const SAFE_SINGLETON: &str = "0x29fcB43b46531BcA003ddC8FCB67FFE91900C762";
const SAFE_4337_MODULE: &str = "0x75cf11467937ce3F2f357CE24ffc3DBF8fD5c226";
const SAFE_MODULE_SETUP: &str = "0x2dd68b007B46fBe91B9A7c3EDa5A7a1063cB5b47";
const WEBAUTHN_SIGNER: &str = "0x94a4F6affBd8975951142c3999aEAB7ecee555c2";
const MULTI_SEND: &str = "0x38869bf66a61cF6bDB996A6aE40D5853Fd43B526";
const PROXY_CREATION_CODE: &str = "608060405234801561001057600080fd5b506040516101e63803806101e68339818101604052602081101561003357600080fd5b8101908080519060200190929190505050600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff1614156100ca576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260228152602001806101c46022913960400191505060405180910390fd5b806000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505060ab806101196000396000f3fe608060405273ffffffffffffffffffffffffffffffffffffffff600054167fa619486e0000000000000000000000000000000000000000000000000000000060003514156050578060005260206000f35b3660008037600080366000845af43d6000803e60008114156070573d6000fd5b3d6000f3fea264697066735822122003d1488ee65e08fa41e58e888a9865554c535f2c77126a82cb4c0f917f31441364736f6c63430007060033496e76616c69642073696e676c65746f6e20616464726573732070726f7669646564";

/// V3 packed metadata convention: bytes32("VelaWalletV1") right-padded,
/// followed by the wallet's ordered 65-byte uncompressed P-256 pubkeys.
pub const METADATA_PREFIX: &[u8; 12] = b"VelaWalletV1";
pub const MAX_METADATA_KEYS: usize = 21;
const P256_KEY_LENGTH: usize = 65;

fn metadata_prefix_word() -> [u8; 32] {
    let mut word = [0u8; 32];
    word[..METADATA_PREFIX.len()].copy_from_slice(METADATA_PREFIX);
    word
}

/// Metadata for a single-key wallet: prefix word || the key itself.
pub fn default_metadata(public_key: &str) -> Result<String> {
    let public_key = parse_hex_bytes(public_key)?;
    Ok(format!(
        "0x{}{}",
        hex::encode(metadata_prefix_word()),
        hex::encode(public_key)
    ))
}

/// Metadata for an ordered key set: prefix word || pk1 || .. || pkN. This is
/// exactly what the V3 contract's createWallet constructs on-chain, so the
/// stored task metadata mirrors what every member record will carry.
pub fn packed_metadata(public_keys: &[Vec<u8>]) -> String {
    let mut out = format!("0x{}", hex::encode(metadata_prefix_word()));
    for key in public_keys {
        out.push_str(&hex::encode(key));
    }
    out
}

/// Parse and validate packed metadata, returning the ordered pubkey set.
/// Mirrors the V3 contract's `_validateMetadata`: exact prefix word, length
/// 32 + 65*N with 1 <= N <= 21, every key an uncompressed on-curve point.
pub fn parse_metadata_keys(metadata: &str) -> Result<Vec<Vec<u8>>> {
    let bytes = parse_hex_bytes(metadata)?;
    if bytes.len() < 32 + P256_KEY_LENGTH || !(bytes.len() - 32).is_multiple_of(P256_KEY_LENGTH) {
        bail!(
            "metadata must be bytes32(\"VelaWalletV1\") followed by 1-{MAX_METADATA_KEYS} packed 65-byte public keys"
        );
    }
    if bytes[..32] != metadata_prefix_word() {
        bail!("metadata must start with bytes32(\"VelaWalletV1\")");
    }
    let keys: Vec<Vec<u8>> = bytes[32..]
        .chunks(P256_KEY_LENGTH)
        .map(<[u8]>::to_vec)
        .collect();
    if keys.len() > MAX_METADATA_KEYS {
        bail!("metadata holds more than {MAX_METADATA_KEYS} public keys");
    }
    for key in &keys {
        if key[0] != 4 || p256::PublicKey::from_sec1_bytes(key).is_err() {
            bail!("every metadata public key must be a valid uncompressed P-256 point");
        }
    }
    Ok(keys)
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
    use super::{build_wallet_ref, default_metadata, parse_metadata_keys};
    use crate::protocol::parse_hex_bytes;
    use alloy::sol_types::SolValue;

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
    fn encodes_the_packed_default_metadata() {
        let metadata = default_metadata(GENERATOR).unwrap();
        // bytes32("VelaWalletV1") right-padded, then the raw 65-byte key.
        assert!(metadata.starts_with("0x56656c6157616c6c65745631"));
        assert_eq!(metadata.len(), 2 + 64 + 130);
        let keys = parse_metadata_keys(&metadata).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(hex::encode(&keys[0]), GENERATOR);
        assert_eq!(parse_hex_bytes("0x00ff").unwrap(), vec![0, 255]);
    }

    #[test]
    fn parses_multi_key_metadata_in_order() {
        let single = default_metadata(GENERATOR).unwrap();
        let two_keys = format!("{single}{GENERATOR}");
        let keys = parse_metadata_keys(&two_keys).unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(hex::encode(&keys[1]), GENERATOR);
    }

    #[test]
    fn rejects_malformed_metadata() {
        // Legacy V2 abi.encode encoding is no longer valid.
        let key: alloy::primitives::Bytes = parse_hex_bytes(GENERATOR).unwrap().into();
        let legacy = format!(
            "0x{}",
            hex::encode(("VelaWalletV1".to_owned(), key).abi_encode_params())
        );
        assert!(parse_metadata_keys(&legacy).is_err());

        // Prefix word alone, truncated key, wrong prefix, too many keys.
        let single = default_metadata(GENERATOR).unwrap();
        assert!(parse_metadata_keys(&single[..2 + 64]).is_err());
        assert!(parse_metadata_keys(&format!("{single}04aa")).is_err());
        assert!(parse_metadata_keys(&single.replacen("56", "76", 1)).is_err());
        let mut too_many = default_metadata(GENERATOR).unwrap();
        for _ in 0..21 {
            too_many.push_str(GENERATOR);
        }
        assert!(parse_metadata_keys(&too_many).is_err());

        // Off-curve key body.
        let mut off_curve = single.clone();
        off_curve.replace_range(2 + 64 + 2..2 + 64 + 6, "aaaa");
        assert!(parse_metadata_keys(&off_curve).is_err());
    }
}
