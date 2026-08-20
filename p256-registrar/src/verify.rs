//! Pure possession-proof verification, mirroring the registry contract's
//! `_verifyProof` check for check — so the service can reject an invalid
//! proof at admission and never spend gas on a transaction that must revert.

use alloy::primitives::B256;
use anyhow::{Result, bail};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use sha2::{Digest, Sha256};

use crate::protocol::{parse_b256, parse_hex_bytes};
use crate::task::Proof;

const BASE64URL_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// The 43-character unpadded base64url of a 32-byte value — exactly what a
/// WebAuthn clientDataJSON challenge carries (mirror of Base64Url.encode32).
pub fn base64url_32(value: &B256) -> String {
    let bytes = value.0;
    let mut out = Vec::with_capacity(43);
    for chunk in bytes[..30].chunks(3) {
        let v = (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8) | u32::from(chunk[2]);
        out.push(BASE64URL_ALPHABET[(v >> 18) as usize & 0x3f]);
        out.push(BASE64URL_ALPHABET[(v >> 12) as usize & 0x3f]);
        out.push(BASE64URL_ALPHABET[(v >> 6) as usize & 0x3f]);
        out.push(BASE64URL_ALPHABET[v as usize & 0x3f]);
    }
    let tail = (u32::from(bytes[30]) << 8) | u32::from(bytes[31]);
    out.push(BASE64URL_ALPHABET[(tail >> 10) as usize & 0x3f]);
    out.push(BASE64URL_ALPHABET[(tail >> 4) as usize & 0x3f]);
    out.push(BASE64URL_ALPHABET[((tail << 2) & 0x3f) as usize]);
    String::from_utf8(out).expect("alphabet is ascii")
}

fn check_substring(data: &[u8], offset: u64, expected: &[u8]) -> bool {
    let Ok(offset) = usize::try_from(offset) else {
        return false;
    };
    let Some(end) = offset.checked_add(expected.len()) else {
        return false;
    };
    end <= data.len() && &data[offset..end] == expected
}

/// Verifies one member's WebAuthn-shaped possession proof against its
/// storage-authorization challenge; error messages name the failed check.
pub fn verify_proof(proof: &Proof, challenge: B256, rp_id: &str, public_key: &[u8]) -> Result<()> {
    let auth_data = parse_hex_bytes(&proof.authenticator_data)
        .map_err(|_| anyhow::anyhow!("authenticatorData must be a valid hex string"))?;
    if auth_data.len() < 37 {
        bail!("authenticatorData must be at least 37 bytes");
    }
    let rp_id_hash: [u8; 32] = Sha256::digest(rp_id.as_bytes()).into();
    if auth_data[..32] != rp_id_hash {
        bail!("authenticatorData rpIdHash does not match rpId");
    }
    if auth_data[32] & 0x01 == 0 {
        bail!("authenticatorData user-present flag is not set");
    }

    let client_data = proof.client_data_json.as_bytes();
    if !check_substring(client_data, proof.type_index, br#""type":"webauthn.get""#) {
        bail!("clientDataJSON does not carry \"type\":\"webauthn.get\" at typeIndex");
    }
    let expected_challenge = format!("\"challenge\":\"{}\"", base64url_32(&challenge));
    if !check_substring(
        client_data,
        proof.challenge_index,
        expected_challenge.as_bytes(),
    ) {
        bail!(
            "clientDataJSON does not carry the storage-authorization challenge at challengeIndex"
        );
    }

    let client_data_hash: [u8; 32] = Sha256::digest(client_data).into();
    let mut signed = Vec::with_capacity(auth_data.len() + 32);
    signed.extend_from_slice(&auth_data);
    signed.extend_from_slice(&client_data_hash);
    let digest: [u8; 32] = Sha256::digest(&signed).into();

    let verifying_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|_| anyhow::anyhow!("publicKey is not a valid P-256 point"))?;
    let r = parse_b256(&proof.r).map_err(|_| anyhow::anyhow!("signature r must be 32-byte hex"))?;
    let s = parse_b256(&proof.s).map_err(|_| anyhow::anyhow!("signature s must be 32-byte hex"))?;
    let signature = p256::ecdsa::Signature::from_scalars(r.0, s.0)
        .map_err(|_| anyhow::anyhow!("signature scalars are out of range"))?;
    verifying_key
        .verify_prehash(&digest, &signature)
        .map_err(|_| anyhow::anyhow!("signature does not verify for this publicKey"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::Address;
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use std::str::FromStr;

    fn keypair() -> (p256::ecdsa::SigningKey, Vec<u8>) {
        // A fixed scalar keeps the test deterministic.
        let secret = [
            0xba, 0xb2, 0x6f, 0x1a, 0xb9, 0x4e, 0x84, 0xa2, 0x31, 0x99, 0xc4, 0x6e, 0xc2, 0xdd,
            0x44, 0x89, 0x50, 0x7c, 0x27, 0x8d, 0xd3, 0xdd, 0xf2, 0xba, 0x0a, 0x47, 0xec, 0x20,
            0x12, 0x05, 0xfe, 0x7a,
        ];
        let key = p256::ecdsa::SigningKey::from_bytes((&secret).into()).unwrap();
        let public = key.verifying_key().to_sec1_point(false).as_bytes().to_vec();
        (key, public)
    }

    fn signed_proof(challenge: B256, rp_id: &str, flags: u8) -> (Proof, Vec<u8>) {
        let (signing, public) = keypair();
        let client_data = format!(
            "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"https://example.com\"}}",
            base64url_32(&challenge)
        );
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
        auth_data.push(flags);
        auth_data.extend_from_slice(&[0, 0, 0, 0]);
        let client_hash: [u8; 32] = Sha256::digest(client_data.as_bytes()).into();
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&client_hash);
        let digest: [u8; 32] = Sha256::digest(&signed).into();
        let signature: p256::ecdsa::Signature = signing.sign_prehash(&digest).unwrap();
        let (r, s) = {
            let bytes = signature.to_bytes();
            (
                format!("0x{}", hex::encode(&bytes[..32])),
                format!("0x{}", hex::encode(&bytes[32..])),
            )
        };
        (
            Proof {
                authenticator_data: hex::encode(auth_data),
                client_data_json: client_data,
                challenge_index: 23,
                type_index: 1,
                r,
                s,
            },
            public,
        )
    }

    fn challenge() -> B256 {
        let registry = Address::from_str("0x1111111111111111111111111111111111111111").unwrap();
        let (_, public) = keypair();
        crate::protocol::challenge_for(
            100,
            registry,
            "example.com",
            &public,
            B256::repeat_byte(0x11),
        )
    }

    #[test]
    fn a_real_signature_verifies() {
        let (proof, public) = signed_proof(challenge(), "example.com", 0x05);
        verify_proof(&proof, challenge(), "example.com", &public).unwrap();
    }

    #[test]
    fn each_check_rejects_its_own_failure() {
        let (good, public) = signed_proof(challenge(), "example.com", 0x05);

        // Wrong challenge expectation.
        let err = verify_proof(&good, B256::repeat_byte(0x99), "example.com", &public).unwrap_err();
        assert!(err.to_string().contains("challenge"), "{err}");

        // Wrong rpId (hash mismatch).
        let err = verify_proof(&good, challenge(), "other.com", &public).unwrap_err();
        assert!(err.to_string().contains("rpIdHash"), "{err}");

        // UP flag unset.
        let (no_up, public_up) = signed_proof(challenge(), "example.com", 0x04);
        let err = verify_proof(&no_up, challenge(), "example.com", &public_up).unwrap_err();
        assert!(err.to_string().contains("user-present"), "{err}");

        // Foreign key.
        let other = p256::ecdsa::SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let other_pub = other
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();
        let err = verify_proof(&good, challenge(), "example.com", &other_pub).unwrap_err();
        assert!(err.to_string().contains("does not verify"), "{err}");

        // Tampered clientDataJSON breaks the signature.
        let mut tampered = good.clone();
        tampered.client_data_json = tampered.client_data_json.replace("example.com", "evil.com");
        let err = verify_proof(&tampered, challenge(), "example.com", &public).unwrap_err();
        assert!(err.to_string().contains("does not verify"), "{err}");

        // Wrong ceremony type at typeIndex.
        let mut wrong_type = good.clone();
        wrong_type.type_index = 2;
        let err = verify_proof(&wrong_type, challenge(), "example.com", &public).unwrap_err();
        assert!(err.to_string().contains("webauthn.get"), "{err}");
    }

    #[test]
    fn base64url_matches_the_contract_shape() {
        // 43 chars, no padding, url-safe alphabet.
        let encoded = base64url_32(&B256::repeat_byte(0xfb));
        assert_eq!(encoded.len(), 43);
        assert!(!encoded.contains('='));
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
        // Spot value: 0xfb repeated = "-_v7..." pattern start "-_v7".
        assert!(encoded.starts_with("-_v7"));
    }
}
