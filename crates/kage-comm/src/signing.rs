use crate::crypto::aad_for_kid;
use crate::error::{KageError, Result};
use crate::kid::Kid;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signer, Verifier};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

pub type SigningPublicKey = [u8; 32];
pub type SigningSecretKey = Zeroizing<[u8; 32]>;

/// Derive the signing-key seal key from k_env via HKDF-SHA256.
/// This is distinct from k_wrap (different info string).
pub fn derive_k_sign_seal(k_env: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    let hk = Hkdf::<Sha256>::new(None, k_env);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(b"kage-v3-sign-seal", &mut okm[..])
        .map_err(|e| KageError::Crypto(format!("HKDF expand failed: {e:?}")))?;
    Ok(okm)
}

/// Generate a random Ed25519 keypair.
pub fn generate_keypair() -> (SigningPublicKey, SigningSecretKey) {
    let mut rng = rand::thread_rng();
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();

    let public_key = verifying_key.to_bytes();
    let secret_key = Zeroizing::new(signing_key.to_bytes());

    (public_key, secret_key)
}

/// Seal an Ed25519 secret key with XChaCha20-Poly1305.
/// AAD = kid bytes (binds sealed key to specific environment).
/// Output: nonce (24 bytes) || ciphertext+tag.
pub fn seal_signing_key(
    k_sign_seal: &[u8; 32],
    kid: Kid,
    secret_key: &[u8; 32],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(k_sign_seal.into());
    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce);

    let aad = aad_for_kid(kid);
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: secret_key.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|e| KageError::Crypto(format!("seal signing key failed: {e:?}")))?;

    let mut out = Vec::with_capacity(24 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Unseal an Ed25519 secret key.
/// Input format: nonce (24 bytes) || ciphertext+tag.
pub fn unseal_signing_key(
    k_sign_seal: &[u8; 32],
    kid: Kid,
    sealed: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    if sealed.len() < 24 + 16 {
        return Err(KageError::Crypto("sealed signing key too short".into()));
    }
    let (nonce, ct) = sealed.split_at(24);
    let cipher = XChaCha20Poly1305::new(k_sign_seal.into());
    let aad = aad_for_kid(kid);
    let pt = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad: &aad,
            },
        )
        .map_err(|e| KageError::Crypto(format!("unseal signing key failed: {e:?}")))?;

    if pt.len() != 32 {
        return Err(KageError::Crypto(format!(
            "invalid signing key length {}, expected 32",
            pt.len()
        )));
    }
    let mut raw = [0u8; 32];
    raw.copy_from_slice(&pt);
    Ok(Zeroizing::new(raw))
}

/// Sign a message with an Ed25519 secret key.
pub fn sign_message(secret_key: &[u8; 32], message: &[u8]) -> Result<[u8; 64]> {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(secret_key);
    let signature = signing_key.sign(message);
    Ok(signature.to_bytes())
}

/// Verify an Ed25519 signature.
pub fn verify_signature(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<bool> {
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(public_key)
        .map_err(|e| KageError::Crypto(format!("invalid public key: {e}")))?;
    let sig = ed25519_dalek::Signature::from_bytes(signature);
    Ok(verifying_key.verify(message, &sig).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::derive_k_wrap;
    use crate::kid::derive_kid;

    #[test]
    fn seal_unseal_roundtrip() {
        let k_env = [42u8; 32];
        let kid = derive_kid("acme", "dev");
        let k_sign_seal = derive_k_sign_seal(&k_env).unwrap();

        let (_, secret_key) = generate_keypair();
        let sealed = seal_signing_key(&k_sign_seal, kid, &secret_key).unwrap();
        let unsealed = unseal_signing_key(&k_sign_seal, kid, &sealed).unwrap();

        assert_eq!(&*unsealed, &*secret_key);
    }

    #[test]
    fn sign_verify_roundtrip() {
        let (public_key, secret_key) = generate_keypair();
        let message = b"hello, world";

        let signature = sign_message(&secret_key, message).unwrap();
        let valid = verify_signature(&public_key, message, &signature).unwrap();

        assert!(valid);
    }

    #[test]
    fn wrong_seal_key_fails() {
        let k_env_a = [1u8; 32];
        let k_env_b = [2u8; 32];
        let kid = derive_kid("acme", "dev");

        let k_sign_seal_a = derive_k_sign_seal(&k_env_a).unwrap();
        let k_sign_seal_b = derive_k_sign_seal(&k_env_b).unwrap();

        let (_, secret_key) = generate_keypair();
        let sealed = seal_signing_key(&k_sign_seal_a, kid, &secret_key).unwrap();

        assert!(unseal_signing_key(&k_sign_seal_b, kid, &sealed).is_err());
    }

    #[test]
    fn wrong_kid_aad_fails() {
        let k_env = [42u8; 32];
        let kid_a = derive_kid("acme", "dev");
        let kid_b = derive_kid("acme", "prod");
        let k_sign_seal = derive_k_sign_seal(&k_env).unwrap();

        let (_, secret_key) = generate_keypair();
        let sealed = seal_signing_key(&k_sign_seal, kid_a, &secret_key).unwrap();

        assert!(unseal_signing_key(&k_sign_seal, kid_b, &sealed).is_err());
    }

    #[test]
    fn tampered_signature_fails() {
        let (public_key, secret_key) = generate_keypair();
        let message = b"important data";

        let mut signature = sign_message(&secret_key, message).unwrap();
        signature[0] ^= 0xFF; // flip bits

        let valid = verify_signature(&public_key, message, &signature).unwrap();
        assert!(!valid);
    }

    #[test]
    fn k_sign_seal_is_deterministic() {
        let k_env = [99u8; 32];
        let a = derive_k_sign_seal(&k_env).unwrap();
        let b = derive_k_sign_seal(&k_env).unwrap();
        assert_eq!(&*a, &*b);
    }

    #[test]
    fn k_sign_seal_differs_from_k_wrap() {
        let k_env = [42u8; 32];
        let k_sign_seal = derive_k_sign_seal(&k_env).unwrap();
        let k_wrap = derive_k_wrap(&k_env).unwrap();
        assert_ne!(&*k_sign_seal, &*k_wrap);
    }
}
