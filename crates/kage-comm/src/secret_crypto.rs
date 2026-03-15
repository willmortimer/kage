use crate::error::{KageError, Result};
use crate::kid::canonical;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;

/// Derive a per-secret key from k_env using HKDF-SHA256.
///
/// info = "kage-secret-v1" || canonical(org) || canonical(env) || canonical(secret_name)
pub fn derive_k_secret(
    k_env: &[u8; 32],
    org: &str,
    env: &str,
    secret_name: &str,
) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, k_env);
    let mut info = Vec::new();
    info.extend_from_slice(b"kage-secret-v1");
    info.extend_from_slice(&canonical(org));
    info.extend_from_slice(&canonical(env));
    info.extend_from_slice(&canonical(secret_name));
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm)
        .map_err(|e| KageError::Crypto(format!("HKDF expand failed: {e:?}")))?;
    Ok(okm)
}

/// Encrypt a secret with XChaCha20-Poly1305.
/// Returns nonce (24 bytes) || ciphertext+tag.
pub fn encrypt_secret(k_secret: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(k_secret.into());
    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce);

    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|e| KageError::Crypto(format!("encrypt failed: {e:?}")))?;

    let mut out = Vec::with_capacity(24 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a secret. Input format: nonce (24 bytes) || ciphertext+tag.
pub fn decrypt_secret(k_secret: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() < 24 {
        return Err(KageError::Crypto(
            "ciphertext too short (missing nonce)".into(),
        ));
    }
    let (nonce, ct) = ciphertext.split_at(24);
    let cipher = XChaCha20Poly1305::new(k_secret.into());
    let pt = cipher
        .decrypt(XNonce::from_slice(nonce), ct)
        .map_err(|e| KageError::Crypto(format!("decrypt failed: {e:?}")))?;
    Ok(pt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let k_env = [42u8; 32];
        let k_secret = derive_k_secret(&k_env, "acme", "dev", "DB_PASSWORD").unwrap();
        let plaintext = b"super-secret-password";
        let ct = encrypt_secret(&k_secret, plaintext).unwrap();
        let pt = decrypt_secret(&k_secret, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let k_env = [42u8; 32];
        let k_secret = derive_k_secret(&k_env, "acme", "dev", "DB_PASSWORD").unwrap();
        let plaintext = b"secret";
        let ct = encrypt_secret(&k_secret, plaintext).unwrap();

        let wrong_key = derive_k_secret(&k_env, "acme", "prod", "DB_PASSWORD").unwrap();
        assert!(decrypt_secret(&wrong_key, &ct).is_err());
    }

    #[test]
    fn empty_plaintext_works() {
        let k_env = [7u8; 32];
        let k_secret = derive_k_secret(&k_env, "acme", "dev", "EMPTY").unwrap();
        let ct = encrypt_secret(&k_secret, b"").unwrap();
        let pt = decrypt_secret(&k_secret, &ct).unwrap();
        assert_eq!(pt, b"");
    }

    #[test]
    fn different_secret_names_derive_different_keys() {
        let k_env = [1u8; 32];
        let k1 = derive_k_secret(&k_env, "acme", "dev", "A").unwrap();
        let k2 = derive_k_secret(&k_env, "acme", "dev", "B").unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn short_ciphertext_rejected() {
        let k = [0u8; 32];
        assert!(decrypt_secret(&k, &[0u8; 10]).is_err());
    }
}
