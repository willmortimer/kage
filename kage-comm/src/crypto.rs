use crate::error::{KageError, Result};
use crate::kid::{Kid, KAGE_V2_PROTOCOL_VERSION};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

pub fn derive_k_env(k_org: &[u8], org: &str, env: &str) -> Result<Zeroizing<[u8; 32]>> {
    let hk = Hkdf::<Sha256>::new(None, k_org);
    let mut info = Vec::new();
    info.extend_from_slice(b"kage-v2-env");
    info.extend_from_slice(&crate::kid::canonical(org));
    info.extend_from_slice(&crate::kid::canonical(env));
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(&info, &mut okm[..])
        .map_err(|e| KageError::Crypto(format!("HKDF expand failed: {e:?}")))?;
    Ok(okm)
}

pub fn derive_k_wrap(k_env: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    let hk = Hkdf::<Sha256>::new(None, k_env);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(b"kage-v2-wrap", &mut okm[..])
        .map_err(|e| KageError::Crypto(format!("HKDF expand failed: {e:?}")))?;
    Ok(okm)
}

pub fn aad_for_kid(kid: Kid) -> [u8; 1 + 16] {
    let mut aad = [0u8; 17];
    aad[0] = KAGE_V2_PROTOCOL_VERSION;
    aad[1..].copy_from_slice(&kid.0);
    aad
}

pub fn wrap_file_key(
    k_wrap: &[u8; 32],
    kid: Kid,
    file_key: &[u8],
) -> Result<(Kid, [u8; 24], Vec<u8>)> {
    if file_key.is_empty() {
        return Err(KageError::InvalidInput("file_key is empty".into()));
    }

    let cipher = XChaCha20Poly1305::new(k_wrap.into());
    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce);

    let aad = aad_for_kid(kid);
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: file_key,
                aad: &aad,
            },
        )
        .map_err(|e| KageError::Crypto(format!("encrypt failed: {e:?}")))?;

    Ok((kid, nonce, ct))
}

pub fn unwrap_file_key(
    k_wrap: &[u8; 32],
    kid: Kid,
    nonce: &[u8; 24],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(k_wrap.into());
    let aad = aad_for_kid(kid);
    let pt = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|e| KageError::Crypto(format!("decrypt failed: {e:?}")))?;
    Ok(pt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kid::derive_kid;

    #[test]
    fn wrap_unwrap_roundtrip() {
        let k_org = [7u8; 32];
        let k_env = derive_k_env(&k_org, "acme", "dev").unwrap();
        let mut k_env_arr = [0u8; 32];
        k_env_arr.copy_from_slice(&k_env[..]);
        let k_wrap = derive_k_wrap(&k_env_arr).unwrap();
        let mut k_wrap_arr = [0u8; 32];
        k_wrap_arr.copy_from_slice(&k_wrap[..]);

        let kid = derive_kid("acme", "dev");
        let file_key = [42u8; 16];

        let (_kid2, nonce, ct) = wrap_file_key(&k_wrap_arr, kid, &file_key).unwrap();
        let pt = unwrap_file_key(&k_wrap_arr, kid, &nonce, &ct).unwrap();
        assert_eq!(pt, file_key);
    }

    #[test]
    fn aad_binds_to_kid() {
        let k_wrap = [9u8; 32];
        let kid_a = derive_kid("acme", "dev");
        let kid_b = derive_kid("acme", "prod");
        let file_key = [1u8; 16];

        let (_kid2, nonce, ct) = wrap_file_key(&k_wrap, kid_a, &file_key).unwrap();
        assert!(unwrap_file_key(&k_wrap, kid_b, &nonce, &ct).is_err());
    }
}
