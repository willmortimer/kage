use crate::error::{KageError, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rand::RngCore;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const DEVICE_WRAP_KEY_FILE: &str = "device_wrap.key";
const ENV_WRAP_AAD: &[u8] = b"kage-v2-env-wrap";

fn home_dir() -> Result<PathBuf> {
    dirs::home_dir().ok_or_else(|| KageError::InvalidInput("HOME not set".into()))
}

pub fn v2_dir() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("KAGE_V2_DIR") {
        return Ok(PathBuf::from(p));
    }
    Ok(home_dir()?.join(".kage").join("v2"))
}

fn ensure_parent_dir(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

pub fn ensure_device_wrap_key() -> Result<Zeroizing<[u8; 32]>> {
    let path = v2_dir()?.join(DEVICE_WRAP_KEY_FILE);
    ensure_parent_dir(&path)?;

    if path.exists() {
        let bytes = fs::read(&path)?;
        if bytes.len() != 32 {
            return Err(KageError::InvalidInput(format!(
                "device wrap key has invalid length {}, expected 32",
                bytes.len()
            )));
        }
        let mut raw = [0u8; 32];
        raw.copy_from_slice(&bytes);
        return Ok(Zeroizing::new(raw));
    }

    let mut raw = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    fs::write(&path, raw)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    Ok(Zeroizing::new(raw))
}

pub fn wrap_k_env_software(k_env: &[u8; 32]) -> Result<String> {
    let device_key = ensure_device_wrap_key()?;
    let cipher = XChaCha20Poly1305::new((&device_key[..]).into());
    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: k_env,
                aad: ENV_WRAP_AAD,
            },
        )
        .map_err(|e| KageError::Crypto(format!("encrypt failed: {e:?}")))?;
    let mut blob = Vec::with_capacity(24 + ct.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ct);
    Ok(BASE64.encode(blob))
}

pub fn unwrap_k_env_software(wrapped_b64: &str) -> Result<Zeroizing<[u8; 32]>> {
    let device_key = ensure_device_wrap_key()?;
    let blob = BASE64.decode(wrapped_b64.trim())?;
    if blob.len() < 24 + 16 {
        return Err(KageError::InvalidInput(
            "wrapped K_env blob too short".into(),
        ));
    }
    let nonce: [u8; 24] = blob[0..24].try_into().expect("len checked");
    let ct = &blob[24..];

    let cipher = XChaCha20Poly1305::new((&device_key[..]).into());
    let pt = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: ct,
                aad: ENV_WRAP_AAD,
            },
        )
        .map_err(|e| KageError::Crypto(format!("decrypt failed: {e:?}")))?;
    if pt.len() != 32 {
        return Err(KageError::InvalidInput(format!(
            "invalid K_env length {}, expected 32",
            pt.len()
        )));
    }
    let mut raw = [0u8; 32];
    raw.copy_from_slice(&pt);
    Ok(Zeroizing::new(raw))
}
