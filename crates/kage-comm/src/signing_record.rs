use crate::error::{KageError, Result};
use crate::kid::Kid;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SigningKeyRecord {
    pub kid_bech32: String,
    pub algorithm: String,
    pub public_key_b64: String,
    pub sealed_private_key_b64: String,
    pub created_at: String,
}

fn signing_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| KageError::InvalidInput("HOME not set".into()))?;
    Ok(home.join(".kage").join("v2").join("signing"))
}

pub fn signing_record_path(kid: Kid) -> Result<PathBuf> {
    Ok(signing_dir()?.join(format!("{}.json", kid.to_base64url_nopad())))
}

pub fn save_signing_record(kid: Kid, record: &SigningKeyRecord) -> Result<()> {
    let path = signing_record_path(kid)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(KageError::Io)?;
    }
    let bytes = serde_json::to_vec_pretty(record)?;
    fs::write(&path, bytes).map_err(KageError::Io)?;

    #[cfg(unix)]
    {
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).map_err(KageError::Io)?;
    }

    Ok(())
}

pub fn load_signing_record(kid: Kid) -> Result<SigningKeyRecord> {
    let path = signing_record_path(kid)?;
    let bytes = fs::read(&path).map_err(|_| KageError::Daemon {
        code: crate::error::daemon_codes::KEY_NOT_FOUND,
        message: "signing record not found".into(),
    })?;
    serde_json::from_slice(&bytes).map_err(KageError::Json)
}

pub fn signing_record_exists(kid: Kid) -> Result<bool> {
    let path = signing_record_path(kid)?;
    Ok(path.exists())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kid::derive_kid;

    #[test]
    fn signing_record_path_structure() {
        let kid = derive_kid("acme", "dev");
        let path = signing_record_path(kid).unwrap();
        let fname = path.file_name().unwrap().to_string_lossy();
        assert!(fname.ends_with(".json"));
        assert!(path.to_string_lossy().contains(".kage/v2/signing"));
    }

    #[test]
    fn save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let orig_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", dir.path());

        let kid = derive_kid("acme", "dev");
        let record = SigningKeyRecord {
            kid_bech32: kid.to_bech32().unwrap(),
            algorithm: "ed25519".to_string(),
            public_key_b64: "dGVzdC1wdWJsaWMta2V5".to_string(),
            sealed_private_key_b64: "c2VhbGVkLWtleQ==".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
        };

        save_signing_record(kid, &record).unwrap();
        assert!(signing_record_exists(kid).unwrap());

        let loaded = load_signing_record(kid).unwrap();
        assert_eq!(loaded.kid_bech32, record.kid_bech32);
        assert_eq!(loaded.algorithm, "ed25519");
        assert_eq!(loaded.public_key_b64, record.public_key_b64);
        assert_eq!(loaded.sealed_private_key_b64, record.sealed_private_key_b64);

        if let Some(h) = orig_home {
            std::env::set_var("HOME", h);
        }
    }
}
