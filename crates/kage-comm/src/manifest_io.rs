use crate::error::{KageError, Result};
use kage_types::secret::SecretManifest;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

fn secrets_base_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| KageError::InvalidInput("HOME not set".into()))?;
    Ok(home.join(".kage").join("v3").join("secrets"))
}

pub fn manifest_path(org: &str, env: &str) -> Result<PathBuf> {
    Ok(secrets_base_dir()?.join(org).join(format!("{env}.enc.json")))
}

pub fn load_manifest(org: &str, env: &str) -> Result<SecretManifest> {
    let path = manifest_path(org, env)?;
    if !path.exists() {
        return Ok(SecretManifest {
            version: 1,
            org: org.to_string(),
            env: env.to_string(),
            secrets: BTreeMap::new(),
        });
    }
    let bytes = fs::read(&path).map_err(KageError::Io)?;
    serde_json::from_slice(&bytes).map_err(KageError::Json)
}

fn overrides_base_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| KageError::InvalidInput("HOME not set".into()))?;
    Ok(home.join(".kage").join("v3").join("overrides"))
}

/// Path for local overrides: `~/.kage/v3/overrides/{org}/{env}.enc.json`
pub fn local_override_path(org: &str, env: &str) -> Result<PathBuf> {
    Ok(overrides_base_dir()?.join(org).join(format!("{env}.enc.json")))
}

/// Path for repo-shared secrets: `{repo_root}/.kage/secrets/{env}.enc.json`
pub fn repo_manifest_path(repo_root: &std::path::Path, env: &str) -> PathBuf {
    repo_root
        .join(".kage")
        .join("secrets")
        .join(format!("{env}.enc.json"))
}

/// Load a manifest from an arbitrary path, returning empty if not found.
fn load_manifest_from_path(
    path: &std::path::Path,
    org: &str,
    env: &str,
) -> Result<SecretManifest> {
    if !path.exists() {
        return Ok(SecretManifest {
            version: 1,
            org: org.to_string(),
            env: env.to_string(),
            secrets: BTreeMap::new(),
        });
    }
    let bytes = fs::read(path).map_err(KageError::Io)?;
    serde_json::from_slice(&bytes).map_err(KageError::Json)
}

/// Load local override manifest.
pub fn load_overrides(org: &str, env: &str) -> Result<SecretManifest> {
    let path = local_override_path(org, env)?;
    load_manifest_from_path(&path, org, env)
}

/// Save a local override manifest.
pub fn save_overrides(manifest: &SecretManifest) -> Result<()> {
    let path = local_override_path(&manifest.org, &manifest.env)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(KageError::Io)?;
    }
    let bytes = serde_json::to_vec_pretty(manifest)?;
    fs::write(&path, bytes).map_err(KageError::Io)?;

    #[cfg(unix)]
    {
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).map_err(KageError::Io)?;
    }

    Ok(())
}

/// Load a layered manifest by merging: base < repo-shared < local-overrides.
/// Each layer's secrets override the previous layer. The `source` field tracks provenance.
pub fn load_layered_manifest(
    org: &str,
    env: &str,
    repo_root: Option<&std::path::Path>,
) -> Result<SecretManifest> {
    // Layer 1: base manifest
    let mut merged = load_manifest(org, env)?;
    for secret in merged.secrets.values_mut() {
        if secret.source.is_none() {
            secret.source = Some("base".to_string());
        }
    }

    // Layer 2: repo-shared (if repo_root provided)
    if let Some(root) = repo_root {
        let repo_path = repo_manifest_path(root, env);
        let repo_manifest = load_manifest_from_path(&repo_path, org, env)?;
        for (name, mut secret) in repo_manifest.secrets {
            secret.source = Some("repo".to_string());
            merged.secrets.insert(name, secret);
        }
    }

    // Layer 3: local overrides (always win)
    let overrides = load_overrides(org, env)?;
    for (name, mut secret) in overrides.secrets {
        secret.source = Some("local".to_string());
        merged.secrets.insert(name, secret);
    }

    Ok(merged)
}

pub fn save_manifest(manifest: &SecretManifest) -> Result<()> {
    let path = manifest_path(&manifest.org, &manifest.env)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(KageError::Io)?;
    }
    let bytes = serde_json::to_vec_pretty(manifest)?;
    fs::write(&path, bytes).map_err(KageError::Io)?;

    #[cfg(unix)]
    {
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .map_err(KageError::Io)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kage_types::secret::EncryptedSecret;

    static HOME_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn manifest_path_structure() {
        let _guard = HOME_LOCK.lock().unwrap();
        let path = manifest_path("acme", "dev").unwrap();
        assert!(path.ends_with("acme/dev.enc.json"));
        assert!(path.to_string_lossy().contains(".kage/v3/secrets"));
    }

    #[test]
    fn load_missing_returns_empty() {
        let _guard = HOME_LOCK.lock().unwrap();
        let manifest = load_manifest("nonexistent-org-test", "nonexistent-env").unwrap();
        assert_eq!(manifest.version, 1);
        assert!(manifest.secrets.is_empty());
    }

    #[test]
    fn layered_manifest_base_only() {
        let _guard = HOME_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let orig_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", dir.path());

        let mut manifest = SecretManifest {
            version: 1,
            org: "test-org".to_string(),
            env: "dev".to_string(),
            secrets: BTreeMap::new(),
        };
        manifest.secrets.insert(
            "DB_PASS".to_string(),
            EncryptedSecret {
                ciphertext_b64: "base-ct".to_string(),
                created_at: "2026-01-01T00:00:00Z".to_string(),
                source: None,
            },
        );
        save_manifest(&manifest).unwrap();

        let merged = load_layered_manifest("test-org", "dev", None).unwrap();
        assert_eq!(merged.secrets.len(), 1);
        assert_eq!(
            merged.secrets["DB_PASS"].source.as_deref(),
            Some("base")
        );

        if let Some(h) = orig_home {
            std::env::set_var("HOME", h);
        }
    }

    #[test]
    fn layered_manifest_with_repo() {
        let _guard = HOME_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let orig_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", dir.path());

        // Base manifest
        let mut base = SecretManifest {
            version: 1,
            org: "test-org".to_string(),
            env: "dev".to_string(),
            secrets: BTreeMap::new(),
        };
        base.secrets.insert(
            "DB_PASS".to_string(),
            EncryptedSecret {
                ciphertext_b64: "base-ct".to_string(),
                created_at: "2026-01-01T00:00:00Z".to_string(),
                source: None,
            },
        );
        save_manifest(&base).unwrap();

        // Repo manifest (overrides DB_PASS, adds API_KEY)
        let repo_root = dir.path().join("repo");
        let repo_secrets_dir = repo_root.join(".kage").join("secrets");
        std::fs::create_dir_all(&repo_secrets_dir).unwrap();
        let mut repo = SecretManifest {
            version: 1,
            org: "test-org".to_string(),
            env: "dev".to_string(),
            secrets: BTreeMap::new(),
        };
        repo.secrets.insert(
            "DB_PASS".to_string(),
            EncryptedSecret {
                ciphertext_b64: "repo-ct".to_string(),
                created_at: "2026-01-01T00:00:00Z".to_string(),
                source: None,
            },
        );
        repo.secrets.insert(
            "API_KEY".to_string(),
            EncryptedSecret {
                ciphertext_b64: "repo-api".to_string(),
                created_at: "2026-01-01T00:00:00Z".to_string(),
                source: None,
            },
        );
        let repo_path = repo_manifest_path(&repo_root, "dev");
        std::fs::write(&repo_path, serde_json::to_vec_pretty(&repo).unwrap()).unwrap();

        let merged = load_layered_manifest("test-org", "dev", Some(&repo_root)).unwrap();
        assert_eq!(merged.secrets.len(), 2);
        assert_eq!(merged.secrets["DB_PASS"].ciphertext_b64, "repo-ct");
        assert_eq!(merged.secrets["DB_PASS"].source.as_deref(), Some("repo"));
        assert_eq!(merged.secrets["API_KEY"].source.as_deref(), Some("repo"));

        if let Some(h) = orig_home {
            std::env::set_var("HOME", h);
        }
    }

    #[test]
    fn layered_manifest_local_overrides_win() {
        let _guard = HOME_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let orig_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", dir.path());

        // Base manifest
        let mut base = SecretManifest {
            version: 1,
            org: "test-org".to_string(),
            env: "dev".to_string(),
            secrets: BTreeMap::new(),
        };
        base.secrets.insert(
            "DB_PASS".to_string(),
            EncryptedSecret {
                ciphertext_b64: "base-ct".to_string(),
                created_at: "2026-01-01T00:00:00Z".to_string(),
                source: None,
            },
        );
        save_manifest(&base).unwrap();

        // Local override
        let mut overrides = SecretManifest {
            version: 1,
            org: "test-org".to_string(),
            env: "dev".to_string(),
            secrets: BTreeMap::new(),
        };
        overrides.secrets.insert(
            "DB_PASS".to_string(),
            EncryptedSecret {
                ciphertext_b64: "local-ct".to_string(),
                created_at: "2026-01-01T00:00:00Z".to_string(),
                source: Some("local".to_string()),
            },
        );
        save_overrides(&overrides).unwrap();

        let merged = load_layered_manifest("test-org", "dev", None).unwrap();
        assert_eq!(merged.secrets.len(), 1);
        assert_eq!(merged.secrets["DB_PASS"].ciphertext_b64, "local-ct");
        assert_eq!(merged.secrets["DB_PASS"].source.as_deref(), Some("local"));

        if let Some(h) = orig_home {
            std::env::set_var("HOME", h);
        }
    }

    #[test]
    fn roundtrip_save_load() {
        let _guard = HOME_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let orig_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", dir.path());

        let mut manifest = SecretManifest {
            version: 1,
            org: "test-org".to_string(),
            env: "dev".to_string(),
            secrets: BTreeMap::new(),
        };
        manifest.secrets.insert(
            "DB_PASS".to_string(),
            EncryptedSecret {
                ciphertext_b64: "dGVzdA==".to_string(),
                created_at: "2026-01-01T00:00:00Z".to_string(),
                source: None,
            },
        );

        save_manifest(&manifest).unwrap();
        let loaded = load_manifest("test-org", "dev").unwrap();
        assert_eq!(loaded.org, "test-org");
        assert_eq!(loaded.env, "dev");
        assert_eq!(loaded.secrets.len(), 1);
        assert!(loaded.secrets.contains_key("DB_PASS"));

        if let Some(h) = orig_home {
            std::env::set_var("HOME", h);
        }
    }
}
