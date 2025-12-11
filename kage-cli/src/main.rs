mod cli;
mod helpers;

use clap::Parser;
use cli::{Cli, Commands};
use helpers::HelperKeystore;
use kage_core::backend::OnePasswordBackend;
use kage_core::config::{Config, DeviceConfig, BackendConfig, OnePasswordConfig, OrgConfig, PolicyConfig, KeystoreConfig, Tpm2Config};
use kage_core::crypto::{derive_k_env, bech32_age_secret};
use kage_core::keystore::DeviceKeystore;
use kage_core::error::{Result, KageError};
use std::collections::HashMap;
use std::path::{PathBuf};
use std::fs;
use anyhow::Context;

fn get_config_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or(KageError::Config("No home dir".into()))?;
    #[cfg(target_os = "macos")]
    let path = home.join("Library/Application Support/kage");
    #[cfg(target_os = "linux")]
    let path = home.join(".config/kage");
    
    if !path.exists() {
        fs::create_dir_all(&path)?;
    }
    Ok(path)
}

fn get_data_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or(KageError::Config("No home dir".into()))?;
    #[cfg(target_os = "macos")]
    let path = home.join("Library/Application Support/kage"); // Same as config for mac? Spec says so.
    #[cfg(target_os = "linux")]
    let path = home.join(".local/share/kage");
    
    if !path.exists() {
        fs::create_dir_all(&path)?;
    }
    Ok(path)
}

fn load_config() -> Result<Option<Config>> {
    let dir = get_config_dir()?;
    let path = dir.join("config.toml");
    if !path.exists() {
        return Ok(None);
    }
    let content = fs::read_to_string(path)?;
    let config: Config = toml::from_str(&content).map_err(|e| KageError::Config(e.to_string()))?;
    Ok(Some(config))
}

fn save_config(config: &Config) -> Result<()> {
    let dir = get_config_dir()?;
    let path = dir.join("config.toml");
    let content = toml::to_string(config).map_err(|e| KageError::Config(e.to_string()))?;
    fs::write(path, content)?;
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let keystore = HelperKeystore::new()?;
    let backend = OnePasswordBackend::new();

    match cli.command {
        Commands::Init { org_id, env, vault, non_interactive: _ } => {
            // Check dependencies
            if !keystore.is_available() {
                anyhow::bail!("Hardware backend unavailable");
            }
            
            // Generate or fetch K_org
            // Check if config exists to get item_id, else None
            let mut config = load_config()?.unwrap_or_else(|| {
                 // Create default config
                 Config {
                     version: 1,
                     device: DeviceConfig {
                         id: uuid::Uuid::new_v4().to_string(),
                         hostname: hostname::get().unwrap_or_default().to_string_lossy().into(),
                         keystore: KeystoreConfig {
                             keystore_type: "auto".into(),
                             tpm2: Some(Tpm2Config { handle: "0x81000001".into(), pcr_banks: vec![0, 2, 7] }),
                         }
                     },
                     backend: BackendConfig {
                         onepassword: OnePasswordConfig { vault: vault.clone(), item_id: None }
                     },
                     org: OrgConfig {
                         id: org_id.clone(),
                         envs: vec![],
                         danger_levels: HashMap::from([
                             ("dev".into(), "low".into()),
                             ("stage".into(), "medium".into()),
                             ("prod".into(), "high".into()),
                         ]),
                     },
                     policy: PolicyConfig {
                         mapping: HashMap::from([
                             ("low".into(), "none".into()),
                             ("medium".into(), "presence".into()),
                             ("high".into(), "strong".into()),
                         ]),
                     }
                 }
            });
            
            // Check 1Password
            let (item_id, k_org) = backend.ensure_k_org(&config.backend.onepassword.vault, config.backend.onepassword.item_id.as_deref())
                .context("Failed to ensure K_org in 1Password")?;
            
            config.backend.onepassword.item_id = Some(item_id);
            config.org.envs = env.clone(); // Update envs
            
            // Save config early
            save_config(&config)?;
            
            let data_dir = get_data_dir()?;
            
            for e in &env {
                // Derive K_env
                let k_env = derive_k_env(&k_org, e);
                
                // Determine policy
                let danger = config.org.danger_levels.get(e).map(|s| s.as_str()).unwrap_or("medium");
                let policy = config.policy.mapping.get(danger).map(|s| s.as_str()).unwrap_or("presence");
                
                // Determine label
                // For TPM, use handle. For macOS, use something unique like "kage-v1-{org}-{env}"?
                // Spec says "Label is ignored in v1.0 TPM... single persistent key handle".
                // For macOS, we need a label to store in keychain.
                // Using device.id might be good, but we have multiple envs.
                // Spec: "wrapped/{org_id}/{env}/{device_id}.bin"
                // The wrapper key is unique per device.
                // If TPM uses ONE persistent key, then ALL envs are wrapped by the SAME key.
                // If macOS uses ONE key per label...
                // Ideally we use one device key for everything to minimize authentications/keys?
                // Or one key per env?
                // Spec 5.3: "Authentication Policy... Configurable per environment".
                // If we have one key, it has ONE policy.
                // If we want different policies per env (dev=none, prod=strong), we need DIFFERENT keys.
                // Spec 8.3: "rotate-device-key... Reset Key: Delete existing hardware key... Re-create... Re-wrap K_env".
                // This implies one key per K_env? Or one key per "device"?
                // "wrapped/.../{device_id}.bin".
                // If we rotate, we re-wrap.
                // If we use one key for all envs, then rotating it affects all envs.
                // But policy is per env.
                // So we MUST have different keys per policy/env if policy differs.
                // Spec 6.1: "[device.keystore.tpm2] handle = ..." - This implies ONE handle.
                // This suggests TPM implementation in v1 only supports ONE key/policy for the whole device?
                // Or maybe we use the same handle but different policies? TPM keys have policy baked in.
                // So for TPM v1, we probably only support one policy or one key.
                // Spec 16 (Future Scope): "Labels: Support for multiple keys (distinct labels) on TPM backend."
                // This confirms TPM v1 has single key.
                // So for TPM, all envs share the policy of that key?
                // Or maybe we just use the HIGHEST required policy for the single key?
                // Or we accept that TPM v1 limits us.
                
                // For macOS, we can support multiple labels easily.
                // Let's use `kage-{org_id}-{env}` as label for macOS.
                // For TPM, we use the handle.
                
                let label = if cfg!(target_os = "macos") {
                    format!("kage-{}-{}", org_id, e)
                } else {
                    config.device.keystore.tpm2.as_ref().unwrap().handle.clone()
                };
                
                keystore.ensure_key(&label, policy)?;
                
                let wrapped = keystore.wrap(&k_env, &label, policy)?;
                
                // Write to disk
                let blob_path = data_dir.join("wrapped").join(&org_id).join(e);
                fs::create_dir_all(&blob_path)?;
                fs::write(blob_path.join(format!("{}.bin", config.device.id)), wrapped)?;
            }
            
            println!("Initialization complete.");
        }
        Commands::AgeIdentities { env } => {
            let config = load_config()?.context("Config not found. Run init first.")?;
            
            let data_dir = get_data_dir()?;
            let blob_path = data_dir
                .join("wrapped")
                .join(&config.org.id)
                .join(&env)
                .join(format!("{}.bin", config.device.id));
                
            if !blob_path.exists() {
                 anyhow::bail!("Key blob not found for env '{}'. Has this device been initialized with `kage-cli init`?", env);
            }
            
            let wrapped = fs::read(blob_path)?;
            
            let danger = config.org.danger_levels.get(&env).map(|s| s.as_str()).unwrap_or("medium");
            let policy = config.policy.mapping.get(danger).map(|s| s.as_str()).unwrap_or("presence");
            
            let label = if cfg!(target_os = "macos") {
                format!("kage-{}-{}", config.org.id, env)
            } else {
                config.device.keystore.tpm2.as_ref().unwrap().handle.clone()
            };
            
            let k_env_bytes = keystore.unwrap(&wrapped, &label, policy)?;
            let k_env: [u8; 32] = k_env_bytes.try_into().map_err(|_| KageError::Crypto("Invalid key length".into()))?;
            
            let identity = bech32_age_secret(&k_env)?;
            println!("{}", identity);
        }
        Commands::RotateDeviceKey { env } => {
            let config = load_config()?.context("Config not found")?;
            
            let data_dir = get_data_dir()?;
            let blob_path = data_dir
                .join("wrapped")
                .join(&config.org.id)
                .join(&env)
                .join(format!("{}.bin", config.device.id));
                
            if !blob_path.exists() {
                 anyhow::bail!("Key blob not found for env '{}'. Has this device been initialized with `kage-cli init`?", env);
            }
            
            let wrapped = fs::read(&blob_path)?;
            
            let danger = config.org.danger_levels.get(&env).map(|s| s.as_str()).unwrap_or("medium");
            let policy = config.policy.mapping.get(danger).map(|s| s.as_str()).unwrap_or("presence");
            
            let label = if cfg!(target_os = "macos") {
                format!("kage-{}-{}", config.org.id, env)
            } else {
                config.device.keystore.tpm2.as_ref().unwrap().handle.clone()
            };
            
            // 1. Unwrap old
            // If unwrap fails (e.g. stale ACLs or auth failure), we fallback to 1Password recovery
            let k_env = match keystore.unwrap(&wrapped, &label, policy) {
                Ok(bytes) => bytes,
                Err(e) => {
                    let msg = e.to_string();
                    // Check for Auth Failed (2), Auth Not Enrolled (3), or helper stderr containing interaction/auth keywords
                    // Also check for "Helper decrypt failed" which is the generic wrapper for stderr output
                    if msg.contains("Auth Failed") || msg.contains("Auth Not Enrolled") || msg.contains("interaction") || msg.contains("deny") {
                        eprintln!("Warning: Unwrap blocked by ACL / interaction policy ({}). Recovering from 1Password...", msg);
                        // Re-instantiate backend and fetch
                        let (item_id, k_org) = backend.ensure_k_org(
                            &config.backend.onepassword.vault, 
                            config.backend.onepassword.item_id.as_deref()
                        )?;
                        
                        // Update config if item_id changed (unlikely but possible)
                        if config.backend.onepassword.item_id.as_deref() != Some(&item_id) {
                             let mut new_config = config.clone();
                             new_config.backend.onepassword.item_id = Some(item_id);
                             save_config(&new_config)?;
                        }

                        // Derive k_env
                        derive_k_env(&k_org, &env).to_vec()
                    } else {
                        // For other errors (IO, binary missing, etc.), bail out
                        return Err(e.into());
                    }
                }
            };
            
            // 2. Delete
            keystore.delete_key(&label)?;
            
            // 3. Create
            keystore.ensure_key(&label, policy)?;
            
            // 4. Wrap
            let new_wrapped = keystore.wrap(&k_env, &label, policy)?;
            
            // 5. Write
            fs::write(blob_path, new_wrapped)?;
            
            println!("Key rotated successfully.");
        }
    }

    Ok(())
}
