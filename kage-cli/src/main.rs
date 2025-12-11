mod cli;
mod helpers;

use anyhow::bail;
use anyhow::Context;
use clap::Parser;
use cli::{Cli, Commands};
use helpers::HelperKeystore;
use kage_core::backend::OnePasswordBackend;
use kage_core::config::{
    BackendConfig, Config, DeviceConfig, KeystoreConfig, OnePasswordConfig, OrgConfig,
    PolicyConfig, Tpm2Config,
};
use kage_core::crypto::{bech32_age_secret, derive_k_env};
use kage_core::error::{KageError, Result};
use kage_core::keystore::DeviceKeystore;
use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

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

fn env_policy(config: &Config, env: &str) -> String {
    let danger = config
        .org
        .danger_levels
        .get(env)
        .map(|s| s.as_str())
        .unwrap_or("medium");
    config
        .policy
        .mapping
        .get(danger)
        .map(|s| s.as_str())
        .unwrap_or("presence")
        .to_string()
}

fn env_label(config: &Config, env: &str) -> String {
    if cfg!(target_os = "macos") {
        format!("kage-{}-{}", config.org.id, env)
    } else {
        config
            .device
            .keystore
            .tpm2
            .as_ref()
            .expect("TPM config must exist on non-macOS")
            .handle
            .clone()
    }
}

fn env_blob_path(config: &Config, env: &str) -> anyhow::Result<PathBuf> {
    let data_dir = get_data_dir()?;
    Ok(data_dir
        .join("wrapped")
        .join(&config.org.id)
        .join(env)
        .join(format!("{}.bin", config.device.id)))
}

fn load_env_context(config: &Config, env: &str) -> anyhow::Result<(String, String, PathBuf)> {
    let policy = env_policy(config, env);
    let label = env_label(config, env);
    let blob_path = env_blob_path(config, env)?;
    if !blob_path.exists() {
        bail!(
            "Key blob not found for env '{}'. Run `kage init --env {}` first.",
            env,
            env
        );
    }
    Ok((policy, label, blob_path))
}

fn load_k_env(
    env: &str,
    keystore: &HelperKeystore,
    config: &Config,
) -> anyhow::Result<(Vec<u8>, String, String)> {
    let (policy, label, blob_path) = load_env_context(config, env)?;
    let wrapped = fs::read(&blob_path)
        .with_context(|| format!("Failed to read blob at {}", blob_path.display()))?;
    let k_env_bytes = keystore
        .unwrap(&wrapped, &label, &policy)
        .with_context(|| "Failed to unwrap K_env with helper")?;
    Ok((k_env_bytes, policy, label))
}

fn age_identity_for_env(
    env: &str,
    keystore: &HelperKeystore,
    config: &Config,
) -> anyhow::Result<(String, String, String)> {
    let (k_env_bytes, policy, label) = load_k_env(env, keystore, config)?;
    let k_env: [u8; 32] = k_env_bytes
        .try_into()
        .map_err(|_| KageError::Crypto("Invalid key length".into()))?;
    let identity = bech32_age_secret(&k_env)?;
    Ok((identity, policy, label))
}

fn ensure_sops_available() -> anyhow::Result<()> {
    which::which("sops")
        .map(|_| ())
        .with_context(|| "sops not found in PATH; install SOPS or add it to PATH")
}

fn derive_recipient_from_identity(identity: &str) -> anyhow::Result<String> {
    which::which("age-keygen")
        .map(|_| ())
        .with_context(|| "age-keygen not found in PATH; install age to derive recipient")?;

    let mut child = Command::new("age-keygen")
        .arg("-y")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .with_context(|| "Failed to spawn age-keygen -y")?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(format!("{identity}\n").as_bytes())
            .with_context(|| "Failed to write identity to age-keygen stdin")?;
    }

    let output = child
        .wait_with_output()
        .with_context(|| "Failed to read age-keygen output")?;

    if !output.status.success() {
        bail!(
            "age-keygen -y failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn run_sops_decrypt(
    env: &str,
    file: &str,
    output: Option<String>,
    keystore: &HelperKeystore,
    config: &Config,
) -> anyhow::Result<()> {
    ensure_sops_available()?;
    let (identity, _, _) = age_identity_for_env(env, keystore, config)?;

    let mut cmd = Command::new("sops");
    cmd.env("SOPS_AGE_KEY", &identity).arg("-d").arg(file);

    let res = cmd.output().with_context(|| "Failed to run sops -d")?;
    if !res.status.success() {
        bail!(
            "sops decrypt failed: {}",
            String::from_utf8_lossy(&res.stderr)
        );
    }

    if let Some(out_path) = output {
        fs::write(&out_path, &res.stdout)
            .with_context(|| format!("Failed to write output to {}", out_path))?;
    } else {
        io::stdout().write_all(&res.stdout)?;
    }
    Ok(())
}

fn run_sops_encrypt(
    env: &str,
    file: &str,
    output: Option<String>,
    recipient: Option<String>,
    keystore: &HelperKeystore,
    config: &Config,
) -> anyhow::Result<()> {
    ensure_sops_available()?;
    let (identity, _, _) = age_identity_for_env(env, keystore, config)?;
    let recip = if let Some(r) = recipient {
        r
    } else {
        derive_recipient_from_identity(&identity)?
    };

    let mut cmd = Command::new("sops");
    cmd.env("SOPS_AGE_KEY", &identity)
        .arg("-e")
        .arg("--age")
        .arg(&recip)
        .arg(file);

    let res = cmd.output().with_context(|| "Failed to run sops -e")?;
    if !res.status.success() {
        bail!(
            "sops encrypt failed: {}",
            String::from_utf8_lossy(&res.stderr)
        );
    }

    if let Some(out_path) = output {
        fs::write(&out_path, &res.stdout)
            .with_context(|| format!("Failed to write output to {}", out_path))?;
    } else {
        io::stdout().write_all(&res.stdout)?;
    }
    Ok(())
}

fn run_self_test(env: &str, keystore: &HelperKeystore, config: &Config) -> anyhow::Result<()> {
    let (_, policy, label) = load_k_env(env, keystore, config)?;
    keystore
        .ensure_key(&label, &policy)
        .with_context(|| "Failed to ensure key exists before self-test")?;

    let sample = b"ping";
    let ct = keystore
        .wrap(sample, &label, &policy)
        .with_context(|| "Self-test encrypt failed")?;
    let pt = keystore
        .unwrap(&ct, &label, &policy)
        .with_context(|| "Self-test decrypt failed")?;

    if pt != sample {
        bail!("Self-test roundtrip mismatch");
    }

    println!(
        "Self-test ok for env '{}' (label='{}', policy='{}')",
        env, label, policy
    );
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let keystore = HelperKeystore::new()?;
    let backend = OnePasswordBackend::new();

    match cli.command {
        Commands::Init {
            org_id,
            env,
            vault,
            non_interactive: _,
        } => {
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
                            tpm2: Some(Tpm2Config {
                                handle: "0x81000001".into(),
                                pcr_banks: vec![0, 2, 7],
                            }),
                        },
                    },
                    backend: BackendConfig {
                        onepassword: OnePasswordConfig {
                            vault: vault.clone(),
                            item_id: None,
                        },
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
                    },
                }
            });

            // Check 1Password
            let (item_id, k_org) = backend
                .ensure_k_org(
                    &config.backend.onepassword.vault,
                    config.backend.onepassword.item_id.as_deref(),
                )
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
                let danger = config
                    .org
                    .danger_levels
                    .get(e)
                    .map(|s| s.as_str())
                    .unwrap_or("medium");
                let policy = config
                    .policy
                    .mapping
                    .get(danger)
                    .map(|s| s.as_str())
                    .unwrap_or("presence");

                // Label selection:
                // - macOS uses per-environment Secure Enclave keys: `kage-{org_id}-{env}`.
                // - TPM v1 uses the single persistent handle from config; all envs share that key/policy.

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
            let (identity, _, _) = age_identity_for_env(&env, &keystore, &config)?;
            println!("{}", identity);
        }
        Commands::SelfTest { env } => {
            let config = load_config()?.context("Config not found. Run init first.")?;
            run_self_test(&env, &keystore, &config)?;
        }
        Commands::RotateDeviceKey { env } => {
            let config = load_config()?.context("Config not found")?;
            let (policy, label, blob_path) = load_env_context(&config, &env)?;
            let wrapped = fs::read(&blob_path)?;

            // 1. Unwrap old
            // If unwrap fails (e.g. stale ACLs or auth failure), we fallback to 1Password recovery
            let k_env = match keystore.unwrap(&wrapped, &label, &policy) {
                Ok(bytes) => bytes,
                Err(e) => {
                    let msg = e.to_string();
                    // Check for Auth Failed (2), Auth Not Enrolled (3), or helper stderr containing interaction/auth keywords
                    // Also check for "Helper decrypt failed" which is the generic wrapper for stderr output
                    if msg.contains("Auth Failed")
                        || msg.contains("Auth Not Enrolled")
                        || msg.contains("interaction")
                        || msg.contains("deny")
                    {
                        eprintln!("Warning: Unwrap blocked by ACL / interaction policy ({}). Recovering from 1Password...", msg);
                        // Re-instantiate backend and fetch
                        let (item_id, k_org) = backend.ensure_k_org(
                            &config.backend.onepassword.vault,
                            config.backend.onepassword.item_id.as_deref(),
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
            keystore.ensure_key(&label, &policy)?;

            // 4. Wrap
            let new_wrapped = keystore.wrap(&k_env, &label, &policy)?;

            // 5. Write
            fs::write(blob_path, new_wrapped)?;

            println!("Key rotated successfully.");
        }
        Commands::SopsDecrypt { env, file, output } => {
            let config = load_config()?.context("Config not found. Run init first.")?;
            run_sops_decrypt(&env, &file, output, &keystore, &config)?;
        }
        Commands::SopsEncrypt {
            env,
            file,
            output,
            recipient,
        } => {
            let config = load_config()?.context("Config not found. Run init first.")?;
            run_sops_encrypt(&env, &file, output, recipient, &keystore, &config)?;
        }
    }

    Ok(())
}
