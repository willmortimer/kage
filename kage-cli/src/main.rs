mod onepassword;
mod platform;

use anyhow::Context;
use clap::{Parser, Subcommand};
use kage_comm::crypto;
use kage_comm::devwrap;
use kage_comm::kid::{derive_kid, Kid};
use kage_comm::transport::default_daemon_transport;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "kage")]
#[command(about = "Kage v2 admin CLI (setup/diagnostics/session control)")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Enrollment flow: fetch org root key, derive env keys, and write local records
    Setup {
        #[arg(long)]
        org: String,
        #[arg(long)]
        env: Vec<String>,
        /// 1Password vault containing the org root key
        #[arg(long = "1p-vault")]
        vault: String,
        /// Optional existing 1Password item id (if omitted, it is created)
        #[arg(long = "1p-item-id")]
        item_id: Option<String>,
        /// Policy per env (repeatable): e.g. --policy dev=none --policy prod=strong
        #[arg(long)]
        policy: Vec<String>,
    },
    /// Print Kage recipients (age1kage...) for configured envs
    List,
    /// Verify daemon connectivity and config sanity
    Doctor,
    /// Create a temporary unlock session for a KID (Strong policy batching)
    Unlock {
        #[arg(long)]
        env: String,
        #[arg(long, default_value_t = 60)]
        duration: u32,
    },
    /// Print an `age` plugin identity for `sops`/`age` decryption (non-secret)
    Identity,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Config {
    version: u32,
    org: String,
    onepassword_vault: String,
    onepassword_item_id: String,
    envs: BTreeMap<String, EnvConfig>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct EnvConfig {
    kid_bech32: String,
    policy: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct EnvRecord {
    kid_bech32: String,
    policy: String,
    wrapped_k_env_b64: String,
}

fn config_path() -> anyhow::Result<PathBuf> {
    Ok(devwrap::v2_dir()?.join("config.toml"))
}

fn records_dir() -> anyhow::Result<PathBuf> {
    Ok(devwrap::v2_dir()?.join("records"))
}

fn record_path(kid: Kid) -> anyhow::Result<PathBuf> {
    Ok(records_dir()?.join(format!("{}.json", kid.to_base64url_nopad())))
}

fn save_config(cfg: &Config) -> anyhow::Result<()> {
    let path = config_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let toml = toml::to_string_pretty(cfg)?;
    fs::write(&path, toml)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn load_config() -> anyhow::Result<Config> {
    let path = config_path()?;
    let s = fs::read_to_string(&path)
        .with_context(|| format!("missing config at {}", path.display()))?;
    Ok(toml::from_str(&s)?)
}

fn parse_policy_overrides(pairs: &[String]) -> anyhow::Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for p in pairs {
        let (env, pol) = p
            .split_once('=')
            .with_context(|| format!("invalid --policy value '{p}', expected env=policy"))?;
        out.insert(env.to_string(), pol.to_string());
    }
    Ok(out)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Setup {
            org,
            env,
            vault,
            item_id,
            policy,
        } => {
            let policy_overrides = parse_policy_overrides(&policy)?;
            let backend = onepassword::OnePasswordBackend::new();

            let (resolved_item_id, k_org) = backend
                .ensure_k_org(&vault, item_id.as_deref())
                .context("failed to fetch or create org root key in 1Password")?;

            let mut envs_cfg = BTreeMap::new();
            for e in &env {
                let kid = derive_kid(&org, e);
                let kid_bech32 = kid.to_bech32()?;

                let policy = policy_overrides
                    .get(e)
                    .cloned()
                    .unwrap_or_else(|| default_policy_for_env(e));

                let k_env = crypto::derive_k_env(&k_org, &org, e)?;
                let mut k_env_arr = [0u8; 32];
                k_env_arr.copy_from_slice(&k_env[..]);
                let wrapped_k_env_b64 = platform::wrap_k_env(kid, &policy, &k_env_arr)?;

                let record = EnvRecord {
                    kid_bech32: kid_bech32.clone(),
                    policy: policy.clone(),
                    wrapped_k_env_b64,
                };

                let rp = record_path(kid)?;
                if let Some(parent) = rp.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(&rp, serde_json::to_vec_pretty(&record)?)?;
                fs::set_permissions(&rp, fs::Permissions::from_mode(0o600))?;

                envs_cfg.insert(e.to_string(), EnvConfig { kid_bech32, policy });
            }

            save_config(&Config {
                version: 2,
                org,
                onepassword_vault: vault,
                onepassword_item_id: resolved_item_id,
                envs: envs_cfg,
            })?;

            println!("kage setup complete.");
        }
        Commands::List => {
            let cfg = load_config()?;
            for (env, e) in cfg.envs {
                println!("{env}\t{}\t{}", e.kid_bech32, e.policy);
            }
        }
        Commands::Doctor => {
            let transport = default_daemon_transport()?;
            match transport.ping().await {
                Ok(s) => println!("daemon: {s}"),
                Err(e) => {
                    println!("daemon: unavailable ({e})");
                }
            }
            let cfg = load_config()?;
            println!("config: ok (org={}, envs={})", cfg.org, cfg.envs.len());
        }
        Commands::Unlock { env, duration } => {
            let cfg = load_config()?;
            let e = cfg
                .envs
                .get(&env)
                .with_context(|| format!("unknown env '{env}'"))?;
            let transport = default_daemon_transport()?;
            transport.unlock(&e.kid_bech32, duration).await?;
            println!("unlocked env={env} for {duration}s");
        }
        Commands::Identity => {
            println!("{}", kage_comm::kid::plugin_identity()?);
        }
    }

    Ok(())
}

fn default_policy_for_env(env: &str) -> String {
    match env {
        "prod" | "production" => "strong".into(),
        "stage" | "staging" => "presence".into(),
        _ => "none".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_temp_v2_dir<T>(f: impl FnOnce(&TempDir) -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("KAGE_V2_DIR", dir.path());
        let out = f(&dir);
        std::env::remove_var("KAGE_V2_DIR");
        out
    }

    #[test]
    fn config_roundtrip() {
        with_temp_v2_dir(|_dir| {
            let cfg = Config {
                version: 2,
                org: "acme".to_string(),
                onepassword_vault: "Private".to_string(),
                onepassword_item_id: "item123".to_string(),
                envs: BTreeMap::from([(
                    "dev".to_string(),
                    EnvConfig {
                        kid_bech32: derive_kid("acme", "dev").to_bech32().unwrap(),
                        policy: "none".to_string(),
                    },
                )]),
            };

            save_config(&cfg).unwrap();
            let got = load_config().unwrap();

            assert_eq!(got.version, cfg.version);
            assert_eq!(got.org, cfg.org);
            assert_eq!(got.onepassword_vault, cfg.onepassword_vault);
            assert_eq!(got.onepassword_item_id, cfg.onepassword_item_id);
            assert_eq!(got.envs.len(), 1);
            assert_eq!(got.envs.get("dev").unwrap().policy, "none");
        });
    }

    #[test]
    fn record_path_is_safe_filename() {
        with_temp_v2_dir(|_dir| {
            let kid = derive_kid("acme", "prod");
            let rp = record_path(kid).unwrap();
            let fname = rp.file_name().unwrap().to_string_lossy();
            assert!(fname.ends_with(".json"));
            assert!(!fname.contains('/'));
        });
    }
}
