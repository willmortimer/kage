mod onepassword;
mod platform;

use anyhow::Context;
use clap::{Parser, Subcommand};
use kage_comm::crypto;
use kage_comm::devwrap;
use kage_comm::kid::{derive_kid, Kid};
use kage_comm::manifest_io;
use kage_comm::transport::{self, default_daemon_transport};
use kage_types::secret::EncryptedSecret;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "kage")]
#[command(about = "Kage v3 admin CLI (setup/diagnostics/session control/secrets)")]
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
    /// Revoke an active session for an environment
    Lock {
        #[arg(long)]
        env: String,
    },
    /// Print an `age` plugin identity for `sops`/`age` decryption (non-secret)
    Identity,
    /// Manage encrypted secrets
    Secret {
        #[command(subcommand)]
        action: SecretCommands,
    },
    /// Run a command with secrets injected as environment variables
    Run {
        /// Environment name
        env: String,
        /// Secret delivery mode
        #[arg(long, default_value = "env")]
        mode: String,
        /// Git repo root for repo-shared secrets (auto-detected if omitted)
        #[arg(long)]
        repo_root: Option<PathBuf>,
        /// Command and arguments to execute
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Signing key operations
    Sign {
        #[command(subcommand)]
        action: SignCommands,
    },
    /// Assertion token operations
    Assert {
        #[command(subcommand)]
        action: AssertCommands,
    },
    /// Artifact signing operations
    Artifact {
        #[command(subcommand)]
        action: ArtifactCommands,
    },
}

#[derive(Subcommand)]
enum SignCommands {
    /// Generate a signing keypair for an environment
    Init {
        /// Environment name
        env: String,
    },
    /// Sign data from stdin, print base64 signature to stdout
    Data {
        /// Environment name
        env: String,
    },
    /// Print the base64 public key for an environment
    Pubkey {
        /// Environment name
        env: String,
    },
    /// Print the SSH public key line (for allowed_signers / git)
    GitPubkey {
        /// Environment name
        env: String,
    },
    /// Configure git to use kage for commit/tag signing
    GitSetup {
        /// Environment name
        env: String,
    },
}

#[derive(Subcommand)]
enum AssertCommands {
    /// Issue a short-lived signed assertion token
    Issue {
        /// Environment name
        env: String,
        /// Purpose (e.g. admin, deploy)
        #[arg(long)]
        purpose: String,
        /// Scope string (e.g. org:acme/env:dev)
        #[arg(long, default_value = "")]
        scope: String,
        /// Token TTL in seconds
        #[arg(long, default_value_t = 300)]
        ttl: i64,
    },
    /// Verify an assertion token
    Verify {
        /// Environment name
        env: String,
        /// The assertion token to verify
        #[arg(long)]
        token: String,
    },
}

#[derive(Subcommand)]
enum ArtifactCommands {
    /// Sign a file (compute SHA-256, sign digest, write .kage-sig)
    Sign {
        /// Environment name
        env: String,
        /// Path to the file to sign
        #[arg(long)]
        file: PathBuf,
    },
    /// Sign a release manifest (walk directory, compute digests)
    SignManifest {
        /// Environment name
        env: String,
        /// Path to the directory to sign
        #[arg(long)]
        dir: PathBuf,
    },
    /// Verify an artifact signature
    Verify {
        /// Environment name
        env: String,
        /// Path to the .kage-sig signature file
        #[arg(long)]
        signature: PathBuf,
    },
    /// Verify a release manifest signature and check file digests
    VerifyManifest {
        /// Environment name
        env: String,
        /// Path to the manifest JSON file
        #[arg(long)]
        manifest: PathBuf,
        /// Base directory to check file digests against
        #[arg(long)]
        dir: PathBuf,
    },
}

#[derive(Subcommand)]
enum SecretCommands {
    /// Store an encrypted secret
    Set {
        /// Environment name
        env: String,
        /// Secret name
        name: String,
        /// Secret value (if omitted, reads from stdin)
        #[arg(long)]
        value: Option<String>,
    },
    /// List secret names in an environment
    List {
        /// Environment name
        env: String,
    },
    /// Remove a secret
    Rm {
        /// Environment name
        env: String,
        /// Secret name
        name: String,
    },
    /// Decrypt and print a secret
    Get {
        /// Environment name
        env: String,
        /// Secret name
        name: String,
    },
    /// Store a local override secret (takes precedence over base/repo)
    SetOverride {
        /// Environment name
        env: String,
        /// Secret name
        name: String,
        /// Secret value (if omitted, reads from stdin)
        #[arg(long)]
        value: Option<String>,
    },
    /// List secrets showing which layer each comes from
    ListLayers {
        /// Environment name
        env: String,
        /// Git repo root for repo-shared secrets (auto-detected if omitted)
        #[arg(long)]
        repo_root: Option<PathBuf>,
    },
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
        Commands::Lock { env } => {
            let cfg = load_config()?;
            let e = cfg
                .envs
                .get(&env)
                .with_context(|| format!("unknown env '{env}'"))?;
            let transport = default_daemon_transport()?;
            transport.lock(&e.kid_bech32).await?;
            println!("locked env={env}");
        }
        Commands::Identity => {
            println!("{}", kage_comm::kid::plugin_identity()?);
        }
        Commands::Secret { action } => {
            let cfg = load_config()?;
            let transport = default_daemon_transport()?;

            match action {
                SecretCommands::Set { env, name, value } => {
                    cfg.envs
                        .get(&env)
                        .with_context(|| format!("unknown env '{env}'"))?;

                    let plaintext = match value {
                        Some(v) => v.into_bytes(),
                        None => {
                            use std::io::Read;
                            let mut buf = Vec::new();
                            std::io::stdin().read_to_end(&mut buf)?;
                            if buf.last() == Some(&b'\n') {
                                buf.pop();
                            }
                            buf
                        }
                    };

                    let ciphertext_b64 = transport::encrypt_secret(
                        transport.as_ref(),
                        &cfg.org,
                        &env,
                        &name,
                        &plaintext,
                    )
                    .await?;

                    let mut manifest = manifest_io::load_manifest(&cfg.org, &env)?;
                    manifest.secrets.insert(
                        name.clone(),
                        EncryptedSecret {
                            ciphertext_b64,
                            created_at: chrono::Utc::now()
                                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                            source: None,
                        },
                    );
                    manifest_io::save_manifest(&manifest)?;
                    println!("secret '{name}' set in env '{env}'");
                }
                SecretCommands::List { env } => {
                    let manifest = manifest_io::load_manifest(&cfg.org, &env)?;
                    for name in manifest.secrets.keys() {
                        println!("{name}");
                    }
                }
                SecretCommands::Rm { env, name } => {
                    let mut manifest = manifest_io::load_manifest(&cfg.org, &env)?;
                    if manifest.secrets.remove(&name).is_none() {
                        anyhow::bail!("secret '{name}' not found in env '{env}'");
                    }
                    manifest_io::save_manifest(&manifest)?;
                    println!("secret '{name}' removed from env '{env}'");
                }
                SecretCommands::Get { env, name } => {
                    cfg.envs
                        .get(&env)
                        .with_context(|| format!("unknown env '{env}'"))?;

                    let manifest = manifest_io::load_manifest(&cfg.org, &env)?;
                    let entry = manifest
                        .secrets
                        .get(&name)
                        .with_context(|| format!("secret '{name}' not found in env '{env}'"))?;

                    let plaintext = transport::decrypt_secret(
                        transport.as_ref(),
                        &cfg.org,
                        &env,
                        &name,
                        &entry.ciphertext_b64,
                    )
                    .await?;

                    let stdout = std::io::stdout();
                    use std::io::Write;
                    stdout.lock().write_all(&plaintext)?;
                }
                SecretCommands::SetOverride { env, name, value } => {
                    cfg.envs
                        .get(&env)
                        .with_context(|| format!("unknown env '{env}'"))?;

                    let plaintext = match value {
                        Some(v) => v.into_bytes(),
                        None => {
                            use std::io::Read;
                            let mut buf = Vec::new();
                            std::io::stdin().read_to_end(&mut buf)?;
                            if buf.last() == Some(&b'\n') {
                                buf.pop();
                            }
                            buf
                        }
                    };

                    let ciphertext_b64 = transport::encrypt_secret(
                        transport.as_ref(),
                        &cfg.org,
                        &env,
                        &name,
                        &plaintext,
                    )
                    .await?;

                    let mut overrides = manifest_io::load_overrides(&cfg.org, &env)?;
                    overrides.secrets.insert(
                        name.clone(),
                        EncryptedSecret {
                            ciphertext_b64,
                            created_at: chrono::Utc::now()
                                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                            source: Some("local".to_string()),
                        },
                    );
                    manifest_io::save_overrides(&overrides)?;
                    println!("override '{name}' set in env '{env}'");
                }
                SecretCommands::ListLayers { env, repo_root } => {
                    let repo = repo_root.or_else(detect_repo_root);
                    let manifest = manifest_io::load_layered_manifest(
                        &cfg.org,
                        &env,
                        repo.as_deref(),
                    )?;
                    for (name, secret) in &manifest.secrets {
                        let source = secret.source.as_deref().unwrap_or("base");
                        println!("{name}\t{source}");
                    }
                }
            }
        }
        Commands::Sign { action } => {
            let cfg = load_config()?;
            let transport = default_daemon_transport()?;

            match action {
                SignCommands::Init { env } => {
                    let e = cfg
                        .envs
                        .get(&env)
                        .with_context(|| format!("unknown env '{env}'"))?;
                    let public_key_b64 =
                        transport::sign_init(transport.as_ref(), &e.kid_bech32).await?;
                    println!("{public_key_b64}");
                }
                SignCommands::Data { env } => {
                    let e = cfg
                        .envs
                        .get(&env)
                        .with_context(|| format!("unknown env '{env}'"))?;

                    use std::io::Read;
                    let mut buf = Vec::new();
                    std::io::stdin().read_to_end(&mut buf)?;

                    let (signature_b64, _public_key_b64) =
                        transport::sign_bytes(transport.as_ref(), &e.kid_bech32, &buf).await?;
                    println!("{signature_b64}");
                }
                SignCommands::Pubkey { env } => {
                    let e = cfg
                        .envs
                        .get(&env)
                        .with_context(|| format!("unknown env '{env}'"))?;
                    let public_key_b64 =
                        transport::get_signing_public_key(transport.as_ref(), &e.kid_bech32)
                            .await?;
                    println!("{public_key_b64}");
                }
                SignCommands::GitPubkey { env } => {
                    let e = cfg
                        .envs
                        .get(&env)
                        .with_context(|| format!("unknown env '{env}'"))?;
                    let ssh_pubkey =
                        transport::get_git_ssh_pubkey(transport.as_ref(), &e.kid_bech32).await?;
                    println!("{ssh_pubkey}");
                }
                SignCommands::GitSetup { env } => {
                    let e = cfg
                        .envs
                        .get(&env)
                        .with_context(|| format!("unknown env '{env}'"))?;

                    // Write kid_bech32 to ~/.kage/v2/git-signing-key
                    let v2_dir = kage_comm::devwrap::v2_dir()?;
                    let key_path = v2_dir.join("git-signing-key");
                    fs::write(&key_path, &e.kid_bech32)?;
                    #[cfg(unix)]
                    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))?;

                    // Configure git globally
                    let signer_path = which::which("kage-git-signer")
                        .unwrap_or_else(|_| PathBuf::from("kage-git-signer"));
                    std::process::Command::new("git")
                        .args(["config", "--global", "gpg.format", "ssh"])
                        .status()
                        .context("failed to set gpg.format")?;
                    std::process::Command::new("git")
                        .args([
                            "config",
                            "--global",
                            "gpg.ssh.program",
                            &signer_path.to_string_lossy(),
                        ])
                        .status()
                        .context("failed to set gpg.ssh.program")?;
                    std::process::Command::new("git")
                        .args([
                            "config",
                            "--global",
                            "user.signingkey",
                            &key_path.to_string_lossy(),
                        ])
                        .status()
                        .context("failed to set user.signingkey")?;

                    println!("git signing configured (env={env})");
                    println!("  signing key: {}", key_path.display());
                    println!("  signer: {}", signer_path.display());
                }
            }
        }
        Commands::Assert { action } => {
            let cfg = load_config()?;
            let transport = default_daemon_transport()?;

            match action {
                AssertCommands::Issue {
                    env,
                    purpose,
                    scope,
                    ttl,
                } => {
                    let e = cfg
                        .envs
                        .get(&env)
                        .with_context(|| format!("unknown env '{env}'"))?;
                    let (token, expires_at) = transport::issue_assertion(
                        transport.as_ref(),
                        &e.kid_bech32,
                        &purpose,
                        &scope,
                        ttl,
                    )
                    .await?;
                    println!("{token}");
                    eprintln!("expires: {expires_at}");
                }
                AssertCommands::Verify { env, token } => {
                    let e = cfg
                        .envs
                        .get(&env)
                        .with_context(|| format!("unknown env '{env}'"))?;
                    let valid =
                        transport::verify_assertion_remote(transport.as_ref(), &e.kid_bech32, &token)
                            .await?;
                    if valid {
                        println!("valid");
                    } else {
                        println!("invalid");
                        std::process::exit(1);
                    }
                }
            }
        }
        Commands::Artifact { action } => {
            let cfg = load_config()?;
            let transport = default_daemon_transport()?;

            match action {
                ArtifactCommands::Sign { env, file } => {
                    let e = cfg
                        .envs
                        .get(&env)
                        .with_context(|| format!("unknown env '{env}'"))?;

                    use sha2::{Digest, Sha256};
                    let data = fs::read(&file)
                        .with_context(|| format!("reading file: {}", file.display()))?;
                    let digest = hex::encode(Sha256::digest(&data));

                    let metadata = BTreeMap::new();
                    let envelope_json = transport::sign_artifact_digest(
                        transport.as_ref(),
                        &e.kid_bech32,
                        &digest,
                        &metadata,
                    )
                    .await?;

                    let sig_path = format!("{}.kage-sig", file.display());
                    fs::write(&sig_path, &envelope_json)?;
                    println!("{sig_path}");
                }
                ArtifactCommands::SignManifest { env, dir } => {
                    let e = cfg
                        .envs
                        .get(&env)
                        .with_context(|| format!("unknown env '{env}'"))?;

                    use sha2::{Digest, Sha256};
                    let mut entries = Vec::new();
                    for entry in walkdir(&dir)? {
                        let path = entry.strip_prefix(&dir).unwrap_or(&entry);
                        let data = fs::read(&entry)?;
                        let digest = hex::encode(Sha256::digest(&data));
                        let size = data.len() as u64;
                        entries.push(serde_json::json!({
                            "path": path.to_string_lossy(),
                            "digest": digest,
                            "size": size,
                        }));
                    }

                    let metadata = BTreeMap::new();
                    let manifest_json = transport::sign_release_manifest(
                        transport.as_ref(),
                        &e.kid_bech32,
                        &entries,
                        &metadata,
                    )
                    .await?;

                    println!("{manifest_json}");
                }
                ArtifactCommands::Verify { env, signature } => {
                    let e = cfg
                        .envs
                        .get(&env)
                        .with_context(|| format!("unknown env '{env}'"))?;

                    let envelope_json = fs::read_to_string(&signature)
                        .with_context(|| format!("reading signature: {}", signature.display()))?;

                    let valid = transport::verify_artifact_digest(
                        transport.as_ref(),
                        &e.kid_bech32,
                        &envelope_json,
                    )
                    .await?;

                    if valid {
                        println!("valid");
                    } else {
                        println!("invalid");
                        std::process::exit(1);
                    }
                }
                ArtifactCommands::VerifyManifest { env, manifest, dir } => {
                    let e = cfg
                        .envs
                        .get(&env)
                        .with_context(|| format!("unknown env '{env}'"))?;

                    let manifest_json = fs::read_to_string(&manifest)
                        .with_context(|| format!("reading manifest: {}", manifest.display()))?;

                    // Verify the manifest signature via daemon
                    let sig_valid = transport::verify_release_manifest_remote(
                        transport.as_ref(),
                        &e.kid_bech32,
                        &manifest_json,
                    )
                    .await?;

                    if !sig_valid {
                        println!("manifest signature: invalid");
                        std::process::exit(1);
                    }
                    println!("manifest signature: valid");

                    // Verify file digests locally
                    let release_manifest: kage_comm::artifact_signature::ReleaseManifest =
                        serde_json::from_str(&manifest_json)
                            .context("invalid manifest JSON")?;

                    let mismatches =
                        kage_comm::artifact_signature::verify_manifest_files(&release_manifest, &dir);

                    if mismatches.is_empty() {
                        println!("file digests: all {} entries verified", release_manifest.payload.entries.len());
                    } else {
                        for m in &mismatches {
                            println!("MISMATCH: {} — {}", m.path, m.reason);
                        }
                        std::process::exit(1);
                    }
                }
            }
        }
        Commands::Run {
            env,
            mode,
            repo_root,
            command,
        } => {
            if command.is_empty() {
                anyhow::bail!("no command specified; usage: kage run <env> -- <command...>");
            }

            let cfg = load_config()?;
            cfg.envs
                .get(&env)
                .with_context(|| format!("unknown env '{env}'"))?;

            let repo = repo_root.or_else(detect_repo_root);
            let manifest =
                manifest_io::load_layered_manifest(&cfg.org, &env, repo.as_deref())?;
            if manifest.secrets.is_empty() {
                anyhow::bail!("no secrets in env '{env}'");
            }

            let transport = default_daemon_transport()?;

            let entries: Vec<(String, String)> = manifest
                .secrets
                .iter()
                .map(|(name, e)| (name.clone(), e.ciphertext_b64.clone()))
                .collect();

            let secrets =
                transport::release_secrets(transport.as_ref(), &cfg.org, &env, &entries).await?;

            match mode.as_str() {
                "env" => {
                    let mut cmd = std::process::Command::new(&command[0]);
                    cmd.args(&command[1..]);
                    for (name, value) in &secrets {
                        cmd.env(format!("KAGE_SECRET_{}", name.to_uppercase()), value);
                    }
                    let status = cmd.status().with_context(|| {
                        format!("failed to execute: {}", command[0])
                    })?;
                    std::process::exit(status.code().unwrap_or(1));
                }
                "tempfile" => {
                    let tmpdir = tempfile::tempdir()
                        .context("failed to create temp directory for secrets")?;

                    for (name, value) in &secrets {
                        let path = tmpdir.path().join(name);
                        fs::write(&path, value)?;
                        #[cfg(unix)]
                        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
                    }

                    let mut cmd = std::process::Command::new(&command[0]);
                    cmd.args(&command[1..]);
                    cmd.env("KAGE_SECRETS_DIR", tmpdir.path());
                    let status = cmd.status().with_context(|| {
                        format!("failed to execute: {}", command[0])
                    })?;

                    // tmpdir is cleaned up on drop
                    drop(tmpdir);
                    std::process::exit(status.code().unwrap_or(1));
                }
                other => {
                    anyhow::bail!("unknown mode '{other}'; supported: env, tempfile");
                }
            }
        }
    }

    Ok(())
}

/// Try to auto-detect the git repo root via `git rev-parse --show-toplevel`.
fn detect_repo_root() -> Option<PathBuf> {
    std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| PathBuf::from(String::from_utf8_lossy(&o.stdout).trim().to_string()))
}

/// Recursively walk a directory and return all file paths.
fn walkdir(dir: &std::path::Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        for entry in fs::read_dir(&current)
            .with_context(|| format!("reading directory: {}", current.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                files.push(path);
            }
        }
    }
    files.sort();
    Ok(files)
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
