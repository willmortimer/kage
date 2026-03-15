use anyhow::Context;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use kage_comm::kid::Kid;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

#[cfg(target_os = "macos")]
pub fn v2_key_label(kid: Kid) -> String {
    format!("kage-v2-{}", kid.to_base64url_nopad())
}

#[cfg(target_os = "macos")]
fn find_kagehelper_binary() -> anyhow::Result<PathBuf> {
    if let Ok(p) = std::env::var("KAGE_HELPER_PATH") {
        return Ok(PathBuf::from(p));
    }

    let exe = std::env::current_exe().context("cannot resolve current exe")?;
    let exe_dir = exe
        .parent()
        .context("cannot resolve exe directory")?
        .to_path_buf();

    let bundle = exe_dir.join("KageHelper.app/Contents/MacOS/KageHelper");
    if bundle.exists() {
        return Ok(bundle);
    }

    if let Ok(p) = which::which("KageHelper") {
        return Ok(p);
    }

    anyhow::bail!(
        "KageHelper not found; set KAGE_HELPER_PATH or build it into target/release/KageHelper.app"
    );
}

#[cfg(target_os = "macos")]
pub fn wrap_k_env(kid: Kid, policy: &str, k_env: &[u8; 32]) -> anyhow::Result<String> {
    let helper = find_kagehelper_binary()?;
    let label = v2_key_label(kid);

    // Ensure the hardware key exists for this environment.
    let status = Command::new(&helper)
        .arg("init-key")
        .arg(&label)
        .arg("--policy")
        .arg(policy)
        .status()
        .with_context(|| format!("failed to run {} init-key", helper.display()))?;
    if !status.success() {
        anyhow::bail!("KageHelper init-key failed (status={status})");
    }

    // Encrypt K_env with the public key; store ciphertext on disk (base64).
    let mut child = Command::new(&helper)
        .arg("encrypt")
        .arg(&label)
        .arg("--policy")
        .arg(policy)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to spawn {} encrypt", helper.display()))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(k_env)?;
    }

    let out = child
        .wait_with_output()
        .with_context(|| "failed to read KageHelper encrypt output")?;
    if !out.status.success() {
        anyhow::bail!(
            "KageHelper encrypt failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }

    Ok(BASE64.encode(out.stdout))
}

#[cfg(not(target_os = "macos"))]
pub fn wrap_k_env(kid: Kid, policy: &str, k_env: &[u8; 32]) -> anyhow::Result<String> {
    #[cfg(target_os = "linux")]
    {
        wrap_k_env_linux(kid, policy, k_env)
    }
    #[cfg(windows)]
    {
        let _ = policy;
        return Ok(kage_comm::dpapi::seal_k_env(kid, k_env)?);
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = (kid, policy, k_env);
        anyhow::bail!("unsupported platform")
    }
}

#[cfg(target_os = "linux")]
fn find_linux_helper() -> anyhow::Result<PathBuf> {
    if let Ok(p) = std::env::var("KAGE_LINUX_HELPER_PATH") {
        return Ok(PathBuf::from(p));
    }
    let exe = std::env::current_exe().context("cannot resolve current exe")?;
    if let Some(dir) = exe.parent() {
        let candidate = dir.join("kage-linux-helper");
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    which::which("kage-linux-helper").context("kage-linux-helper not found in PATH")
}

#[cfg(target_os = "linux")]
fn tpm_handle() -> String {
    std::env::var("KAGE_TPM_HANDLE").unwrap_or_else(|_| "0x81000001".to_string())
}

#[cfg(target_os = "linux")]
fn wrap_k_env_linux(_kid: Kid, policy: &str, k_env: &[u8; 32]) -> anyhow::Result<String> {
    let helper = find_linux_helper()?;
    let handle = tpm_handle();

    let mut init = Command::new(&helper);
    init.arg("init-key")
        .arg(&handle)
        .arg("--policy")
        .arg(policy);
    if (policy == "presence" || policy == "strong") && std::env::var("TPM_PIN").is_err() {
        anyhow::bail!("TPM_PIN must be set in the environment for policy={policy}");
    }
    let st = init
        .status()
        .with_context(|| format!("failed to run {}", helper.display()))?;
    if !st.success() {
        anyhow::bail!("kage-linux-helper init-key failed (status={st})");
    }

    let mut child = Command::new(&helper)
        .arg("encrypt")
        .arg(&handle)
        .arg("--policy")
        .arg(policy)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .with_context(|| "failed to spawn kage-linux-helper encrypt")?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(k_env)?;
    }

    let out = child.wait_with_output()?;
    if !out.status.success() {
        anyhow::bail!(
            "kage-linux-helper encrypt failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }

    Ok(BASE64.encode(out.stdout))
}
