use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::io::{Write, Read};
use kage_core::keystore::DeviceKeystore;
use kage_core::error::{Result, KageError};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct AgentRequest<'a> {
    cmd: &'a str,
    label: &'a str,
    policy: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<String>, // base64
}

#[derive(Deserialize)]
struct AgentResponse {
    ok: bool,
    #[serde(default)]
    data: Option<String>, // base64
    #[serde(default)]
    error: Option<String>,
}

#[cfg(unix)]
fn agent_socket_path() -> Option<PathBuf> {
    dirs::home_dir().map(|mut p| {
        p.push(".kage/agent.sock");
        p
    })
}

fn agent_enabled() -> bool {
    std::env::var("KAGE_USE_AGENT")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn agent_available() -> bool {
    if !agent_enabled() {
        return false;
    }
    #[cfg(unix)]
    {
        if let Some(p) = agent_socket_path() {
            return p.exists();
        }
        false
    }
    #[cfg(not(unix))]
    {
        false
    }
}

#[cfg(unix)]
fn call_agent(
    cmd: &str,
    label: &str,
    policy: &str,
    input: Option<&[u8]>,
) -> Result<AgentResponse> {
    use std::os::unix::net::UnixStream;
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

    let sock_path = agent_socket_path()
        .ok_or_else(|| KageError::Keystore("HOME not set".into()))?;

    let mut stream = UnixStream::connect(&sock_path)
        .map_err(|e| KageError::Keystore(format!("Agent connect failed: {e}")))?;

    let data_b64 = input.map(|bytes| BASE64.encode(bytes));

    let req = AgentRequest {
        cmd,
        label,
        policy,
        data: data_b64,
    };

    let mut payload = serde_json::to_vec(&req)
        .map_err(|e| KageError::Keystore(format!("Agent request encode failed: {e}")))?;
    payload.push(b'\n'); // Newline delimiter

    stream
        .write_all(&payload)
        .map_err(|e| KageError::Keystore(format!("Agent write failed: {e}")))?;

    // Read until newline
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];

    loop {
        let n = stream
            .read(&mut byte)
            .map_err(|e| KageError::Keystore(format!("Agent read failed: {e}")))?;
        if n == 0 {
            break;
        }
        if byte[0] == b'\n' {
            break;
        }
        buf.push(byte[0]);
    }

    let resp: AgentResponse = serde_json::from_slice(&buf)
        .map_err(|e| KageError::Keystore(format!("Agent response decode failed: {e}")))?;

    Ok(resp)
}

pub struct HelperKeystore {
    helper_path: PathBuf,
}

impl HelperKeystore {
    pub fn new() -> Result<Self> {
        let exe_path = std::env::current_exe()?;
        let exe_dir = exe_path.parent().ok_or(KageError::Keystore("Cannot find exe dir".into()))?;
        
        #[cfg(target_os = "macos")]
        {
            // Try App Bundle path first
            // Xcode target "KageHelper" produces binary "KageHelper" inside the bundle
            let app_path = exe_dir.join("KageHelper.app/Contents/MacOS/KageHelper");
            if app_path.exists() {
                return Ok(Self { helper_path: app_path });
            }
            
            // Fallback to side-by-side binary (old way)
            let raw_path = exe_dir.join("kage-mac-helper");
            if raw_path.exists() {
                return Ok(Self { helper_path: raw_path });
            }
        }
        
        #[cfg(target_os = "linux")]
        {
             let path = exe_dir.join("kage-linux-helper");
             if path.exists() {
                 return Ok(Self { helper_path: path });
             }
        }
        
        // Try looking in PATH
        let lookup_name = if cfg!(target_os = "macos") { "kage-mac-helper" } else { "kage-linux-helper" };
        if let Ok(path) = which::which(lookup_name) {
            return Ok(Self { helper_path: path });
        }

        Err(KageError::Keystore(format!("Helper binary not found")))
    }

    fn ensure_key_via_subprocess(&self, label: &str, policy: &str) -> Result<()> {
        let mut cmd = Command::new(&self.helper_path);
        cmd.arg("init-key")
            .arg(label)
            .arg("--policy")
            .arg(policy);
            
        // Propagate KAGE_LOCAL_DEV env var if set
        if let Ok(val) = std::env::var("KAGE_LOCAL_DEV") {
            cmd.env("KAGE_LOCAL_DEV", val);
        }

        let status = cmd.status()
            .map_err(|e| KageError::Keystore(format!("Failed to run helper: {}", e)))?;

        if status.success() {
            Ok(())
        } else {
            Err(KageError::Keystore(format!("Helper init-key failed with {:?}", status.code())))
        }
    }
    
    fn wrap_via_subprocess(&self, plaintext: &[u8], label: &str, policy: &str) -> Result<Vec<u8>> {
        let mut cmd = Command::new(&self.helper_path);
        cmd.arg("encrypt")
            .arg(label)
            .arg("--policy")
            .arg(policy)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
            
        if let Ok(val) = std::env::var("KAGE_LOCAL_DEV") {
            cmd.env("KAGE_LOCAL_DEV", val);
        }

        let mut child = cmd.spawn()
            .map_err(|e| KageError::Keystore(format!("Failed to spawn helper: {}", e)))?;
            
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(plaintext)?;
        }
        
        let output = child.wait_with_output()?;
        
        if output.status.success() {
            Ok(output.stdout)
        } else {
            Err(KageError::Keystore(format!("Helper encrypt failed: {}", String::from_utf8_lossy(&output.stderr))))
        }
    }
    
    fn unwrap_via_subprocess(&self, ciphertext: &[u8], label: &str, policy: &str) -> Result<Vec<u8>> {
        let mut cmd = Command::new(&self.helper_path);
        cmd.arg("decrypt")
            .arg(label)
            .arg("--policy")
            .arg(policy)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
            
        if let Ok(val) = std::env::var("KAGE_LOCAL_DEV") {
            cmd.env("KAGE_LOCAL_DEV", val);
        }

        let mut child = cmd.spawn()
            .map_err(|e| KageError::Keystore(format!("Failed to spawn helper: {}", e)))?;
            
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(ciphertext)?;
        }
        
        let output = child.wait_with_output()?;
        
        if output.status.success() {
            Ok(output.stdout)
        } else {
             // Map exit codes
             match output.status.code() {
                 Some(2) => Err(KageError::Keystore("Auth Failed".into())),
                 Some(3) => Err(KageError::Keystore("Auth Not Enrolled".into())),
                 _ => Err(KageError::Keystore(format!("Helper decrypt failed: {}", String::from_utf8_lossy(&output.stderr)))),
             }
        }
    }
}

impl DeviceKeystore for HelperKeystore {
    fn ensure_key(&self, label: &str, policy: &str) -> Result<()> {
        #[cfg(unix)]
        if agent_available() {
            match call_agent("init-key", label, policy, None) {
                Ok(resp) if resp.ok => return Ok(()),
                Ok(resp) => {
                    return Err(KageError::Keystore(
                        resp.error.unwrap_or_else(|| "Agent init-key failed".into()),
                    ));
                }
                Err(e) => {
                    if agent_enabled() {
                        return Err(e);
                    }
                }
            }
        }
        self.ensure_key_via_subprocess(label, policy)
    }
    
    fn wrap(&self, plaintext: &[u8], label: &str, policy: &str) -> Result<Vec<u8>> {
        #[cfg(unix)]
        if agent_available() {
            use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
            match call_agent("encrypt", label, policy, Some(plaintext)) {
                Ok(resp) if resp.ok => {
                    let b64 = resp.data.ok_or_else(|| {
                        KageError::Keystore("Agent encrypt returned no data".into())
                    })?;
                    let bytes = BASE64.decode(&b64).map_err(|e| {
                        KageError::Keystore(format!("Agent encrypt base64 decode failed: {e}"))
                    })?;
                    return Ok(bytes);
                }
                Ok(resp) => {
                    return Err(KageError::Keystore(
                        resp.error.unwrap_or_else(|| "Agent encrypt failed".into()),
                    ));
                }
                Err(e) if agent_enabled() => return Err(e),
                Err(_) => { }
            }
        }
        self.wrap_via_subprocess(plaintext, label, policy)
    }
    
    fn unwrap(&self, ciphertext: &[u8], label: &str, policy: &str) -> Result<Vec<u8>> {
        #[cfg(unix)]
        if agent_available() {
            use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
            match call_agent("decrypt", label, policy, Some(ciphertext)) {
                Ok(resp) if resp.ok => {
                    let b64 = resp.data.ok_or_else(|| {
                        KageError::Keystore("Agent decrypt returned no data".into())
                    })?;
                    let bytes = BASE64.decode(&b64).map_err(|e| {
                        KageError::Keystore(format!("Agent decrypt base64 decode failed: {e}"))
                    })?;
                    return Ok(bytes);
                }
                Ok(resp) => {
                    let err_msg = resp.error.unwrap_or_else(|| "Agent decrypt failed".into());
                    if err_msg.contains("AuthFailed") || err_msg.contains("authFailed") {
                         return Err(KageError::Keystore("Auth Failed".into()));
                    }
                    return Err(KageError::Keystore(err_msg));
                }
                Err(e) if agent_enabled() => return Err(e),
                Err(_) => { }
            }
        }
        self.unwrap_via_subprocess(ciphertext, label, policy)
    }

    fn delete_key(&self, label: &str) -> Result<()> {
        let status = Command::new(&self.helper_path)
            .arg("delete-key")
            .arg(label)
            .status()
            .map_err(|e| KageError::Keystore(format!("Failed to run helper: {}", e)))?;

        if status.success() {
            Ok(())
        } else {
            Err(KageError::Keystore(format!("Helper delete-key failed with {:?}", status.code())))
        }
    }

    fn is_available(&self) -> bool {
        if agent_available() { return true; }
        
        Command::new(&self.helper_path)
            .arg("check")
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}
