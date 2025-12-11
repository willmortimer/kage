use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::io::Write;
use kage_core::keystore::DeviceKeystore;
use kage_core::error::{Result, KageError};

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
        let helper_name = "kage-linux-helper";
        #[cfg(target_os = "linux")]
        if 1==1 { // Scope for linux
             let path = exe_dir.join(helper_name);
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
}

impl DeviceKeystore for HelperKeystore {
    fn ensure_key(&self, label: &str, policy: &str) -> Result<()> {
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
    
    fn wrap(&self, plaintext: &[u8], label: &str, policy: &str) -> Result<Vec<u8>> {
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
    
    fn unwrap(&self, ciphertext: &[u8], label: &str, policy: &str) -> Result<Vec<u8>> {
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
        Command::new(&self.helper_path)
            .arg("check")
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}
