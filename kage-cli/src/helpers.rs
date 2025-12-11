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
        let helper_name = "kage-mac-helper";
        #[cfg(target_os = "linux")]
        let helper_name = "kage-linux-helper";
        
        // Try same dir
        let path = exe_dir.join(helper_name);
        if path.exists() {
            return Ok(Self { helper_path: path });
        }
        
        // Try looking in PATH
        if let Ok(path) = which::which(helper_name) {
            return Ok(Self { helper_path: path });
        }

        Err(KageError::Keystore(format!("Helper binary {} not found", helper_name)))
    }
}

impl DeviceKeystore for HelperKeystore {
    fn ensure_key(&self, label: &str, policy: &str) -> Result<()> {
        let status = Command::new(&self.helper_path)
            .arg("init-key")
            .arg(label)
            .arg("--policy")
            .arg(policy)
            .status()
            .map_err(|e| KageError::Keystore(format!("Failed to run helper: {}", e)))?;

        if status.success() {
            Ok(())
        } else {
            Err(KageError::Keystore(format!("Helper init-key failed with {:?}", status.code())))
        }
    }
    
    fn wrap(&self, plaintext: &[u8], label: &str, policy: &str) -> Result<Vec<u8>> {
        let mut child = Command::new(&self.helper_path)
            .arg("encrypt")
            .arg(label)
            .arg("--policy")
            .arg(policy)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
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
        let mut child = Command::new(&self.helper_path)
            .arg("decrypt")
            .arg(label)
            .arg("--policy")
            .arg(policy)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
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
