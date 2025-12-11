use std::process::Command;
use crate::error::{Result, KageError};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rand::RngCore;

pub struct OnePasswordBackend;

impl OnePasswordBackend {
    pub fn new() -> Self {
        Self
    }

    pub fn fetch_k_org(&self, vault: &str, item_id: &str) -> Result<Vec<u8>> {
        let output = Command::new("op")
            .arg("read")
            .arg(format!("op://{}/{}/notesPlain", vault, item_id))
            .output()
            .map_err(|e| KageError::OnePassword(format!("Failed to execute op: {}", e)))?;

        if output.status.success() {
            let encoded = String::from_utf8(output.stdout)
                .map_err(|e| KageError::OnePassword(format!("Invalid UTF-8: {}", e)))?;
            let decoded = BASE64.decode(encoded.trim())
                .map_err(|e| KageError::OnePassword(format!("Invalid Base64: {}", e)))?;
            Ok(decoded)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("not signed in") || stderr.contains("session expired") {
                Err(KageError::OnePassword("Not signed in to 1Password".to_string()))
            } else if stderr.contains("item not found") || output.status.code() == Some(1) { // op read returns 1 on not found usually
                 // For fetch, not found is an error unless we are doing check-then-create logic.
                 // The caller handles logic. Here we just return specific error string to be parsed or custom error type.
                 // For now, let's return a specific error that can be matched if needed, or just text.
                 Err(KageError::OnePassword(format!("Item not found: {}", stderr)))
            } else {
                Err(KageError::OnePassword(format!("op read failed: {}", stderr)))
            }
        }
    }

    pub fn ensure_k_org(&self, vault: &str, item_id: Option<&str>) -> Result<(String, Vec<u8>)> {
        // If item_id exists, try to fetch
        if let Some(id) = item_id {
             match self.fetch_k_org(vault, id) {
                 Ok(key) => return Ok((id.to_string(), key)),
                 Err(KageError::OnePassword(msg)) if msg.contains("Item not found") => {
                     // Fall through to create
                 },
                 Err(e) => return Err(e),
             }
        }

        // Generate new key
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        let encoded = BASE64.encode(key);

        // Create item
        // op item create --category="Secure Note" --title="Kage Master Key" --vault="{vault}" notesPlain="{encoded}"
        let output = Command::new("op")
            .arg("item")
            .arg("create")
            .arg("--category=Secure Note")
            .arg("--title=Kage Master Key")
            .arg(format!("--vault={}", vault))
            .arg(format!("notesPlain={}", encoded))
            .arg("--format=json")
            .output()
            .map_err(|e| KageError::OnePassword(format!("Failed to execute op create: {}", e)))?;

        if !output.status.success() {
             return Err(KageError::OnePassword(format!("Failed to create item: {}", String::from_utf8_lossy(&output.stderr))));
        }

        // Parse JSON output to get ID
        #[derive(serde::Deserialize)]
        struct OpItem {
            id: String,
        }
        let item: OpItem = serde_json::from_slice(&output.stdout)
            .map_err(|e| KageError::OnePassword(format!("Failed to parse op output: {}", e)))?;

        Ok((item.id, key.to_vec()))
    }
}

