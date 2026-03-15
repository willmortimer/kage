use anyhow::Context;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rand::RngCore;
use std::process::Command;

pub struct OnePasswordBackend;

impl OnePasswordBackend {
    pub fn new() -> Self {
        Self
    }

    pub fn fetch_k_org(&self, vault: &str, item_id: &str) -> anyhow::Result<Vec<u8>> {
        let output = Command::new("op")
            .arg("read")
            .arg(format!("op://{}/{}/notesPlain", vault, item_id))
            .output()
            .with_context(|| "failed to execute `op read`")?;

        if !output.status.success() {
            anyhow::bail!(
                "op read failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }

        let encoded = String::from_utf8(output.stdout).context("op output was not utf-8")?;
        Ok(BASE64.decode(encoded.trim())?)
    }

    pub fn ensure_k_org(
        &self,
        vault: &str,
        item_id: Option<&str>,
    ) -> anyhow::Result<(String, Vec<u8>)> {
        if let Some(id) = item_id {
            let key = self.fetch_k_org(vault, id)?;
            return Ok((id.to_string(), key));
        }

        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        let encoded = BASE64.encode(key);

        let output = Command::new("op")
            .arg("item")
            .arg("create")
            .arg("--category=Secure Note")
            .arg("--title=Kage v2 Org Root Key")
            .arg(format!("--vault={}", vault))
            .arg(format!("notesPlain={}", encoded))
            .arg("--format=json")
            .output()
            .with_context(|| "failed to execute `op item create`")?;

        if !output.status.success() {
            anyhow::bail!(
                "op item create failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }

        #[derive(serde::Deserialize)]
        struct OpItem {
            id: String,
        }
        let item: OpItem = serde_json::from_slice(&output.stdout)?;

        Ok((item.id, key.to_vec()))
    }
}
