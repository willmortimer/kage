use crate::state::DaemonState;
use crate::{load_env_record, unwrap_k_env};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use kage_comm::adapter::Adapter;
use kage_comm::secret_crypto;
use kage_types::adapter::AdapterId;
use kage_types::capability::Capability;
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct RuntimeAdapter {
    id: AdapterId,
    capabilities: Vec<Capability>,
    #[allow(dead_code)]
    state: Arc<Mutex<DaemonState>>,
}

impl RuntimeAdapter {
    pub fn new(state: Arc<Mutex<DaemonState>>) -> Self {
        Self {
            id: AdapterId::new(AdapterId::RUNTIME),
            capabilities: vec![Capability::SecretRelease],
            state,
        }
    }
}

fn get_k_env_for_org_env(org: &str, env: &str) -> Result<[u8; 32], String> {
    let kid = kage_comm::kid::derive_kid(org, env);
    let record = load_env_record(kid).map_err(|e| format!("load record: {e}"))?;
    let k_env = unwrap_k_env(&record).map_err(|e| format!("unwrap k_env: {e}"))?;
    let mut k_env_arr = [0u8; 32];
    k_env_arr.copy_from_slice(&k_env[..]);
    Ok(k_env_arr)
}

#[async_trait]
impl Adapter for RuntimeAdapter {
    fn id(&self) -> &AdapterId {
        &self.id
    }

    fn capabilities(&self) -> &[Capability] {
        &self.capabilities
    }

    async fn dispatch(
        &self,
        capability: Capability,
        operation: &str,
        params: Value,
    ) -> Result<Value, String> {
        if capability != Capability::SecretRelease {
            return Err(format!("unsupported capability: {:?}", capability));
        }

        match operation {
            "encrypt" => {
                #[derive(Deserialize)]
                struct EncryptParams {
                    org: String,
                    env: String,
                    name: String,
                    plaintext_b64: String,
                }
                let p: EncryptParams =
                    serde_json::from_value(params).map_err(|e| format!("invalid params: {e}"))?;

                let k_env = get_k_env_for_org_env(&p.org, &p.env)?;
                let k_secret = secret_crypto::derive_k_secret(&k_env, &p.org, &p.env, &p.name)
                    .map_err(|e| format!("derive k_secret: {e}"))?;

                let plaintext = BASE64
                    .decode(p.plaintext_b64.trim())
                    .map_err(|e| format!("invalid base64: {e}"))?;

                let ct = secret_crypto::encrypt_secret(&k_secret, &plaintext)
                    .map_err(|e| format!("encrypt: {e}"))?;

                Ok(serde_json::json!({ "ciphertext_b64": BASE64.encode(ct) }))
            }
            "decrypt" => {
                #[derive(Deserialize)]
                struct DecryptParams {
                    org: String,
                    env: String,
                    name: String,
                    ciphertext_b64: String,
                }
                let p: DecryptParams =
                    serde_json::from_value(params).map_err(|e| format!("invalid params: {e}"))?;

                let k_env = get_k_env_for_org_env(&p.org, &p.env)?;
                let k_secret = secret_crypto::derive_k_secret(&k_env, &p.org, &p.env, &p.name)
                    .map_err(|e| format!("derive k_secret: {e}"))?;

                let ct = BASE64
                    .decode(p.ciphertext_b64.trim())
                    .map_err(|e| format!("invalid base64: {e}"))?;

                let pt = secret_crypto::decrypt_secret(&k_secret, &ct)
                    .map_err(|e| format!("decrypt: {e}"))?;

                Ok(serde_json::json!({ "plaintext_b64": BASE64.encode(pt) }))
            }
            "release" => {
                #[derive(Deserialize)]
                struct ReleaseParams {
                    org: String,
                    env: String,
                    secrets: Vec<ReleaseEntry>,
                }
                #[derive(Deserialize)]
                struct ReleaseEntry {
                    name: String,
                    ciphertext_b64: String,
                }
                let p: ReleaseParams =
                    serde_json::from_value(params).map_err(|e| format!("invalid params: {e}"))?;

                let k_env = get_k_env_for_org_env(&p.org, &p.env)?;

                let mut secrets = BTreeMap::new();
                for entry in &p.secrets {
                    let k_secret =
                        secret_crypto::derive_k_secret(&k_env, &p.org, &p.env, &entry.name)
                            .map_err(|e| format!("derive k_secret for {}: {e}", entry.name))?;
                    let ct = BASE64
                        .decode(entry.ciphertext_b64.trim())
                        .map_err(|e| format!("invalid base64 for {}: {e}", entry.name))?;
                    let pt = secret_crypto::decrypt_secret(&k_secret, &ct)
                        .map_err(|e| format!("decrypt {}: {e}", entry.name))?;
                    let value = String::from_utf8(pt)
                        .map_err(|e| format!("secret {} is not valid UTF-8: {e}", entry.name))?;
                    secrets.insert(entry.name.clone(), value);
                }

                Ok(serde_json::to_value(secrets).map_err(|e| e.to_string())?)
            }
            _ => Err(format!(
                "unsupported operation: {:?}/{}",
                capability, operation
            )),
        }
    }
}
