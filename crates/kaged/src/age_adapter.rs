use crate::state::DaemonState;
use crate::{get_k_wrap_for, load_env_record, map_error, unwrap_k_env};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use kage_comm::adapter::Adapter;
use kage_comm::crypto;
use kage_comm::ipc::KageStanza;
use kage_comm::kid::Kid;
use kage_types::adapter::AdapterId;
use kage_types::capability::Capability;
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{Duration, Instant};

pub struct AgeAdapter {
    id: AdapterId,
    capabilities: Vec<Capability>,
    state: Arc<Mutex<DaemonState>>,
}

impl AgeAdapter {
    pub fn new(state: Arc<Mutex<DaemonState>>) -> Self {
        Self {
            id: AdapterId::new(AdapterId::AGE),
            capabilities: vec![Capability::WrapUnwrap, Capability::SessionGrant],
            state,
        }
    }
}

#[async_trait]
impl Adapter for AgeAdapter {
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
        match (&capability, operation) {
            (Capability::WrapUnwrap, "wrap") => {
                #[derive(Deserialize)]
                struct WrapParams {
                    kid_bech32: String,
                    file_key_b64: String,
                }
                let p: WrapParams =
                    serde_json::from_value(params).map_err(|e| format!("invalid params: {e}"))?;
                let kid = Kid::from_bech32(&p.kid_bech32)
                    .map_err(|e| format!("invalid kid: {e}"))?;
                let file_key = BASE64
                    .decode(p.file_key_b64.trim())
                    .map_err(|e| format!("invalid base64: {e}"))?;
                let record =
                    load_env_record(kid).map_err(|e| map_error(e).message)?;
                let mut guard = self.state.lock().await;
                let k_wrap = get_k_wrap_for(kid, &record, &mut guard)
                    .map_err(|e| map_error(e).message)?;
                let mut k_wrap_arr = [0u8; 32];
                k_wrap_arr.copy_from_slice(&k_wrap[..]);
                let (_kid, nonce, ct) = crypto::wrap_file_key(&k_wrap_arr, kid, &file_key)
                    .map_err(|e| map_error(e).message)?;
                let stanza = KageStanza {
                    kid_bech32: record.kid_bech32,
                    nonce_b64: BASE64.encode(nonce),
                    payload_b64: BASE64.encode(ct),
                };
                serde_json::to_value(stanza).map_err(|e| e.to_string())
            }
            (Capability::WrapUnwrap, "unwrap") => {
                #[derive(Deserialize)]
                struct UnwrapParams {
                    stanza: KageStanza,
                }
                let p: UnwrapParams =
                    serde_json::from_value(params).map_err(|e| format!("invalid params: {e}"))?;
                let kid = p.stanza.kid().map_err(|e| e.to_string())?;
                let nonce = p.stanza.nonce().map_err(|e| e.to_string())?;
                let payload = p.stanza.payload().map_err(|e| e.to_string())?;
                let record = load_env_record(kid).map_err(|e| map_error(e).message)?;
                let mut guard = self.state.lock().await;
                let k_wrap = get_k_wrap_for(kid, &record, &mut guard)
                    .map_err(|e| map_error(e).message)?;
                let mut k_wrap_arr = [0u8; 32];
                k_wrap_arr.copy_from_slice(&k_wrap[..]);
                let pt = crypto::unwrap_file_key(&k_wrap_arr, kid, &nonce, &payload)
                    .map_err(|e| map_error(e).message)?;
                Ok(Value::String(BASE64.encode(pt)))
            }
            (Capability::SessionGrant, "unlock") => {
                #[derive(Deserialize)]
                struct UnlockParams {
                    kid_bech32: String,
                    duration_seconds: u32,
                }
                let p: UnlockParams =
                    serde_json::from_value(params).map_err(|e| format!("invalid params: {e}"))?;
                let kid = Kid::from_bech32(&p.kid_bech32)
                    .map_err(|e| format!("invalid kid: {e}"))?;
                let record = load_env_record(kid).map_err(|e| map_error(e).message)?;

                let mut guard = self.state.lock().await;
                let duration = p.duration_seconds.min(300);
                let k_env = unwrap_k_env(&record).map_err(|e| map_error(e).message)?;
                let mut k_env_arr = [0u8; 32];
                k_env_arr.copy_from_slice(&k_env[..]);
                let k_wrap = crypto::derive_k_wrap(&k_env_arr)
                    .map_err(|e| map_error(e).message)?;

                let expires_at = Instant::now() + Duration::from_secs(duration as u64);
                guard.cache.insert(
                    kid,
                    crate::state::CacheEntry {
                        k_wrap,
                        expires_at: Some(expires_at),
                    },
                );
                Ok(Value::Bool(true))
            }
            _ => Err(format!(
                "unsupported capability/operation: {:?}/{}",
                capability, operation
            )),
        }
    }
}
