use crate::signing_helpers;
use crate::state::DaemonState;
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use kage_comm::adapter::Adapter;
use kage_comm::ssh_signature;
use kage_types::adapter::AdapterId;
use kage_types::capability::Capability;
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct GitSignAdapter {
    id: AdapterId,
    capabilities: Vec<Capability>,
    #[allow(dead_code)]
    state: Arc<Mutex<DaemonState>>,
}

impl GitSignAdapter {
    pub fn new(state: Arc<Mutex<DaemonState>>) -> Self {
        Self {
            id: AdapterId::new(AdapterId::GIT_SIGN),
            capabilities: vec![Capability::Sign],
            state,
        }
    }
}

#[async_trait]
impl Adapter for GitSignAdapter {
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
        if capability != Capability::Sign {
            return Err(format!("unsupported capability: {:?}", capability));
        }

        match operation {
            "sign-commit" => {
                #[derive(Deserialize)]
                struct SignCommitParams {
                    kid_bech32: String,
                    payload_b64: String,
                }
                let p: SignCommitParams =
                    serde_json::from_value(params).map_err(|e| format!("invalid params: {e}"))?;

                let (secret_key, sign_record) =
                    signing_helpers::unseal_signing_key_for_kid(&p.kid_bech32)?;

                let payload = BASE64
                    .decode(p.payload_b64.trim())
                    .map_err(|e| format!("invalid payload base64: {e}"))?;

                let public_key_bytes = BASE64
                    .decode(sign_record.public_key_b64.trim())
                    .map_err(|e| format!("invalid public key base64: {e}"))?;
                let public_key: [u8; 32] = public_key_bytes
                    .try_into()
                    .map_err(|_| "invalid public key length".to_string())?;

                let signature_armored =
                    ssh_signature::create_ssh_signature(&secret_key, &public_key, &payload, "git")
                        .map_err(|e| format!("create SSH signature: {e}"))?;

                Ok(serde_json::json!({
                    "signature_armored": signature_armored,
                }))
            }
            "sign-tag" => {
                #[derive(Deserialize)]
                struct SignTagParams {
                    kid_bech32: String,
                    payload_b64: String,
                }
                let p: SignTagParams =
                    serde_json::from_value(params).map_err(|e| format!("invalid params: {e}"))?;

                let (secret_key, sign_record) =
                    signing_helpers::unseal_signing_key_for_kid(&p.kid_bech32)?;

                let payload = BASE64
                    .decode(p.payload_b64.trim())
                    .map_err(|e| format!("invalid payload base64: {e}"))?;

                let public_key_bytes = BASE64
                    .decode(sign_record.public_key_b64.trim())
                    .map_err(|e| format!("invalid public key base64: {e}"))?;
                let public_key: [u8; 32] = public_key_bytes
                    .try_into()
                    .map_err(|_| "invalid public key length".to_string())?;

                let signature_armored =
                    ssh_signature::create_ssh_signature(&secret_key, &public_key, &payload, "git")
                        .map_err(|e| format!("create SSH signature: {e}"))?;

                Ok(serde_json::json!({
                    "signature_armored": signature_armored,
                }))
            }
            "get-ssh-pubkey" => {
                #[derive(Deserialize)]
                struct GetSshPubkeyParams {
                    kid_bech32: String,
                }
                let p: GetSshPubkeyParams =
                    serde_json::from_value(params).map_err(|e| format!("invalid params: {e}"))?;

                let sign_record = signing_helpers::get_public_key_for_kid(&p.kid_bech32)?;

                let public_key_bytes = BASE64
                    .decode(sign_record.public_key_b64.trim())
                    .map_err(|e| format!("invalid public key base64: {e}"))?;
                let public_key: [u8; 32] = public_key_bytes
                    .try_into()
                    .map_err(|_| "invalid public key length".to_string())?;

                let ssh_pubkey =
                    ssh_signature::format_ssh_pubkey_line(&public_key, &format!("kage:{}", p.kid_bech32));

                Ok(serde_json::json!({
                    "ssh_pubkey": ssh_pubkey,
                }))
            }
            _ => Err(format!(
                "unsupported operation: {:?}/{}",
                capability, operation
            )),
        }
    }
}
