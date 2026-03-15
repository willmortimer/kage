use crate::signing_helpers;
use crate::state::DaemonState;
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use kage_comm::adapter::Adapter;
use kage_comm::kid::Kid;
use kage_comm::signing;
use kage_comm::signing_record;
use kage_types::adapter::AdapterId;
use kage_types::capability::Capability;
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct SignAdapter {
    id: AdapterId,
    capabilities: Vec<Capability>,
    #[allow(dead_code)]
    state: Arc<Mutex<DaemonState>>,
}

impl SignAdapter {
    pub fn new(state: Arc<Mutex<DaemonState>>) -> Self {
        Self {
            id: AdapterId::new(AdapterId::SIGN),
            capabilities: vec![Capability::Sign],
            state,
        }
    }
}

#[async_trait]
impl Adapter for SignAdapter {
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
            "init" => {
                #[derive(Deserialize)]
                struct InitParams {
                    kid_bech32: String,
                }
                let p: InitParams =
                    serde_json::from_value(params).map_err(|e| format!("invalid params: {e}"))?;

                let kid = Kid::from_bech32(&p.kid_bech32)
                    .map_err(|e| format!("invalid kid_bech32: {e}"))?;

                if signing_record::signing_record_exists(kid)
                    .map_err(|e| format!("check signing record: {e}"))?
                {
                    return Err("signing key already exists for this environment".to_string());
                }

                let k_sign_seal = signing_helpers::get_k_sign_seal_for_kid(kid)?;

                let (public_key, secret_key) = signing::generate_keypair();
                let sealed = signing::seal_signing_key(&k_sign_seal, kid, &secret_key)
                    .map_err(|e| format!("seal signing key: {e}"))?;

                let record = signing_record::SigningKeyRecord {
                    kid_bech32: p.kid_bech32,
                    algorithm: "ed25519".to_string(),
                    public_key_b64: BASE64.encode(public_key),
                    sealed_private_key_b64: BASE64.encode(sealed),
                    created_at: chrono::Utc::now()
                        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                };
                signing_record::save_signing_record(kid, &record)
                    .map_err(|e| format!("save signing record: {e}"))?;

                Ok(serde_json::json!({
                    "public_key_b64": record.public_key_b64,
                    "algorithm": "ed25519",
                }))
            }
            "sign" => {
                #[derive(Deserialize)]
                struct SignParams {
                    kid_bech32: String,
                    message_b64: String,
                }
                let p: SignParams =
                    serde_json::from_value(params).map_err(|e| format!("invalid params: {e}"))?;

                let (secret_key, sign_record) =
                    signing_helpers::unseal_signing_key_for_kid(&p.kid_bech32)?;

                let message = BASE64
                    .decode(p.message_b64.trim())
                    .map_err(|e| format!("invalid message base64: {e}"))?;

                let signature = signing::sign_message(&secret_key, &message)
                    .map_err(|e| format!("sign: {e}"))?;

                Ok(serde_json::json!({
                    "signature_b64": BASE64.encode(signature),
                    "public_key_b64": sign_record.public_key_b64,
                }))
            }
            "get-public-key" => {
                #[derive(Deserialize)]
                struct GetPubKeyParams {
                    kid_bech32: String,
                }
                let p: GetPubKeyParams =
                    serde_json::from_value(params).map_err(|e| format!("invalid params: {e}"))?;

                let sign_record = signing_helpers::get_public_key_for_kid(&p.kid_bech32)?;

                Ok(serde_json::json!({
                    "public_key_b64": sign_record.public_key_b64,
                    "algorithm": sign_record.algorithm,
                }))
            }
            _ => Err(format!(
                "unsupported operation: {:?}/{}",
                capability, operation
            )),
        }
    }
}
