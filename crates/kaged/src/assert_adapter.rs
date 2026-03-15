use crate::signing_helpers;
use crate::state::DaemonState;
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use kage_comm::adapter::Adapter;
use kage_comm::assertion;
use kage_types::adapter::AdapterId;
use kage_types::capability::Capability;
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct AssertAdapter {
    id: AdapterId,
    capabilities: Vec<Capability>,
    #[allow(dead_code)]
    state: Arc<Mutex<DaemonState>>,
}

impl AssertAdapter {
    pub fn new(state: Arc<Mutex<DaemonState>>) -> Self {
        Self {
            id: AdapterId::new(AdapterId::ASSERT),
            capabilities: vec![Capability::Assert],
            state,
        }
    }
}

#[async_trait]
impl Adapter for AssertAdapter {
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
        if capability != Capability::Assert {
            return Err(format!("unsupported capability: {:?}", capability));
        }

        match operation {
            "issue" => {
                #[derive(Deserialize)]
                struct IssueParams {
                    kid_bech32: String,
                    purpose: String,
                    #[serde(default)]
                    scope: Option<String>,
                    #[serde(default)]
                    ttl_seconds: Option<i64>,
                }
                let p: IssueParams =
                    serde_json::from_value(params).map_err(|e| format!("invalid params: {e}"))?;

                let (secret_key, _sign_record) =
                    signing_helpers::unseal_signing_key_for_kid(&p.kid_bech32)?;

                let ttl = p.ttl_seconds.unwrap_or(300);
                let now = chrono::Utc::now().timestamp();

                let mut nonce_bytes = [0u8; 16];
                rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);

                let claims = assertion::AssertionClaims {
                    v: 1,
                    iss: p.kid_bech32,
                    sub: p.purpose,
                    scope: p.scope.unwrap_or_default(),
                    iat: now,
                    exp: now + ttl,
                    nonce: hex::encode(nonce_bytes),
                };

                let token = assertion::create_assertion(&claims, &secret_key)
                    .map_err(|e| format!("create assertion: {e}"))?;

                let expires_at = chrono::DateTime::from_timestamp(claims.exp, 0)
                    .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
                    .unwrap_or_default();

                Ok(serde_json::json!({
                    "token": token,
                    "expires_at": expires_at,
                }))
            }
            "verify" => {
                #[derive(Deserialize)]
                struct VerifyParams {
                    kid_bech32: String,
                    token: String,
                }
                let p: VerifyParams =
                    serde_json::from_value(params).map_err(|e| format!("invalid params: {e}"))?;

                let sign_record = signing_helpers::get_public_key_for_kid(&p.kid_bech32)?;

                let public_key_bytes = BASE64
                    .decode(sign_record.public_key_b64.trim())
                    .map_err(|e| format!("invalid public key base64: {e}"))?;
                let public_key: [u8; 32] = public_key_bytes
                    .try_into()
                    .map_err(|_| "invalid public key length".to_string())?;

                match assertion::verify_assertion(&p.token, &public_key) {
                    Ok(claims) => Ok(serde_json::json!({
                        "valid": true,
                        "claims": {
                            "v": claims.v,
                            "iss": claims.iss,
                            "sub": claims.sub,
                            "scope": claims.scope,
                            "iat": claims.iat,
                            "exp": claims.exp,
                            "nonce": claims.nonce,
                        }
                    })),
                    Err(_) => Ok(serde_json::json!({
                        "valid": false,
                    })),
                }
            }
            _ => Err(format!(
                "unsupported operation: {:?}/{}",
                capability, operation
            )),
        }
    }
}
