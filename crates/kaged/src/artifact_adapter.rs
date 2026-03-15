use crate::signing_helpers;
use crate::state::DaemonState;
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use kage_comm::adapter::Adapter;
use kage_comm::artifact_signature;
use kage_types::adapter::AdapterId;
use kage_types::capability::Capability;
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct ArtifactAdapter {
    id: AdapterId,
    capabilities: Vec<Capability>,
    #[allow(dead_code)]
    state: Arc<Mutex<DaemonState>>,
}

impl ArtifactAdapter {
    pub fn new(state: Arc<Mutex<DaemonState>>) -> Self {
        Self {
            id: AdapterId::new(AdapterId::ARTIFACT),
            capabilities: vec![Capability::Sign],
            state,
        }
    }
}

#[async_trait]
impl Adapter for ArtifactAdapter {
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
            "sign-digest" => {
                #[derive(Deserialize)]
                struct SignDigestParams {
                    kid_bech32: String,
                    digest: String,
                    #[serde(default)]
                    metadata: BTreeMap<String, String>,
                }
                let p: SignDigestParams =
                    serde_json::from_value(params).map_err(|e| format!("invalid params: {e}"))?;

                let (secret_key, _sign_record) =
                    signing_helpers::unseal_signing_key_for_kid(&p.kid_bech32)?;

                let payload = artifact_signature::ArtifactSignaturePayload {
                    v: 1,
                    kid: p.kid_bech32,
                    algorithm: "ed25519".to_string(),
                    digest_algorithm: "sha256".to_string(),
                    digest: p.digest,
                    timestamp: chrono::Utc::now()
                        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    metadata: p.metadata,
                };

                let envelope =
                    artifact_signature::create_artifact_signature(&payload, &secret_key)
                        .map_err(|e| format!("create artifact signature: {e}"))?;

                serde_json::to_value(envelope).map_err(|e| format!("serialize envelope: {e}"))
            }
            "sign-manifest" => {
                #[derive(Deserialize)]
                struct ManifestEntryParam {
                    path: String,
                    digest: String,
                    size: u64,
                }
                #[derive(Deserialize)]
                struct SignManifestParams {
                    kid_bech32: String,
                    entries: Vec<ManifestEntryParam>,
                    #[serde(default)]
                    metadata: BTreeMap<String, String>,
                }
                let p: SignManifestParams =
                    serde_json::from_value(params).map_err(|e| format!("invalid params: {e}"))?;

                let (secret_key, _sign_record) =
                    signing_helpers::unseal_signing_key_for_kid(&p.kid_bech32)?;

                let entries: Vec<artifact_signature::ManifestEntry> = p
                    .entries
                    .into_iter()
                    .map(|e| artifact_signature::ManifestEntry {
                        path: e.path,
                        digest: e.digest,
                        size: e.size,
                    })
                    .collect();

                let payload = artifact_signature::ReleaseManifestPayload {
                    v: 1,
                    kid: p.kid_bech32,
                    entries,
                    timestamp: chrono::Utc::now()
                        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    metadata: p.metadata,
                };

                let manifest =
                    artifact_signature::create_release_manifest(&payload, &secret_key)
                        .map_err(|e| format!("create release manifest: {e}"))?;

                serde_json::to_value(manifest).map_err(|e| format!("serialize manifest: {e}"))
            }
            "verify-digest" => {
                #[derive(Deserialize)]
                struct VerifyDigestParams {
                    kid_bech32: String,
                    envelope: artifact_signature::ArtifactSignatureEnvelope,
                }
                let p: VerifyDigestParams =
                    serde_json::from_value(params).map_err(|e| format!("invalid params: {e}"))?;

                let sign_record = signing_helpers::get_public_key_for_kid(&p.kid_bech32)?;
                let public_key_bytes = BASE64
                    .decode(sign_record.public_key_b64.trim())
                    .map_err(|e| format!("invalid public key base64: {e}"))?;
                let public_key: [u8; 32] = public_key_bytes
                    .try_into()
                    .map_err(|_| "invalid public key length".to_string())?;

                let valid =
                    artifact_signature::verify_artifact_signature(&p.envelope, &public_key)
                        .map_err(|e| format!("verify artifact signature: {e}"))?;

                Ok(serde_json::json!({ "valid": valid }))
            }
            "verify-manifest" => {
                #[derive(Deserialize)]
                struct VerifyManifestParams {
                    kid_bech32: String,
                    manifest: artifact_signature::ReleaseManifest,
                }
                let p: VerifyManifestParams =
                    serde_json::from_value(params).map_err(|e| format!("invalid params: {e}"))?;

                let sign_record = signing_helpers::get_public_key_for_kid(&p.kid_bech32)?;
                let public_key_bytes = BASE64
                    .decode(sign_record.public_key_b64.trim())
                    .map_err(|e| format!("invalid public key base64: {e}"))?;
                let public_key: [u8; 32] = public_key_bytes
                    .try_into()
                    .map_err(|_| "invalid public key length".to_string())?;

                let valid =
                    artifact_signature::verify_release_manifest(&p.manifest, &public_key)
                        .map_err(|e| format!("verify release manifest: {e}"))?;

                Ok(serde_json::json!({ "valid": valid }))
            }
            _ => Err(format!(
                "unsupported operation: {:?}/{}",
                capability, operation
            )),
        }
    }
}
