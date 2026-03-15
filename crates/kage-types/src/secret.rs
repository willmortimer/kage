use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretManifest {
    pub version: u32,
    pub org: String,
    pub env: String,
    pub secrets: BTreeMap<String, EncryptedSecret>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedSecret {
    pub ciphertext_b64: String,
    pub created_at: String,
    /// Tracks which layer this secret came from after merge (e.g. "base", "repo", "local").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}
