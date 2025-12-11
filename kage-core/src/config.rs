use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub version: u32,
    pub device: DeviceConfig,
    pub backend: BackendConfig,
    pub org: OrgConfig,
    pub policy: PolicyConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DeviceConfig {
    pub id: String,
    pub hostname: String,
    pub keystore: KeystoreConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct KeystoreConfig {
    #[serde(rename = "type")]
    pub keystore_type: String, // "auto", "secure-enclave", "tpm2", "software"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tpm2: Option<Tpm2Config>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Tpm2Config {
    pub handle: String,
    pub pcr_banks: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BackendConfig {
    pub onepassword: OnePasswordConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OnePasswordConfig {
    pub vault: String,
    pub item_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OrgConfig {
    pub id: String,
    pub envs: Vec<String>,
    pub danger_levels: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PolicyConfig {
    pub mapping: HashMap<String, String>,
}

