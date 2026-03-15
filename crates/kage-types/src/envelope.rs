use crate::adapter::AdapterId;
use crate::capability::Capability;
use crate::scope::AdvisoryScope;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestEnvelope {
    pub version: u32,
    pub adapter: AdapterId,
    pub capability: Capability,
    pub operation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advisory: Option<AdvisoryScope>,
    #[serde(default)]
    pub params: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResponseEnvelope {
    pub version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}
