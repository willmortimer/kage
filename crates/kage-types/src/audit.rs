use crate::adapter::AdapterId;
use crate::capability::Capability;
use crate::scope::{AdvisoryScope, AuthoritativeScope};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const AUDIT_SCHEMA_VERSION: u32 = 2;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Success,
    Error,
    Denied,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEvent {
    pub schema_version: u32,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub adapter: AdapterId,
    pub capability: Capability,
    pub operation: String,
    #[serde(flatten)]
    pub scope: AuthoritativeScope,
    pub outcome: AuditOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advisory: Option<AdvisoryScope>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_seconds: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<BTreeMap<String, String>>,
}
