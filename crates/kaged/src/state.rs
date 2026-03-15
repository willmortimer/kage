use kage_audit::AuditLog;
use kage_comm::kid::Kid;
use kage_comm::registry::AdapterRegistry;
use std::collections::HashMap;
use tokio::time::Instant;
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct CacheEntry {
    pub k_wrap: Zeroizing<[u8; 32]>,
    pub expires_at: Option<Instant>,
}

pub struct DaemonState {
    pub cache: HashMap<Kid, CacheEntry>,
    pub registry: AdapterRegistry,
    pub audit_log: Option<AuditLog>,
}

impl Default for DaemonState {
    fn default() -> Self {
        Self {
            cache: HashMap::new(),
            registry: AdapterRegistry::new(),
            audit_log: AuditLog::open_default(),
        }
    }
}
