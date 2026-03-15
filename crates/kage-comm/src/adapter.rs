use async_trait::async_trait;
use kage_types::adapter::AdapterId;
use kage_types::capability::Capability;
use serde_json::Value;

#[async_trait]
pub trait Adapter: Send + Sync {
    fn id(&self) -> &AdapterId;
    fn capabilities(&self) -> &[Capability];
    async fn dispatch(
        &self,
        capability: Capability,
        operation: &str,
        params: Value,
    ) -> Result<Value, String>;
}
