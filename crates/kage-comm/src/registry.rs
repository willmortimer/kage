use crate::adapter::Adapter;
use kage_types::adapter::AdapterId;
use std::collections::HashMap;
use std::sync::Arc;

pub struct AdapterRegistry {
    adapters: HashMap<String, Arc<dyn Adapter>>,
}

impl AdapterRegistry {
    pub fn new() -> Self {
        Self {
            adapters: HashMap::new(),
        }
    }

    pub fn register(&mut self, adapter: Arc<dyn Adapter>) {
        self.adapters
            .insert(adapter.id().as_str().to_string(), adapter);
    }

    pub fn get(&self, id: &AdapterId) -> Option<&Arc<dyn Adapter>> {
        self.adapters.get(id.as_str())
    }
}

impl Default for AdapterRegistry {
    fn default() -> Self {
        Self::new()
    }
}
