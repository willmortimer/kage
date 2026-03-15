use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AdapterId(pub String);

impl AdapterId {
    pub const AGE: &'static str = "age";
    pub const RUNTIME: &'static str = "runtime";
    pub const SIGN: &'static str = "sign";
    pub const GIT_SIGN: &'static str = "git-sign";
    pub const ASSERT: &'static str = "assert";
    pub const ARTIFACT: &'static str = "artifact";

    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AdapterId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
