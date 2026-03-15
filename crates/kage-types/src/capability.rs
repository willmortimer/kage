use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    WrapUnwrap,
    SecretRelease,
    Sign,
    Assert,
    SessionGrant,
}
