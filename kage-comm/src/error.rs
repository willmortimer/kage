use thiserror::Error;

pub type Result<T> = std::result::Result<T, KageError>;

#[derive(Error, Debug)]
pub enum KageError {
    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("bech32 error: {0}")]
    Bech32(#[from] bech32::Error),

    #[error("base64 error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("daemon error: {code} {message}")]
    Daemon { code: i32, message: String },
}

// Standard daemon error codes from docs/v2/IPC_PROTOCOL.md.
pub mod daemon_codes {
    pub const KEY_NOT_FOUND: i32 = -32001;
    pub const AUTH_CANCELLED: i32 = -32002;
    pub const AUTH_FAILED: i32 = -32003;
    pub const POLICY_VIOLATION: i32 = -32004;
    pub const CONFIG_ERROR: i32 = -32005;
    pub const DAEMON_BUSY: i32 = -32006;
}

#[cfg(test)]
mod tests {
    use super::daemon_codes;

    #[test]
    fn daemon_codes_match_ipc_protocol_spec() {
        assert_eq!(daemon_codes::KEY_NOT_FOUND, -32001);
        assert_eq!(daemon_codes::AUTH_CANCELLED, -32002);
        assert_eq!(daemon_codes::AUTH_FAILED, -32003);
        assert_eq!(daemon_codes::POLICY_VIOLATION, -32004);
        assert_eq!(daemon_codes::CONFIG_ERROR, -32005);
        assert_eq!(daemon_codes::DAEMON_BUSY, -32006);
    }
}
