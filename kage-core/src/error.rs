use thiserror::Error;

#[derive(Error, Debug)]
pub enum KageError {
    #[error("Crypto error: {0}")]
    Crypto(String),
    #[error("Config error: {0}")]
    Config(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Bech32 error: {0}")]
    Bech32(#[from] bech32::Error),
    #[error("UTF8 error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("1Password error: {0}")]
    OnePassword(String),
    #[error("Keystore error: {0}")]
    Keystore(String),
}

pub type Result<T> = std::result::Result<T, KageError>;

