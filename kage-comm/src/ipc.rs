use crate::error::{KageError, Result};
use crate::kid::Kid;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KageStanza {
    pub kid_bech32: String,
    pub nonce_b64: String,
    pub payload_b64: String,
}

impl KageStanza {
    pub fn kid(&self) -> Result<Kid> {
        Kid::from_bech32(&self.kid_bech32)
    }

    pub fn nonce(&self) -> Result<[u8; 24]> {
        let bytes = BASE64.decode(self.nonce_b64.trim())?;
        if bytes.len() != 24 {
            return Err(KageError::InvalidInput(format!(
                "invalid nonce length {}, expected 24",
                bytes.len()
            )));
        }
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&bytes);
        Ok(nonce)
    }

    pub fn payload(&self) -> Result<Vec<u8>> {
        Ok(BASE64.decode(self.payload_b64.trim())?)
    }

    /// Kage v2 stanza format:
    /// `-> kage {KID_Base64} {Nonce_Base64}`
    /// `{Ciphertext_Base64}`
    pub fn to_age_parts(&self) -> Result<(Vec<String>, String)> {
        let kid = self.kid()?;
        let args = vec![kid.to_base64(), self.nonce_b64.clone()];
        Ok((args, format!("{}\n", self.payload_b64.trim())))
    }

    pub fn from_age_parts(kid_b64: &str, nonce_b64: &str, payload_b64: &str) -> Result<Self> {
        let kid_raw = BASE64.decode(kid_b64.trim())?;
        if kid_raw.len() != 16 {
            return Err(KageError::InvalidInput(format!(
                "invalid stanza kid length {}, expected 16",
                kid_raw.len()
            )));
        }
        let kid = Kid(kid_raw.try_into().expect("len checked"));
        Ok(Self {
            kid_bech32: kid.to_bech32()?,
            nonce_b64: nonce_b64.trim().to_string(),
            payload_b64: payload_b64.trim().to_string(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolveIdentityParams {
    pub org: String,
    pub env: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WrapKeyParams {
    pub kid_bech32: String,
    pub file_key_b64: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnwrapKeyParams {
    pub stanza: KageStanza,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnlockParams {
    pub kid_bech32: String,
    pub duration_seconds: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonRpcRequest<T> {
    pub jsonrpc: String,
    pub id: u64,
    pub method: String,
    pub params: T,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonRpcResponse<T> {
    pub jsonrpc: String,
    pub id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}
