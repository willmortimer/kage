use crate::error::{KageError, Result};
use base64::Engine as _;
use bech32::{FromBase32, ToBase32, Variant};

pub const KAGE_RECIPIENT_HRP: &str = "age1kage";
pub const KAGE_IDENTITY_HRP: &str = "age-plugin-kage-";
pub const KAGE_V2_PROTOCOL_VERSION: u8 = 0x02;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Kid(pub [u8; 16]);

impl Kid {
    pub fn to_bech32(self) -> Result<String> {
        let s = bech32::encode(KAGE_RECIPIENT_HRP, self.0.to_base32(), Variant::Bech32)?;
        Ok(s)
    }

    pub fn from_bech32(s: &str) -> Result<Self> {
        let (hrp, data, _variant) = bech32::decode(s)?;
        if hrp != KAGE_RECIPIENT_HRP {
            return Err(KageError::InvalidInput(format!(
                "unexpected HRP {hrp}, expected {KAGE_RECIPIENT_HRP}"
            )));
        }
        let bytes = Vec::<u8>::from_base32(&data)
            .map_err(|e| KageError::InvalidInput(format!("invalid bech32 data: {e}")))?;
        if bytes.len() != 16 {
            return Err(KageError::InvalidInput(format!(
                "invalid KID length {}, expected 16",
                bytes.len()
            )));
        }
        let mut raw = [0u8; 16];
        raw.copy_from_slice(&bytes);
        Ok(Kid(raw))
    }

    pub fn to_base64(self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.0)
    }

    /// Stable filename-safe encoding for on-disk record keys.
    pub fn to_base64url_nopad(self) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.0)
    }
}

/// Returns a non-secret `age` plugin identity string for `kage`.
///
/// Tools like `sops` require at least one identity to be present during
/// decryption to dispatch to the plugin's `identity-v1` state machine.
pub fn plugin_identity() -> Result<String> {
    // The identity payload is currently unused by the plugin, but must be valid
    // Bech32 data so age/sops will invoke `age-plugin-kage`.
    let bytes = [0u8; 1];
    let s = bech32::encode(KAGE_IDENTITY_HRP, bytes.to_base32(), Variant::Bech32)?;
    Ok(s.to_uppercase())
}

pub fn canonical(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + s.len());
    out.extend_from_slice(&(s.len() as u64).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
    out
}

pub fn derive_kid(org: &str, env: &str) -> Kid {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kage-v2-kid");
    hasher.update(&canonical(org));
    hasher.update(&canonical(env));
    let digest = hasher.finalize();
    let mut raw = [0u8; 16];
    raw.copy_from_slice(&digest.as_bytes()[0..16]);
    Kid(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_is_length_prefixed() {
        let got = canonical("hi");
        assert_eq!(got, vec![2u8, 0, 0, 0, 0, 0, 0, 0, b'h', b'i']);
    }

    #[test]
    fn kid_bech32_hrp() {
        let kid = derive_kid("acme", "dev");
        let s = kid.to_bech32().unwrap();
        assert!(s.starts_with("age1kage1"));
        let round = Kid::from_bech32(&s).unwrap();
        assert_eq!(kid, round);
    }
}
