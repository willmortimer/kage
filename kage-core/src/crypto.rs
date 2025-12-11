use hkdf::Hkdf;
use sha2::Sha256;
use bech32::{self, ToBase32, Variant};
use crate::error::{Result};

pub fn derive_k_env(k_org: &[u8], env: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, k_org);
    let info = format!("kage-env-derivation-v1:{}", env);
    let mut okm = [0u8; 32];
    hk.expand(info.as_bytes(), &mut okm).expect("HKDF expand failed");
    okm
}

pub fn bech32_age_secret(k_env: &[u8; 32]) -> Result<String> {
    let hrp = "age-secret-key-";
    let data = k_env.to_base32();
    let encoded = bech32::encode(hrp, data, Variant::Bech32)?;
    Ok(encoded.to_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bech32_canonical_vector() {
        let input = [0x42u8; 32];
        let expected = "AGE-SECRET-KEY-1GFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPQ4EGAEX";
        let output = bech32_age_secret(&input).unwrap();
        assert_eq!(output, expected);
    }
}

