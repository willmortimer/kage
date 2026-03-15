use crate::error::{KageError, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL, Engine as _};
use ed25519_dalek::{Signer, Verifier};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AssertionClaims {
    pub v: u32,
    pub iss: String,
    pub sub: String,
    pub scope: String,
    pub iat: i64,
    pub exp: i64,
    pub nonce: String,
}

/// Create a signed assertion token: `<claims_b64url>.<signature_b64url>`.
pub fn create_assertion(claims: &AssertionClaims, secret_key: &[u8; 32]) -> Result<String> {
    let claims_json =
        serde_json::to_vec(claims).map_err(|e| KageError::InvalidInput(e.to_string()))?;
    let claims_b64 = BASE64URL.encode(&claims_json);

    let signing_key = ed25519_dalek::SigningKey::from_bytes(secret_key);
    let signature = signing_key.sign(claims_b64.as_bytes());
    let sig_b64 = BASE64URL.encode(signature.to_bytes());

    Ok(format!("{claims_b64}.{sig_b64}"))
}

/// Verify a signed assertion token. Checks signature and expiry.
pub fn verify_assertion(token: &str, public_key: &[u8; 32]) -> Result<AssertionClaims> {
    let (claims_b64, sig_b64) = token
        .split_once('.')
        .ok_or_else(|| KageError::InvalidInput("invalid assertion format".into()))?;

    let sig_bytes = BASE64URL
        .decode(sig_b64)
        .map_err(|e| KageError::InvalidInput(format!("invalid signature base64: {e}")))?;

    if sig_bytes.len() != 64 {
        return Err(KageError::InvalidInput("invalid signature length".into()));
    }

    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(public_key)
        .map_err(|e| KageError::Crypto(format!("invalid public key: {e}")))?;
    let sig = ed25519_dalek::Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap());

    verifying_key
        .verify(claims_b64.as_bytes(), &sig)
        .map_err(|_| KageError::Crypto("assertion signature verification failed".into()))?;

    let claims_json = BASE64URL
        .decode(claims_b64)
        .map_err(|e| KageError::InvalidInput(format!("invalid claims base64: {e}")))?;
    let claims: AssertionClaims =
        serde_json::from_slice(&claims_json).map_err(|e| KageError::InvalidInput(e.to_string()))?;

    let now = chrono::Utc::now().timestamp();
    if claims.exp <= now {
        return Err(KageError::InvalidInput("assertion token has expired".into()));
    }

    Ok(claims)
}

/// Parse assertion claims without verifying the signature.
pub fn parse_assertion_unverified(token: &str) -> Result<AssertionClaims> {
    let (claims_b64, _) = token
        .split_once('.')
        .ok_or_else(|| KageError::InvalidInput("invalid assertion format".into()))?;

    let claims_json = BASE64URL
        .decode(claims_b64)
        .map_err(|e| KageError::InvalidInput(format!("invalid claims base64: {e}")))?;

    serde_json::from_slice(&claims_json).map_err(|e| KageError::InvalidInput(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::generate_keypair;

    fn test_claims(iss: &str, exp_offset: i64) -> AssertionClaims {
        let now = chrono::Utc::now().timestamp();
        let mut nonce_bytes = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);
        AssertionClaims {
            v: 1,
            iss: iss.to_string(),
            sub: "admin".to_string(),
            scope: "org:acme/env:dev".to_string(),
            iat: now,
            exp: now + exp_offset,
            nonce: hex::encode(nonce_bytes),
        }
    }

    #[test]
    fn create_verify_roundtrip() {
        let (public_key, secret_key) = generate_keypair();
        let claims = test_claims("test-kid", 300);

        let token = create_assertion(&claims, &secret_key).unwrap();
        let verified = verify_assertion(&token, &public_key).unwrap();

        assert_eq!(verified.v, 1);
        assert_eq!(verified.iss, "test-kid");
        assert_eq!(verified.sub, "admin");
        assert_eq!(verified.scope, "org:acme/env:dev");
    }

    #[test]
    fn expired_token_rejected() {
        let (public_key, secret_key) = generate_keypair();
        let claims = test_claims("test-kid", -10); // expired 10 seconds ago

        let token = create_assertion(&claims, &secret_key).unwrap();
        let result = verify_assertion(&token, &public_key);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expired"));
    }

    #[test]
    fn wrong_key_rejected() {
        let (_, secret_key) = generate_keypair();
        let (other_public_key, _) = generate_keypair();
        let claims = test_claims("test-kid", 300);

        let token = create_assertion(&claims, &secret_key).unwrap();
        let result = verify_assertion(&token, &other_public_key);
        assert!(result.is_err());
    }

    #[test]
    fn tampered_claims_rejected() {
        let (public_key, secret_key) = generate_keypair();
        let claims = test_claims("test-kid", 300);

        let token = create_assertion(&claims, &secret_key).unwrap();

        // Tamper with the claims part
        let parts: Vec<&str> = token.split('.').collect();
        let mut claims_bytes = BASE64URL.decode(parts[0]).unwrap();
        claims_bytes[5] ^= 0xFF;
        let tampered_claims = BASE64URL.encode(&claims_bytes);
        let tampered_token = format!("{}.{}", tampered_claims, parts[1]);

        let result = verify_assertion(&tampered_token, &public_key);
        assert!(result.is_err());
    }

    #[test]
    fn nonce_is_unique() {
        let (_, secret_key) = generate_keypair();
        let claims1 = test_claims("test-kid", 300);
        let claims2 = test_claims("test-kid", 300);

        let token1 = create_assertion(&claims1, &secret_key).unwrap();
        let token2 = create_assertion(&claims2, &secret_key).unwrap();

        let parsed1 = parse_assertion_unverified(&token1).unwrap();
        let parsed2 = parse_assertion_unverified(&token2).unwrap();
        assert_ne!(parsed1.nonce, parsed2.nonce);
    }
}
