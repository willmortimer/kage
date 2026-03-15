use crate::error::{KageError, Result};
use ed25519_dalek::{Signer, Verifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

// ----- Single artifact signature -----

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArtifactSignaturePayload {
    pub v: u32,
    pub kid: String,
    pub algorithm: String,
    pub digest_algorithm: String,
    pub digest: String,
    pub timestamp: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArtifactSignatureEnvelope {
    #[serde(flatten)]
    pub payload: ArtifactSignaturePayload,
    pub signature_b64: String,
}

// ----- Release manifest -----

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub path: String,
    pub digest: String,
    pub size: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReleaseManifestPayload {
    pub v: u32,
    pub kid: String,
    pub entries: Vec<ManifestEntry>,
    pub timestamp: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReleaseManifest {
    #[serde(flatten)]
    pub payload: ReleaseManifestPayload,
    pub signature_b64: String,
}

/// Compute SHA-256 hex digest of data.
pub fn compute_digest(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    hex::encode(hash)
}

/// Create a signed artifact signature envelope.
pub fn create_artifact_signature(
    payload: &ArtifactSignaturePayload,
    secret_key: &[u8; 32],
) -> Result<ArtifactSignatureEnvelope> {
    let canonical = serde_json::to_vec(payload)
        .map_err(|e| KageError::InvalidInput(format!("serialize payload: {e}")))?;

    let signing_key = ed25519_dalek::SigningKey::from_bytes(secret_key);
    let signature = signing_key.sign(&canonical);

    Ok(ArtifactSignatureEnvelope {
        payload: payload.clone(),
        signature_b64: BASE64.encode(signature.to_bytes()),
    })
}

/// Verify an artifact signature envelope.
pub fn verify_artifact_signature(
    envelope: &ArtifactSignatureEnvelope,
    public_key: &[u8; 32],
) -> Result<bool> {
    let canonical = serde_json::to_vec(&envelope.payload)
        .map_err(|e| KageError::InvalidInput(format!("serialize payload: {e}")))?;

    let sig_bytes = BASE64
        .decode(&envelope.signature_b64)
        .map_err(|e| KageError::InvalidInput(format!("invalid signature base64: {e}")))?;

    if sig_bytes.len() != 64 {
        return Ok(false);
    }

    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(public_key)
        .map_err(|e| KageError::Crypto(format!("invalid public key: {e}")))?;
    let sig = ed25519_dalek::Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap());

    Ok(verifying_key.verify(&canonical, &sig).is_ok())
}

/// Create a signed release manifest.
pub fn create_release_manifest(
    payload: &ReleaseManifestPayload,
    secret_key: &[u8; 32],
) -> Result<ReleaseManifest> {
    let canonical = serde_json::to_vec(payload)
        .map_err(|e| KageError::InvalidInput(format!("serialize manifest: {e}")))?;

    let signing_key = ed25519_dalek::SigningKey::from_bytes(secret_key);
    let signature = signing_key.sign(&canonical);

    Ok(ReleaseManifest {
        payload: payload.clone(),
        signature_b64: BASE64.encode(signature.to_bytes()),
    })
}

/// Verify a release manifest signature.
pub fn verify_release_manifest(
    manifest: &ReleaseManifest,
    public_key: &[u8; 32],
) -> Result<bool> {
    let canonical = serde_json::to_vec(&manifest.payload)
        .map_err(|e| KageError::InvalidInput(format!("serialize manifest: {e}")))?;

    let sig_bytes = BASE64
        .decode(&manifest.signature_b64)
        .map_err(|e| KageError::InvalidInput(format!("invalid signature base64: {e}")))?;

    if sig_bytes.len() != 64 {
        return Ok(false);
    }

    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(public_key)
        .map_err(|e| KageError::Crypto(format!("invalid public key: {e}")))?;
    let sig = ed25519_dalek::Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap());

    Ok(verifying_key.verify(&canonical, &sig).is_ok())
}

/// Result of verifying a single manifest entry against a file on disk.
#[derive(Clone, Debug)]
pub struct ManifestMismatch {
    pub path: String,
    pub expected_digest: String,
    pub actual_digest: Option<String>,
    pub reason: String,
}

/// Verify manifest entries against actual files in a directory.
/// Returns a list of mismatches (empty means all OK).
pub fn verify_manifest_files(
    manifest: &ReleaseManifest,
    base_dir: &std::path::Path,
) -> Vec<ManifestMismatch> {
    let mut mismatches = Vec::new();
    for entry in &manifest.payload.entries {
        let file_path = base_dir.join(&entry.path);
        match std::fs::read(&file_path) {
            Ok(data) => {
                let actual_digest = compute_digest(&data);
                if actual_digest != entry.digest {
                    mismatches.push(ManifestMismatch {
                        path: entry.path.clone(),
                        expected_digest: entry.digest.clone(),
                        actual_digest: Some(actual_digest),
                        reason: "digest mismatch".to_string(),
                    });
                }
            }
            Err(_) => {
                mismatches.push(ManifestMismatch {
                    path: entry.path.clone(),
                    expected_digest: entry.digest.clone(),
                    actual_digest: None,
                    reason: "file not found".to_string(),
                });
            }
        }
    }
    mismatches
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::generate_keypair;

    fn test_payload(kid: &str) -> ArtifactSignaturePayload {
        ArtifactSignaturePayload {
            v: 1,
            kid: kid.to_string(),
            algorithm: "ed25519".to_string(),
            digest_algorithm: "sha256".to_string(),
            digest: compute_digest(b"test artifact content"),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn digest_computation() {
        let d1 = compute_digest(b"hello");
        let d2 = compute_digest(b"hello");
        let d3 = compute_digest(b"world");
        assert_eq!(d1, d2);
        assert_ne!(d1, d3);
        assert_eq!(d1.len(), 64); // SHA-256 hex = 64 chars
    }

    #[test]
    fn artifact_sign_verify_roundtrip() {
        let (public_key, secret_key) = generate_keypair();
        let payload = test_payload("test-kid");

        let envelope = create_artifact_signature(&payload, &secret_key).unwrap();
        let valid = verify_artifact_signature(&envelope, &public_key).unwrap();
        assert!(valid);
    }

    #[test]
    fn tampered_digest_rejected() {
        let (public_key, secret_key) = generate_keypair();
        let payload = test_payload("test-kid");

        let mut envelope = create_artifact_signature(&payload, &secret_key).unwrap();
        envelope.payload.digest = compute_digest(b"tampered content");

        let valid = verify_artifact_signature(&envelope, &public_key).unwrap();
        assert!(!valid);
    }

    #[test]
    fn manifest_sign_verify_roundtrip() {
        let (public_key, secret_key) = generate_keypair();
        let payload = ReleaseManifestPayload {
            v: 1,
            kid: "test-kid".to_string(),
            entries: vec![
                ManifestEntry {
                    path: "bin/kage".to_string(),
                    digest: compute_digest(b"binary-data"),
                    size: 1024,
                },
                ManifestEntry {
                    path: "lib/libkage.so".to_string(),
                    digest: compute_digest(b"lib-data"),
                    size: 2048,
                },
            ],
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            metadata: BTreeMap::new(),
        };

        let manifest = create_release_manifest(&payload, &secret_key).unwrap();
        let valid = verify_release_manifest(&manifest, &public_key).unwrap();
        assert!(valid);
    }

    #[test]
    fn tampered_manifest_entry_rejected() {
        let (public_key, secret_key) = generate_keypair();
        let payload = ReleaseManifestPayload {
            v: 1,
            kid: "test-kid".to_string(),
            entries: vec![ManifestEntry {
                path: "bin/kage".to_string(),
                digest: compute_digest(b"binary-data"),
                size: 1024,
            }],
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            metadata: BTreeMap::new(),
        };

        let mut manifest = create_release_manifest(&payload, &secret_key).unwrap();
        manifest.payload.entries[0].digest = compute_digest(b"tampered");

        let valid = verify_release_manifest(&manifest, &public_key).unwrap();
        assert!(!valid);
    }
}
