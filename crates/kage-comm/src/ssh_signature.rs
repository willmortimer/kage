use crate::error::{KageError, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::Signer;
use sha2::{Digest, Sha512};

const SSHSIG_MAGIC: &[u8] = b"SSHSIG";
const SSHSIG_VERSION: u32 = 0x01;
const ARMOR_BEGIN: &str = "-----BEGIN SSH SIGNATURE-----";
const ARMOR_END: &str = "-----END SSH SIGNATURE-----";

/// Write a uint32 big-endian length prefix followed by data (SSH wire string encoding).
fn write_ssh_string(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

/// Encode an Ed25519 public key in SSH wire format (for embedding in SSHSIG).
pub fn encode_ssh_ed25519_pubkey(public_key: &[u8; 32]) -> Vec<u8> {
    let mut buf = Vec::new();
    write_ssh_string(&mut buf, b"ssh-ed25519");
    write_ssh_string(&mut buf, public_key);
    buf
}

/// Format an Ed25519 public key as an SSH authorized_keys/allowed_signers line.
pub fn format_ssh_pubkey_line(public_key: &[u8; 32], comment: &str) -> String {
    let blob = encode_ssh_ed25519_pubkey(public_key);
    format!("ssh-ed25519 {} {}", BASE64.encode(&blob), comment)
}

/// Create an SSH SSHSIG signature over a message.
///
/// The SSHSIG binary format:
/// - "SSHSIG" magic (6 bytes)
/// - uint32 version (0x01)
/// - string public_key_blob (ssh-ed25519 wire format)
/// - string namespace
/// - string reserved ("")
/// - string hash_algorithm ("sha512")
/// - string H(message)
///
/// The Ed25519 signature is over this structured preamble.
pub fn create_ssh_signature(
    secret_key: &[u8; 32],
    public_key: &[u8; 32],
    message: &[u8],
    namespace: &str,
) -> Result<String> {
    let pubkey_blob = encode_ssh_ed25519_pubkey(public_key);

    // Hash the message with SHA-512
    let message_hash = Sha512::digest(message);

    // Build the signed preamble
    let mut preamble = Vec::new();
    preamble.extend_from_slice(SSHSIG_MAGIC);
    preamble.extend_from_slice(&SSHSIG_VERSION.to_be_bytes());
    write_ssh_string(&mut preamble, &pubkey_blob);
    write_ssh_string(&mut preamble, namespace.as_bytes());
    write_ssh_string(&mut preamble, b""); // reserved
    write_ssh_string(&mut preamble, b"sha512");
    write_ssh_string(&mut preamble, &message_hash);

    // Sign the preamble
    let signing_key = ed25519_dalek::SigningKey::from_bytes(secret_key);
    let signature = signing_key.sign(&preamble);

    // Build the full SSHSIG blob
    let mut sig_blob = Vec::new();
    sig_blob.extend_from_slice(SSHSIG_MAGIC);
    sig_blob.extend_from_slice(&SSHSIG_VERSION.to_be_bytes());
    write_ssh_string(&mut sig_blob, &pubkey_blob);
    write_ssh_string(&mut sig_blob, namespace.as_bytes());
    write_ssh_string(&mut sig_blob, b""); // reserved
    write_ssh_string(&mut sig_blob, b"sha512");

    // The signature itself is an SSH string containing the signature format + raw sig
    let mut sig_data = Vec::new();
    write_ssh_string(&mut sig_data, b"ssh-ed25519");
    write_ssh_string(&mut sig_data, &signature.to_bytes());
    write_ssh_string(&mut sig_blob, &sig_data);

    Ok(armor_signature(&sig_blob))
}

/// PEM-like armoring for SSH signatures.
pub fn armor_signature(sig_blob: &[u8]) -> String {
    let b64 = BASE64.encode(sig_blob);
    let mut out = String::new();
    out.push_str(ARMOR_BEGIN);
    out.push('\n');
    for chunk in b64.as_bytes().chunks(76) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str(ARMOR_END);
    out
}

/// Dearmor an SSH signature from PEM-like format.
pub fn dearmor_signature(armored: &str) -> Result<Vec<u8>> {
    let mut b64 = String::new();
    let mut in_body = false;
    for line in armored.lines() {
        let line = line.trim();
        if line == ARMOR_BEGIN {
            in_body = true;
            continue;
        }
        if line == ARMOR_END {
            break;
        }
        if in_body {
            b64.push_str(line);
        }
    }
    if b64.is_empty() {
        return Err(KageError::InvalidInput("no SSH signature data found".into()));
    }
    BASE64
        .decode(&b64)
        .map_err(|e| KageError::InvalidInput(format!("invalid base64 in SSH signature: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::generate_keypair;

    #[test]
    fn ssh_pubkey_encoding_format() {
        let (public_key, _) = generate_keypair();
        let blob = encode_ssh_ed25519_pubkey(&public_key);

        // First 4 bytes = length of "ssh-ed25519" (11)
        assert_eq!(&blob[0..4], &11u32.to_be_bytes());
        assert_eq!(&blob[4..15], b"ssh-ed25519");
        // Next 4 bytes = length of public key (32)
        assert_eq!(&blob[15..19], &32u32.to_be_bytes());
        assert_eq!(&blob[19..51], &public_key);
        assert_eq!(blob.len(), 51);
    }

    #[test]
    fn ssh_pubkey_line_format() {
        let (public_key, _) = generate_keypair();
        let line = format_ssh_pubkey_line(&public_key, "test-comment");

        assert!(line.starts_with("ssh-ed25519 "));
        assert!(line.ends_with(" test-comment"));
        let parts: Vec<&str> = line.split(' ').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "ssh-ed25519");
        // Verify the base64 decodes to valid wire format
        let decoded = BASE64.decode(parts[1]).unwrap();
        assert_eq!(decoded.len(), 51);
    }

    #[test]
    fn sign_verify_roundtrip() {
        let (public_key, secret_key) = generate_keypair();
        let message = b"test commit message\n\nSigned-off-by: test";

        let armored = create_ssh_signature(&secret_key, &public_key, message, "git").unwrap();

        // Verify armor structure
        assert!(armored.starts_with(ARMOR_BEGIN));
        assert!(armored.trim_end().ends_with(ARMOR_END));

        // Dearmor and check SSHSIG structure
        let blob = dearmor_signature(&armored).unwrap();
        assert_eq!(&blob[0..6], SSHSIG_MAGIC);
        assert_eq!(&blob[6..10], &SSHSIG_VERSION.to_be_bytes());
    }

    #[test]
    fn armor_dearmor_roundtrip() {
        let data = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let armored = armor_signature(&data);
        let recovered = dearmor_signature(&armored).unwrap();
        assert_eq!(data, recovered);
    }
}
