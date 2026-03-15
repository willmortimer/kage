use crate::{load_env_record, unwrap_k_env};
use kage_comm::kid::Kid;
use kage_comm::signing;
use kage_comm::signing_record::{self, SigningKeyRecord};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use zeroize::Zeroizing;

/// Derive k_sign_seal from an environment's k_env.
pub fn get_k_sign_seal_for_kid(kid: Kid) -> Result<Zeroizing<[u8; 32]>, String> {
    let record = load_env_record(kid).map_err(|e| format!("load record: {e}"))?;
    let k_env = unwrap_k_env(&record).map_err(|e| format!("unwrap k_env: {e}"))?;
    let mut k_env_arr = [0u8; 32];
    k_env_arr.copy_from_slice(&k_env[..]);
    signing::derive_k_sign_seal(&k_env_arr).map_err(|e| format!("derive k_sign_seal: {e}"))
}

/// Unseal the Ed25519 secret key for a given kid_bech32.
/// Returns the secret key and the signing record.
pub fn unseal_signing_key_for_kid(
    kid_bech32: &str,
) -> Result<(Zeroizing<[u8; 32]>, SigningKeyRecord), String> {
    let kid =
        Kid::from_bech32(kid_bech32).map_err(|e| format!("invalid kid_bech32: {e}"))?;

    let k_sign_seal = get_k_sign_seal_for_kid(kid)?;

    let sign_record = signing_record::load_signing_record(kid)
        .map_err(|e| format!("load signing record: {e}"))?;

    let sealed = BASE64
        .decode(sign_record.sealed_private_key_b64.trim())
        .map_err(|e| format!("invalid sealed key base64: {e}"))?;

    let secret_key = signing::unseal_signing_key(&k_sign_seal, kid, &sealed)
        .map_err(|e| format!("unseal signing key: {e}"))?;

    Ok((secret_key, sign_record))
}

/// Load the signing record for a given kid_bech32 (public key only, no unsealing).
pub fn get_public_key_for_kid(kid_bech32: &str) -> Result<SigningKeyRecord, String> {
    let kid =
        Kid::from_bech32(kid_bech32).map_err(|e| format!("invalid kid_bech32: {e}"))?;

    signing_record::load_signing_record(kid)
        .map_err(|e| format!("load signing record: {e}"))
}
