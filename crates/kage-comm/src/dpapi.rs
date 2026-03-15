// Windows DPAPI-based K_env sealing.
// Compile-gated: only active on Windows targets.

#![cfg(windows)]

use crate::error::{KageError, Result};
use crate::kid::Kid;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use std::ptr;
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB,
};
use windows_sys::Win32::System::Memory::LocalFree;

/// Seal K_env using Windows DPAPI (CryptProtectData).
/// The sealed blob is returned as a base64-encoded string.
pub fn seal_k_env(_kid: Kid, k_env: &[u8; 32]) -> Result<String> {
    let mut input = CRYPT_INTEGER_BLOB {
        cbData: k_env.len() as u32,
        pbData: k_env.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };

    let ok = unsafe {
        CryptProtectData(
            &mut input,
            ptr::null(),     // description
            ptr::null_mut(), // entropy (none — user-scope only)
            ptr::null_mut(), // reserved
            ptr::null_mut(), // prompt struct
            0,               // flags
            &mut output,
        )
    };

    if ok == 0 {
        return Err(KageError::Crypto("CryptProtectData failed".into()));
    }

    let sealed = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) };
    let b64 = BASE64.encode(sealed);

    unsafe {
        LocalFree(output.pbData as _);
    }

    Ok(b64)
}

/// Unseal K_env using Windows DPAPI (CryptUnprotectData).
pub fn unseal_k_env(_kid: Kid, sealed_b64: &str) -> Result<[u8; 32]> {
    let sealed = BASE64
        .decode(sealed_b64.trim())
        .map_err(|e| KageError::InvalidInput(format!("invalid base64: {e}")))?;

    let mut input = CRYPT_INTEGER_BLOB {
        cbData: sealed.len() as u32,
        pbData: sealed.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };

    let ok = unsafe {
        CryptUnprotectData(
            &mut input,
            ptr::null_mut(), // description out
            ptr::null_mut(), // entropy
            ptr::null_mut(), // reserved
            ptr::null_mut(), // prompt struct
            0,               // flags
            &mut output,
        )
    };

    if ok == 0 {
        return Err(KageError::Crypto("CryptUnprotectData failed".into()));
    }

    let plaintext = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) };
    if plaintext.len() != 32 {
        unsafe {
            LocalFree(output.pbData as _);
        }
        return Err(KageError::Crypto(format!(
            "unexpected K_env length {}, expected 32",
            plaintext.len()
        )));
    }

    let mut k_env = [0u8; 32];
    k_env.copy_from_slice(plaintext);

    unsafe {
        LocalFree(output.pbData as _);
    }

    Ok(k_env)
}
