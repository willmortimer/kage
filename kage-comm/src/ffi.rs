use crate::crypto;
use crate::error::KageError;
use crate::kid::{derive_kid, Kid};
use std::ffi::{c_char, CStr};
use std::ptr;

fn cstr_to_str<'a>(p: *const c_char) -> Result<&'a str, KageError> {
    if p.is_null() {
        return Err(KageError::InvalidInput("null string".into()));
    }
    // Safety: caller passes NUL-terminated string.
    let s = unsafe { CStr::from_ptr(p) }
        .to_str()
        .map_err(|e| KageError::InvalidInput(format!("invalid utf-8: {e}")))?;
    Ok(s)
}

fn write_c_string(out: *mut c_char, out_len: usize, s: &str) -> Result<(), KageError> {
    if out.is_null() || out_len == 0 {
        return Err(KageError::InvalidInput("null output buffer".into()));
    }
    let bytes = s.as_bytes();
    if bytes.len() + 1 > out_len {
        return Err(KageError::InvalidInput("output buffer too small".into()));
    }
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), out as *mut u8, bytes.len());
        *(out.add(bytes.len())) = 0;
    }
    Ok(())
}

#[no_mangle]
/// # Safety
/// - `kid_bech32` must be a valid NUL-terminated C string.
/// - `out_kid16` must be valid for writes of 16 bytes.
pub unsafe extern "C" fn kage_v2_parse_kid_bech32(
    kid_bech32: *const c_char,
    out_kid16: *mut u8,
) -> i32 {
    let res: Result<(), KageError> = (|| {
        if out_kid16.is_null() {
            return Err(KageError::InvalidInput("null out_kid16".into()));
        }
        let kid = Kid::from_bech32(cstr_to_str(kid_bech32)?)?;
        unsafe {
            ptr::copy_nonoverlapping(kid.0.as_ptr(), out_kid16, 16);
        }
        Ok(())
    })();
    if res.is_ok() {
        0
    } else {
        -1
    }
}

#[no_mangle]
/// # Safety
/// - `org` and `env` must be valid NUL-terminated C strings.
/// - `out` must be valid for writes of `out_len` bytes and `out_len` must be > 0.
pub unsafe extern "C" fn kage_v2_derive_kid_bech32(
    org: *const c_char,
    env: *const c_char,
    out: *mut c_char,
    out_len: usize,
) -> i32 {
    let res: Result<(), KageError> = (|| {
        let kid = derive_kid(cstr_to_str(org)?, cstr_to_str(env)?);
        let s = kid.to_bech32()?;
        write_c_string(out, out_len, &s)?;
        Ok(())
    })();
    if res.is_ok() {
        0
    } else {
        -1
    }
}

#[no_mangle]
/// # Safety
/// - `k_env32` must point to 32 readable bytes.
/// - `out_k_wrap32` must point to 32 writable bytes.
pub unsafe extern "C" fn kage_v2_derive_k_wrap(k_env32: *const u8, out_k_wrap32: *mut u8) -> i32 {
    let res: Result<(), KageError> = (|| {
        if k_env32.is_null() || out_k_wrap32.is_null() {
            return Err(KageError::InvalidInput("null pointer".into()));
        }
        let mut k_env = [0u8; 32];
        unsafe {
            ptr::copy_nonoverlapping(k_env32, k_env.as_mut_ptr(), 32);
        }
        let k_wrap = crypto::derive_k_wrap(&k_env)?;
        unsafe {
            ptr::copy_nonoverlapping(k_wrap.as_ptr(), out_k_wrap32, 32);
        }
        Ok(())
    })();
    if res.is_ok() {
        0
    } else {
        -1
    }
}

#[no_mangle]
/// # Safety
/// - `k_wrap32` must point to 32 readable bytes.
/// - `kid16` must point to 16 readable bytes.
/// - `file_key16` must point to 16 readable bytes.
/// - `out_nonce24` must point to 24 writable bytes.
/// - `out_ciphertext32` must point to 32 writable bytes.
pub unsafe extern "C" fn kage_v2_wrap_file_key(
    k_wrap32: *const u8,
    kid16: *const u8,
    file_key16: *const u8,
    out_nonce24: *mut u8,
    out_ciphertext32: *mut u8,
) -> i32 {
    let res: Result<(), KageError> = (|| {
        if k_wrap32.is_null()
            || kid16.is_null()
            || file_key16.is_null()
            || out_nonce24.is_null()
            || out_ciphertext32.is_null()
        {
            return Err(KageError::InvalidInput("null pointer".into()));
        }
        let mut k_wrap = [0u8; 32];
        let mut kid_raw = [0u8; 16];
        let mut file_key = [0u8; 16];
        unsafe {
            ptr::copy_nonoverlapping(k_wrap32, k_wrap.as_mut_ptr(), 32);
            ptr::copy_nonoverlapping(kid16, kid_raw.as_mut_ptr(), 16);
            ptr::copy_nonoverlapping(file_key16, file_key.as_mut_ptr(), 16);
        }
        let kid = Kid(kid_raw);
        let (_kid, nonce, ct) = crypto::wrap_file_key(&k_wrap, kid, &file_key)?;
        if ct.len() != 32 {
            return Err(KageError::Crypto(format!(
                "unexpected ciphertext length {}, expected 32",
                ct.len()
            )));
        }
        unsafe {
            ptr::copy_nonoverlapping(nonce.as_ptr(), out_nonce24, 24);
            ptr::copy_nonoverlapping(ct.as_ptr(), out_ciphertext32, 32);
        }
        Ok(())
    })();
    if res.is_ok() {
        0
    } else {
        -1
    }
}

#[no_mangle]
/// # Safety
/// - `k_wrap32` must point to 32 readable bytes.
/// - `kid16` must point to 16 readable bytes.
/// - `nonce24` must point to 24 readable bytes.
/// - `ciphertext32` must point to 32 readable bytes.
/// - `out_file_key16` must point to 16 writable bytes.
pub unsafe extern "C" fn kage_v2_unwrap_file_key(
    k_wrap32: *const u8,
    kid16: *const u8,
    nonce24: *const u8,
    ciphertext32: *const u8,
    out_file_key16: *mut u8,
) -> i32 {
    let res: Result<(), KageError> = (|| {
        if k_wrap32.is_null()
            || kid16.is_null()
            || nonce24.is_null()
            || ciphertext32.is_null()
            || out_file_key16.is_null()
        {
            return Err(KageError::InvalidInput("null pointer".into()));
        }
        let mut k_wrap = [0u8; 32];
        let mut kid_raw = [0u8; 16];
        let mut nonce = [0u8; 24];
        let mut ct = [0u8; 32];
        unsafe {
            ptr::copy_nonoverlapping(k_wrap32, k_wrap.as_mut_ptr(), 32);
            ptr::copy_nonoverlapping(kid16, kid_raw.as_mut_ptr(), 16);
            ptr::copy_nonoverlapping(nonce24, nonce.as_mut_ptr(), 24);
            ptr::copy_nonoverlapping(ciphertext32, ct.as_mut_ptr(), 32);
        }
        let kid = Kid(kid_raw);
        let pt = crypto::unwrap_file_key(&k_wrap, kid, &nonce, &ct)?;
        if pt.len() != 16 {
            return Err(KageError::Crypto(format!(
                "unexpected file key length {}, expected 16",
                pt.len()
            )));
        }
        unsafe {
            ptr::copy_nonoverlapping(pt.as_ptr(), out_file_key16, 16);
        }
        Ok(())
    })();
    if res.is_ok() {
        0
    } else {
        -1
    }
}
