use crate::error::{daemon_codes, KageError, Result};
use crate::ipc::{
    JsonRpcRequest, JsonRpcResponse, KageStanza, LockParams, ResolveIdentityParams, UnlockParams,
    UnwrapKeyParams, WrapKeyParams,
};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use kage_types::envelope::{RequestEnvelope, ResponseEnvelope};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

#[async_trait]
pub trait DaemonTransport: Send + Sync {
    async fn resolve_identity(&self, org: &str, env: &str) -> Result<String>;
    async fn wrap_key(&self, kid_bech32: &str, file_key: &[u8]) -> Result<KageStanza>;
    async fn unwrap_key(&self, stanza: &KageStanza) -> Result<Vec<u8>>;
    async fn unlock(&self, kid_bech32: &str, duration_seconds: u32) -> Result<()>;
    async fn lock(&self, kid_bech32: &str) -> Result<()>;
    async fn ping(&self) -> Result<String>;
    async fn dispatch(&self, envelope: RequestEnvelope) -> Result<ResponseEnvelope>;
}

pub struct UnixJsonRpcTransport {
    pub socket_path: PathBuf,
}

impl Clone for UnixJsonRpcTransport {
    fn clone(&self) -> Self {
        Self {
            socket_path: self.socket_path.clone(),
        }
    }
}

impl UnixJsonRpcTransport {
    pub fn default_socket_path() -> Result<PathBuf> {
        let home =
            dirs::home_dir().ok_or_else(|| KageError::InvalidInput("HOME not set".into()))?;
        Ok(home.join(".kage").join("kaged.sock"))
    }

    async fn call<P: Serialize, R: DeserializeOwned>(&self, method: &str, params: P) -> Result<R> {
        let mut stream = UnixStream::connect(&self.socket_path).await?;
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: rand::random::<u64>(),
            method: method.to_string(),
            params,
        };
        let mut line = serde_json::to_vec(&req)?;
        line.push(b'\n');
        stream.write_all(&line).await?;

        let mut reader = BufReader::new(stream);
        let mut resp_line = String::new();
        reader.read_line(&mut resp_line).await?;
        let resp: JsonRpcResponse<R> = serde_json::from_str(resp_line.trim())?;

        if let Some(err) = resp.error {
            return Err(KageError::Daemon {
                code: err.code,
                message: err.message,
            });
        }
        resp.result.ok_or_else(|| KageError::Daemon {
            code: daemon_codes::CONFIG_ERROR,
            message: "missing result".into(),
        })
    }
}

#[async_trait]
impl DaemonTransport for UnixJsonRpcTransport {
    async fn resolve_identity(&self, org: &str, env: &str) -> Result<String> {
        self.call(
            "ResolveIdentity",
            ResolveIdentityParams {
                org: org.to_string(),
                env: env.to_string(),
            },
        )
        .await
    }

    async fn wrap_key(&self, kid_bech32: &str, file_key: &[u8]) -> Result<KageStanza> {
        self.call(
            "WrapKey",
            WrapKeyParams {
                kid_bech32: kid_bech32.to_string(),
                file_key_b64: BASE64.encode(file_key),
            },
        )
        .await
    }

    async fn unwrap_key(&self, stanza: &KageStanza) -> Result<Vec<u8>> {
        let out_b64: String = self
            .call(
                "UnwrapKey",
                UnwrapKeyParams {
                    stanza: stanza.clone(),
                },
            )
            .await?;
        Ok(BASE64.decode(out_b64)?)
    }

    async fn unlock(&self, kid_bech32: &str, duration_seconds: u32) -> Result<()> {
        let _ok: bool = self
            .call(
                "Unlock",
                UnlockParams {
                    kid_bech32: kid_bech32.to_string(),
                    duration_seconds,
                },
            )
            .await?;
        Ok(())
    }

    async fn lock(&self, kid_bech32: &str) -> Result<()> {
        let _ok: serde_json::Value = self
            .call(
                "Lock",
                LockParams {
                    kid_bech32: kid_bech32.to_string(),
                },
            )
            .await?;
        Ok(())
    }

    async fn ping(&self) -> Result<String> {
        self.call::<(), String>("Ping", ()).await
    }

    async fn dispatch(&self, envelope: RequestEnvelope) -> Result<ResponseEnvelope> {
        self.call("Dispatch", envelope).await
    }
}

#[cfg(target_os = "macos")]
mod macos_xpc {
    use super::DaemonTransport;
    use crate::error::{KageError, Result};
    use crate::ipc::KageStanza;
    use async_trait::async_trait;
    use std::ffi::{c_char, CString};

    extern "C" {
        fn kage_xpc_ping(out: *mut c_char, out_len: usize, err: *mut c_char, err_len: usize)
            -> i32;
        fn kage_xpc_resolve_identity(
            org: *const c_char,
            env: *const c_char,
            out: *mut c_char,
            out_len: usize,
            err: *mut c_char,
            err_len: usize,
        ) -> i32;
        fn kage_xpc_unlock(
            kid_bech32: *const c_char,
            duration_seconds: u32,
            err: *mut c_char,
            err_len: usize,
        ) -> i32;
        fn kage_xpc_wrap_key(
            kid_bech32: *const c_char,
            file_key: *const u8,
            file_key_len: usize,
            nonce_b64_out: *mut c_char,
            nonce_b64_out_len: usize,
            payload_b64_out: *mut c_char,
            payload_b64_out_len: usize,
            err: *mut c_char,
            err_len: usize,
        ) -> i32;
        fn kage_xpc_unwrap_key(
            kid_bech32: *const c_char,
            nonce_b64: *const c_char,
            payload_b64: *const c_char,
            file_key_out: *mut u8,
            file_key_out_len: usize,
            err: *mut c_char,
            err_len: usize,
        ) -> i32;
    }

    fn c_buf_to_string(buf: &[c_char]) -> String {
        let bytes: Vec<u8> = buf
            .iter()
            .take_while(|&&b| b != 0)
            .map(|&b| b as u8)
            .collect();
        String::from_utf8_lossy(&bytes).to_string()
    }

    fn daemon_err(code: i32, msg: String) -> KageError {
        KageError::Daemon { code, message: msg }
    }

    #[derive(Clone, Debug)]
    pub struct MacosXpcTransport;

    impl Default for MacosXpcTransport {
        fn default() -> Self {
            Self::new()
        }
    }

    impl MacosXpcTransport {
        pub fn new() -> Self {
            Self
        }
    }

    #[async_trait]
    impl DaemonTransport for MacosXpcTransport {
        async fn resolve_identity(&self, org: &str, env: &str) -> Result<String> {
            let org = org.to_string();
            let env = env.to_string();
            tokio::task::spawn_blocking(move || unsafe {
                let org_c =
                    CString::new(org).map_err(|e| KageError::InvalidInput(e.to_string()))?;
                let env_c =
                    CString::new(env).map_err(|e| KageError::InvalidInput(e.to_string()))?;
                let mut out = vec![0 as c_char; 128];
                let mut err = vec![0 as c_char; 512];
                let rc = kage_xpc_resolve_identity(
                    org_c.as_ptr(),
                    env_c.as_ptr(),
                    out.as_mut_ptr(),
                    out.len(),
                    err.as_mut_ptr(),
                    err.len(),
                );
                if rc == 0 {
                    Ok(c_buf_to_string(&out))
                } else {
                    Err(daemon_err(rc, c_buf_to_string(&err)))
                }
            })
            .await
            .map_err(|e| KageError::Io(std::io::Error::other(e.to_string())))?
        }

        async fn wrap_key(&self, kid_bech32: &str, file_key: &[u8]) -> Result<KageStanza> {
            let kid = kid_bech32.to_string();
            let fk = file_key.to_vec();
            tokio::task::spawn_blocking(move || unsafe {
                let kid_c = CString::new(kid.clone())
                    .map_err(|e| KageError::InvalidInput(e.to_string()))?;
                let mut nonce = vec![0 as c_char; 128];
                let mut payload = vec![0 as c_char; 256];
                let mut err = vec![0 as c_char; 512];
                let rc = kage_xpc_wrap_key(
                    kid_c.as_ptr(),
                    fk.as_ptr(),
                    fk.len(),
                    nonce.as_mut_ptr(),
                    nonce.len(),
                    payload.as_mut_ptr(),
                    payload.len(),
                    err.as_mut_ptr(),
                    err.len(),
                );
                if rc == 0 {
                    Ok(KageStanza {
                        kid_bech32: kid,
                        nonce_b64: c_buf_to_string(&nonce),
                        payload_b64: c_buf_to_string(&payload),
                    })
                } else {
                    Err(daemon_err(rc, c_buf_to_string(&err)))
                }
            })
            .await
            .map_err(|e| KageError::Io(std::io::Error::other(e.to_string())))?
        }

        async fn unwrap_key(&self, stanza: &KageStanza) -> Result<Vec<u8>> {
            let kid = stanza.kid_bech32.clone();
            let nonce_b64 = stanza.nonce_b64.clone();
            let payload_b64 = stanza.payload_b64.clone();
            tokio::task::spawn_blocking(move || unsafe {
                let kid_c =
                    CString::new(kid).map_err(|e| KageError::InvalidInput(e.to_string()))?;
                let nonce_c =
                    CString::new(nonce_b64).map_err(|e| KageError::InvalidInput(e.to_string()))?;
                let payload_c = CString::new(payload_b64)
                    .map_err(|e| KageError::InvalidInput(e.to_string()))?;
                let mut file_key = [0u8; 16];
                let mut err = vec![0 as c_char; 512];
                let rc = kage_xpc_unwrap_key(
                    kid_c.as_ptr(),
                    nonce_c.as_ptr(),
                    payload_c.as_ptr(),
                    file_key.as_mut_ptr(),
                    file_key.len(),
                    err.as_mut_ptr(),
                    err.len(),
                );
                if rc == 0 {
                    Ok(file_key.to_vec())
                } else {
                    Err(daemon_err(rc, c_buf_to_string(&err)))
                }
            })
            .await
            .map_err(|e| KageError::Io(std::io::Error::other(e.to_string())))?
        }

        async fn unlock(&self, kid_bech32: &str, duration_seconds: u32) -> Result<()> {
            let kid = kid_bech32.to_string();
            tokio::task::spawn_blocking(move || unsafe {
                let kid_c =
                    CString::new(kid).map_err(|e| KageError::InvalidInput(e.to_string()))?;
                let mut err = vec![0 as c_char; 512];
                let rc = kage_xpc_unlock(
                    kid_c.as_ptr(),
                    duration_seconds,
                    err.as_mut_ptr(),
                    err.len(),
                );
                if rc == 0 {
                    Ok(())
                } else {
                    Err(daemon_err(rc, c_buf_to_string(&err)))
                }
            })
            .await
            .map_err(|e| KageError::Io(std::io::Error::other(e.to_string())))?
        }

        async fn lock(&self, _kid_bech32: &str) -> Result<()> {
            Err(KageError::InvalidInput(
                "Lock not yet supported over XPC".into(),
            ))
        }

        async fn ping(&self) -> Result<String> {
            tokio::task::spawn_blocking(move || unsafe {
                let mut out = vec![0 as c_char; 256];
                let mut err = vec![0 as c_char; 512];
                let rc = kage_xpc_ping(out.as_mut_ptr(), out.len(), err.as_mut_ptr(), err.len());
                if rc == 0 {
                    Ok(c_buf_to_string(&out))
                } else {
                    Err(daemon_err(rc, c_buf_to_string(&err)))
                }
            })
            .await
            .map_err(|e| KageError::Io(std::io::Error::other(e.to_string())))?
        }

        async fn dispatch(
            &self,
            _envelope: kage_types::envelope::RequestEnvelope,
        ) -> Result<kage_types::envelope::ResponseEnvelope> {
            Err(KageError::InvalidInput(
                "Dispatch not yet supported over XPC".into(),
            ))
        }
    }

    pub fn default_transport() -> MacosXpcTransport {
        MacosXpcTransport::new()
    }
}

#[cfg(target_os = "macos")]
pub use macos_xpc::MacosXpcTransport;

pub fn default_daemon_transport() -> Result<Box<dyn DaemonTransport>> {
    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(macos_xpc::default_transport()))
    }
    #[cfg(windows)]
    {
        Ok(Box::new(crate::named_pipe::NamedPipeJsonRpcTransport::new()))
    }
    #[cfg(all(not(target_os = "macos"), not(windows)))]
    {
        Ok(Box::new(UnixJsonRpcTransport {
            socket_path: UnixJsonRpcTransport::default_socket_path()?,
        }))
    }
}

// ----- Secret operation convenience methods -----

use kage_types::adapter::AdapterId;
use kage_types::capability::Capability;
use std::collections::BTreeMap;

/// Encrypt a secret via the daemon's runtime adapter.
pub async fn encrypt_secret(
    transport: &dyn DaemonTransport,
    org: &str,
    env: &str,
    name: &str,
    plaintext: &[u8],
) -> Result<String> {
    let envelope = kage_types::envelope::RequestEnvelope {
        version: 1,
        adapter: AdapterId::new(AdapterId::RUNTIME),
        capability: Capability::SecretRelease,
        operation: "encrypt".to_string(),
        advisory: None,
        params: serde_json::json!({
            "org": org,
            "env": env,
            "name": name,
            "plaintext_b64": BASE64.encode(plaintext),
        }),
    };
    let resp = transport.dispatch(envelope).await?;
    if let Some(err) = resp.error {
        return Err(KageError::Daemon {
            code: daemon_codes::CONFIG_ERROR,
            message: err,
        });
    }
    let result = resp.result.ok_or_else(|| KageError::Daemon {
        code: daemon_codes::CONFIG_ERROR,
        message: "missing result".into(),
    })?;
    result["ciphertext_b64"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| KageError::Daemon {
            code: daemon_codes::CONFIG_ERROR,
            message: "missing ciphertext_b64 in response".into(),
        })
}

/// Decrypt a secret via the daemon's runtime adapter.
pub async fn decrypt_secret(
    transport: &dyn DaemonTransport,
    org: &str,
    env: &str,
    name: &str,
    ciphertext_b64: &str,
) -> Result<Vec<u8>> {
    let envelope = kage_types::envelope::RequestEnvelope {
        version: 1,
        adapter: AdapterId::new(AdapterId::RUNTIME),
        capability: Capability::SecretRelease,
        operation: "decrypt".to_string(),
        advisory: None,
        params: serde_json::json!({
            "org": org,
            "env": env,
            "name": name,
            "ciphertext_b64": ciphertext_b64,
        }),
    };
    let resp = transport.dispatch(envelope).await?;
    if let Some(err) = resp.error {
        return Err(KageError::Daemon {
            code: daemon_codes::CONFIG_ERROR,
            message: err,
        });
    }
    let result = resp.result.ok_or_else(|| KageError::Daemon {
        code: daemon_codes::CONFIG_ERROR,
        message: "missing result".into(),
    })?;
    let pt_b64 = result["plaintext_b64"]
        .as_str()
        .ok_or_else(|| KageError::Daemon {
            code: daemon_codes::CONFIG_ERROR,
            message: "missing plaintext_b64 in response".into(),
        })?;
    Ok(BASE64.decode(pt_b64)?)
}

// ----- Signing operation convenience methods -----

/// Initialize a signing keypair via the daemon's sign adapter.
/// Returns the base64-encoded public key.
pub async fn sign_init(
    transport: &dyn DaemonTransport,
    kid_bech32: &str,
) -> Result<String> {
    let envelope = kage_types::envelope::RequestEnvelope {
        version: 1,
        adapter: AdapterId::new(AdapterId::SIGN),
        capability: Capability::Sign,
        operation: "init".to_string(),
        advisory: None,
        params: serde_json::json!({
            "kid_bech32": kid_bech32,
        }),
    };
    let resp = transport.dispatch(envelope).await?;
    if let Some(err) = resp.error {
        return Err(KageError::Daemon {
            code: daemon_codes::CONFIG_ERROR,
            message: err,
        });
    }
    let result = resp.result.ok_or_else(|| KageError::Daemon {
        code: daemon_codes::CONFIG_ERROR,
        message: "missing result".into(),
    })?;
    result["public_key_b64"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| KageError::Daemon {
            code: daemon_codes::CONFIG_ERROR,
            message: "missing public_key_b64 in response".into(),
        })
}

/// Sign arbitrary bytes via the daemon's sign adapter.
/// Returns (signature_b64, public_key_b64).
pub async fn sign_bytes(
    transport: &dyn DaemonTransport,
    kid_bech32: &str,
    message: &[u8],
) -> Result<(String, String)> {
    let envelope = kage_types::envelope::RequestEnvelope {
        version: 1,
        adapter: AdapterId::new(AdapterId::SIGN),
        capability: Capability::Sign,
        operation: "sign".to_string(),
        advisory: None,
        params: serde_json::json!({
            "kid_bech32": kid_bech32,
            "message_b64": BASE64.encode(message),
        }),
    };
    let resp = transport.dispatch(envelope).await?;
    if let Some(err) = resp.error {
        return Err(KageError::Daemon {
            code: daemon_codes::CONFIG_ERROR,
            message: err,
        });
    }
    let result = resp.result.ok_or_else(|| KageError::Daemon {
        code: daemon_codes::CONFIG_ERROR,
        message: "missing result".into(),
    })?;
    let sig = result["signature_b64"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| KageError::Daemon {
            code: daemon_codes::CONFIG_ERROR,
            message: "missing signature_b64 in response".into(),
        })?;
    let pubkey = result["public_key_b64"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| KageError::Daemon {
            code: daemon_codes::CONFIG_ERROR,
            message: "missing public_key_b64 in response".into(),
        })?;
    Ok((sig, pubkey))
}

/// Retrieve the signing public key via the daemon's sign adapter.
pub async fn get_signing_public_key(
    transport: &dyn DaemonTransport,
    kid_bech32: &str,
) -> Result<String> {
    let envelope = kage_types::envelope::RequestEnvelope {
        version: 1,
        adapter: AdapterId::new(AdapterId::SIGN),
        capability: Capability::Sign,
        operation: "get-public-key".to_string(),
        advisory: None,
        params: serde_json::json!({
            "kid_bech32": kid_bech32,
        }),
    };
    let resp = transport.dispatch(envelope).await?;
    if let Some(err) = resp.error {
        return Err(KageError::Daemon {
            code: daemon_codes::CONFIG_ERROR,
            message: err,
        });
    }
    let result = resp.result.ok_or_else(|| KageError::Daemon {
        code: daemon_codes::CONFIG_ERROR,
        message: "missing result".into(),
    })?;
    result["public_key_b64"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| KageError::Daemon {
            code: daemon_codes::CONFIG_ERROR,
            message: "missing public_key_b64 in response".into(),
        })
}

/// Release multiple secrets via the daemon's runtime adapter.
/// Returns a map of secret name -> plaintext value.
pub async fn release_secrets(
    transport: &dyn DaemonTransport,
    org: &str,
    env: &str,
    secrets: &[(String, String)], // (name, ciphertext_b64)
) -> Result<BTreeMap<String, String>> {
    let entries: Vec<serde_json::Value> = secrets
        .iter()
        .map(|(name, ct_b64)| {
            serde_json::json!({
                "name": name,
                "ciphertext_b64": ct_b64,
            })
        })
        .collect();

    let envelope = kage_types::envelope::RequestEnvelope {
        version: 1,
        adapter: AdapterId::new(AdapterId::RUNTIME),
        capability: Capability::SecretRelease,
        operation: "release".to_string(),
        advisory: None,
        params: serde_json::json!({
            "org": org,
            "env": env,
            "secrets": entries,
        }),
    };
    let resp = transport.dispatch(envelope).await?;
    if let Some(err) = resp.error {
        return Err(KageError::Daemon {
            code: daemon_codes::CONFIG_ERROR,
            message: err,
        });
    }
    let result = resp.result.ok_or_else(|| KageError::Daemon {
        code: daemon_codes::CONFIG_ERROR,
        message: "missing result".into(),
    })?;
    serde_json::from_value(result).map_err(KageError::Json)
}

// ----- Git signing convenience methods -----

/// Sign a git commit payload via the daemon's git-sign adapter.
/// Returns the armored SSH signature.
pub async fn git_sign_commit(
    transport: &dyn DaemonTransport,
    kid_bech32: &str,
    payload: &[u8],
) -> Result<String> {
    let envelope = kage_types::envelope::RequestEnvelope {
        version: 1,
        adapter: AdapterId::new(AdapterId::GIT_SIGN),
        capability: Capability::Sign,
        operation: "sign-commit".to_string(),
        advisory: None,
        params: serde_json::json!({
            "kid_bech32": kid_bech32,
            "payload_b64": BASE64.encode(payload),
        }),
    };
    let resp = transport.dispatch(envelope).await?;
    if let Some(err) = resp.error {
        return Err(KageError::Daemon {
            code: daemon_codes::CONFIG_ERROR,
            message: err,
        });
    }
    let result = resp.result.ok_or_else(|| KageError::Daemon {
        code: daemon_codes::CONFIG_ERROR,
        message: "missing result".into(),
    })?;
    result["signature_armored"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| KageError::Daemon {
            code: daemon_codes::CONFIG_ERROR,
            message: "missing signature_armored in response".into(),
        })
}

/// Sign a git tag payload via the daemon's git-sign adapter.
pub async fn git_sign_tag(
    transport: &dyn DaemonTransport,
    kid_bech32: &str,
    payload: &[u8],
) -> Result<String> {
    let envelope = kage_types::envelope::RequestEnvelope {
        version: 1,
        adapter: AdapterId::new(AdapterId::GIT_SIGN),
        capability: Capability::Sign,
        operation: "sign-tag".to_string(),
        advisory: None,
        params: serde_json::json!({
            "kid_bech32": kid_bech32,
            "payload_b64": BASE64.encode(payload),
        }),
    };
    let resp = transport.dispatch(envelope).await?;
    if let Some(err) = resp.error {
        return Err(KageError::Daemon {
            code: daemon_codes::CONFIG_ERROR,
            message: err,
        });
    }
    let result = resp.result.ok_or_else(|| KageError::Daemon {
        code: daemon_codes::CONFIG_ERROR,
        message: "missing result".into(),
    })?;
    result["signature_armored"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| KageError::Daemon {
            code: daemon_codes::CONFIG_ERROR,
            message: "missing signature_armored in response".into(),
        })
}

/// Get the SSH-format public key for a git signing identity.
pub async fn get_git_ssh_pubkey(
    transport: &dyn DaemonTransport,
    kid_bech32: &str,
) -> Result<String> {
    let envelope = kage_types::envelope::RequestEnvelope {
        version: 1,
        adapter: AdapterId::new(AdapterId::GIT_SIGN),
        capability: Capability::Sign,
        operation: "get-ssh-pubkey".to_string(),
        advisory: None,
        params: serde_json::json!({
            "kid_bech32": kid_bech32,
        }),
    };
    let resp = transport.dispatch(envelope).await?;
    if let Some(err) = resp.error {
        return Err(KageError::Daemon {
            code: daemon_codes::CONFIG_ERROR,
            message: err,
        });
    }
    let result = resp.result.ok_or_else(|| KageError::Daemon {
        code: daemon_codes::CONFIG_ERROR,
        message: "missing result".into(),
    })?;
    result["ssh_pubkey"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| KageError::Daemon {
            code: daemon_codes::CONFIG_ERROR,
            message: "missing ssh_pubkey in response".into(),
        })
}

// ----- Assertion convenience methods -----

/// Issue a short-lived signed assertion via the daemon's assert adapter.
/// Returns (token, expires_at).
pub async fn issue_assertion(
    transport: &dyn DaemonTransport,
    kid_bech32: &str,
    purpose: &str,
    scope: &str,
    ttl_seconds: i64,
) -> Result<(String, String)> {
    let envelope = kage_types::envelope::RequestEnvelope {
        version: 1,
        adapter: AdapterId::new(AdapterId::ASSERT),
        capability: Capability::Assert,
        operation: "issue".to_string(),
        advisory: None,
        params: serde_json::json!({
            "kid_bech32": kid_bech32,
            "purpose": purpose,
            "scope": scope,
            "ttl_seconds": ttl_seconds,
        }),
    };
    let resp = transport.dispatch(envelope).await?;
    if let Some(err) = resp.error {
        return Err(KageError::Daemon {
            code: daemon_codes::CONFIG_ERROR,
            message: err,
        });
    }
    let result = resp.result.ok_or_else(|| KageError::Daemon {
        code: daemon_codes::CONFIG_ERROR,
        message: "missing result".into(),
    })?;
    let token = result["token"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| KageError::Daemon {
            code: daemon_codes::CONFIG_ERROR,
            message: "missing token in response".into(),
        })?;
    let expires_at = result["expires_at"]
        .as_str()
        .map(|s| s.to_string())
        .unwrap_or_default();
    Ok((token, expires_at))
}

/// Verify an assertion token via the daemon's assert adapter.
pub async fn verify_assertion_remote(
    transport: &dyn DaemonTransport,
    kid_bech32: &str,
    token: &str,
) -> Result<bool> {
    let envelope = kage_types::envelope::RequestEnvelope {
        version: 1,
        adapter: AdapterId::new(AdapterId::ASSERT),
        capability: Capability::Assert,
        operation: "verify".to_string(),
        advisory: None,
        params: serde_json::json!({
            "kid_bech32": kid_bech32,
            "token": token,
        }),
    };
    let resp = transport.dispatch(envelope).await?;
    if let Some(err) = resp.error {
        return Err(KageError::Daemon {
            code: daemon_codes::CONFIG_ERROR,
            message: err,
        });
    }
    let result = resp.result.ok_or_else(|| KageError::Daemon {
        code: daemon_codes::CONFIG_ERROR,
        message: "missing result".into(),
    })?;
    Ok(result["valid"].as_bool().unwrap_or(false))
}

// ----- Artifact signing convenience methods -----

/// Sign an artifact digest via the daemon's artifact adapter.
/// Returns the envelope JSON string.
pub async fn sign_artifact_digest(
    transport: &dyn DaemonTransport,
    kid_bech32: &str,
    digest: &str,
    metadata: &BTreeMap<String, String>,
) -> Result<String> {
    let envelope = kage_types::envelope::RequestEnvelope {
        version: 1,
        adapter: AdapterId::new(AdapterId::ARTIFACT),
        capability: Capability::Sign,
        operation: "sign-digest".to_string(),
        advisory: None,
        params: serde_json::json!({
            "kid_bech32": kid_bech32,
            "digest": digest,
            "metadata": metadata,
        }),
    };
    let resp = transport.dispatch(envelope).await?;
    if let Some(err) = resp.error {
        return Err(KageError::Daemon {
            code: daemon_codes::CONFIG_ERROR,
            message: err,
        });
    }
    let result = resp.result.ok_or_else(|| KageError::Daemon {
        code: daemon_codes::CONFIG_ERROR,
        message: "missing result".into(),
    })?;
    serde_json::to_string_pretty(&result).map_err(KageError::Json)
}

/// Sign a release manifest via the daemon's artifact adapter.
pub async fn sign_release_manifest(
    transport: &dyn DaemonTransport,
    kid_bech32: &str,
    entries: &[serde_json::Value],
    metadata: &BTreeMap<String, String>,
) -> Result<String> {
    let envelope = kage_types::envelope::RequestEnvelope {
        version: 1,
        adapter: AdapterId::new(AdapterId::ARTIFACT),
        capability: Capability::Sign,
        operation: "sign-manifest".to_string(),
        advisory: None,
        params: serde_json::json!({
            "kid_bech32": kid_bech32,
            "entries": entries,
            "metadata": metadata,
        }),
    };
    let resp = transport.dispatch(envelope).await?;
    if let Some(err) = resp.error {
        return Err(KageError::Daemon {
            code: daemon_codes::CONFIG_ERROR,
            message: err,
        });
    }
    let result = resp.result.ok_or_else(|| KageError::Daemon {
        code: daemon_codes::CONFIG_ERROR,
        message: "missing result".into(),
    })?;
    serde_json::to_string_pretty(&result).map_err(KageError::Json)
}

/// Verify an artifact digest signature via the daemon's artifact adapter.
pub async fn verify_artifact_digest(
    transport: &dyn DaemonTransport,
    kid_bech32: &str,
    envelope_json: &str,
) -> Result<bool> {
    let envelope_value: serde_json::Value =
        serde_json::from_str(envelope_json).map_err(KageError::Json)?;
    let envelope = kage_types::envelope::RequestEnvelope {
        version: 1,
        adapter: AdapterId::new(AdapterId::ARTIFACT),
        capability: Capability::Sign,
        operation: "verify-digest".to_string(),
        advisory: None,
        params: serde_json::json!({
            "kid_bech32": kid_bech32,
            "envelope": envelope_value,
        }),
    };
    let resp = transport.dispatch(envelope).await?;
    if let Some(err) = resp.error {
        return Err(KageError::Daemon {
            code: daemon_codes::CONFIG_ERROR,
            message: err,
        });
    }
    let result = resp.result.ok_or_else(|| KageError::Daemon {
        code: daemon_codes::CONFIG_ERROR,
        message: "missing result".into(),
    })?;
    Ok(result["valid"].as_bool().unwrap_or(false))
}

/// Verify a release manifest signature via the daemon's artifact adapter.
pub async fn verify_release_manifest_remote(
    transport: &dyn DaemonTransport,
    kid_bech32: &str,
    manifest_json: &str,
) -> Result<bool> {
    let manifest_value: serde_json::Value =
        serde_json::from_str(manifest_json).map_err(KageError::Json)?;
    let envelope = kage_types::envelope::RequestEnvelope {
        version: 1,
        adapter: AdapterId::new(AdapterId::ARTIFACT),
        capability: Capability::Sign,
        operation: "verify-manifest".to_string(),
        advisory: None,
        params: serde_json::json!({
            "kid_bech32": kid_bech32,
            "manifest": manifest_value,
        }),
    };
    let resp = transport.dispatch(envelope).await?;
    if let Some(err) = resp.error {
        return Err(KageError::Daemon {
            code: daemon_codes::CONFIG_ERROR,
            message: err,
        });
    }
    let result = resp.result.ok_or_else(|| KageError::Daemon {
        code: daemon_codes::CONFIG_ERROR,
        message: "missing result".into(),
    })?;
    Ok(result["valid"].as_bool().unwrap_or(false))
}
