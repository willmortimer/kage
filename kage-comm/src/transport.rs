use crate::error::{daemon_codes, KageError, Result};
use crate::ipc::{
    JsonRpcRequest, JsonRpcResponse, KageStanza, ResolveIdentityParams, UnlockParams,
    UnwrapKeyParams, WrapKeyParams,
};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
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
    async fn ping(&self) -> Result<String>;
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

    async fn ping(&self) -> Result<String> {
        self.call::<(), String>("Ping", ()).await
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
    #[cfg(not(target_os = "macos"))]
    {
        Ok(Box::new(UnixJsonRpcTransport {
            socket_path: UnixJsonRpcTransport::default_socket_path()?,
        }))
    }
}
