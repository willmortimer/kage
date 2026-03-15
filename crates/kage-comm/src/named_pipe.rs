// Windows named pipe transport for kage daemon communication.
// Compile-gated: only active on Windows targets.

#![cfg(windows)]

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
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::windows::named_pipe::ClientOptions;

use super::DaemonTransport;

const PIPE_NAME: &str = r"\\.\pipe\kage-daemon";

pub struct NamedPipeJsonRpcTransport {
    pub pipe_name: String,
}

impl Clone for NamedPipeJsonRpcTransport {
    fn clone(&self) -> Self {
        Self {
            pipe_name: self.pipe_name.clone(),
        }
    }
}

impl NamedPipeJsonRpcTransport {
    pub fn new() -> Self {
        Self {
            pipe_name: PIPE_NAME.to_string(),
        }
    }

    async fn call<P: Serialize, R: DeserializeOwned>(&self, method: &str, params: P) -> Result<R> {
        let client = ClientOptions::new()
            .open(&self.pipe_name)
            .map_err(|e| KageError::Io(e))?;

        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: rand::random::<u64>(),
            method: method.to_string(),
            params,
        };
        let mut line = serde_json::to_vec(&req)?;
        line.push(b'\n');

        let (read_half, mut write_half) = tokio::io::split(client);
        write_half.write_all(&line).await?;

        let mut reader = BufReader::new(read_half);
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
impl DaemonTransport for NamedPipeJsonRpcTransport {
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
