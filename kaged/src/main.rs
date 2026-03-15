use anyhow::Context;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use clap::Parser;
use kage_comm::crypto;
use kage_comm::devwrap;
use kage_comm::error::{daemon_codes, KageError};
use kage_comm::ipc::{JsonRpcError, JsonRpcRequest, JsonRpcResponse, KageStanza};
use kage_comm::kid::{derive_kid, Kid};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use tokio::time::{Duration, Instant};
use zeroize::Zeroizing;

#[derive(Parser, Debug)]
#[command(name = "kaged")]
struct Args {
    /// Override the default socket path (~/.kage/kaged.sock)
    #[arg(long)]
    socket: Option<PathBuf>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Policy {
    None,
    Presence,
    Strong,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct EnvRecord {
    kid_bech32: String,
    policy: Policy,
    wrapped_k_env_b64: String,
}

#[derive(Clone)]
struct CacheEntry {
    k_wrap: Zeroizing<[u8; 32]>,
    expires_at: Option<Instant>,
}

#[derive(Default)]
struct DaemonState {
    cache: HashMap<Kid, CacheEntry>,
}

fn records_dir() -> Result<PathBuf, KageError> {
    Ok(devwrap::v2_dir()?.join("records"))
}

fn record_path(kid: Kid) -> Result<PathBuf, KageError> {
    Ok(records_dir()?.join(format!("{}.json", kid.to_base64url_nopad())))
}

fn load_env_record(kid: Kid) -> Result<EnvRecord, KageError> {
    let path = record_path(kid)?;
    let bytes = fs::read(&path).map_err(|_| KageError::Daemon {
        code: daemon_codes::KEY_NOT_FOUND,
        message: "KID not found".into(),
    })?;
    Ok(serde_json::from_slice(&bytes)?)
}

#[cfg(target_os = "linux")]
fn find_linux_helper() -> Result<std::path::PathBuf, KageError> {
    if let Ok(p) = std::env::var("KAGE_LINUX_HELPER_PATH") {
        return Ok(std::path::PathBuf::from(p));
    }
    let exe = std::env::current_exe().map_err(|e| KageError::Io(e))?;
    if let Some(dir) = exe.parent() {
        let candidate = dir.join("kage-linux-helper");
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    which::which("kage-linux-helper")
        .map_err(|e| KageError::InvalidInput(format!("kage-linux-helper not found: {e}")))
}

#[cfg(target_os = "linux")]
fn tpm_handle() -> String {
    std::env::var("KAGE_TPM_HANDLE").unwrap_or_else(|_| "0x81000001".to_string())
}

#[cfg(target_os = "linux")]
fn systemd_ask_password(prompt: &str) -> Result<String, KageError> {
    let out = std::process::Command::new("systemd-ask-password")
        .arg("--no-tty")
        .arg(prompt)
        .output()
        .map_err(|e| KageError::InvalidInput(format!("systemd-ask-password failed: {e}")))?;
    if !out.status.success() {
        return Err(KageError::Daemon {
            code: daemon_codes::AUTH_CANCELLED,
            message: "PIN prompt cancelled".into(),
        });
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

#[cfg(target_os = "linux")]
fn unwrap_k_env_tpm2(record: &EnvRecord) -> Result<Zeroizing<[u8; 32]>, KageError> {
    let helper = find_linux_helper()?;
    let handle = tpm_handle();
    let wrapped = BASE64.decode(record.wrapped_k_env_b64.trim())?;

    let mut cmd = std::process::Command::new(helper);
    cmd.arg("decrypt")
        .arg(&handle)
        .arg("--policy")
        .arg(match record.policy {
            Policy::None => "none",
            Policy::Presence => "presence",
            Policy::Strong => "strong",
        })
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    if matches!(record.policy, Policy::Presence | Policy::Strong) {
        let pin = match std::env::var("TPM_PIN") {
            Ok(p) => p,
            Err(_) => systemd_ask_password("Kage TPM PIN")?,
        };
        cmd.env("TPM_PIN", pin);
    }

    let mut child = cmd.spawn().map_err(|e| KageError::Io(e))?;
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        stdin.write_all(&wrapped)?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        let code = out.status.code().unwrap_or(4);
        let msg = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let mapped = match code {
            1 => daemon_codes::KEY_NOT_FOUND,
            2 => daemon_codes::AUTH_FAILED,
            3 => daemon_codes::AUTH_FAILED,
            _ => daemon_codes::CONFIG_ERROR,
        };
        return Err(KageError::Daemon {
            code: mapped,
            message: if msg.is_empty() {
                "TPM decrypt failed".into()
            } else {
                msg
            },
        });
    }
    if out.stdout.len() != 32 {
        return Err(KageError::Daemon {
            code: daemon_codes::CONFIG_ERROR,
            message: format!("invalid K_env length {}, expected 32", out.stdout.len()),
        });
    }
    let mut raw = [0u8; 32];
    raw.copy_from_slice(&out.stdout);
    Ok(Zeroizing::new(raw))
}

fn unwrap_k_env(record: &EnvRecord) -> Result<Zeroizing<[u8; 32]>, KageError> {
    // In tests we use devwrap everywhere so CI doesn't require a real TPM2.
    #[cfg(all(test, target_os = "linux"))]
    {
        devwrap::unwrap_k_env_software(&record.wrapped_k_env_b64)
    }
    #[cfg(all(not(test), target_os = "linux"))]
    {
        unwrap_k_env_tpm2(record)
    }
    #[cfg(not(target_os = "linux"))]
    {
        devwrap::unwrap_k_env_software(&record.wrapped_k_env_b64)
    }
}

fn get_k_wrap_for(
    kid: Kid,
    record: &EnvRecord,
    state: &mut DaemonState,
) -> Result<Zeroizing<[u8; 32]>, KageError> {
    let now = Instant::now();
    if let Some(entry) = state.cache.get(&kid) {
        if entry.expires_at.map(|t| now < t).unwrap_or(true) {
            return Ok(entry.k_wrap.clone());
        }
    }

    let k_env = unwrap_k_env(record)?;
    let mut k_env_arr = [0u8; 32];
    k_env_arr.copy_from_slice(&k_env[..]);
    let k_wrap = crypto::derive_k_wrap(&k_env_arr)?;

    match record.policy {
        Policy::None => {
            state.cache.insert(
                kid,
                CacheEntry {
                    k_wrap: k_wrap.clone(),
                    expires_at: None,
                },
            );
        }
        Policy::Presence => {
            state.cache.insert(
                kid,
                CacheEntry {
                    k_wrap: k_wrap.clone(),
                    expires_at: Some(now + Duration::from_secs(300)),
                },
            );
        }
        Policy::Strong => {
            // Default: no caching.
        }
    }

    Ok(k_wrap)
}

async fn handle_request(
    state: Arc<Mutex<DaemonState>>,
    req_line: &str,
) -> JsonRpcResponse<serde_json::Value> {
    let mut resp = JsonRpcResponse::<serde_json::Value> {
        jsonrpc: "2.0".into(),
        id: 0,
        result: None,
        error: None,
    };

    let req: JsonRpcRequest<serde_json::Value> = match serde_json::from_str(req_line.trim()) {
        Ok(r) => r,
        Err(e) => {
            resp.error = Some(JsonRpcError {
                code: daemon_codes::CONFIG_ERROR,
                message: format!("invalid JSON-RPC request: {e}"),
                data: None,
            });
            return resp;
        }
    };
    resp.id = req.id;

    let method = req.method.as_str();
    match method {
        "Ping" => {
            resp.result = Some(serde_json::Value::String("kaged v2.0.0".into()));
            resp
        }
        "ResolveIdentity" => {
            #[derive(Deserialize)]
            struct Params {
                org: String,
                env: String,
            }
            match serde_json::from_value::<Params>(req.params) {
                Ok(p) => {
                    let kid = derive_kid(&p.org, &p.env);
                    match kid.to_bech32() {
                        Ok(s) => resp.result = Some(serde_json::Value::String(s)),
                        Err(e) => resp.error = Some(map_error(e)),
                    }
                }
                Err(e) => {
                    resp.error = Some(JsonRpcError {
                        code: daemon_codes::CONFIG_ERROR,
                        message: format!("invalid params: {e}"),
                        data: None,
                    })
                }
            }
            resp
        }
        "WrapKey" => {
            #[derive(Deserialize)]
            struct Params {
                kid_bech32: String,
                file_key_b64: String,
            }
            let p = match serde_json::from_value::<Params>(req.params) {
                Ok(v) => v,
                Err(e) => {
                    resp.error = Some(JsonRpcError {
                        code: daemon_codes::CONFIG_ERROR,
                        message: format!("invalid params: {e}"),
                        data: None,
                    });
                    return resp;
                }
            };
            let kid = match Kid::from_bech32(&p.kid_bech32) {
                Ok(k) => k,
                Err(e) => {
                    resp.error = Some(map_error(e));
                    return resp;
                }
            };
            let file_key = match BASE64.decode(p.file_key_b64.trim()) {
                Ok(v) => v,
                Err(e) => {
                    resp.error = Some(JsonRpcError {
                        code: daemon_codes::CONFIG_ERROR,
                        message: format!("invalid base64: {e}"),
                        data: None,
                    });
                    return resp;
                }
            };
            let record = match load_env_record(kid) {
                Ok(r) => r,
                Err(e) => {
                    resp.error = Some(map_error(e));
                    return resp;
                }
            };
            let mut guard = state.lock().await;
            let k_wrap = match get_k_wrap_for(kid, &record, &mut guard) {
                Ok(k) => k,
                Err(e) => {
                    resp.error = Some(map_error(e));
                    return resp;
                }
            };
            let mut k_wrap_arr = [0u8; 32];
            k_wrap_arr.copy_from_slice(&k_wrap[..]);
            match crypto::wrap_file_key(&k_wrap_arr, kid, &file_key) {
                Ok((_kid, nonce, ct)) => {
                    let stanza = KageStanza {
                        kid_bech32: record.kid_bech32,
                        nonce_b64: BASE64.encode(nonce),
                        payload_b64: BASE64.encode(ct),
                    };
                    resp.result = Some(serde_json::to_value(stanza).unwrap());
                }
                Err(e) => resp.error = Some(map_error(e)),
            }
            resp
        }
        "UnwrapKey" => {
            #[derive(Deserialize)]
            struct Params {
                stanza: KageStanza,
            }
            let p = match serde_json::from_value::<Params>(req.params) {
                Ok(v) => v,
                Err(e) => {
                    resp.error = Some(JsonRpcError {
                        code: daemon_codes::CONFIG_ERROR,
                        message: format!("invalid params: {e}"),
                        data: None,
                    });
                    return resp;
                }
            };
            let kid = match p.stanza.kid() {
                Ok(k) => k,
                Err(e) => {
                    resp.error = Some(map_error(e));
                    return resp;
                }
            };
            let nonce = match p.stanza.nonce() {
                Ok(n) => n,
                Err(e) => {
                    resp.error = Some(map_error(e));
                    return resp;
                }
            };
            let payload = match p.stanza.payload() {
                Ok(v) => v,
                Err(e) => {
                    resp.error = Some(map_error(e));
                    return resp;
                }
            };
            let record = match load_env_record(kid) {
                Ok(r) => r,
                Err(e) => {
                    resp.error = Some(map_error(e));
                    return resp;
                }
            };
            let mut guard = state.lock().await;
            let k_wrap = match get_k_wrap_for(kid, &record, &mut guard) {
                Ok(k) => k,
                Err(e) => {
                    resp.error = Some(map_error(e));
                    return resp;
                }
            };
            let mut k_wrap_arr = [0u8; 32];
            k_wrap_arr.copy_from_slice(&k_wrap[..]);
            match crypto::unwrap_file_key(&k_wrap_arr, kid, &nonce, &payload) {
                Ok(pt) => resp.result = Some(serde_json::Value::String(BASE64.encode(pt))),
                Err(e) => resp.error = Some(map_error(e)),
            }
            resp
        }
        "Unlock" => {
            #[derive(Deserialize)]
            struct Params {
                kid_bech32: String,
                duration_seconds: u32,
            }
            let p = match serde_json::from_value::<Params>(req.params) {
                Ok(v) => v,
                Err(e) => {
                    resp.error = Some(JsonRpcError {
                        code: daemon_codes::CONFIG_ERROR,
                        message: format!("invalid params: {e}"),
                        data: None,
                    });
                    return resp;
                }
            };
            let kid = match Kid::from_bech32(&p.kid_bech32) {
                Ok(k) => k,
                Err(e) => {
                    resp.error = Some(map_error(e));
                    return resp;
                }
            };
            let record = match load_env_record(kid) {
                Ok(r) => r,
                Err(e) => {
                    resp.error = Some(map_error(e));
                    return resp;
                }
            };

            let mut guard = state.lock().await;
            let duration = p.duration_seconds.min(300);
            let k_env = match unwrap_k_env(&record) {
                Ok(k) => k,
                Err(e) => {
                    resp.error = Some(map_error(e));
                    return resp;
                }
            };
            let mut k_env_arr = [0u8; 32];
            k_env_arr.copy_from_slice(&k_env[..]);
            let k_wrap = match crypto::derive_k_wrap(&k_env_arr) {
                Ok(k) => k,
                Err(e) => {
                    resp.error = Some(map_error(e));
                    return resp;
                }
            };

            let expires_at = Instant::now() + Duration::from_secs(duration as u64);
            guard.cache.insert(
                kid,
                CacheEntry {
                    k_wrap,
                    expires_at: Some(expires_at),
                },
            );
            resp.result = Some(serde_json::Value::Bool(true));
            resp
        }
        _ => {
            resp.error = Some(JsonRpcError {
                code: daemon_codes::CONFIG_ERROR,
                message: format!("unknown method: {}", req.method),
                data: None,
            });
            resp
        }
    }
}

fn map_error(e: KageError) -> JsonRpcError {
    match e {
        KageError::Daemon { code, message } => JsonRpcError {
            code,
            message,
            data: None,
        },
        other => JsonRpcError {
            code: daemon_codes::CONFIG_ERROR,
            message: other.to_string(),
            data: None,
        },
    }
}

#[cfg(target_os = "linux")]
fn enforce_peer_uid(stream: &UnixStream) -> anyhow::Result<()> {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    let mut ucred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut ucred as *mut _ as *mut _,
            &mut len as *mut _,
        )
    };
    if rc != 0 {
        anyhow::bail!("getsockopt(SO_PEERCRED) failed");
    }
    let uid = unsafe { libc::getuid() } as u32;
    if ucred.uid != uid {
        anyhow::bail!("peer uid {} does not match daemon uid {}", ucred.uid, uid);
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn enforce_peer_uid(_stream: &UnixStream) -> anyhow::Result<()> {
    Ok(())
}

async fn handle_client(state: Arc<Mutex<DaemonState>>, stream: UnixStream) -> anyhow::Result<()> {
    enforce_peer_uid(&stream)?;

    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            return Ok(());
        }
        let resp = handle_request(state.clone(), &line).await;
        let mut out = serde_json::to_vec(&resp)?;
        out.push(b'\n');
        write_half.write_all(&out).await?;
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let socket_path = match args.socket {
        Some(p) => p,
        None => kage_comm::transport::UnixJsonRpcTransport::default_socket_path()
            .context("could not resolve default socket path")?,
    };

    // Ensure ~/.kage exists.
    if let Some(parent) = socket_path.parent() {
        fs::create_dir_all(parent)?;
    }

    if socket_path.exists() {
        fs::remove_file(&socket_path).ok();
    }

    let listener = UnixListener::bind(&socket_path)?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;

    let state = Arc::new(Mutex::new(DaemonState::default()));
    eprintln!("kaged listening on {}", socket_path.display());

    loop {
        tokio::select! {
            res = listener.accept() => {
                let (stream, _addr) = res?;
                let state = state.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_client(state, stream).await {
                        eprintln!("client error: {e:#}");
                    }
                });
            }
            _ = tokio::signal::ctrl_c() => {
                eprintln!("shutdown");
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    async fn call_with_state(
        state: Arc<Mutex<DaemonState>>,
        req: serde_json::Value,
    ) -> JsonRpcResponse<serde_json::Value> {
        let line = serde_json::to_string(&req).unwrap();
        handle_request(state, &line).await
    }

    async fn call(req: serde_json::Value) -> JsonRpcResponse<serde_json::Value> {
        call_with_state(Arc::new(Mutex::new(DaemonState::default())), req).await
    }

    #[tokio::test]
    async fn jsonrpc_ping_ok() {
        let resp = call(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "Ping",
            "params": {}
        }))
        .await;
        assert!(resp.error.is_none());
        assert_eq!(
            resp.result.unwrap(),
            serde_json::Value::String("kaged v2.0.0".into())
        );
    }

    #[tokio::test]
    async fn jsonrpc_unknown_method_is_error() {
        let resp = call(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "Nope",
            "params": {}
        }))
        .await;
        assert!(resp.result.is_none());
        assert_eq!(resp.error.unwrap().code, daemon_codes::CONFIG_ERROR);
    }

    #[tokio::test]
    async fn jsonrpc_resolve_identity_ok() {
        let resp = call(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "ResolveIdentity",
            "params": { "org": "acme", "env": "dev" }
        }))
        .await;
        assert!(resp.error.is_none());
        let kid_bech32 = resp.result.unwrap().as_str().unwrap().to_string();
        assert!(kid_bech32.starts_with("age1kage"));
    }

    #[test]
    fn jsonrpc_wrap_missing_record_is_key_not_found() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("KAGE_V2_DIR", dir.path());

        let kid_bech32 = derive_kid("acme", "dev").to_bech32().unwrap();
        let file_key_b64 = BASE64.encode([9u8; 16]);

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let resp = runtime.block_on(call(serde_json::json!({
          "jsonrpc": "2.0",
          "id": 2,
          "method": "WrapKey",
          "params": { "kid_bech32": kid_bech32, "file_key_b64": file_key_b64 }
        })));

        assert!(resp.result.is_none());
        assert_eq!(resp.error.unwrap().code, daemon_codes::KEY_NOT_FOUND);

        std::env::remove_var("KAGE_V2_DIR");
    }

    #[test]
    fn jsonrpc_wrap_unwrap_roundtrip_devwrap() {
        let _guard = ENV_LOCK.lock().unwrap();

        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("KAGE_V2_DIR", dir.path());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let kid = derive_kid("acme", "dev");
        let kid_bech32 = kid.to_bech32().unwrap();

        let mut k_env = [0u8; 32];
        k_env[0] = 42;
        let wrapped_k_env_b64 = devwrap::wrap_k_env_software(&k_env).unwrap();

        let record = EnvRecord {
            kid_bech32: kid_bech32.clone(),
            policy: Policy::None,
            wrapped_k_env_b64,
        };

        let rp = record_path(kid).unwrap();
        fs::create_dir_all(rp.parent().unwrap()).unwrap();
        fs::write(&rp, serde_json::to_vec_pretty(&record).unwrap()).unwrap();
        fs::set_permissions(&rp, fs::Permissions::from_mode(0o600)).unwrap();

        let file_key = [9u8; 16];
        let file_key_b64 = BASE64.encode(file_key);

        let wrap_resp = runtime.block_on(call(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "WrapKey",
            "params": { "kid_bech32": kid_bech32, "file_key_b64": file_key_b64 }
        })));
        assert!(wrap_resp.error.is_none());
        let stanza: KageStanza = serde_json::from_value(wrap_resp.result.unwrap()).unwrap();

        let unwrap_resp = runtime.block_on(call(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "UnwrapKey",
            "params": { "stanza": stanza }
        })));
        assert!(unwrap_resp.error.is_none());
        let got_b64 = unwrap_resp.result.unwrap().as_str().unwrap().to_string();
        let got = BASE64.decode(got_b64).unwrap();
        assert_eq!(got, file_key);

        std::env::remove_var("KAGE_V2_DIR");
    }

    #[test]
    fn strong_policy_does_not_cache_without_unlock() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("KAGE_V2_DIR", dir.path());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let kid = derive_kid("acme", "prod");
        let kid_bech32 = kid.to_bech32().unwrap();

        let mut k_env = [0u8; 32];
        k_env[0] = 7;
        let wrapped_k_env_b64 = devwrap::wrap_k_env_software(&k_env).unwrap();

        let record = EnvRecord {
            kid_bech32: kid_bech32.clone(),
            policy: Policy::Strong,
            wrapped_k_env_b64,
        };
        let rp = record_path(kid).unwrap();
        fs::create_dir_all(rp.parent().unwrap()).unwrap();
        fs::write(&rp, serde_json::to_vec_pretty(&record).unwrap()).unwrap();
        fs::set_permissions(&rp, fs::Permissions::from_mode(0o600)).unwrap();

        let state = Arc::new(Mutex::new(DaemonState::default()));

        let file_key = [9u8; 16];
        let file_key_b64 = BASE64.encode(file_key);
        let resp = runtime.block_on(call_with_state(
            state.clone(),
            serde_json::json!({
              "jsonrpc": "2.0",
              "id": 1,
              "method": "WrapKey",
              "params": { "kid_bech32": kid_bech32, "file_key_b64": file_key_b64 }
            }),
        ));
        assert!(resp.error.is_none());

        runtime.block_on(async {
            let guard = state.lock().await;
            assert!(
                !guard.cache.contains_key(&kid),
                "strong policy must not populate the cache by default"
            );
        });

        std::env::remove_var("KAGE_V2_DIR");
    }

    #[test]
    fn unlock_caches_k_wrap_for_strong_policy() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("KAGE_V2_DIR", dir.path());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let kid = derive_kid("acme", "prod");
        let kid_bech32 = kid.to_bech32().unwrap();

        let mut k_env = [0u8; 32];
        k_env[0] = 9;
        let wrapped_k_env_b64 = devwrap::wrap_k_env_software(&k_env).unwrap();

        let record = EnvRecord {
            kid_bech32: kid_bech32.clone(),
            policy: Policy::Strong,
            wrapped_k_env_b64,
        };
        let rp = record_path(kid).unwrap();
        fs::create_dir_all(rp.parent().unwrap()).unwrap();
        fs::write(&rp, serde_json::to_vec_pretty(&record).unwrap()).unwrap();
        fs::set_permissions(&rp, fs::Permissions::from_mode(0o600)).unwrap();

        let state = Arc::new(Mutex::new(DaemonState::default()));

        let resp = runtime.block_on(call_with_state(
            state.clone(),
            serde_json::json!({
              "jsonrpc": "2.0",
              "id": 1,
              "method": "Unlock",
              "params": { "kid_bech32": kid_bech32, "duration_seconds": 9999 }
            }),
        ));
        assert!(resp.error.is_none());

        runtime.block_on(async {
            let guard = state.lock().await;
            let entry = guard.cache.get(&kid).expect("unlock should populate cache");
            let expires_at = entry.expires_at.expect("unlock cache must expire");
            assert!(
                expires_at <= Instant::now() + Duration::from_secs(300),
                "unlock duration must be capped to 300s"
            );
        });

        std::env::remove_var("KAGE_V2_DIR");
    }

    #[test]
    fn presence_policy_populates_cache_with_ttl() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("KAGE_V2_DIR", dir.path());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let kid = derive_kid("acme", "dev");
        let kid_bech32 = kid.to_bech32().unwrap();

        let mut k_env = [0u8; 32];
        k_env[0] = 1;
        let wrapped_k_env_b64 = devwrap::wrap_k_env_software(&k_env).unwrap();

        let record = EnvRecord {
            kid_bech32: kid_bech32.clone(),
            policy: Policy::Presence,
            wrapped_k_env_b64,
        };
        let rp = record_path(kid).unwrap();
        fs::create_dir_all(rp.parent().unwrap()).unwrap();
        fs::write(&rp, serde_json::to_vec_pretty(&record).unwrap()).unwrap();
        fs::set_permissions(&rp, fs::Permissions::from_mode(0o600)).unwrap();

        let state = Arc::new(Mutex::new(DaemonState::default()));

        let file_key = [9u8; 16];
        let file_key_b64 = BASE64.encode(file_key);
        let resp = runtime.block_on(call_with_state(
            state.clone(),
            serde_json::json!({
              "jsonrpc": "2.0",
              "id": 1,
              "method": "WrapKey",
              "params": { "kid_bech32": kid_bech32, "file_key_b64": file_key_b64 }
            }),
        ));
        assert!(resp.error.is_none());

        runtime.block_on(async {
            let guard = state.lock().await;
            let entry = guard
                .cache
                .get(&kid)
                .expect("presence policy should populate cache");
            assert!(entry.expires_at.is_some(), "presence cache should expire");
        });

        std::env::remove_var("KAGE_V2_DIR");
    }

    #[test]
    fn none_policy_populates_cache_without_expiry() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("KAGE_V2_DIR", dir.path());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let kid = derive_kid("acme", "dev");
        let kid_bech32 = kid.to_bech32().unwrap();

        let mut k_env = [0u8; 32];
        k_env[0] = 2;
        let wrapped_k_env_b64 = devwrap::wrap_k_env_software(&k_env).unwrap();

        let record = EnvRecord {
            kid_bech32: kid_bech32.clone(),
            policy: Policy::None,
            wrapped_k_env_b64,
        };
        let rp = record_path(kid).unwrap();
        fs::create_dir_all(rp.parent().unwrap()).unwrap();
        fs::write(&rp, serde_json::to_vec_pretty(&record).unwrap()).unwrap();
        fs::set_permissions(&rp, fs::Permissions::from_mode(0o600)).unwrap();

        let state = Arc::new(Mutex::new(DaemonState::default()));

        let file_key = [9u8; 16];
        let file_key_b64 = BASE64.encode(file_key);
        let resp = runtime.block_on(call_with_state(
            state.clone(),
            serde_json::json!({
              "jsonrpc": "2.0",
              "id": 1,
              "method": "WrapKey",
              "params": { "kid_bech32": kid_bech32, "file_key_b64": file_key_b64 }
            }),
        ));
        assert!(resp.error.is_none());

        runtime.block_on(async {
            let guard = state.lock().await;
            let entry = guard
                .cache
                .get(&kid)
                .expect("none policy should populate cache");
            assert!(
                entry.expires_at.is_none(),
                "none policy cache should not expire"
            );
        });

        std::env::remove_var("KAGE_V2_DIR");
    }
}
