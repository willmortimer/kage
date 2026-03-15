mod age_adapter;
mod artifact_adapter;
mod assert_adapter;
mod git_sign_adapter;
mod runtime_adapter;
mod sign_adapter;
mod signing_helpers;
mod state;

use age_adapter::AgeAdapter;
use anyhow::Context;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use clap::Parser;
use kage_comm::crypto;
use kage_comm::devwrap;
use kage_comm::error::{daemon_codes, KageError};
use kage_comm::ipc::{JsonRpcError, JsonRpcRequest, JsonRpcResponse, KageStanza};
use kage_comm::kid::{derive_kid, Kid};
use kage_types::adapter::AdapterId;
use kage_types::audit::{AuditEvent, AuditOutcome, AUDIT_SCHEMA_VERSION};
use kage_types::capability::Capability;
use kage_types::envelope::{RequestEnvelope, ResponseEnvelope};
use kage_types::scope::AuthoritativeScope;
use serde::{Deserialize, Serialize};
use state::{CacheEntry, DaemonState};
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
pub(crate) enum Policy {
    None,
    Presence,
    Strong,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct EnvRecord {
    pub kid_bech32: String,
    pub policy: Policy,
    pub wrapped_k_env_b64: String,
}

fn records_dir() -> Result<PathBuf, KageError> {
    Ok(devwrap::v2_dir()?.join("records"))
}

fn record_path(kid: Kid) -> Result<PathBuf, KageError> {
    Ok(records_dir()?.join(format!("{}.json", kid.to_base64url_nopad())))
}

pub(crate) fn load_env_record(kid: Kid) -> Result<EnvRecord, KageError> {
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
    let exe = std::env::current_exe().map_err(KageError::Io)?;
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

    let mut child = cmd.spawn().map_err(KageError::Io)?;
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

pub(crate) fn unwrap_k_env(record: &EnvRecord) -> Result<Zeroizing<[u8; 32]>, KageError> {
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

pub(crate) fn get_k_wrap_for(
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

fn now_iso8601() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn current_platform() -> String {
    if std::env::var("WSL_DISTRO_NAME").is_ok() {
        "wsl".to_string()
    } else if cfg!(target_os = "macos") {
        "macos".to_string()
    } else if cfg!(target_os = "windows") {
        "windows".to_string()
    } else {
        "linux".to_string()
    }
}

fn emit_audit(state: &DaemonState, event: AuditEvent) {
    if let Some(ref log) = state.audit_log {
        log.append_or_log(&event);
    }
}

fn audit_event_for_legacy(
    method: &str,
    kid_bech32: Option<&str>,
    outcome: AuditOutcome,
    error: Option<String>,
) -> AuditEvent {
    let (capability, operation) = match method {
        "WrapKey" => (Capability::WrapUnwrap, "wrap"),
        "UnwrapKey" => (Capability::WrapUnwrap, "unwrap"),
        "Unlock" => (Capability::SessionGrant, "session.create"),
        "Lock" => (Capability::SessionGrant, "session.revoke"),
        _ => (Capability::WrapUnwrap, method),
    };
    AuditEvent {
        schema_version: AUDIT_SCHEMA_VERSION,
        timestamp: now_iso8601(),
        session_id: None,
        adapter: AdapterId::new(AdapterId::AGE),
        capability,
        operation: operation.to_string(),
        scope: AuthoritativeScope {
            org: None,
            env: None,
            kid_bech32: kid_bech32.map(|s| s.to_string()),
        },
        outcome,
        platform: Some(current_platform()),
        advisory: None,
        error,
        duration_seconds: None,
        metadata: None,
    }
}

/// Try to extract kid_bech32 from dispatch params for audit scope enrichment.
fn extract_kid_from_params(params: &serde_json::Value) -> Option<String> {
    params["kid_bech32"].as_str().map(|s| s.to_string())
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
            resp.result = Some(serde_json::Value::String("kaged v3.0.0-alpha.1".into()));
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
            let kid_bech32_clone = p.kid_bech32.clone();
            let kid = match Kid::from_bech32(&p.kid_bech32) {
                Ok(k) => k,
                Err(e) => {
                    let guard = state.lock().await;
                    emit_audit(
                        &guard,
                        audit_event_for_legacy(
                            "WrapKey",
                            Some(&kid_bech32_clone),
                            AuditOutcome::Error,
                            Some(e.to_string()),
                        ),
                    );
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
                    let guard = state.lock().await;
                    emit_audit(
                        &guard,
                        audit_event_for_legacy(
                            "WrapKey",
                            Some(&kid_bech32_clone),
                            AuditOutcome::Error,
                            Some(e.to_string()),
                        ),
                    );
                    resp.error = Some(map_error(e));
                    return resp;
                }
            };
            let mut guard = state.lock().await;
            let k_wrap = match get_k_wrap_for(kid, &record, &mut guard) {
                Ok(k) => k,
                Err(e) => {
                    emit_audit(
                        &guard,
                        audit_event_for_legacy(
                            "WrapKey",
                            Some(&kid_bech32_clone),
                            AuditOutcome::Error,
                            Some(e.to_string()),
                        ),
                    );
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
                    emit_audit(
                        &guard,
                        audit_event_for_legacy(
                            "WrapKey",
                            Some(&kid_bech32_clone),
                            AuditOutcome::Success,
                            None,
                        ),
                    );
                    resp.result = Some(serde_json::to_value(stanza).unwrap());
                }
                Err(e) => {
                    emit_audit(
                        &guard,
                        audit_event_for_legacy(
                            "WrapKey",
                            Some(&kid_bech32_clone),
                            AuditOutcome::Error,
                            Some(e.to_string()),
                        ),
                    );
                    resp.error = Some(map_error(e));
                }
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
            let kid_bech32_clone = p.stanza.kid_bech32.clone();
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
                    emit_audit(
                        &guard,
                        audit_event_for_legacy(
                            "UnwrapKey",
                            Some(&kid_bech32_clone),
                            AuditOutcome::Error,
                            Some(e.to_string()),
                        ),
                    );
                    resp.error = Some(map_error(e));
                    return resp;
                }
            };
            let mut k_wrap_arr = [0u8; 32];
            k_wrap_arr.copy_from_slice(&k_wrap[..]);
            match crypto::unwrap_file_key(&k_wrap_arr, kid, &nonce, &payload) {
                Ok(pt) => {
                    emit_audit(
                        &guard,
                        audit_event_for_legacy(
                            "UnwrapKey",
                            Some(&kid_bech32_clone),
                            AuditOutcome::Success,
                            None,
                        ),
                    );
                    resp.result = Some(serde_json::Value::String(BASE64.encode(pt)));
                }
                Err(e) => {
                    emit_audit(
                        &guard,
                        audit_event_for_legacy(
                            "UnwrapKey",
                            Some(&kid_bech32_clone),
                            AuditOutcome::Error,
                            Some(e.to_string()),
                        ),
                    );
                    resp.error = Some(map_error(e));
                }
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
            let kid_bech32_clone = p.kid_bech32.clone();
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
                    emit_audit(
                        &guard,
                        audit_event_for_legacy(
                            "Unlock",
                            Some(&kid_bech32_clone),
                            AuditOutcome::Error,
                            Some(e.to_string()),
                        ),
                    );
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
            {
                let mut event = audit_event_for_legacy(
                    "Unlock",
                    Some(&kid_bech32_clone),
                    AuditOutcome::Success,
                    None,
                );
                event.duration_seconds = Some(duration);
                emit_audit(&guard, event);
            }
            resp.result = Some(serde_json::Value::Bool(true));
            resp
        }
        "Lock" => {
            #[derive(Deserialize)]
            struct Params {
                kid_bech32: String,
            }
            let p: Params = match serde_json::from_value(req.params) {
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
            let kid_bech32_clone = p.kid_bech32.clone();
            let kid = match Kid::from_bech32(&p.kid_bech32) {
                Ok(k) => k,
                Err(e) => {
                    resp.error = Some(map_error(e));
                    return resp;
                }
            };

            let mut guard = state.lock().await;
            let was_cached = guard.cache.remove(&kid).is_some();
            emit_audit(
                &guard,
                audit_event_for_legacy(
                    "Lock",
                    Some(&kid_bech32_clone),
                    AuditOutcome::Success,
                    None,
                ),
            );
            resp.result = Some(serde_json::json!({ "was_cached": was_cached }));
            resp
        }
        "Dispatch" => {
            let envelope: RequestEnvelope = match serde_json::from_value(req.params) {
                Ok(e) => e,
                Err(e) => {
                    resp.error = Some(JsonRpcError {
                        code: daemon_codes::CONFIG_ERROR,
                        message: format!("invalid Dispatch envelope: {e}"),
                        data: None,
                    });
                    return resp;
                }
            };

            let guard = state.lock().await;
            let adapter = match guard.registry.get(&envelope.adapter) {
                Some(a) => Arc::clone(a),
                None => {
                    resp.error = Some(JsonRpcError {
                        code: daemon_codes::CONFIG_ERROR,
                        message: format!("unknown adapter: {}", envelope.adapter),
                        data: None,
                    });
                    return resp;
                }
            };
            drop(guard);

            let result = adapter
                .dispatch(
                    envelope.capability.clone(),
                    &envelope.operation,
                    envelope.params.clone(),
                )
                .await;

            let kid_for_scope = extract_kid_from_params(&envelope.params);
            let audit_scope = AuthoritativeScope {
                org: None,
                env: None,
                kid_bech32: kid_for_scope,
            };

            let guard = state.lock().await;
            match &result {
                Ok(value) => {
                    emit_audit(
                        &guard,
                        AuditEvent {
                            schema_version: AUDIT_SCHEMA_VERSION,
                            timestamp: now_iso8601(),
                            session_id: None,
                            adapter: envelope.adapter.clone(),
                            capability: envelope.capability.clone(),
                            operation: envelope.operation.clone(),
                            scope: audit_scope.clone(),
                            outcome: AuditOutcome::Success,
                            platform: Some(current_platform()),
                            advisory: envelope.advisory.clone(),
                            error: None,
                            duration_seconds: None,
                            metadata: None,
                        },
                    );
                    let response_envelope = ResponseEnvelope {
                        version: 1,
                        request_id: None,
                        result: Some(value.clone()),
                        error: None,
                    };
                    resp.result = Some(serde_json::to_value(response_envelope).unwrap());
                }
                Err(e) => {
                    emit_audit(
                        &guard,
                        AuditEvent {
                            schema_version: AUDIT_SCHEMA_VERSION,
                            timestamp: now_iso8601(),
                            session_id: None,
                            adapter: envelope.adapter.clone(),
                            capability: envelope.capability.clone(),
                            operation: envelope.operation.clone(),
                            scope: audit_scope,
                            outcome: AuditOutcome::Error,
                            platform: Some(current_platform()),
                            advisory: envelope.advisory.clone(),
                            error: Some(e.clone()),
                            duration_seconds: None,
                            metadata: None,
                        },
                    );
                    resp.error = Some(JsonRpcError {
                        code: daemon_codes::CONFIG_ERROR,
                        message: e.clone(),
                        data: None,
                    });
                }
            }
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

pub(crate) fn map_error(e: KageError) -> JsonRpcError {
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

    if let Some(parent) = socket_path.parent() {
        fs::create_dir_all(parent)?;
    }

    if socket_path.exists() {
        fs::remove_file(&socket_path).ok();
    }

    let listener = UnixListener::bind(&socket_path)?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;

    let state = Arc::new(Mutex::new(DaemonState::default()));

    // Register adapters
    {
        let age_adapter = AgeAdapter::new(state.clone());
        let runtime_adapter = runtime_adapter::RuntimeAdapter::new(state.clone());
        let sign_adapter = sign_adapter::SignAdapter::new(state.clone());
        let git_sign_adapter = git_sign_adapter::GitSignAdapter::new(state.clone());
        let assert_adapter = assert_adapter::AssertAdapter::new(state.clone());
        let artifact_adapter = artifact_adapter::ArtifactAdapter::new(state.clone());
        let mut guard = state.lock().await;
        guard.registry.register(Arc::new(age_adapter));
        guard.registry.register(Arc::new(runtime_adapter));
        guard.registry.register(Arc::new(sign_adapter));
        guard.registry.register(Arc::new(git_sign_adapter));
        guard.registry.register(Arc::new(assert_adapter));
        guard.registry.register(Arc::new(artifact_adapter));
    }

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
    use kage_audit::AuditLog;
    use std::collections::HashMap;
    use std::os::unix::fs::PermissionsExt;

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn test_state() -> Arc<Mutex<DaemonState>> {
        Arc::new(Mutex::new(DaemonState {
            cache: HashMap::new(),
            registry: kage_comm::registry::AdapterRegistry::new(),
            audit_log: None,
        }))
    }

    fn test_state_with_audit(audit_path: PathBuf) -> Arc<Mutex<DaemonState>> {
        let state = Arc::new(Mutex::new(DaemonState {
            cache: HashMap::new(),
            registry: kage_comm::registry::AdapterRegistry::new(),
            audit_log: Some(AuditLog::new(audit_path)),
        }));
        // Register adapters — use try_lock since we just created the mutex
        let age_adapter = AgeAdapter::new(state.clone());
        let runtime_adapter = runtime_adapter::RuntimeAdapter::new(state.clone());
        let sign_adapter = sign_adapter::SignAdapter::new(state.clone());
        let git_sign_adapter = git_sign_adapter::GitSignAdapter::new(state.clone());
        let assert_adapter = assert_adapter::AssertAdapter::new(state.clone());
        let artifact_adapter = artifact_adapter::ArtifactAdapter::new(state.clone());
        let mut guard = state.try_lock().unwrap();
        guard.registry.register(Arc::new(age_adapter));
        guard.registry.register(Arc::new(runtime_adapter));
        guard.registry.register(Arc::new(sign_adapter));
        guard.registry.register(Arc::new(git_sign_adapter));
        guard.registry.register(Arc::new(assert_adapter));
        guard.registry.register(Arc::new(artifact_adapter));
        drop(guard);
        state
    }

    async fn call_with_state(
        state: Arc<Mutex<DaemonState>>,
        req: serde_json::Value,
    ) -> JsonRpcResponse<serde_json::Value> {
        let line = serde_json::to_string(&req).unwrap();
        handle_request(state, &line).await
    }

    async fn call(req: serde_json::Value) -> JsonRpcResponse<serde_json::Value> {
        call_with_state(test_state(), req).await
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
            serde_json::Value::String("kaged v3.0.0-alpha.1".into())
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

        let state = test_state();

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

        let state = test_state();

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

        let state = test_state();

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

        let state = test_state();

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

    #[test]
    fn dispatch_wrap_unwrap_roundtrip() {
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
        k_env[0] = 55;
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

        let audit_path = dir.path().join("audit.ndjson");
        let state = test_state_with_audit(audit_path.clone());

        let file_key = [9u8; 16];
        let file_key_b64 = BASE64.encode(file_key);

        // Dispatch wrap
        let wrap_resp = runtime.block_on(call_with_state(
            state.clone(),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 10,
                "method": "Dispatch",
                "params": {
                    "version": 1,
                    "adapter": "age",
                    "capability": "wrap_unwrap",
                    "operation": "wrap",
                    "params": {
                        "kid_bech32": kid_bech32,
                        "file_key_b64": file_key_b64
                    }
                }
            }),
        ));
        assert!(
            wrap_resp.error.is_none(),
            "dispatch wrap failed: {:?}",
            wrap_resp.error
        );
        let envelope: ResponseEnvelope =
            serde_json::from_value(wrap_resp.result.unwrap()).unwrap();
        let stanza: KageStanza = serde_json::from_value(envelope.result.unwrap()).unwrap();

        // Dispatch unwrap
        let unwrap_resp = runtime.block_on(call_with_state(
            state.clone(),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 11,
                "method": "Dispatch",
                "params": {
                    "version": 1,
                    "adapter": "age",
                    "capability": "wrap_unwrap",
                    "operation": "unwrap",
                    "params": {
                        "stanza": stanza
                    }
                }
            }),
        ));
        assert!(
            unwrap_resp.error.is_none(),
            "dispatch unwrap failed: {:?}",
            unwrap_resp.error
        );
        let envelope: ResponseEnvelope =
            serde_json::from_value(unwrap_resp.result.unwrap()).unwrap();
        let got_b64 = envelope.result.unwrap().as_str().unwrap().to_string();
        let got = BASE64.decode(got_b64).unwrap();
        assert_eq!(got, file_key);

        // Verify audit log
        let audit_content = fs::read_to_string(&audit_path).unwrap();
        let lines: Vec<&str> = audit_content.trim().lines().collect();
        assert_eq!(lines.len(), 2, "expected 2 audit events (wrap + unwrap)");
        for line in &lines {
            let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(parsed["schema_version"], 2);
            assert_eq!(parsed["adapter"], "age");
            assert_eq!(parsed["outcome"], "success");
        }

        std::env::remove_var("KAGE_V2_DIR");
    }

    #[test]
    fn audit_log_written_for_legacy_wrap() {
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
        k_env[0] = 77;
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

        let audit_path = dir.path().join("audit.ndjson");
        let state = test_state_with_audit(audit_path.clone());

        let file_key_b64 = BASE64.encode([9u8; 16]);
        let resp = runtime.block_on(call_with_state(
            state,
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "WrapKey",
                "params": { "kid_bech32": kid_bech32, "file_key_b64": file_key_b64 }
            }),
        ));
        assert!(resp.error.is_none());

        let audit_content = fs::read_to_string(&audit_path).unwrap();
        let lines: Vec<&str> = audit_content.trim().lines().collect();
        assert_eq!(lines.len(), 1);
        let parsed: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(parsed["operation"], "wrap");
        assert_eq!(parsed["outcome"], "success");
        assert_eq!(parsed["kid_bech32"], kid_bech32);

        std::env::remove_var("KAGE_V2_DIR");
    }

    #[test]
    fn dispatch_runtime_encrypt_decrypt_roundtrip() {
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
        k_env[0] = 88;
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

        let audit_path = dir.path().join("audit.ndjson");
        let state = test_state_with_audit(audit_path.clone());

        // Encrypt a secret via dispatch
        let encrypt_resp = runtime.block_on(call_with_state(
            state.clone(),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 20,
                "method": "Dispatch",
                "params": {
                    "version": 1,
                    "adapter": "runtime",
                    "capability": "secret_release",
                    "operation": "encrypt",
                    "params": {
                        "org": "acme",
                        "env": "dev",
                        "name": "DB_PASSWORD",
                        "plaintext_b64": BASE64.encode(b"super-secret-123")
                    }
                }
            }),
        ));
        assert!(
            encrypt_resp.error.is_none(),
            "dispatch encrypt failed: {:?}",
            encrypt_resp.error
        );
        let envelope: kage_types::envelope::ResponseEnvelope =
            serde_json::from_value(encrypt_resp.result.unwrap()).unwrap();
        let ct_b64 = envelope.result.unwrap()["ciphertext_b64"]
            .as_str()
            .unwrap()
            .to_string();

        // Decrypt the secret via dispatch
        let decrypt_resp = runtime.block_on(call_with_state(
            state.clone(),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 21,
                "method": "Dispatch",
                "params": {
                    "version": 1,
                    "adapter": "runtime",
                    "capability": "secret_release",
                    "operation": "decrypt",
                    "params": {
                        "org": "acme",
                        "env": "dev",
                        "name": "DB_PASSWORD",
                        "ciphertext_b64": ct_b64
                    }
                }
            }),
        ));
        assert!(
            decrypt_resp.error.is_none(),
            "dispatch decrypt failed: {:?}",
            decrypt_resp.error
        );
        let envelope: kage_types::envelope::ResponseEnvelope =
            serde_json::from_value(decrypt_resp.result.unwrap()).unwrap();
        let pt_b64 = envelope.result.unwrap()["plaintext_b64"]
            .as_str()
            .unwrap()
            .to_string();
        let plaintext = BASE64.decode(pt_b64).unwrap();
        assert_eq!(plaintext, b"super-secret-123");

        // Verify audit log contains SecretRelease events
        let audit_content = fs::read_to_string(&audit_path).unwrap();
        let lines: Vec<&str> = audit_content.trim().lines().collect();
        assert_eq!(lines.len(), 2, "expected 2 audit events (encrypt + decrypt)");
        for line in &lines {
            let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(parsed["adapter"], "runtime");
            assert_eq!(parsed["capability"], "secret_release");
            assert_eq!(parsed["outcome"], "success");
        }

        std::env::remove_var("KAGE_V2_DIR");
    }

    #[test]
    fn dispatch_runtime_release_multiple_secrets() {
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
        k_env[0] = 99;
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

        let state = test_state_with_audit(dir.path().join("audit.ndjson"));

        // Encrypt two secrets
        let mut ciphertexts = HashMap::new();
        for (name, value) in [("API_KEY", "key-abc"), ("DB_URL", "postgres://localhost")] {
            let resp = runtime.block_on(call_with_state(
                state.clone(),
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 30,
                    "method": "Dispatch",
                    "params": {
                        "version": 1,
                        "adapter": "runtime",
                        "capability": "secret_release",
                        "operation": "encrypt",
                        "params": {
                            "org": "acme",
                            "env": "dev",
                            "name": name,
                            "plaintext_b64": BASE64.encode(value.as_bytes())
                        }
                    }
                }),
            ));
            assert!(resp.error.is_none());
            let envelope: kage_types::envelope::ResponseEnvelope =
                serde_json::from_value(resp.result.unwrap()).unwrap();
            let ct = envelope.result.unwrap()["ciphertext_b64"]
                .as_str()
                .unwrap()
                .to_string();
            ciphertexts.insert(name.to_string(), ct);
        }

        // Release both secrets at once
        let secrets: Vec<serde_json::Value> = ciphertexts
            .iter()
            .map(|(name, ct)| serde_json::json!({"name": name, "ciphertext_b64": ct}))
            .collect();
        let release_resp = runtime.block_on(call_with_state(
            state.clone(),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 31,
                "method": "Dispatch",
                "params": {
                    "version": 1,
                    "adapter": "runtime",
                    "capability": "secret_release",
                    "operation": "release",
                    "params": {
                        "org": "acme",
                        "env": "dev",
                        "secrets": secrets
                    }
                }
            }),
        ));
        assert!(
            release_resp.error.is_none(),
            "release failed: {:?}",
            release_resp.error
        );
        let envelope: kage_types::envelope::ResponseEnvelope =
            serde_json::from_value(release_resp.result.unwrap()).unwrap();
        let released: HashMap<String, String> =
            serde_json::from_value(envelope.result.unwrap()).unwrap();
        assert_eq!(released["API_KEY"], "key-abc");
        assert_eq!(released["DB_URL"], "postgres://localhost");

        std::env::remove_var("KAGE_V2_DIR");
    }

    // Helper to set up an env record and return kid_bech32
    fn setup_env_record(dir: &std::path::Path) -> String {
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

        // Also set HOME so signing_record can find ~/.kage/v2/signing/
        std::env::set_var("HOME", dir);

        kid_bech32
    }

    #[test]
    fn dispatch_sign_init_creates_record() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("KAGE_V2_DIR", dir.path());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let kid_bech32 = setup_env_record(dir.path());
        let state = test_state_with_audit(dir.path().join("audit.ndjson"));

        let resp = runtime.block_on(call_with_state(
            state,
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 40,
                "method": "Dispatch",
                "params": {
                    "version": 1,
                    "adapter": "sign",
                    "capability": "sign",
                    "operation": "init",
                    "params": {
                        "kid_bech32": kid_bech32
                    }
                }
            }),
        ));
        assert!(
            resp.error.is_none(),
            "dispatch sign init failed: {:?}",
            resp.error
        );
        let envelope: kage_types::envelope::ResponseEnvelope =
            serde_json::from_value(resp.result.unwrap()).unwrap();
        let result = envelope.result.unwrap();
        assert!(result["public_key_b64"].as_str().is_some());
        assert_eq!(result["algorithm"], "ed25519");

        std::env::remove_var("KAGE_V2_DIR");
    }

    #[test]
    fn dispatch_sign_init_rejects_duplicate() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("KAGE_V2_DIR", dir.path());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let kid_bech32 = setup_env_record(dir.path());
        let state = test_state_with_audit(dir.path().join("audit.ndjson"));

        let dispatch_params = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 41,
            "method": "Dispatch",
            "params": {
                "version": 1,
                "adapter": "sign",
                "capability": "sign",
                "operation": "init",
                "params": {
                    "kid_bech32": kid_bech32
                }
            }
        });

        // First init succeeds
        let resp = runtime.block_on(call_with_state(state.clone(), dispatch_params.clone()));
        assert!(resp.error.is_none());

        // Second init fails
        let resp = runtime.block_on(call_with_state(state, dispatch_params));
        assert!(resp.error.is_some(), "duplicate init should fail");
        assert!(resp
            .error
            .unwrap()
            .message
            .contains("already exists"));

        std::env::remove_var("KAGE_V2_DIR");
    }

    #[test]
    fn dispatch_sign_roundtrip() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("KAGE_V2_DIR", dir.path());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let kid_bech32 = setup_env_record(dir.path());
        let state = test_state_with_audit(dir.path().join("audit.ndjson"));

        // Init signing key
        let init_resp = runtime.block_on(call_with_state(
            state.clone(),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 50,
                "method": "Dispatch",
                "params": {
                    "version": 1,
                    "adapter": "sign",
                    "capability": "sign",
                    "operation": "init",
                    "params": { "kid_bech32": kid_bech32 }
                }
            }),
        ));
        assert!(init_resp.error.is_none());
        let init_envelope: kage_types::envelope::ResponseEnvelope =
            serde_json::from_value(init_resp.result.unwrap()).unwrap();
        let public_key_b64 = init_envelope.result.unwrap()["public_key_b64"]
            .as_str()
            .unwrap()
            .to_string();

        // Sign a message
        let message = b"test message for signing";
        let message_b64 = BASE64.encode(message);
        let sign_resp = runtime.block_on(call_with_state(
            state.clone(),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 51,
                "method": "Dispatch",
                "params": {
                    "version": 1,
                    "adapter": "sign",
                    "capability": "sign",
                    "operation": "sign",
                    "params": {
                        "kid_bech32": kid_bech32,
                        "message_b64": message_b64
                    }
                }
            }),
        ));
        assert!(
            sign_resp.error.is_none(),
            "dispatch sign failed: {:?}",
            sign_resp.error
        );
        let sign_envelope: kage_types::envelope::ResponseEnvelope =
            serde_json::from_value(sign_resp.result.unwrap()).unwrap();
        let sign_result = sign_envelope.result.unwrap();
        let signature_b64 = sign_result["signature_b64"].as_str().unwrap();
        assert_eq!(
            sign_result["public_key_b64"].as_str().unwrap(),
            public_key_b64
        );

        // Verify signature using ed25519-dalek in test
        let public_key_bytes = BASE64.decode(&public_key_b64).unwrap();
        let signature_bytes = BASE64.decode(signature_b64).unwrap();
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(
            public_key_bytes.as_slice().try_into().unwrap(),
        )
        .unwrap();
        let signature =
            ed25519_dalek::Signature::from_bytes(signature_bytes.as_slice().try_into().unwrap());
        use ed25519_dalek::Verifier;
        assert!(verifying_key.verify(message, &signature).is_ok());

        std::env::remove_var("KAGE_V2_DIR");
    }

    #[test]
    fn dispatch_sign_get_public_key() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("KAGE_V2_DIR", dir.path());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let kid_bech32 = setup_env_record(dir.path());
        let state = test_state_with_audit(dir.path().join("audit.ndjson"));

        // Init signing key
        let init_resp = runtime.block_on(call_with_state(
            state.clone(),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 60,
                "method": "Dispatch",
                "params": {
                    "version": 1,
                    "adapter": "sign",
                    "capability": "sign",
                    "operation": "init",
                    "params": { "kid_bech32": kid_bech32 }
                }
            }),
        ));
        assert!(init_resp.error.is_none());
        let init_envelope: kage_types::envelope::ResponseEnvelope =
            serde_json::from_value(init_resp.result.unwrap()).unwrap();
        let init_pubkey = init_envelope.result.unwrap()["public_key_b64"]
            .as_str()
            .unwrap()
            .to_string();

        // Get public key
        let get_resp = runtime.block_on(call_with_state(
            state,
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 61,
                "method": "Dispatch",
                "params": {
                    "version": 1,
                    "adapter": "sign",
                    "capability": "sign",
                    "operation": "get-public-key",
                    "params": { "kid_bech32": kid_bech32 }
                }
            }),
        ));
        assert!(
            get_resp.error.is_none(),
            "get-public-key failed: {:?}",
            get_resp.error
        );
        let get_envelope: kage_types::envelope::ResponseEnvelope =
            serde_json::from_value(get_resp.result.unwrap()).unwrap();
        let get_result = get_envelope.result.unwrap();
        assert_eq!(get_result["public_key_b64"].as_str().unwrap(), init_pubkey);
        assert_eq!(get_result["algorithm"], "ed25519");

        std::env::remove_var("KAGE_V2_DIR");
    }

    #[test]
    fn dispatch_sign_audit_events() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("KAGE_V2_DIR", dir.path());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let kid_bech32 = setup_env_record(dir.path());
        let audit_path = dir.path().join("audit.ndjson");
        let state = test_state_with_audit(audit_path.clone());

        // Init
        let resp = runtime.block_on(call_with_state(
            state.clone(),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 70,
                "method": "Dispatch",
                "params": {
                    "version": 1,
                    "adapter": "sign",
                    "capability": "sign",
                    "operation": "init",
                    "params": { "kid_bech32": kid_bech32 }
                }
            }),
        ));
        assert!(resp.error.is_none());

        // Sign
        let resp = runtime.block_on(call_with_state(
            state,
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 71,
                "method": "Dispatch",
                "params": {
                    "version": 1,
                    "adapter": "sign",
                    "capability": "sign",
                    "operation": "sign",
                    "params": {
                        "kid_bech32": kid_bech32,
                        "message_b64": BASE64.encode(b"audit test")
                    }
                }
            }),
        ));
        assert!(resp.error.is_none());

        // Check audit log
        let audit_content = fs::read_to_string(&audit_path).unwrap();
        let lines: Vec<&str> = audit_content.trim().lines().collect();
        assert_eq!(lines.len(), 2, "expected 2 audit events (init + sign)");

        let init_event: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(init_event["adapter"], "sign");
        assert_eq!(init_event["capability"], "sign");
        assert_eq!(init_event["operation"], "init");
        assert_eq!(init_event["outcome"], "success");

        let sign_event: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(sign_event["adapter"], "sign");
        assert_eq!(sign_event["capability"], "sign");
        assert_eq!(sign_event["operation"], "sign");
        assert_eq!(sign_event["outcome"], "success");

        std::env::remove_var("KAGE_V2_DIR");
    }

    // ----- Git signing tests (Step 6) -----

    #[test]
    fn dispatch_git_sign_commit() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("KAGE_V2_DIR", dir.path());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let kid_bech32 = setup_env_record(dir.path());
        let state = test_state_with_audit(dir.path().join("audit.ndjson"));

        // Init signing key
        let resp = runtime.block_on(call_with_state(
            state.clone(),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 100,
                "method": "Dispatch",
                "params": {
                    "version": 1,
                    "adapter": "sign",
                    "capability": "sign",
                    "operation": "init",
                    "params": { "kid_bech32": kid_bech32 }
                }
            }),
        ));
        assert!(resp.error.is_none(), "init failed: {:?}", resp.error);

        // Sign a commit
        let commit_payload = b"tree abc123\nparent def456\nauthor test\n\ntest commit";
        let resp = runtime.block_on(call_with_state(
            state,
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 101,
                "method": "Dispatch",
                "params": {
                    "version": 1,
                    "adapter": "git-sign",
                    "capability": "sign",
                    "operation": "sign-commit",
                    "params": {
                        "kid_bech32": kid_bech32,
                        "payload_b64": BASE64.encode(commit_payload)
                    }
                }
            }),
        ));
        assert!(resp.error.is_none(), "sign-commit failed: {:?}", resp.error);
        let envelope: kage_types::envelope::ResponseEnvelope =
            serde_json::from_value(resp.result.unwrap()).unwrap();
        let result = envelope.result.unwrap();
        let sig = result["signature_armored"].as_str().unwrap();
        assert!(sig.contains("-----BEGIN SSH SIGNATURE-----"));
        assert!(sig.contains("-----END SSH SIGNATURE-----"));

        std::env::remove_var("KAGE_V2_DIR");
    }

    #[test]
    fn dispatch_git_sign_tag() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("KAGE_V2_DIR", dir.path());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let kid_bech32 = setup_env_record(dir.path());
        let state = test_state_with_audit(dir.path().join("audit.ndjson"));

        // Init signing key
        let resp = runtime.block_on(call_with_state(
            state.clone(),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 110,
                "method": "Dispatch",
                "params": {
                    "version": 1,
                    "adapter": "sign",
                    "capability": "sign",
                    "operation": "init",
                    "params": { "kid_bech32": kid_bech32 }
                }
            }),
        ));
        assert!(resp.error.is_none());

        // Sign a tag
        let tag_payload = b"object abc123\ntype commit\ntag v1.0\ntagger test\n\nrelease v1.0";
        let resp = runtime.block_on(call_with_state(
            state,
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 111,
                "method": "Dispatch",
                "params": {
                    "version": 1,
                    "adapter": "git-sign",
                    "capability": "sign",
                    "operation": "sign-tag",
                    "params": {
                        "kid_bech32": kid_bech32,
                        "payload_b64": BASE64.encode(tag_payload)
                    }
                }
            }),
        ));
        assert!(resp.error.is_none(), "sign-tag failed: {:?}", resp.error);
        let envelope: kage_types::envelope::ResponseEnvelope =
            serde_json::from_value(resp.result.unwrap()).unwrap();
        let result = envelope.result.unwrap();
        let sig = result["signature_armored"].as_str().unwrap();
        assert!(sig.contains("-----BEGIN SSH SIGNATURE-----"));

        std::env::remove_var("KAGE_V2_DIR");
    }

    #[test]
    fn dispatch_git_get_ssh_pubkey() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("KAGE_V2_DIR", dir.path());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let kid_bech32 = setup_env_record(dir.path());
        let state = test_state_with_audit(dir.path().join("audit.ndjson"));

        // Init signing key
        let resp = runtime.block_on(call_with_state(
            state.clone(),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 120,
                "method": "Dispatch",
                "params": {
                    "version": 1,
                    "adapter": "sign",
                    "capability": "sign",
                    "operation": "init",
                    "params": { "kid_bech32": kid_bech32 }
                }
            }),
        ));
        assert!(resp.error.is_none());

        // Get SSH pubkey
        let resp = runtime.block_on(call_with_state(
            state,
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 121,
                "method": "Dispatch",
                "params": {
                    "version": 1,
                    "adapter": "git-sign",
                    "capability": "sign",
                    "operation": "get-ssh-pubkey",
                    "params": { "kid_bech32": kid_bech32 }
                }
            }),
        ));
        assert!(
            resp.error.is_none(),
            "get-ssh-pubkey failed: {:?}",
            resp.error
        );
        let envelope: kage_types::envelope::ResponseEnvelope =
            serde_json::from_value(resp.result.unwrap()).unwrap();
        let result = envelope.result.unwrap();
        let ssh_pubkey = result["ssh_pubkey"].as_str().unwrap();
        assert!(ssh_pubkey.starts_with("ssh-ed25519 "));
        assert!(ssh_pubkey.contains("kage:"));

        std::env::remove_var("KAGE_V2_DIR");
    }

    #[test]
    fn dispatch_git_sign_without_init_fails() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("KAGE_V2_DIR", dir.path());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let kid_bech32 = setup_env_record(dir.path());
        let state = test_state_with_audit(dir.path().join("audit.ndjson"));

        // Try to sign without initializing
        let resp = runtime.block_on(call_with_state(
            state,
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 130,
                "method": "Dispatch",
                "params": {
                    "version": 1,
                    "adapter": "git-sign",
                    "capability": "sign",
                    "operation": "sign-commit",
                    "params": {
                        "kid_bech32": kid_bech32,
                        "payload_b64": BASE64.encode(b"test")
                    }
                }
            }),
        ));
        // The dispatch should succeed at JSON-RPC level but return an error envelope
        assert!(resp.error.is_some(), "expected error without init");

        std::env::remove_var("KAGE_V2_DIR");
    }

    #[test]
    fn dispatch_git_sign_audit_events() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("KAGE_V2_DIR", dir.path());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let kid_bech32 = setup_env_record(dir.path());
        let audit_path = dir.path().join("audit.ndjson");
        let state = test_state_with_audit(audit_path.clone());

        // Init signing key
        let resp = runtime.block_on(call_with_state(
            state.clone(),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 140,
                "method": "Dispatch",
                "params": {
                    "version": 1,
                    "adapter": "sign",
                    "capability": "sign",
                    "operation": "init",
                    "params": { "kid_bech32": kid_bech32 }
                }
            }),
        ));
        assert!(resp.error.is_none());

        // Sign a commit via git-sign adapter
        let resp = runtime.block_on(call_with_state(
            state,
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 141,
                "method": "Dispatch",
                "params": {
                    "version": 1,
                    "adapter": "git-sign",
                    "capability": "sign",
                    "operation": "sign-commit",
                    "params": {
                        "kid_bech32": kid_bech32,
                        "payload_b64": BASE64.encode(b"audit test commit")
                    }
                }
            }),
        ));
        assert!(resp.error.is_none());

        // Check audit log
        let audit_content = fs::read_to_string(&audit_path).unwrap();
        let lines: Vec<&str> = audit_content.trim().lines().collect();
        assert!(
            lines.len() >= 2,
            "expected at least 2 audit events, got {}",
            lines.len()
        );

        // Find the git-sign event
        let git_sign_events: Vec<serde_json::Value> = lines
            .iter()
            .map(|l| serde_json::from_str(l).unwrap())
            .filter(|e: &serde_json::Value| e["adapter"] == "git-sign")
            .collect();
        assert_eq!(git_sign_events.len(), 1);
        assert_eq!(git_sign_events[0]["operation"], "sign-commit");
        assert_eq!(git_sign_events[0]["outcome"], "success");

        std::env::remove_var("KAGE_V2_DIR");
    }

    // ----- Assertion tests (Step 9) -----

    #[test]
    fn dispatch_assert_issue_returns_token() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("KAGE_V2_DIR", dir.path());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let kid_bech32 = setup_env_record(dir.path());
        let state = test_state_with_audit(dir.path().join("audit.ndjson"));

        // Init signing key
        let resp = runtime.block_on(call_with_state(
            state.clone(),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 200,
                "method": "Dispatch",
                "params": {
                    "version": 1,
                    "adapter": "sign",
                    "capability": "sign",
                    "operation": "init",
                    "params": { "kid_bech32": kid_bech32 }
                }
            }),
        ));
        assert!(resp.error.is_none());

        // Issue assertion
        let resp = runtime.block_on(call_with_state(
            state,
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 201,
                "method": "Dispatch",
                "params": {
                    "version": 1,
                    "adapter": "assert",
                    "capability": "assert",
                    "operation": "issue",
                    "params": {
                        "kid_bech32": kid_bech32,
                        "purpose": "admin",
                        "ttl_seconds": 300
                    }
                }
            }),
        ));
        assert!(
            resp.error.is_none(),
            "issue assertion failed: {:?}",
            resp.error
        );
        let envelope: kage_types::envelope::ResponseEnvelope =
            serde_json::from_value(resp.result.unwrap()).unwrap();
        let result = envelope.result.unwrap();
        let token = result["token"].as_str().unwrap();
        assert!(!token.is_empty());
        assert!(token.contains('.')); // claims.signature format
        assert!(result["expires_at"].as_str().is_some());

        std::env::remove_var("KAGE_V2_DIR");
    }

    #[test]
    fn dispatch_assert_verify_valid_token() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("KAGE_V2_DIR", dir.path());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let kid_bech32 = setup_env_record(dir.path());
        let state = test_state_with_audit(dir.path().join("audit.ndjson"));

        // Init signing key
        let resp = runtime.block_on(call_with_state(
            state.clone(),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 210,
                "method": "Dispatch",
                "params": {
                    "version": 1,
                    "adapter": "sign",
                    "capability": "sign",
                    "operation": "init",
                    "params": { "kid_bech32": kid_bech32 }
                }
            }),
        ));
        assert!(resp.error.is_none());

        // Issue assertion
        let resp = runtime.block_on(call_with_state(
            state.clone(),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 211,
                "method": "Dispatch",
                "params": {
                    "version": 1,
                    "adapter": "assert",
                    "capability": "assert",
                    "operation": "issue",
                    "params": {
                        "kid_bech32": kid_bech32,
                        "purpose": "deploy",
                        "ttl_seconds": 300
                    }
                }
            }),
        ));
        assert!(resp.error.is_none());
        let envelope: kage_types::envelope::ResponseEnvelope =
            serde_json::from_value(resp.result.unwrap()).unwrap();
        let token = envelope.result.unwrap()["token"]
            .as_str()
            .unwrap()
            .to_string();

        // Verify assertion
        let resp = runtime.block_on(call_with_state(
            state,
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 212,
                "method": "Dispatch",
                "params": {
                    "version": 1,
                    "adapter": "assert",
                    "capability": "assert",
                    "operation": "verify",
                    "params": {
                        "kid_bech32": kid_bech32,
                        "token": token
                    }
                }
            }),
        ));
        assert!(
            resp.error.is_none(),
            "verify assertion failed: {:?}",
            resp.error
        );
        let envelope: kage_types::envelope::ResponseEnvelope =
            serde_json::from_value(resp.result.unwrap()).unwrap();
        let result = envelope.result.unwrap();
        assert_eq!(result["valid"], true);
        assert!(result["claims"]["sub"].as_str().is_some());

        std::env::remove_var("KAGE_V2_DIR");
    }

    #[test]
    fn dispatch_assert_verify_expired_token() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("KAGE_V2_DIR", dir.path());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let kid_bech32 = setup_env_record(dir.path());
        let state = test_state_with_audit(dir.path().join("audit.ndjson"));

        // Init signing key
        let resp = runtime.block_on(call_with_state(
            state.clone(),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 220,
                "method": "Dispatch",
                "params": {
                    "version": 1,
                    "adapter": "sign",
                    "capability": "sign",
                    "operation": "init",
                    "params": { "kid_bech32": kid_bech32 }
                }
            }),
        ));
        assert!(resp.error.is_none());

        // Issue assertion with ttl=0 (immediate expiry)
        let resp = runtime.block_on(call_with_state(
            state.clone(),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 221,
                "method": "Dispatch",
                "params": {
                    "version": 1,
                    "adapter": "assert",
                    "capability": "assert",
                    "operation": "issue",
                    "params": {
                        "kid_bech32": kid_bech32,
                        "purpose": "admin",
                        "ttl_seconds": 0
                    }
                }
            }),
        ));
        assert!(resp.error.is_none());
        let envelope: kage_types::envelope::ResponseEnvelope =
            serde_json::from_value(resp.result.unwrap()).unwrap();
        let token = envelope.result.unwrap()["token"]
            .as_str()
            .unwrap()
            .to_string();

        // Small sleep to ensure expiry
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Verify should report invalid
        let resp = runtime.block_on(call_with_state(
            state,
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 222,
                "method": "Dispatch",
                "params": {
                    "version": 1,
                    "adapter": "assert",
                    "capability": "assert",
                    "operation": "verify",
                    "params": {
                        "kid_bech32": kid_bech32,
                        "token": token
                    }
                }
            }),
        ));
        assert!(resp.error.is_none());
        let envelope: kage_types::envelope::ResponseEnvelope =
            serde_json::from_value(resp.result.unwrap()).unwrap();
        let result = envelope.result.unwrap();
        assert_eq!(result["valid"], false);

        std::env::remove_var("KAGE_V2_DIR");
    }

    #[test]
    fn dispatch_assert_audit_events() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("KAGE_V2_DIR", dir.path());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let kid_bech32 = setup_env_record(dir.path());
        let audit_path = dir.path().join("audit.ndjson");
        let state = test_state_with_audit(audit_path.clone());

        // Init signing key
        let resp = runtime.block_on(call_with_state(
            state.clone(),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 230,
                "method": "Dispatch",
                "params": {
                    "version": 1,
                    "adapter": "sign",
                    "capability": "sign",
                    "operation": "init",
                    "params": { "kid_bech32": kid_bech32 }
                }
            }),
        ));
        assert!(resp.error.is_none());

        // Issue assertion
        let resp = runtime.block_on(call_with_state(
            state,
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 231,
                "method": "Dispatch",
                "params": {
                    "version": 1,
                    "adapter": "assert",
                    "capability": "assert",
                    "operation": "issue",
                    "params": {
                        "kid_bech32": kid_bech32,
                        "purpose": "admin",
                        "ttl_seconds": 300
                    }
                }
            }),
        ));
        assert!(resp.error.is_none());

        // Check audit log
        let audit_content = fs::read_to_string(&audit_path).unwrap();
        let lines: Vec<&str> = audit_content.trim().lines().collect();

        let assert_events: Vec<serde_json::Value> = lines
            .iter()
            .map(|l| serde_json::from_str(l).unwrap())
            .filter(|e: &serde_json::Value| e["adapter"] == "assert")
            .collect();
        assert_eq!(assert_events.len(), 1);
        assert_eq!(assert_events[0]["operation"], "issue");
        assert_eq!(assert_events[0]["outcome"], "success");

        std::env::remove_var("KAGE_V2_DIR");
    }

    // ----- Artifact signing tests (Step 12) -----

    #[test]
    fn dispatch_artifact_sign_digest_roundtrip() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("KAGE_V2_DIR", dir.path());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let kid_bech32 = setup_env_record(dir.path());
        let state = test_state_with_audit(dir.path().join("audit.ndjson"));

        // Init signing key
        let resp = runtime.block_on(call_with_state(
            state.clone(),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 300,
                "method": "Dispatch",
                "params": {
                    "version": 1,
                    "adapter": "sign",
                    "capability": "sign",
                    "operation": "init",
                    "params": { "kid_bech32": kid_bech32 }
                }
            }),
        ));
        assert!(resp.error.is_none());

        // Sign digest
        let resp = runtime.block_on(call_with_state(
            state.clone(),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 301,
                "method": "Dispatch",
                "params": {
                    "version": 1,
                    "adapter": "artifact",
                    "capability": "sign",
                    "operation": "sign-digest",
                    "params": {
                        "kid_bech32": kid_bech32,
                        "digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    }
                }
            }),
        ));
        assert!(
            resp.error.is_none(),
            "sign-digest failed: {:?}",
            resp.error
        );
        let envelope_resp: kage_types::envelope::ResponseEnvelope =
            serde_json::from_value(resp.result.unwrap()).unwrap();
        let signed_envelope = envelope_resp.result.unwrap();
        assert!(signed_envelope["signature_b64"].as_str().is_some());

        // Verify digest
        let resp = runtime.block_on(call_with_state(
            state,
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 302,
                "method": "Dispatch",
                "params": {
                    "version": 1,
                    "adapter": "artifact",
                    "capability": "sign",
                    "operation": "verify-digest",
                    "params": {
                        "kid_bech32": kid_bech32,
                        "envelope": signed_envelope
                    }
                }
            }),
        ));
        assert!(
            resp.error.is_none(),
            "verify-digest failed: {:?}",
            resp.error
        );
        let envelope: kage_types::envelope::ResponseEnvelope =
            serde_json::from_value(resp.result.unwrap()).unwrap();
        assert_eq!(envelope.result.unwrap()["valid"], true);

        std::env::remove_var("KAGE_V2_DIR");
    }

    #[test]
    fn dispatch_artifact_sign_manifest_roundtrip() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("KAGE_V2_DIR", dir.path());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let kid_bech32 = setup_env_record(dir.path());
        let state = test_state_with_audit(dir.path().join("audit.ndjson"));

        // Init signing key
        let resp = runtime.block_on(call_with_state(
            state.clone(),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 310,
                "method": "Dispatch",
                "params": {
                    "version": 1,
                    "adapter": "sign",
                    "capability": "sign",
                    "operation": "init",
                    "params": { "kid_bech32": kid_bech32 }
                }
            }),
        ));
        assert!(resp.error.is_none());

        // Sign manifest
        let resp = runtime.block_on(call_with_state(
            state.clone(),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 311,
                "method": "Dispatch",
                "params": {
                    "version": 1,
                    "adapter": "artifact",
                    "capability": "sign",
                    "operation": "sign-manifest",
                    "params": {
                        "kid_bech32": kid_bech32,
                        "entries": [
                            { "path": "bin/kage", "digest": "abc123", "size": 1024 },
                            { "path": "lib/libkage.so", "digest": "def456", "size": 2048 }
                        ]
                    }
                }
            }),
        ));
        assert!(
            resp.error.is_none(),
            "sign-manifest failed: {:?}",
            resp.error
        );
        let envelope_resp: kage_types::envelope::ResponseEnvelope =
            serde_json::from_value(resp.result.unwrap()).unwrap();
        let signed_manifest = envelope_resp.result.unwrap();
        assert!(signed_manifest["signature_b64"].as_str().is_some());

        // Verify manifest
        let resp = runtime.block_on(call_with_state(
            state,
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 312,
                "method": "Dispatch",
                "params": {
                    "version": 1,
                    "adapter": "artifact",
                    "capability": "sign",
                    "operation": "verify-manifest",
                    "params": {
                        "kid_bech32": kid_bech32,
                        "manifest": signed_manifest
                    }
                }
            }),
        ));
        assert!(resp.error.is_none());
        let envelope: kage_types::envelope::ResponseEnvelope =
            serde_json::from_value(resp.result.unwrap()).unwrap();
        assert_eq!(envelope.result.unwrap()["valid"], true);

        std::env::remove_var("KAGE_V2_DIR");
    }

    #[test]
    fn dispatch_artifact_tampered_digest_rejected() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("KAGE_V2_DIR", dir.path());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let kid_bech32 = setup_env_record(dir.path());
        let state = test_state_with_audit(dir.path().join("audit.ndjson"));

        // Init signing key
        let resp = runtime.block_on(call_with_state(
            state.clone(),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 320,
                "method": "Dispatch",
                "params": {
                    "version": 1,
                    "adapter": "sign",
                    "capability": "sign",
                    "operation": "init",
                    "params": { "kid_bech32": kid_bech32 }
                }
            }),
        ));
        assert!(resp.error.is_none());

        // Sign digest
        let resp = runtime.block_on(call_with_state(
            state.clone(),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 321,
                "method": "Dispatch",
                "params": {
                    "version": 1,
                    "adapter": "artifact",
                    "capability": "sign",
                    "operation": "sign-digest",
                    "params": {
                        "kid_bech32": kid_bech32,
                        "digest": "original_digest_hex"
                    }
                }
            }),
        ));
        assert!(resp.error.is_none());
        let envelope_resp: kage_types::envelope::ResponseEnvelope =
            serde_json::from_value(resp.result.unwrap()).unwrap();
        let mut signed_envelope = envelope_resp.result.unwrap();

        // Tamper with the digest
        signed_envelope["digest"] = serde_json::json!("tampered_digest_hex");

        // Verify should fail
        let resp = runtime.block_on(call_with_state(
            state,
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 322,
                "method": "Dispatch",
                "params": {
                    "version": 1,
                    "adapter": "artifact",
                    "capability": "sign",
                    "operation": "verify-digest",
                    "params": {
                        "kid_bech32": kid_bech32,
                        "envelope": signed_envelope
                    }
                }
            }),
        ));
        assert!(resp.error.is_none());
        let envelope: kage_types::envelope::ResponseEnvelope =
            serde_json::from_value(resp.result.unwrap()).unwrap();
        assert_eq!(envelope.result.unwrap()["valid"], false);

        std::env::remove_var("KAGE_V2_DIR");
    }

    #[test]
    fn dispatch_artifact_audit_events() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("KAGE_V2_DIR", dir.path());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let kid_bech32 = setup_env_record(dir.path());
        let audit_path = dir.path().join("audit.ndjson");
        let state = test_state_with_audit(audit_path.clone());

        // Init signing key
        let resp = runtime.block_on(call_with_state(
            state.clone(),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 330,
                "method": "Dispatch",
                "params": {
                    "version": 1,
                    "adapter": "sign",
                    "capability": "sign",
                    "operation": "init",
                    "params": { "kid_bech32": kid_bech32 }
                }
            }),
        ));
        assert!(resp.error.is_none());

        // Sign digest via artifact adapter
        let resp = runtime.block_on(call_with_state(
            state,
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 331,
                "method": "Dispatch",
                "params": {
                    "version": 1,
                    "adapter": "artifact",
                    "capability": "sign",
                    "operation": "sign-digest",
                    "params": {
                        "kid_bech32": kid_bech32,
                        "digest": "abc123"
                    }
                }
            }),
        ));
        assert!(resp.error.is_none());

        // Check audit log
        let audit_content = fs::read_to_string(&audit_path).unwrap();
        let lines: Vec<&str> = audit_content.trim().lines().collect();

        let artifact_events: Vec<serde_json::Value> = lines
            .iter()
            .map(|l| serde_json::from_str(l).unwrap())
            .filter(|e: &serde_json::Value| e["adapter"] == "artifact")
            .collect();
        assert_eq!(artifact_events.len(), 1);
        assert_eq!(artifact_events[0]["operation"], "sign-digest");
        assert_eq!(artifact_events[0]["outcome"], "success");

        std::env::remove_var("KAGE_V2_DIR");
    }
}
