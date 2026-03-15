use anyhow::{bail, Context};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use kage_comm::transport::default_daemon_transport;
use kage_types::adapter::AdapterId;
use kage_types::capability::Capability;
use std::fs;

/// Drop-in replacement for `ssh-keygen -Y sign` that Git calls.
///
/// Git invokes: `kage-git-signer -Y sign -f <key_identity_file> -n git <buffer_file>`
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    let mut key_file = None;
    let mut _namespace = "git".to_string();
    let mut buffer_file = None;
    let mut i = 1;

    while i < args.len() {
        match args[i].as_str() {
            "-Y" => {
                // skip "sign"
                i += 1;
            }
            "-f" => {
                i += 1;
                if i < args.len() {
                    key_file = Some(args[i].clone());
                }
            }
            "-n" => {
                i += 1;
                if i < args.len() {
                    _namespace = args[i].clone();
                }
            }
            arg if !arg.starts_with('-') => {
                buffer_file = Some(arg.to_string());
            }
            _ => {}
        }
        i += 1;
    }

    let key_file = key_file.context("missing -f <key_identity_file>")?;
    let buffer_file = buffer_file.context("missing <buffer_file>")?;

    // The key file contains the kid_bech32 string
    let kid_bech32 = fs::read_to_string(&key_file)
        .with_context(|| format!("reading key file: {key_file}"))?
        .trim()
        .to_string();

    // Read the buffer to sign
    let payload = fs::read(&buffer_file)
        .with_context(|| format!("reading buffer file: {buffer_file}"))?;

    let transport = default_daemon_transport()?;

    let operation = "sign-commit";

    let envelope = kage_types::envelope::RequestEnvelope {
        version: 1,
        adapter: AdapterId::new(AdapterId::GIT_SIGN),
        capability: Capability::Sign,
        operation: operation.to_string(),
        advisory: None,
        params: serde_json::json!({
            "kid_bech32": kid_bech32,
            "payload_b64": BASE64.encode(&payload),
        }),
    };

    let resp = transport.dispatch(envelope).await.map_err(|e| {
        anyhow::anyhow!("daemon dispatch failed: {e}")
    })?;

    if let Some(err) = resp.error {
        bail!("daemon error: {err}");
    }

    let result = resp.result.context("missing result from daemon")?;
    let signature_armored = result["signature_armored"]
        .as_str()
        .context("missing signature_armored in response")?;

    // Write signature to buffer_file (Git expects it there for SSH signing)
    fs::write(&buffer_file, signature_armored)
        .with_context(|| format!("writing signature to: {buffer_file}"))?;

    Ok(())
}
