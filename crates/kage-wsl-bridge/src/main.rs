// kage-wsl-bridge: WSL2 bridge binary that forwards daemon requests
// to the Windows host's kaged via named pipe interop.
//
// This is a scaffold — full WSL2 interop requires Windows-side testing.

use anyhow::{bail, Context, Result};
use std::fs;
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

fn is_wsl2() -> bool {
    if let Ok(version) = fs::read_to_string("/proc/version") {
        let lower = version.to_lowercase();
        return lower.contains("microsoft") || lower.contains("wsl");
    }
    false
}

fn default_socket_path() -> Result<PathBuf> {
    let home = dirs::home_dir().context("HOME not set")?;
    Ok(home.join(".kage").join("kaged.sock"))
}

/// Attempt to find the Windows named pipe path accessible from WSL2.
/// The Windows pipe `\\.\pipe\kage-daemon` is accessible via
/// `/mnt/c/Users/<user>/.kage/kaged.sock` or through npiperelay/socat.
///
/// For now this is a stub that uses a Unix socket relay.
fn windows_relay_socket_path() -> Result<PathBuf> {
    // Check KAGE_WINDOWS_SOCKET for override
    if let Ok(p) = std::env::var("KAGE_WINDOWS_SOCKET") {
        return Ok(PathBuf::from(p));
    }

    // Default: assume npiperelay is set up to expose the Windows pipe
    // as a Unix socket at ~/.kage/kaged-windows.sock
    let home = dirs::home_dir().context("HOME not set")?;
    Ok(home.join(".kage").join("kaged-windows.sock"))
}

/// Forward a single request line to the Windows-side daemon socket and
/// return the response line.
async fn forward_request(relay_path: &PathBuf, request: &str) -> Result<String> {
    let stream = tokio::net::UnixStream::connect(relay_path)
        .await
        .with_context(|| {
            format!(
                "cannot connect to Windows relay at {}",
                relay_path.display()
            )
        })?;

    let (read_half, mut write_half) = stream.into_split();
    let mut line = request.to_string();
    if !line.ends_with('\n') {
        line.push('\n');
    }
    write_half.write_all(line.as_bytes()).await?;

    let mut reader = BufReader::new(read_half);
    let mut resp = String::new();
    reader.read_line(&mut resp).await?;
    Ok(resp)
}

#[tokio::main]
async fn main() -> Result<()> {
    if !is_wsl2() {
        bail!("kage-wsl-bridge is intended to run inside WSL2. /proc/version does not indicate a WSL environment.");
    }

    let relay_path = windows_relay_socket_path()?;
    eprintln!(
        "kage-wsl-bridge: relay to Windows daemon via {}",
        relay_path.display()
    );

    let socket_path = default_socket_path()?;
    if let Some(parent) = socket_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if socket_path.exists() {
        fs::remove_file(&socket_path).ok();
    }

    let listener = UnixListener::bind(&socket_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
    }

    eprintln!(
        "kage-wsl-bridge: listening on {}",
        socket_path.display()
    );

    loop {
        let (stream, _addr) = listener.accept().await?;
        let relay = relay_path.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_client(stream, &relay).await {
                eprintln!("kage-wsl-bridge client error: {e:#}");
            }
        });
    }
}

async fn handle_client(
    stream: tokio::net::UnixStream,
    relay_path: &PathBuf,
) -> Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            return Ok(());
        }
        let resp = forward_request(relay_path, &line).await?;
        write_half.write_all(resp.as_bytes()).await?;
        if !resp.ends_with('\n') {
            write_half.write_all(b"\n").await?;
        }
    }
}
