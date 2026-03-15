# Kage

**Hardware-backed age plugin for teams (v2 in progress).**

Kage v2 is a native `age` plugin with a daemon that unwraps environment keys using platform hardware (Secure Enclave on macOS, TPM2 on Linux) and wraps age file keys using XChaCha20-Poly1305.

## Documentation

*   [**v2 Design Spec**](docs/v2/DESIGN_SPEC_V2.md)
*   [**v2 Implementation Guide**](docs/v2/IMPLEMENTATION_GUIDE.md)
*   [**v2 IPC Protocol**](docs/v2/IPC_PROTOCOL.md)
*   [**v2 Security & Crypto**](docs/v2/SECURITY_AND_CRYPTO.md)
*   Legacy v1 docs remain under `docs/`.

## Installation (Homebrew)

macOS requirements: Apple silicon (arm64) + macOS 26+.

```bash
brew tap willmortimer/kage
brew install kage
brew install --cask kage-helper

# SOPS integration:
export SOPS_AGE_KEY_CMD="kage identity"
```

## Development Setup

This project uses `mise` to manage dependencies (Rust, Just, SOPS, Age). Run everything via `mise` so you don’t depend on system/Homebrew versions.

```bash
mise trust --all --yes
mise install
```

### Building

```bash
mise run build
```
This builds:

- `target/release/kage` (admin CLI)
- `target/release/kaged` (daemon, Linux/macOS dev)
- `target/release/age-plugin-kage` (age plugin)

The `Justfile` remains as a compatibility wrapper (it calls the `mise` tasks).

## Usage

The commands below assume `kage` is on your `PATH` (Homebrew install). When developing from source, use `./target/release/kage` instead.

### 1. Start the daemon
macOS (XPC `com.kage.daemon`):

```bash
# Homebrew users: `brew install --cask kage-helper` installs + loads the LaunchAgent.
# Source users: end-to-end smoke (installs app, starts LaunchAgent, runs sops roundtrip)
mise run macos-smoke
```

Linux (Unix socket `~/.kage/kaged.sock`):

```bash
kaged
```

### 2. Enroll this machine

```bash
kage setup --org my-org --env dev --env prod --1p-vault "Private"
```

### 3. List recipients (for `.sops.yaml`)

```bash
kage list
```

### 4. Use with SOPS/age

```bash
# Source build only:
# export PATH="$PWD/target/release:$PATH"

# Tell sops how to get an age identity (kage prints plugin identity lines).
export SOPS_AGE_KEY_CMD="kage identity"

# Encrypt using a Kage recipient (from `kage list`)
mise exec -- sops -e --age "age1kage1..." secrets.plain.yaml > secrets.yaml

# Decrypt (plugin will call the daemon)
mise exec -- sops -d secrets.yaml
```

## Troubleshooting

*   **SOPS says it can’t find plugin**: ensure `age-plugin-kage` is on `PATH` (see above).
*   **Daemon unreachable (macOS)**: ensure `kage-helper` is running (`launchctl print gui/$(id -u)/com.kage.daemon`).
*   **Daemon unreachable (Linux)**: start `kaged` and confirm the socket exists at `~/.kage/kaged.sock`.
