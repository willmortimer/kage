# Kage

**Local trust runtime for developer workflows.**

Kage v3 is a resident daemon that performs policy-gated cryptographic operations on behalf of developer tools. It generalizes the v2 hardware-backed age plugin into a broader capability security runtime with adapters for secret management, code signing, assertions, and artifact verification.

## What It Does

- **Secret management**: Encrypt, decrypt, and inject secrets into processes (`kage run`)
- **Age/SOPS integration**: Hardware-backed age plugin for transparent encryption/decryption
- **Git signing**: Ed25519 commit/tag signing via SSH signature format
- **Assertion tokens**: Short-lived signed tokens for local auth workflows
- **Artifact signing**: File and release manifest signing with verification
- **Audit trail**: Append-only NDJSON log of all trust operations

## Documentation

- [Architecture](docs/ARCHITECTURE.md) -- system design, crate layout, data flow
- [v3 Design Spec](docs/v3/DESIGN_SPEC_V3.md) -- full design specification
- [v3 Implementation Status](docs/v3/IMPLEMENTATION_STATUS.md) -- what's done, what's left, platform-specific work
- [v2 docs](docs/v2/) -- previous version reference (IPC protocol, security model, etc.)

## Installation (Homebrew, macOS)

macOS requirements: Apple silicon (arm64) + macOS 26+.

```bash
brew tap willmortimer/kage
brew install kage
brew install --cask kage-helper

# SOPS integration:
export SOPS_AGE_KEY_CMD="kage identity"
```

## Development Setup

This project uses `mise` to manage toolchain dependencies (Rust, Just, SOPS, Age).

```bash
mise trust --all --yes
mise install
```

### Building

```bash
mise run build        # Build everything (Rust + macOS helper if on macOS)
cargo build --release # Rust-only build on any platform
```

Produces:

- `target/release/kage` -- admin CLI
- `target/release/kaged` -- daemon
- `target/release/age-plugin-kage` -- age plugin
- `target/release/kage-git-signer` -- git signing binary

### Testing

```bash
cargo test            # 74 tests across all crates
cargo clippy          # Lint check
mise run ci           # Full CI: fmt + clippy + test
```

## Usage

### 1. Start the daemon

```bash
# Linux / WSL2 (Unix socket at ~/.kage/kaged.sock):
kaged

# macOS (XPC com.kage.daemon):
brew install --cask kage-helper   # installs + loads LaunchAgent
```

### 2. Enroll this machine

```bash
kage setup --org my-org --env dev --env prod --1p-vault "Private"
```

### 3. Use with SOPS/age

```bash
export SOPS_AGE_KEY_CMD="kage identity"
sops -e --age "age1kage1..." secrets.yaml > secrets.enc.yaml
sops -d secrets.enc.yaml
```

### 4. Manage secrets

```bash
kage secret set dev DB_PASS --value "s3cret"
kage secret get dev DB_PASS
kage secret list dev

# Run a process with secrets injected:
kage run dev -- ./my-app --flag
kage run dev --mode tempfile -- ./my-app   # secrets as temp files
```

### 5. Signing

```bash
# Initialize signing key
kage sign init dev

# Sign data from stdin
echo "payload" | kage sign data dev

# Git integration
kage sign git-setup dev              # configure git globally
git commit -S -m "signed commit"     # uses kage-git-signer
```

### 6. Assertions

```bash
kage assert issue dev --purpose admin --ttl 60
kage assert verify dev --token <token>
```

### 7. Artifact signing

```bash
kage artifact sign dev --file release.tar.gz
kage artifact verify dev --signature release.tar.gz.kage-sig
kage artifact sign-manifest dev --dir dist/
kage artifact verify-manifest dev --manifest manifest.json --dir dist/
```

### 8. Session control

```bash
kage unlock --env prod --duration 60   # unlock for 60s
kage lock --env prod                   # revoke immediately
kage doctor                            # check daemon connectivity
```

## Workspace Structure

```
crates/
├── kage-types/         Shared type definitions
├── kage-audit/         NDJSON audit subsystem
├── kage-comm/          Crypto, transport, IPC, signing formats
├── kage-cli/           Admin CLI
├── kaged/              Daemon with 6 adapters
├── age-plugin-kage/    age plugin binary
├── kage-git-signer/    Git signing binary
└── kage-wsl-bridge/    WSL2 relay (scaffold)
```

## Platform Support

| Platform | Status | Protector |
| --- | --- | --- |
| macOS (arm64) | Production | Secure Enclave via XPC |
| Linux | Production | TPM2 via tpm2-tools, devwrap fallback |
| WSL2 | Scaffold | Relay to Windows daemon |
| Windows | Designed | DPAPI (planned), named pipes |

## Troubleshooting

- **SOPS can't find plugin**: ensure `age-plugin-kage` is on `PATH`
- **Daemon unreachable (macOS)**: check LaunchAgent (`launchctl print gui/$(id -u)/com.kage.daemon`)
- **Daemon unreachable (Linux)**: start `kaged` and confirm socket at `~/.kage/kaged.sock`
- **Daemon unreachable (WSL2)**: start `kage-wsl-bridge` and ensure Windows daemon is running
