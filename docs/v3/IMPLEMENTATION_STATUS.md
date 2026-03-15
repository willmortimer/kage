# Kage v3 Implementation Status

**Date:** March 15, 2026
**Test suite:** 74 tests passing, 0 clippy warnings
**Platform tested:** Ubuntu WSL2 on Windows

---

## Architecture Overview

The v3 codebase is organized as a Cargo workspace with 8 crates:

| Crate | Purpose |
|-------|---------|
| `kage-types` | Core types: adapters, capabilities, scope, audit events, envelopes, secrets |
| `kage-audit` | Append-only NDJSON audit logging subsystem |
| `kage-comm` | Communication layer: crypto, transport, IPC, signing formats, manifest I/O |
| `kage-cli` | Admin CLI (`kage` binary) |
| `kaged` | Resident daemon with adapter registry and dispatch |
| `age-plugin-kage` | age plugin integration for sops/age decryption |
| `kage-git-signer` | Drop-in `ssh-keygen -Y sign` replacement for git |
| `kage-wsl-bridge` | WSL2-to-Windows relay (scaffold) |

---

## What Is Complete

### Core Architecture (Spec Track A — Steps A1-A4)

All foundational v3 abstractions are implemented and tested:

- **5 capability classes**: `WrapUnwrap`, `SecretRelease`, `Sign`, `Assert`, `SessionGrant`
- **Adapter registry** with trait-based dispatch (`Adapter` trait: `id()`, `capabilities()`, `dispatch()`)
- **Authoritative scope** (org, env, kid_bech32) and **advisory scope** (filename, caller_pid, caller_exe, purpose, cwd, repo_root, target_service)
- **Request/Response envelopes** with versioning, adapter routing, and capability gating
- **Audit subsystem**: NDJSON format, schema v2, crash-tolerant, platform-tagged
- **Transitional IPC routing**: legacy JSON-RPC methods coexist with generalized `Dispatch` envelope

### All 6 Adapters (Spec Phases 1-5)

| Adapter | ID | Capabilities | Operations |
|---------|-----|-------------|------------|
| **Age** | `age` | WrapUnwrap, SessionGrant | `wrap`, `unwrap`, `unlock` |
| **Runtime** | `runtime` | SecretRelease | `encrypt`, `decrypt`, `release` (batch) |
| **Sign** | `sign` | Sign | `init`, `sign`, `get-public-key` |
| **GitSign** | `git-sign` | Sign | `sign-commit`, `sign-tag`, `get-ssh-pubkey` |
| **Assert** | `assert` | Assert | `issue`, `verify` |
| **Artifact** | `artifact` | Sign | `sign-digest`, `sign-manifest`, `verify-digest`, `verify-manifest` |

### Cryptographic Subsystems

- **Key hierarchy**: k_org → k_env → (k_wrap, k_secret, k_sign_seal) via HKDF-SHA256
- **Ed25519 signing**: Software-generated keys sealed with XChaCha20-Poly1305 under k_sign_seal
- **SSH SSHSIG format**: Full binary wire format for git signing compatibility
- **Assertion tokens**: Two-part dot-separated format with base64url claims + Ed25519 signature
- **Artifact signatures**: JSON envelope with canonical payload signing, release manifests

### Secret Management (Spec Track D — Steps D1-D2)

- **Three-layer source merging**: base (`~/.kage/v3/secrets/`) < repo-shared (`{repo}/.kage/secrets/`) < local overrides (`~/.kage/v3/overrides/`)
- **Source provenance tracking**: each secret tagged with `source: "base" | "repo" | "local"`
- **Two delivery modes**: `env` (environment variables) and `tempfile` (0600-permission temp files)
- **Auto repo root detection** via `git rev-parse --show-toplevel`

### CLI Commands

```
kage setup          # Enrollment: fetch org key from 1Password, derive env keys
kage list           # Print recipients for configured envs
kage doctor         # Verify daemon connectivity
kage unlock         # Create temporary session (none/presence/strong policy)
kage lock           # Revoke active session
kage identity       # Print age plugin identity

kage secret set     # Encrypt and store a secret
kage secret get     # Decrypt and print a secret
kage secret list    # List secret names
kage secret rm      # Remove a secret
kage secret set-override  # Store a local override (wins over base/repo)
kage secret list-layers   # Show secret provenance per layer

kage run <env> -- <cmd>   # Spawn process with secrets injected

kage sign init      # Generate signing keypair
kage sign data      # Sign stdin data
kage sign pubkey    # Print base64 public key
kage sign git-pubkey    # Print SSH pubkey for allowed_signers
kage sign git-setup     # Configure git to use kage for signing

kage assert issue   # Issue short-lived signed assertion token
kage assert verify  # Verify assertion token

kage artifact sign          # Sign file (SHA-256 + Ed25519)
kage artifact sign-manifest # Sign directory manifest
kage artifact verify        # Verify artifact signature
kage artifact verify-manifest # Verify manifest signature + file digests
```

### Transport Layer

- **Unix domain sockets** (Linux/macOS): full JSON-RPC + envelope dispatch
- **Named pipes** (Windows): full JSON-RPC + envelope dispatch (code complete, untested on Windows)
- **macOS XPC** (macOS): full JSON-RPC (dispatch stubbed)
- **16 high-level transport convenience methods** wrapping all adapter operations

### Session & Policy Model

- **Three policy levels**: `none` (auto-cache), `presence` (TTL-bounded), `strong` (explicit unlock required)
- **Session lifecycle**: `Unlock` (session.create) and `Lock` (session.revoke) with audit events
- **Duration-bounded sessions**: max 300s for unlock windows

### Audit

- Schema version 2 with fields: timestamp, session_id, adapter, capability, operation, scope, outcome, platform, advisory, error, duration_seconds, metadata
- Platform detection: linux/wsl/macos/windows (WSL detected via `WSL_DISTRO_NAME` env var)

---

## What Is Scaffolded / Partially Complete

### WSL2 Bridge (`kage-wsl-bridge`)

**Status: Scaffold complete (Spec Track C — Step C1)**

What exists:
- WSL2 detection via `/proc/version`
- Unix socket listener at `~/.kage/kaged.sock`
- Line-based JSON-RPC relay to Windows socket
- Environment variable override (`KAGE_WINDOWS_SOCKET`)

What it needs (requires Windows daemon):
- Actual Windows named pipe client connection
- Structured bridge protocol (C2)
- Audit correlation with platform=wsl (C4)

### Named Pipe Transport (`kage-comm/src/named_pipe.rs`)

**Status: Code complete, compile-gated on `#[cfg(windows)]`**

All trait methods implemented. Needs Windows environment to test.

### DPAPI Module (`kage-comm/src/dpapi.rs`)

**Status: Stub** — `seal_k_env` and `unseal_k_env` exist but need Windows DPAPI bindings.

---

## What Must Be Done From Other Environments

### From Windows/PowerShell (Spec Track B)

These items require a native Windows build environment:

#### B1 — Windows Rust Scaffold
- [ ] Build `kage-agent.exe` (Windows daemon) — can reuse `kaged` with Windows-specific protector
- [ ] Build `kage.exe` (Windows CLI) — can reuse `kage-cli` with Windows platform module
- [ ] Test named pipe transport end-to-end on Windows
- [ ] Test DPAPI seal/unseal with real Windows APIs

#### B2 — Protector Stage 1 (DPAPI)
- [ ] Implement real DPAPI calls in `kage-comm/src/dpapi.rs` using `windows` crate
  - `CryptProtectData` / `CryptUnprotectData` for k_env sealing
  - Scope: `CRYPTPROTECT_LOCAL_MACHINE` or current-user
- [ ] Integrate Windows Hello prompts for `presence` and `strong` policies
  - Use `windows::Security::Credentials` API
- [ ] Test key unwrap → wrap → session lifecycle on Windows

#### B3 — WPF Tray Shell (C# / .NET)
- [ ] Create WPF application with:
  - System tray icon with status color
  - Status page (daemon state, sessions)
  - Projects/environment page
  - Audit viewer
  - Settings page
  - Unlock/lock quick actions
- [ ] Named pipe client to daemon for all operations
- [ ] Windows notification integration for policy prompts and session expiry

#### B4 — Windows Integration Tests
- [ ] Named pipe request/response roundtrips
- [ ] DPAPI seal/unseal roundtrips
- [ ] Unlock → session → operation → audit flow
- [ ] GUI/daemon state sync

### From Windows (Track C completion)

#### C2 — Real WSL Bridge Protocol
- [ ] Windows-side relay socket server (`kaged-windows.sock`)
- [ ] Structured request envelope forwarding (not just line-based JSON-RPC)
- [ ] Cross-platform scope translation (WSL paths → Windows paths where needed)

#### C3 — Linux-local `kage run` via WSL Bridge
- [ ] WSL bridge receives approved release payload from Windows daemon
- [ ] Spawns Linux child process with secrets
- [ ] Already works natively via `kage run` on Linux; need to wire through bridge

#### C4 — Audit Correlation
- [ ] WSL-originated requests tagged with `platform: "wsl"` (detection already implemented)
- [ ] Advisory Linux context (cwd, exe path) forwarded through bridge
- [ ] Audit events written to Windows daemon's audit log

### From macOS (if applicable)

#### XPC Dispatch
- [ ] Implement `dispatch()` on `MacosXpcTransport` (currently returns error "not yet supported over XPC")
- [ ] This enables generalized envelope routing over XPC, beyond the legacy JSON-RPC methods

### Optional Enhancements (Any Platform)

#### Protector Stage 2 — TPM
- [ ] Linux: TPM2 key sealing via `tpm2-tools` (stubs exist in `kaged/src/main.rs`)
- [ ] Windows: TPM-backed key sealing via platform attestation APIs

#### Advisory Scope Wiring
- [ ] Pass `AdvisoryScope` through all transport convenience methods and CLI commands
- [ ] Populate `cwd`, `repo_root`, `caller_exe`, `caller_pid` automatically at CLI layer
- [ ] Forward advisory context in envelope dispatch for richer audit trails

#### Policy Configuration
- [ ] Per-adapter policy overrides (e.g., artifact signing requires `strong`, assertions allow `none`)
- [ ] Policy configuration file format and CLI management

---

## Test Coverage Summary

| Crate | Tests | What's Covered |
|-------|-------|---------------|
| `age-plugin-kage` | 1 | age stanza roundtrip |
| `kage-audit` | 1 | NDJSON file creation and append |
| `kage-cli` | 2 | Config roundtrip, record path safety |
| `kage-comm` | 39 | Crypto (wrap/unwrap, signing, SSH format), assertions, artifact signatures, manifest I/O with layering, secret crypto |
| `kaged` | 31 | All 6 adapters, JSON-RPC legacy methods, policy/session lifecycle, audit event generation |
| **Total** | **74** | |

---

## File Layout

```
crates/
├── age-plugin-kage/src/main.rs         # age plugin binary
├── kage-audit/src/lib.rs               # NDJSON audit subsystem
├── kage-cli/src/
│   ├── main.rs                         # CLI entry point (all commands)
│   ├── onepassword.rs                  # 1Password backend for setup
│   └── platform.rs                     # Platform-specific key wrapping
├── kage-comm/src/
│   ├── lib.rs                          # Module declarations
│   ├── artifact_signature.rs           # Artifact/manifest signing + verification
│   ├── assertion.rs                    # Assertion token create/verify
│   ├── crypto.rs                       # Key derivation, wrap/unwrap
│   ├── devwrap.rs                      # Dev-mode key wrapping
│   ├── dpapi.rs                        # Windows DPAPI stubs
│   ├── error.rs                        # Error types and daemon codes
│   ├── ffi.rs                          # macOS XPC FFI
│   ├── ipc.rs                          # JSON-RPC message types
│   ├── kid.rs                          # Key ID derivation and bech32 encoding
│   ├── manifest_io.rs                  # Secret manifest I/O with 3-layer merge
│   ├── named_pipe.rs                   # Windows named pipe transport
│   ├── secret_crypto.rs               # Per-secret encryption (k_secret derivation)
│   ├── signing.rs                      # Ed25519 key generation, sealing, signing
│   ├── signing_record.rs              # Signing key record persistence
│   ├── ssh_signature.rs              # SSH SSHSIG wire format
│   └── transport.rs                   # DaemonTransport trait + all convenience methods
├── kage-git-signer/src/main.rs        # git signing binary
├── kage-types/src/
│   ├── lib.rs                         # Module declarations
│   ├── adapter.rs                     # AdapterId constants
│   ├── audit.rs                       # AuditEvent, AuditOutcome
│   ├── capability.rs                  # Capability enum
│   ├── envelope.rs                    # Request/Response envelopes
│   ├── scope.rs                       # AuthoritativeScope, AdvisoryScope
│   └── secret.rs                      # SecretManifest, EncryptedSecret
├── kage-wsl-bridge/src/main.rs        # WSL2 relay scaffold
└── kaged/src/
    ├── main.rs                        # Daemon entry point, dispatch, tests
    ├── age_adapter.rs                 # WrapUnwrap + SessionGrant
    ├── artifact_adapter.rs            # Artifact signing
    ├── assert_adapter.rs              # Assertion tokens
    ├── git_sign_adapter.rs            # Git commit/tag signing
    ├── runtime_adapter.rs             # Secret encryption/decryption/release
    ├── sign_adapter.rs                # Generic Ed25519 signing
    └── signing_helpers.rs             # Shared key-loading helpers
```

---

## Quick Reference: Getting Started on Windows

1. **Clone the repo** and open in Windows terminal (not WSL)
2. **Install Rust** for `x86_64-pc-windows-msvc` target
3. **Build**: `cargo build` — everything compiles on Windows (named pipe and DPAPI code is `#[cfg(windows)]`)
4. **Start with DPAPI**: implement `CryptProtectData`/`CryptUnprotectData` in `crates/kage-comm/src/dpapi.rs`
5. **Test the daemon**: `cargo run --bin kaged` — listens on `\\.\pipe\kage-daemon`
6. **Test the CLI**: `cargo run --bin kage -- doctor` — verifies named pipe connectivity
7. **Build the GUI**: Create a new C#/WPF project that connects to `\\.\pipe\kage-daemon` via JSON-RPC
