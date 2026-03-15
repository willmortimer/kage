Kage v2: Implementation Guide

This document outlines the project structure and build workflows for the Kage v2 monorepo.

## 1. Directory Structure

```
kage/
├── Cargo.toml                  # Rust Workspace Root
├── Justfile                    # Build Command Runner
├── kage-cli/                   # [Rust] The Admin CLI (`kage`)
│   └── src/
├── age-plugin-kage/            # [Rust] The Age Plugin Binary
│   └── src/
├── kage-comm/                  # [Rust] Shared Library: IPC Types & Crypto
│   └── src/
├── kaged/                      # [Rust] Linux Daemon Service
│   └── src/
├── kage-mac-helper/            # [Swift] macOS Daemon & UI
│   ├── KageHelper/             # Xcode Project
│   └── Sources/
└── docs/                       # Specifications
```

### Key Modules

kage-comm: This is the glue. It defines the DaemonTransport trait, the IPC Request/Response structs (serde models), and the shared Cryptographic primitives (XChaCha20 logic). Both the CLI and Plugin depend on this.

## 2. Build Workflows

We use `mise` tasks as the primary task runner. The `Justfile` remains as a compatibility wrapper.

### Standard Commands

```
# Build Everything (Detects OS)
mise run build

# Build only Rust components
mise run build-rust

# Build macOS Helper (Xcode)
mise run build-mac

# Run Tests (Unit + Integration)
mise run test

# CI suite (fmt-check + clippy + tests)
MISE_JOBS=4 MISE_TASK_OUTPUT=prefix mise run ci

# macOS: install + restart daemon + sops smoke (local dev mode)
mise run macos-smoke

# macOS: signed mode smoke (Team ID enforcement)
mise run macos-smoke-signed
```

### Development Environment

Rust: Ensure strict adherence to clippy lints.

```
cargo clippy --all-targets --all-features -- -D warnings
```

Swift: Use Xcode 15+ or `swift build`.

Signing: The macOS Helper MUST be signed to interact with the Secure Enclave.

- Local Dev: Use "Sign to Run Locally" (Ad-hoc).
- Release: Requires Apple Developer ID Application certificate.

Codesigning variables are intentionally not committed. Copy `.env.example` to `.env.local` and set:

- `KAGE_DEVELOPMENT_TEAM` (Apple Team ID)
- `KAGE_CODESIGN_IDENTITY` (e.g. SHA-1 from `security find-identity -v -p codesigning`)
- `KAGE_BUNDLE_IDENTIFIER` (optional; for unique local bundle IDs)

## 3. Implementation Checklist

### Phase 1: Shared Core (kage-comm)

- [ ] Define DaemonTransport async trait.
- [ ] Define IPC Structs (WrapKeyRequest, UnwrapKeyRequest, etc.).
- [ ] Implement Crypto module (HKDF, XChaCha20-Poly1305, Bech32).

### Phase 2: Linux Daemon (kaged)

- [ ] Implement JSON-RPC server over Unix Socket.
- [ ] Implement TpmsStore (File-based mock first, then tss-esapi).
- [ ] Wire up Wrap/Unwrap logic.

Notes:

- This repo currently includes a file-based “devwrap” store for `K_env` under `~/.kage/v2/` as a stand-in for TPM2/Secure Enclave integration.

### Phase 3: macOS Daemon (KageHelper)

- [ ] Update XPC Interface to match kage-comm definitions.
- [ ] Implement Unwrap with LAContext management.
- [ ] Add Unlock command handling (Session Cache).

### Phase 4: Plugin (age-plugin-kage)

- [ ] Implement age-plugin state machine.
- [ ] Implement DaemonTransport for Linux (JSON-RPC Client).
- [ ] Implement DaemonTransport for macOS (XPC Client via FFI).

### Phase 5: CLI (kage)

- [ ] kage setup: Enrollment flow.
- [ ] kage unlock: Batch session trigger.
