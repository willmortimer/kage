# Kage v3 Architecture

This document describes the current architecture of Kage v3 -- a local trust runtime
for developer workflows, built as a generalization of the v2 hardware-backed age plugin.

For the full design rationale, see [v3/DESIGN_SPEC_V3.md](v3/DESIGN_SPEC_V3.md).
For implementation status and remaining work, see [v3/IMPLEMENTATION_STATUS.md](v3/IMPLEMENTATION_STATUS.md).

## Core Model

Kage is a **resident daemon** that performs policy-gated cryptographic operations
on behalf of developer tools. The daemon is the authority; tool integrations are
**adapters** that route operations through a unified dispatch layer.

```
 Developer Tools                    Kage Daemon
 ──────────────                     ───────────
 sops / age  ──────────┐
 git commit -S ────────┤           ┌─────────────────┐
 kage run ─────────────┼──IPC───── │ Adapter Registry │
 kage sign ────────────┤           │  ┌─ AgeAdapter   │
 kage assert ──────────┤           │  ├─ Runtime      │
 kage artifact ────────┘           │  ├─ Sign         │
                                   │  ├─ GitSign      │
                                   │  ├─ Assert       │
                                   │  └─ Artifact     │
                                   └─────────────────┘
                                          │
                              ┌───────────┴───────────┐
                              │   Platform Protector   │
                              │ (SE / TPM / DPAPI)     │
                              └────────────────────────┘
```

## Workspace Crates

```
crates/
├── kage-types/         Type definitions shared across all crates
├── kage-audit/         Append-only NDJSON audit subsystem
├── kage-comm/          Communication: crypto, transport, IPC, signing formats
├── kage-cli/           Admin CLI (kage binary)
├── kaged/              Resident daemon with adapter registry
├── age-plugin-kage/    age plugin binary for sops/age integration
├── kage-git-signer/    Drop-in ssh-keygen replacement for git signing
└── kage-wsl-bridge/    WSL2-to-Windows daemon relay
```

## Capability Classes

Every operation is classified into one of five capability classes.
The daemon gates dispatch based on adapter capabilities.

| Capability | Purpose | Adapters |
| --- | --- | --- |
| `WrapUnwrap` | age file-key encryption/decryption | Age |
| `SecretRelease` | Secret encryption, decryption, batch release | Runtime |
| `Sign` | Ed25519 signing, SSH signatures, artifact signatures | Sign, GitSign, Artifact |
| `Assert` | Short-lived signed assertion tokens | Assert |
| `SessionGrant` | Explicit unlock sessions with TTL | Age |

## Adapter Registry

Adapters implement the `Adapter` trait:

```rust
pub trait Adapter: Send + Sync {
    fn id(&self) -> AdapterId;
    fn capabilities(&self) -> &[Capability];
    fn dispatch(&self, ...) -> Result<serde_json::Value, String>;
}
```

The daemon's `AdapterRegistry` maps `(AdapterId, Capability)` pairs to adapters
and validates that the requested capability is supported before dispatch.

### Registered Adapters

| ID | Struct | Operations |
| --- | --- | --- |
| `age` | `AgeAdapter` | `wrap`, `unwrap`, `unlock` |
| `runtime` | `RuntimeAdapter` | `encrypt`, `decrypt`, `release` |
| `sign` | `SignAdapter` | `init`, `sign`, `get-public-key` |
| `git-sign` | `GitSignAdapter` | `sign-commit`, `sign-tag`, `get-ssh-pubkey` |
| `assert` | `AssertAdapter` | `issue`, `verify` |
| `artifact` | `ArtifactAdapter` | `sign-digest`, `sign-manifest`, `verify-digest`, `verify-manifest` |

## Request/Response Envelope

All generalized operations flow through a versioned envelope:

```rust
pub struct RequestEnvelope {
    pub version: u32,            // schema version (1)
    pub adapter: AdapterId,      // target adapter
    pub capability: Capability,  // required capability
    pub operation: String,       // adapter-specific operation name
    pub advisory: Option<AdvisoryScope>,
    pub params: serde_json::Value,
}

pub struct ResponseEnvelope {
    pub version: u32,
    pub request_id: Option<String>,
    pub result: Option<serde_json::Value>,
    pub error: Option<String>,
}
```

Legacy age operations (WrapKey, UnwrapKey, Unlock, Ping) are also supported
via direct JSON-RPC methods for backward compatibility.

## Scope Model

**Authoritative scope** (enforced by the daemon):

- `org` -- organization identifier
- `env` -- environment name (dev, staging, prod)
- `kid_bech32` -- key identity in bech32 format

**Advisory scope** (informational, logged but not enforced):

- `filename`, `caller_pid`, `caller_exe`, `purpose`
- `cwd`, `repo_root`, `target_service`

## Key Hierarchy

```
K_org (32 bytes, stored in 1Password)
  └─ HKDF-SHA256 ──► K_env (per environment)
                        ├─ HKDF ──► k_wrap (age file-key wrapping, XChaCha20-Poly1305)
                        ├─ HKDF ──► k_secret (per-secret encryption key derivation)
                        └─ HKDF ──► k_sign_seal (Ed25519 signing key sealing)
```

- `k_wrap`: Used by the Age adapter for wrapping/unwrapping age file keys
- `k_secret`: Used by the Runtime adapter; further derived per-secret-name via HKDF
- `k_sign_seal`: Seals Ed25519 signing keys at rest (XChaCha20-Poly1305)

## Session & Policy Model

Three policy levels control when k_env can be unwrapped:

| Policy | Behavior | Platform Mechanism |
| --- | --- | --- |
| `none` | Auto-cached, no user interaction | Software wrap (devwrap) |
| `presence` | TTL-bounded session after user confirmation | Secure Enclave / TPM PIN |
| `strong` | Explicit unlock required for each batch | Biometry / TPM PIN+PCR |

Sessions are created via `Unlock` (with a max duration of 300s) and
revoked via `Lock`. Both emit audit events.

## Transport Layer

| Platform | Transport | Status |
| --- | --- | --- |
| Linux | Unix domain socket (`~/.kage/kaged.sock`) | Production |
| macOS | XPC (`com.kage.daemon`) + Unix socket fallback | Production |
| Windows | Named pipe (`\\.\pipe\kage-daemon`) | Code complete, untested |
| WSL2 | Unix socket relay to Windows daemon | Scaffold |

All transports implement the `DaemonTransport` trait (async, trait-object safe).

## Audit Subsystem

- Format: append-only NDJSON (newline-delimited JSON)
- Schema version: 2
- Location: `~/.kage/v3/audit.ndjson` (Linux), `~/Library/Application Support/kage/audit.ndjson` (macOS)
- Fields: timestamp, adapter, capability, operation, scope, outcome, platform, advisory, error, duration, metadata
- Crash-tolerant: best-effort write with eprintln fallback

## Secret Management

Secrets are stored as encrypted manifests with three-layer source merging:

1. **Base** (`~/.kage/v3/secrets/{org}/{env}.enc.json`) -- primary secrets
2. **Repo-shared** (`{repo}/.kage/secrets/{env}.enc.json`) -- committed to git
3. **Local overrides** (`~/.kage/v3/overrides/{org}/{env}.enc.json`) -- developer-local

Each layer overrides the previous. The `source` field tracks provenance
(`"base"`, `"repo"`, `"local"`).

`kage run` decrypts all secrets via the daemon and injects them into a child
process as environment variables (`KAGE_SECRET_*`) or temp files (mode 0600).

## Signing Substrate

Ed25519 signing keys are software-generated and sealed at rest under `k_sign_seal`
using XChaCha20-Poly1305 with KID-bound AAD.

Built on this substrate:

- **Generic signing**: `kage sign data` / `kage sign pubkey`
- **Git signing**: SSH SSHSIG format compatible with `git -c gpg.format=ssh`
- **Assertion tokens**: Dot-separated `<claims_b64url>.<signature_b64url>` with expiry
- **Artifact signing**: JSON envelope with canonical payload, release manifests with file digests

## Documentation Index

| Document | Description |
| --- | --- |
| [v3/DESIGN_SPEC_V3.md](v3/DESIGN_SPEC_V3.md) | Full v3 design specification |
| [v3/IMPLEMENTATION_STATUS.md](v3/IMPLEMENTATION_STATUS.md) | Current implementation status and remaining work |
| [v2/DESIGN_SPEC_V2.md](v2/DESIGN_SPEC_V2.md) | v2 design specification |
| [v2/IPC_PROTOCOL.md](v2/IPC_PROTOCOL.md) | v2 IPC protocol reference |
| [v2/SECURITY_AND_CRYPTO.md](v2/SECURITY_AND_CRYPTO.md) | v2 security and cryptography details |
| [v1/DESIGN_SPEC.md](v1/DESIGN_SPEC.md) | Original v1 design specification |
| [v1/ARCHITECTURE.md](v1/ARCHITECTURE.md) | Original v1 architecture guide |
