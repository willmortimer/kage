Kage v2: System Architecture

Version: 2.0.0-FINAL
Status: Approved for Implementation
Philosophy: Native Platform Integration, Symmetric Trust, Clean Slate.

## 1. Executive Summary

Kage v2 is a hardware-backed age plugin. It allows development teams to share secrets securely by deriving environment keys from a shared organization root, protecting those keys on-disk via hardware security modules (Secure Enclave on macOS, TPM2 on Linux).

Key Architectural Changes from v1:

Native Age Plugin: Fully implements the age-plugin protocol. No shell wrappers.

Symmetric Wrapping: Uses XChaCha20-Poly1305 to wrap file keys, replacing X25519 derivation.

Dual Transport IPC: Uses native XPC on macOS and Unix Sockets on Linux via a shared Rust trait abstraction.

Explicit Trust: "Strong" policy requires zero-caching by default, with an explicit unlock command for batch operations.

## 2. System Components

### 2.1 age-plugin-kage (The Client)

Language: Rust.

Role: Stateless CLI tool invoked by age or sops.

Responsibilities:

Handles the age plugin state machine (HRP negotiation, Stanza parsing).

Implements the DaemonTransport trait to route requests to the OS-specific Daemon.

macOS: Bridges to KageHelper.app via C-shim/XPC.

Linux: Connects to ~/.kage/kaged.sock (JSON-RPC).

### 2.2 kaged / KageHelper (The Daemon)

Role: The stateful guardian of keys.

macOS (KageHelper.app):

Type: Menu Bar App (LSUIElement) exposing an XPC Service (com.kage.daemon).

Language: Swift.

Storage: Secure Enclave (Hardware), SecureData (Memory).

UI: Native macOS Alerts / Touch ID prompts.

Linux (kaged):

Type: Systemd User Service.

Language: Rust.

Storage: TPM2 (Hardware), mlock memory.

UI: System notification bubbles / TTY fallback.

### 2.3 kage (Admin CLI)

Role: Setup, diagnostics, and session control.

Commands: kage setup, kage list, kage doctor, kage unlock.

## 3. Cryptographic Flow

### 3.1 The "Org-Rooted" Chain

$K_{org}$ (32B): Stored in 1Password. Never saved to disk.

$K_{env}$ (32B): HKDF(K_org, ...)

At Rest: Wrapped by Hardware Key.

In Use: Resident in Daemon memory (subject to policy).

$K_{wrap}$ (32B): HKDF(K_env, info="kage-v2-wrap").

Purpose: Domain separation. This key is used to encrypt the actual file key.

### 3.2 Age Stanza (The "Lock")

When a file is encrypted, Kage writes this header:

```
-> kage {KID_Base64} {Nonce_Base64}
{Ciphertext_Base64}
```

Algorithm: XChaCha20-Poly1305.

Nonce: 24 bytes (Random).

AAD: 0x02 (Version) || KID_Bytes.

Payload: The file key, encrypted with $K_{wrap}$.

## 4. Policy & Security Model

Kage v2 enforces security policy at the Daemon level.

| Policy Level | Config (toml) | Cache Behavior | macOS Implementation | Linux Implementation |
|-------------|---------------|----------------|----------------------|----------------------|
| None | policy = "none" | Until Daemon Restart | SecAccessControl (Empty) | TPM Key (No Auth) |
| Presence | policy = "presence" | Configurable (Default 5m) | .userPresence | TPM Key + PIN |
| Strong | policy = "strong" | ZERO CACHE (Per-Op) | .biometryCurrentSet | TPM + PIN + PCR |

### 4.1 Batch Operations (kage unlock)

To allow batch operations (like sops updatekeys) under Strong policy without prompting for every file:

User runs: kage unlock --env prod --duration 60s.

Daemon prompts for Auth once.

Daemon creates a temporary UnlockSession in memory for that environment.

Subsequent requests within 60s reuse the session.

Session is wiped on timeout or kage lock.

## 5. Compatibility

Breaking Changes:

Kage v2 is completely incompatible with v1.

No migration logic is provided. Users must decrypt data with v1 and re-encrypt with v2 ("Nuke and Pave").