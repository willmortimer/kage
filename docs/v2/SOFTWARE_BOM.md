Kage v2: Technology Stack & Bill of Materials

This document defines the approved technology stack for Kage v2. Deviations from these choices require strong justification to maintain consistency and security properties.

## 1. Rust Components (age-plugin-kage, kage-cli, kaged-linux)

### Core Frameworks

| Component | Crate / Tool | Rationale |
|-----------|--------------|-----------|
| Async Runtime | tokio | Industry standard; required for async trait support and daemon concurrency. |
| CLI Parser | clap (derive) | Type-safe argument parsing; de facto standard. |
| Serialization | serde, serde_json | Universal serialization; required for JSON-RPC. |
| Error Handling | thiserror, anyhow | thiserror for library code (Plugin/Daemon), anyhow for top-level CLI applications. |

### Cryptography (CRITICAL)

| Primitive | Crate | Version Constraint | Rationale |
|-----------|-------|-------------------|------------|
| AEAD | chacha20poly1305 | ^0.10 | Provides XChaCha20Poly1305 type (24-byte nonce). DO NOT USE standard ChaCha20. |
| KDF | hkdf | ^0.12 | HMAC-based Key Derivation Function (RFC 5869). |
| Hashing | blake3 | ^1.5 | High-performance hashing for KIDs; 128-bit security is sufficient for handles. |
| Encoding | bech32 | ^0.9 | For age1kage... recipient strings. |
| Random | rand | ^0.8 | Cryptographically secure RNG for nonces. |
| Memory Safety | zeroize | ^1.7 | MANDATORY for all structs holding $K_{env}$ or $K_{wrap}$. |

### Age Ecosystem

| Component | Crate | Rationale |
|-----------|-------|-----------|
| Protocol | age-plugin | ^0.5 | |
| Core | age-core | ^0.10 | |

### IPC & System

| Component | Crate | Rationale |
|-----------|-------|-----------|
| JSON-RPC | jsonrpc-core (or similar) | For Linux Daemon transport. Lightweight preferred. |
| Unix Sockets | tokio::net::UnixListener | Native async UDS support. |
| XPC Bridge | objc, block | (MacOS Only) For calling the Swift/ObjC XPC interface. |
| Systemd | systemd | (Linux Only) For socket activation integration. |

## 2. macOS Components (KageHelper.app)

### Language & Runtime

- Language: Swift 5.9+
- Minimum OS: macOS 14.0 (Sonoma)

Frameworks:

- SwiftUI: For the Menu Bar UI and Settings windows.
- LocalAuthentication: For managing Touch ID contexts (LAContext).
- Security: For Keychain and Secure Enclave operations (SecKey, SecAccessControl).
- Foundation: For XPC (NSXPCConnection, NSXPCInterface).

### Architecture

- App Mode: `LSUIElement = 1` (Menu Bar App).
- Sandboxing: NO. Must be disabled to allow AF_UNIX socket creation (if used) or unrestricted file access if needed (though XPC is preferred).
- Signing: Must be signed with a stable Apple Team ID to allow SecAccessControl to persist across updates.

## 3. Build & Dev Tools

- Task Runner: `just` (Justfile) - Central entry point for all build/test commands.
- Dependency Manager: `cargo` (Rust), `xcodebuild` (Swift).
- Version Manager: `mise` (Manages Rust, Just, SOPS versions).