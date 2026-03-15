# Kage Architecture & Implementation Guide

This document describes the current architecture of Kage v1.0, expanding on the original `DESIGN_SPEC.md` with implementation details regarding the macOS Agent, IPC, and security policies.

## System Components

### 1. Kage Core (`kage-core`)
- **Language**: Rust
- **Responsibilities**: 
  - HKDF-SHA256 key derivation.
  - Bech32 encoding/decoding (`age-secret-key-...`).
  - Shared configuration structs (`Config`, `DeviceConfig`, etc.).
  - `DeviceKeystore` trait definition.

### 2. Kage CLI (`kage-cli`)
- **Language**: Rust
- **Responsibilities**:
  - User entry point (`init`, `age-identities`, `rotate-device-key`).
  - Orchestrates 1Password interaction (via `op` CLI).
  - Manages configuration and data files.
  - Interacts with platform-specific helpers via `HelperKeystore`.

### 3. macOS Helper (`KageHelper.app`)
- **Language**: Swift (SwiftUI)
- **Structure**: App Bundle signed with local certificate (`Kage-Local-Dev` or Apple Development).
- **Modes**:
  1.  **CLI Subprocess (Legacy/Fallback)**:
      - Invoked with arguments (e.g., `KageHelper encrypt ...`).
      - Reads plaintext from `stdin`, writes ciphertext to `stdout`.
      - **Limitation**: Cannot easily handle biometric UI prompts (`userPresence`) in headless contexts without hitting `errSecInteractionNotAllowed`.
  2.  **Agent Mode (Recommended)**:
      - Runs as a persistent menu-bar application (`LSUIElement`).
      - Listens on Unix Domain Socket: `~/.kage/agent.sock`.
      - Manages `LAContext` for session-based authentication (e.g., "Unlock for 5 minutes").
      - Provides proper UI context for Touch ID / Password prompts.

### 4. Linux Helper (`kage-linux-helper`)
- **Language**: Bash
- **Responsibilities**:
  - Wraps `tpm2-tools` for TPM2 operations.
  - Manages handles and policies (PINs).

## Inter-Process Communication (IPC)

### macOS Agent Protocol
- **Transport**: Unix Domain Socket (`~/.kage/agent.sock`).
- **Framing**: Newline-delimited JSON.
- **Request Format**:
  ```json
  {
    "cmd": "encrypt" | "decrypt" | "init-key",
    "label": "kage-org-env",
    "policy": "none" | "presence" | "strong",
    "data": "base64_encoded_payload" // Optional
  }
  ```
- **Response Format**:
  ```json
  {
    "ok": true | false,
    "data": "base64_encoded_payload", // Optional
    "error": "Error message" // Optional
  }
  ```

## Security Policies & Environments

Kage supports configurable security policies per environment (`dev`, `stage`, `prod`).

### Policy Levels
| Policy | Intended Behavior | macOS Implementation (Prod) | macOS Implementation (Local Dev) |
| :--- | :--- | :--- | :--- |
| **none** | Software-only or No-Auth Hardware | Secure Enclave, No ACL | Secure Enclave, No ACL |
| **presence** | User Presence (Touch ID / PIN) | Secure Enclave + `.userPresence` | Secure Enclave, No ACL |
| **strong** | Strict Biometry (Invalidated on Change) | Secure Enclave + `.biometryCurrentSet` | Secure Enclave, No ACL |

### Local Development Mode (`KAGE_LOCAL_DEV`)
To facilitate local development and testing (especially CI/CD or headless scripts), Kage implements a **Local Dev Mode**.

- **Activation**: Set `KAGE_LOCAL_DEV=1` environment variable.
- **Behavior**:
  - Forces all key creation policies to **No ACL** (effectively `none`).
  - Allows `init`, `encrypt`, and `decrypt` operations to succeed without user interaction.
  - **Crucial for Testing**: Enables end-to-end integration tests (`just test-integration`) to run without blocking on Touch ID.

### Agent vs. Subprocess Selection
The CLI decides which mode to use based on configuration:
1.  **Check `KAGE_USE_AGENT`**:
    - If `1` or `true`: Attempt to connect to `~/.kage/agent.sock`.
    - If connection succeeds: Use Agent IPC.
    - If connection fails: Fail hard (if explicitly requested) or fall back (if auto).
2.  **Fallback**:
    - Spawn `KageHelper.app/Contents/MacOS/KageHelper` as a subprocess.

## Directory Structure

```text
kage/
├── kage-core/               # Rust library
├── kage-cli/                # Rust binary
├── kage-mac-helper/         # Swift App Bundle
│   ├── KageHelper/          # Xcode Project
│   └── Sources/             # Swift Source
├── kage-linux-helper/       # Bash script
├── docs/                    # Documentation
└── target/                  # Build artifacts
    └── release/
        ├── kage-cli         # Main executable
        └── KageHelper.app   # macOS Helper Bundle
```

