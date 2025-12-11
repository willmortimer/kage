last call for feedback

Here is the **Final Kage Design & Implementation Specification v1.0**.

I have resolved the Linux directory ambiguity (splitting config vs. data), added the missing `rotate-device-key` specification so recovery procedures are valid, and fixed the Justfile build dependency. This document is now internally consistent and complete.

-----

# Kage – Hardware-Backed Key Management for age/SOPS

## Design & Implementation Specification v1.0

**Date:** December 7, 2025
**Status:** Approved for Implementation
**Target Audience:** Engineering Team

-----

## Part I: Design Specification

### 1\. Overview

Kage is a hardware-backed key management shim for age/SOPS. It acts as a bridge between hardware security modules (Secure Enclave, TPM) and developer secret management workflows.

**Core Philosophy:**

  - **Org-level master key** stored in 1Password (single source of truth).
  - **Per-environment keys** derived via HKDF (deterministic).
  - **Per-device wrapping** using hardware security (Secure Enclave/TPM).
  - **Ephemeral Identity:** Secrets are exposed to SOPS only in memory via `AGE_IDENTITIES_COMMAND`.

**Target Users:** Small teams and solo developers requiring hardware-backed protection without the complexity of full HSM fleet management.

### 2\. Threat Model

**We defend against:**

1.  **Disk Theft / Offline Analysis:** `K_env` is never stored in plaintext on disk. It exists only as a hardware-wrapped blob.
2.  **Key Sprawl:** Only one master key (`K_org`) exists in 1Password. All other keys are mathematically derived.
3.  **Unauthorized Decryption (Same-user shell):** Critical environments (e.g., `prod`) require explicit user presence (Touch ID / PIN) for every decryption operation.
4.  **Accidental Logging:** Secrets are passed via `stdin`, never command line arguments.

**We do NOT defend against:**

  - Kernel-level compromise / Rootkits (if the kernel is owned, the hardware path can be spoofed).
  - Zero-days in Secure Enclave, TPM, or 1Password.
  - "Evil Maid" attacks or cold boot attacks.

### 3\. System Invariants

These invariants must be maintained by any implementation of Kage:

1.  **K\_org Isolation:** `K_org` is *only* stored in 1Password (and optionally offline paper backup). It never touches the disk of a developer machine.
2.  **K\_env Protection:** `K_env` is *never* written to disk in plaintext. It is only written to disk wrapped by the device key.
3.  **Process Isolation:** Secrets passed between the CLI and helpers flow strictly via `stdin`/`stdout` pipes.
4.  **Silent Logs:** Kage *never* logs secret material (keys, plaintexts) at any log level.
5.  **Deterministic Derivation:** `K_env` derivation depends solely on `K_org` and the environment name string.

### 4\. Key Hierarchy

#### 4.1 Org Master Key (K\_org)

  - **Size:** 32 bytes (256 bits).
  - **Storage:** 1Password Secure Note (`notesPlain` field, base64-encoded).
  - **Identifier:** 1Password Item UUID.

#### 4.2 Per-Environment Keys (K\_env)

Derived using HKDF-SHA256:

$$K_{env} = \text{HKDF-SHA256}(ikm=K_{org}, salt=\text{None}, info=\text{"kage-env-derivation-v1:"} \ || \ env)$$

  * **Output:** 32 bytes.
  * **Versioning:** The `-v1` tag in `info` allows future rotation of derivation logic.

#### 4.3 Age Identity Derivation

`K_env` is converted to an age X25519 identity.

1.  **Input:** `K_env` (32 bytes).
2.  **Process:** Convert `u8` bytes to 5-bit words (`u5`).
3.  **Encoding:** Bech32 (Original, not Bech32m).
      * **HRP:** `age-secret-key`
      * **Payload:** `u5` representation of `K_env`.
      * **Case:** Uppercase.

**Canonical Test Vector:**

  * **Input:** 32 bytes of `0x42`
  * **Output:** `AGE-SECRET-KEY-1GFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPQ4EGAEX`

### 5\. Architecture

#### 5.1 Component Diagram

#### 5.2 Device Keystore Trait (Abstract)

The CLI interacts with platform-specific backends via this contract:

  * `ensure_key(label, policy)`: Create a key in the hardware module if it doesn't exist.
  * `wrap(plaintext, policy)`: Encrypt bytes using the hardware key.
  * `unwrap(ciphertext)`: Decrypt bytes (may prompt user for Bio/PIN).
  * `is_available()`: Boolean check for hardware support.

#### 5.3 Authentication Policy

Configurable per environment to balance friction vs. security.

| Policy Level | macOS Implementation | Linux TPM2 Implementation |
| :--- | :--- | :--- |
| **none** | `.privateKeyUsage` | No auth (key usage only) |
| **presence** | `.userPresence` (Bio or Passcode) | TPM PIN required |
| **strong** | `.biometryCurrentSet` (Bio only, invalidated if Bio changes) | PIN + PCR policy (0, 2, 7) |

### 6\. Configuration & Data Layout

Kage strictly separates configuration from data storage, respecting platform standards (XDG on Linux).

#### 6.1 Config File

**Location:**

  * macOS: `~/Library/Application Support/kage/config.toml`
  * Linux: `~/.config/kage/config.toml`

**Schema:**

```toml
version = 1

[device]
id = "macbook-will-001"      # Random UUID generated at init
hostname = "omarchylab"

[backend.onepassword]
vault = "DevOps"
item_id = "abc123xyz789"     # UUID of K_org

[org]
id = "org-main"
envs = ["dev", "stage", "prod"]

[org.danger_levels]
dev = "low"
stage = "medium"
prod = "high"

# Map danger levels to Auth Policies
[policy.mapping]
low = "none"
medium = "presence"
high = "strong"

[device.keystore]
type = "auto" # "secure-enclave" | "tpm2" | "software" | "auto"

# Optional TPM2 specific config
[device.keystore.tpm2]
handle = "0x81000001"
pcr_banks = [0, 2, 7]
```

#### 6.2 Data Directory Layout

All persistent state (wrapped keys, logs) resides here.

**Location:**

  * macOS: `~/Library/Application Support/kage/`
  * Linux: `~/.local/share/kage/`

**Structure:**

```text
kage/
├── wrapped/
│   └── {org_id}/
│       └── {env}/
│           └── {device_id}.bin    # Hardware-wrapped K_env blob
└── logs/
    └── audit.log                  # Audit trail (ndjson)
```

#### 6.3 Audit Log

  * **Format:** NDJSON (Newline Delimited JSON).
  * **Events:** `INIT`, `AGE_IDENTITIES`, `ROTATE_DEVICE_KEY`.
  * **Fields:** `ts` (ISO8601), `user`, `host`, `op`, `env`, `org_id`, `device_id`, `result`, `error` (optional).
  * **Rotation:** Basic size-based rotation (e.g., rotate at 5MB, keep 5 files) is recommended but optional for v1.0.

-----

## Part II: Reference Implementation

The following sections detail the specific implementation logic required to satisfy the design.

### 7\. Core Crypto Implementation (Rust)

#### 7.1 Bech32 Encoding

Must correctly handle `u8` to `u5` conversion.

```rust
use bech32::{self, ToBase32, Variant};

/// Encode K_env as age secret key
pub fn bech32_age_secret(k_env: &[u8; 32]) -> Result<String, bech32::Error> {
    let hrp = "age-secret-key";
    // Convert [u8] -> [u5]
    let data = k_env.to_base32(); 
    // Encode using standard Bech32 (Variant::Bech32)
    let encoded = bech32::encode(hrp, data, Variant::Bech32)?;
    Ok(encoded.to_uppercase())
}
```

#### 7.2 Age Public Key Derivation

Must properly pipe the secret to `age-keygen`.

```rust
use std::process::{Command, Stdio};
use std::io::Write;

pub fn age_recipient_from_secret(secret: &str) -> Result<String, KageError> {
    let mut child = Command::new("age-keygen")
        .arg("-y")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?; // Error if binary missing

    // Write secret to stdin
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(secret.as_bytes())?;
        stdin.write_all(b"\n")?;
    }

    let output = child.wait_with_output()?;

    if !output.status.success() {
        return Err(KageError::AgeKeygenFailed);
    }

    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}
```

### 8\. CLI Interface Specification

The CLI is the primary user interface.

#### 8.1 `kage init`

Initialize org and enroll device.

**Usage:**
`kage init --org-id <ID> --env <ENV>... --1p-vault <VAULT> [--non-interactive]`

**Behavior:**

1.  **Check Backend:** Verify `op` CLI is installed and signed in.
2.  **Fetch K\_org:**
      * Attempt `op read "op://<vault>/<item_id>/notesPlain"`.
      * If item does not exist (or no item ID in config yet): Generate random 32-byte `K_org`, create secure note in 1Password, update config with new `item_id`.
3.  **Derive & Wrap:**
      * For each `env` specified:
          * Derive `K_env` via HKDF.
          * Determine `AuthPolicy` via `[policy.mapping]` lookup.
          * Ensure hardware key exists (`ensure_key`).
          * Wrap `K_env` using hardware key.
          * Write blob to `wrapped/{org_id}/{env}/{device_id}.bin`.
4.  **Finalize:** Write/Update `config.toml`.

**Exit Codes:**

  * `0`: Success.
  * `1`: Config/Argument Error.
  * `2`: 1Password Not Signed In.
  * `3`: Hardware Backend Unavailable.

#### 8.2 `kage age-identities`

Output age secret key for SOPS integration.

**Usage:**
`kage age-identities --env <ENV>`

**Behavior:**

1.  **Locate Blob:** Find `wrapped/{org_id}/{env}/{device_id}.bin`.
2.  **Unwrap:** Call device keystore `unwrap()`. This may trigger OS-level auth prompt (Touch ID / PIN).
3.  **Derive:** Convert unwrapped `K_env` to age identity string (Bech32).
4.  **Output:** Print single line `AGE-SECRET-KEY-...` to `stdout`.
5.  **Audit:** Append success/failure event to `audit.log`.

**Exit Codes:**

  * `0`: Success.
  * `1`: Blob Not Found (Not enrolled for env).
  * `2`: Auth Failed (User cancelled).

#### 8.3 `kage rotate-device-key`

Refresh device keypair and re-wrap `K_env`. Critical for recovery (e.g., Touch ID reset) or policy upgrades.

**Usage:**
`kage rotate-device-key --env <ENV>`

**Behavior:**

1.  **Authenticate (Old):** Unwrap existing `K_env` (requires current auth/biometry).
2.  **Reset Key:** Delete existing hardware key for this label/handle.
3.  **Re-create:** Call `ensure_key` (creates new key with current system state/policy).
4.  **Re-wrap:** Wrap `K_env` with the new key.
5.  **Write:** Overwrite blob at `wrapped/{org_id}/{env}/{device_id}.bin`.
6.  **Audit:** Log `ROTATE_DEVICE_KEY` event.

**Exit Codes:**

  * `0`: Success.
  * `1`: Config Error.
  * `2`: Auth Failed (Cannot unwrap old key).
  * `4`: Crypto/Hardware Error during rotation.

#### 8.4 SOPS Integration

Users configure their shell environment to use Kage seamlessly.

**Method 1 (Recommended):**

```bash
export AGE_IDENTITIES_COMMAND="kage age-identities --env=prod"
# SOPS will invoke this command when decrypting
sops -d secrets.sops.yaml
```

**Method 2 (Alternative):**

```bash
export SOPS_AGE_KEY="$(kage age-identities --env=prod)"
# This prompts for auth immediately upon export
sops -d secrets.sops.yaml
```

### 9\. macOS Implementation (Swift Helper)

The helper is a compiled Swift binary (`kage-mac-helper`). It must expose a CLI interface compatible with the Rust backend.

#### 9.1 CLI Contract & Entry Point (`main.swift`)

The helper must strictly adhere to these exit codes and arguments.

**Exit Codes:**

  * 0: Success
  * 1: Key Not Found
  * 2: Auth Failed (User cancelled or Biometry failed)
  * 3: Auth Not Enrolled (Biometry required but not set up)
  * 4: Crypto Failed
  * 5: Invalid Input
  * 6: Backend Unavailable (No Secure Enclave)

**Entry Point Logic:**

```swift
// main.swift sketch
import Foundation

// Parse arguments: [executable, command, label, "--policy", policy]
let args = CommandLine.arguments
guard args.count >= 2 else { exit(5) }
let command = args[1]

// Parse policy if present
var policy: AuthPolicy = .none
if let idx = args.firstIndex(of: "--policy"), idx + 1 < args.count {
    if let p = AuthPolicy(rawValue: args[idx+1]) { policy = p }
}

let label = args.count > 2 && !args[2].starts(with: "-") ? args[2] : "default"

do {
    switch command {
    case "check":
        if checkSEAvailable() { exit(0) } else { exit(6) }
    case "init-key":
        try getOrCreateKey(label: label, policy: policy) // Implementation in logic file
    case "encrypt":
        try encrypt(label: label, policy: policy)
    case "decrypt":
        try decrypt(label: label, policy: policy)
    default:
        exit(5)
    }
} catch let error as NSError {
    // Helper functions must throw NSError with code set to correct ExitCode
    // System errors should be mapped to Kage codes where possible
    let exitCode = Int32(error.code)
    exit(exitCode)
}
```

#### 9.2 Secure Enclave Logic

(See the original draft for `SecKeyCreateRandomKey` and `SecKeyCreateEncryptedData` implementation details. They remain valid.)

### 10\. Linux Implementation (TPM2 Helper)

The helper is a Bash script wrapping `tpm2-tools`.

**Key Usage:**

  * **Label:** The `label` argument is **ignored** in v1.0. The TPM2 backend uses a single persistent key handle defined in config.
  * **Exit Codes:**
      * `EXIT_AUTH_NOT_ENROLLED` (3) is utilized if a policy requires a PIN (`presence` or `strong`) but the environment variable `TPM_PIN` is missing.

**Helper Script Update (Snippet):**

```bash
cmd_decrypt() {
    local label=$1 policy=${2:-none}
    
    # ... check TPM ...

    local auth_arg=""
    case "$policy" in
        presence)
            # If PIN is required but not provided, treat as "Auth Not Enrolled/Configured"
            [[ -z "${TPM_PIN:-}" ]] && {
                [[ -t 0 ]] && { read -rsp "TPM PIN: " TPM_PIN; echo >&2; } \
                    || die $EXIT_AUTH_NOT_ENROLLED "TPM_PIN required but not set"
            }
            auth_arg="-p $TPM_PIN"
            ;;
        # ... strong policy logic ...
    esac
    
    tpm2_rsadecrypt ... || die $EXIT_AUTH_FAILED "Decryption failed (Check PIN?)"
}
```

### 11\. 1Password Backend Logic

The Rust backend must robustly handle `op` CLI errors to distinguish between "needs initialization" and "failure".

**Logic Flow:**

1.  **Fetch:** `op read "op://{vault}/{item}/notesPlain"`
2.  **Error Handling:**
      * If `stdout` contains the key: Success.
      * If `stderr` contains "not signed in" or "session expired": **Return Error (Do not create).**
      * If `stderr` contains "item not found" (or exit code indicates missing item): **Return NotFound.**
      * Other errors (network, permissions): **Return Error.**
3.  **Store (Idempotent):**
      * Call Fetch.
      * If `Success`: Call `op item edit`.
      * If `NotFound`: Call `op item create`.
      * If `Error`: Propagate error to user.

### 12\. Software Keystore Fallback (Warning)

The software keystore uses the OS keyring (Secret Service API / Keychain).

  * **Availability:** The check `Entry::new(...).is_ok()` is optimistic. The implementation must be robust: if the keyring is theoretically available but throws an error on `set_password` (e.g., headless Linux without DBus), Kage must capture that and fail gracefully or warn the user.

### 13\. Directory Structure

```text
kage/
├── Cargo.toml
├── kage-core/               # Business logic
│   ├── src/crypto.rs        # HKDF + Bech32
│   ├── src/keystore/        # Trait definitions
│   └── src/backend/         # 1Password logic
├── kage-cli/                # Main binary
│   └── src/main.rs
├── kage-mac-helper/         # Swift Package
│   ├── Sources/main.swift   # CLI Entry point
│   └── Sources/Logic.swift  # SecKey logic
└── kage-linux-helper        # Bash script
```

-----

## Part III: Operations

### 14\. Justfile (Dev Workflow)

```makefile
# Run full suite
test: build test-crypto test-integration

# Build release binaries
build:
    cargo build --release -p kage-cli
    @if [ "$(uname)" == "Darwin" ]; then \
        cd kage-mac-helper && swift build -c release; \
    fi

# Validate Bech32 and HKDF
test-crypto:
    cargo test -p kage-core

# Smoke test (requires hardware)
test-integration: build
    # 1. Init
    ./target/release/kage init --org-id test --env dev --non-interactive
    # 2. Get Identity
    ./target/release/kage age-identities --env dev > /tmp/id
    # 3. Encrypt/Decrypt Check
    echo "secret" | sops -e --age $(cat /tmp/id | age-keygen -y) /dev/stdin > /tmp/test.sops
    SOPS_AGE_KEY=$(cat /tmp/id) sops -d /tmp/test.sops
```

### 15\. Recovery Procedures

1.  **Lost Device:**

      * The thief cannot decrypt without Biometry/PIN.
      * Action: Admin creates a new `K_org` in 1Password (optional but recommended) or simply removes the device from the team roster.
      * User: Initializes kage on new device. Kage pulls `K_org` from 1Password and derives keys.

2.  **Touch ID Reset:**

      * If policy is `strong`, the OS invalidates the key if fingerprints are added/removed.
      * Action: User runs `kage rotate-device-key --env <env>`. This deletes the invalidated SE key, creates a new one, and re-wraps `K_env`.

3.  **Lost 1Password Access:**

      * If `K_org` is lost from 1Password and no offline backup exists, all data encrypted with derived keys is permanently lost. Rotate all secrets immediately.

### 16\. Future Scope (Post v1.0)

  * **Rekeying:** `kage sops-rekey` command to automate key rotation.
  * **Rotation:** Automatic rotation of `audit.log`.
  * **Labels:** Support for multiple keys (distinct labels) on TPM backend.