# Kage

**Hardware-backed key management shim for `age`/`SOPS`.**

Kage bridges the gap between developer secret management (SOPS) and hardware security modules (Secure Enclave on macOS, TPM2 on Linux). It ensures that environment keys (`K_env`) are never stored in plaintext on disk, but are instead wrapped by hardware-protected keys.

## Documentation

*   [**Design Specification**](docs/DESIGN_SPEC.md): The original requirements and design goals.
*   [**Architecture & Implementation**](docs/ARCHITECTURE.md): Current system architecture, including the macOS Agent and IPC details.

## Development Setup

This project uses `mise` to manage dependencies (Rust, Just, SOPS, Age).

```bash
mise install
```

### Building

```bash
just build
```
This builds the Rust CLI (`kage-cli`) and the macOS Helper App (`KageHelper.app`).

## Usage

### 1. Initialization
Initialize an organization and enroll the current device. This fetches the master key from 1Password and derives per-environment keys.

```bash
# Standard Init (Production/Staging - Requires properly signed binary)
./target/release/kage-cli init --org-id my-org --env dev --1p-vault "Private"

# Local Dev Mode (Recommended for testing)
export KAGE_LOCAL_DEV=1
./target/release/kage-cli init --org-id my-org --env dev --1p-vault "Private" --non-interactive
```

### 2. Get Age Identity
Output the age secret key for use with SOPS.

```bash
# Set up for SOPS
export SOPS_AGE_KEY=$(./target/release/kage-cli age-identities --env dev)

# Or use command mode (SOPS calls Kage)
export AGE_IDENTITIES_COMMAND="./target/release/kage-cli age-identities --env dev"
```

### 3. Rotate Keys
If a device is compromised or biometry changes (invalidating the key), rotate the device key.

```bash
./target/release/kage-cli rotate-device-key --env dev
```

## Modes of Operation (macOS)

### Local Dev Mode (`KAGE_LOCAL_DEV=1`)
For local development, set `KAGE_LOCAL_DEV=1`. This downgrades security policies to allow headless CLI usage without blocking on Touch ID prompts.
*   **Polices**: All environments use Secure Enclave keys with **No Access Control Lists (ACLs)**.
*   **Agent**: Optional. Works with both subprocess and agent.

### Agent Mode (`KAGE_USE_AGENT=1`)
Kage can use a persistent background agent (`KageHelper.app`) for improved performance and session management.

1.  **Start the Agent**:
    *   **Production / Strict Mode**:
        ```bash
        open target/release/KageHelper.app
        ```
    *   **Local Dev Mode (No ACLs)**:
        To run the Agent with `KAGE_LOCAL_DEV=1`, you must launch the binary directly (as `open` does not pass environment variables):
        ```bash
        pkill KageHelper
        KAGE_LOCAL_DEV=1 ./target/release/KageHelper.app/Contents/MacOS/KageHelper &
        ```

2.  **Enable Agent in CLI**:
    ```bash
    export KAGE_USE_AGENT=1
    ```

3.  **Run Commands**:
    ```bash
    ./target/release/kage-cli age-identities --env dev
    ```

### Subprocess Mode (Default)
If `KAGE_USE_AGENT` is not set, `kage-cli` spawns `KageHelper.app` as a one-shot subprocess. This is simpler but has higher latency and cannot handle complex UI interactions (like "Prod" biometry) as gracefully.

## Troubleshooting

*   **`Invalid key length`**: Usually means the helper binary is printing debug info to stdout. Ensure you have the latest build (`just build`).
*   **`Connection refused`**: The Agent is not running. Run `open target/release/KageHelper.app`.
*   **`-34018` / `errSecMissingEntitlement`**: Code signing issue. Ensure the app is signed with a certificate that has a stable Team ID (or use `KAGE_LOCAL_DEV=1` to bypass strict ACLs).
*   **`-1009` / `ACL operation is not allowed`**: This confirms that macOS is blocking strict access controls (Biometry/Passcode) for the local build. You **must** use `KAGE_LOCAL_DEV=1` to downgrade to a supported policy (No ACL).
