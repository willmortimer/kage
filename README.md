# Kage

Hardware-backed key management shim for `age`/`SOPS`.

## Dev vs Prod Keystore Behavior

To support local development without fighting macOS Code Signing and Keychain ACLs, Kage supports an explicit dev mode.

*   **`KAGE_LOCAL_DEV=1`**: All environments (`dev`, `stage`, `prod`) use Secure Enclave keys with **no Access Control Lists (ACLs)**. This means no user presence or biometry is required, making it suitable for headless CLI use and integration testing. **This is the recommended mode for local development.**
*   **No `KAGE_LOCAL_DEV`** (Default): `stage` and `prod` environments use stricter ACLs (`userPresence` and `biometryCurrentSet` respectively). On macOS, this requires the helper to be properly signed with Distribution certificates and may require a GUI host agent to handle system authentication prompts.

### running in dev mode
```bash
just dev-init dev
just dev-cli age-identities --env dev
```

