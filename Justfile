# Global variable for vault, overridable via command line (just test-integration vault=MyVault)
vault := "Private"

# Run full suite
test:
    mise run test

# Build helper via xcodebuild
build-mac-helper:
    mise run build-mac

# Build release binaries
build:
    mise run build

# Run the CLI (release)
kage +args: build
    ./target/release/kage {{args}}

# Validate Bech32 and HKDF
test-crypto:
    mise run test-crypto

# Smoke test (requires hardware and 1Password)
# Usage: just test-integration <vault>
# Example: just test-integration DevOpsTest
test-integration vault_arg="Private": build
    #!/usr/bin/env bash
    set -e
    # Clean the vault argument if the user passed 'vault=Name'
    VAULT="{{vault_arg}}"
    if [[ "$VAULT" == vault=* ]]; then
        VAULT="${VAULT#*=}"
    fi
    
    echo "Running integration test using 1Password vault: $VAULT"
    
    # 1. Init
    ./target/release/kage setup --org test --env dev --1p-vault "$VAULT"
    
    # 2. List recipients
    ./target/release/kage list
    
    # 3. Extract a recipient (age1kage...)
    AGE_RECIPIENT="$(./target/release/kage list | awk 'NR==1 {print $2}')"
    if [ -z "$AGE_RECIPIENT" ]; then
        echo "Error: No recipient produced by kage list"
        exit 1
    fi

    export PATH="$PWD/target/release:$PATH"
    export SOPS_AGE_KEY_CMD="$PWD/target/release/kage identity"

    # 4. Encrypt a test secret using the recipient
    echo "secret" | mise exec -- sops -e --age "$AGE_RECIPIENT" /dev/stdin > /tmp/test.sops
    
    # 5. Decrypt using the identity
    mise exec -- sops -d /tmp/test.sops
    
    echo "Integration test passed!"

# Dev Mode helpers
dev-cli +args: build
    KAGE_LOCAL_DEV=1 ./target/release/kage {{args}}

dev-init env="dev" vault="Private": build
    KAGE_LOCAL_DEV=1 ./target/release/kage setup --org my-company --env {{env}} --1p-vault "{{vault}}"

# Restart KageHelper app
restart:
    pkill KageHelper || true
    open target/release/KageHelper.app

# Rust formatting
fmt:
    mise run fmt

# Rust tests (all)
test-rust:
    mise run test-rust
