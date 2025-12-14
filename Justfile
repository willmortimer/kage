# Global variable for vault, overridable via command line (just test-integration vault=MyVault)
vault := "Private"

# Run full suite
test: build test-crypto test-integration

# Build helper via xcodebuild
build-mac-helper:
    mkdir -p ../target/release
    cd kage-mac-helper && xcodebuild \
      -project KageHelper/KageHelper.xcodeproj \
      -scheme KageHelper \
      -configuration Release \
      -derivedDataPath .xcodebuild \
      MACOSX_DEPLOYMENT_TARGET=15.0
    rm -rf target/release/KageHelper.app
    # Remove stale side-by-side binary to ensure CLI uses the bundle
    rm -f target/release/kage-mac-helper
    cp -R kage-mac-helper/.xcodebuild/Build/Products/Release/KageHelper.app target/release/

# Build release binaries
build:
    cargo build --release -p kage-cli
    @if [ "$(uname)" == "Darwin" ]; then \
        just build-mac-helper; \
    fi

# Run the CLI (release)
kage +args: build
    ./target/release/kage {{args}}

# Validate Bech32 and HKDF
test-crypto:
    cargo test -p kage-core

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
    ./target/release/kage-cli init --org-id test --env dev --1p-vault "$VAULT" --non-interactive
    
    # 2. Get Identity
    ./target/release/kage-cli age-identities --env dev > /tmp/id
    
    # 3. Extract a single secret key line (age format)
    # The grep ensures we only get the key line, and head -n1 ensures we only get one if there are duplicates/comments
    AGE_SECRET_KEY="$(grep '^AGE-SECRET-KEY' /tmp/id | head -n1)"
    
    if [ -z "$AGE_SECRET_KEY" ]; then
        echo "Error: No AGE-SECRET-KEY found in output"
        cat /tmp/id
        exit 1
    fi

    # Derive the recipient (public key)
    AGE_RECIPIENT="$(printf '%s\n' "$AGE_SECRET_KEY" | age-keygen -y)"
    
    # 4. Encrypt a test secret using the recipient
    echo "secret" | SOPS_AGE_KEY="$(cat /tmp/id)" \
        sops -e --age "$AGE_RECIPIENT" /dev/stdin > /tmp/test.sops
    
    # 5. Decrypt using the identity
    # Quote the variable to preserve newlines
    SOPS_AGE_KEY="$(cat /tmp/id)" sops -d /tmp/test.sops
    
    echo "Integration test passed!"

# Dev Mode helpers
dev-cli +args: build
    KAGE_LOCAL_DEV=1 ./target/release/kage {{args}}

dev-init env="dev" vault="Private": build
    KAGE_LOCAL_DEV=1 ./target/release/kage init --org-id my-company --env {{env}} --1p-vault "{{vault}}" --non-interactive

# Restart KageHelper app
restart:
    pkill KageHelper || true
    open target/release/KageHelper.app

# Rust formatting
fmt:
    cargo fmt

# Rust tests (all)
test-rust:
    cargo test

