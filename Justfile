# Global variable for vault, overridable via command line (just test-integration vault=MyVault)
vault := "Private"

# Run full suite
test: build test-crypto test-integration

# Build release binaries
build:
    cargo build --release -p kage-cli
    @if [ "$(uname)" == "Darwin" ]; then \
        cd kage-mac-helper && swift build -c release; \
        codesign -s - --force .build/release/kage-mac-helper; \
        cp .build/release/kage-mac-helper ../target/release/; \
    fi

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
    
    # 3. Encrypt/Decrypt Check
    echo "secret" | sops -e --age $(cat /tmp/id | age-keygen -y) /dev/stdin > /tmp/test.sops
    SOPS_AGE_KEY=$(cat /tmp/id) sops -d /tmp/test.sops
    
    echo "Integration test passed!"

