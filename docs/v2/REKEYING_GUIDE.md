Rekeying to Kage v2

Strategy: Clean Break ("Nuke and Pave")
Warning: Kage v2 is incompatible with v1. This guide assumes you are replacing your infrastructure entirely.

## Step 1: Decrypt Your Data

You must possess the plaintext of your secrets before upgrading. Use your existing v1 setup.

```
# Using your v1 binary/env vars
sops -d secrets/dev.yaml > secrets/dev.plaintext.yaml
sops -d secrets/prod.yaml > secrets/prod.plaintext.yaml
```


Verify: Check that the .plaintext.yaml files are readable text.

## Step 2: Uninstall v1

Remove legacy binaries and config to ensure no conflicts.

```
# Remove binary
rm $(which kage)

# Remove config and data
rm -rf ~/.kage
rm -rf ~/.config/kage
rm -rf ~/Library/Application\ Support/kage
```


Clean your shell:
Open your .zshrc or .bashrc and remove any lines exporting AGE_IDENTITIES_COMMAND or SOPS_AGE_KEY.

## Step 3: Install v2

Install the new native CLI and Daemon.

macOS requirements: macOS 26+ on Apple silicon (arm64).

```
# Via Homebrew (macOS)
brew tap willmortimer/kage
brew install kage
brew install --cask kage-helper

# Or Cargo (Rust)
cargo install kage-cli --force
```


## Step 4: Initialize

Run the setup wizard. This will contact 1Password, fetch your Organization Root Key, and re-enroll your device using the new v2 cryptographic format.

```
kage setup --org <org> --env dev --env prod --1p-vault "<vault>"

# Optional: enforce stronger policy per environment
# kage setup --org <org> --env dev --env prod --1p-vault "<vault>" --policy prod=strong
```


## Step 5: Update Repository

Get New Keys:
Run kage list. You will see new age1kage1... recipients.

Edit .sops.yaml:
Delete the old age1... keys and paste the new age1kage1... keys.

Encrypt:
Encrypt your plaintext files using the new configuration.

```
sops -e secrets/dev.plaintext.yaml > secrets/dev.yaml
sops -e secrets/prod.plaintext.yaml > secrets/prod.yaml
```


Verification & Cleanup:
Test decryption with the new system:

```
sops -d secrets/dev.yaml
```


If successful, securely delete the plaintext files:

```
rm secrets/*.plaintext.yaml
```


## Step 6: Commit

Commit the updated .sops.yaml and encrypted files. Your team is now on Kage v2.
