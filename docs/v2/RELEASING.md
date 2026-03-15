# Releasing (v2)

This repo publishes versioned release artifacts on tag push via `.github/workflows/release.yml`.

## Local packaging

Build + package into `dist/`:

- `mise run package` (uses `build-mac` on macOS, no-op on Linux)
- `mise run package-signed` (macOS only; requires codesigning env vars)

## GitHub Release workflow (tags)

Pushing a tag like `v2.0.0` triggers:

- Linux: builds Rust binaries and produces `dist/kage-<version>-linux-x86_64.tar.gz` + `dist/SHA256SUMS-linux-x86_64.txt`
- macOS (arm64 only, macOS 26+): builds + signs + notarizes `KageHelper.app`, signs Rust binaries, and produces:
  - `dist/kage-<version>-macos-arm64.tar.gz`
  - `dist/kagehelper-<version>-macos-arm64.zip`
  - `dist/SHA256SUMS-macos-arm64.txt`
- Publish: uploads all `dist/*` files to the GitHub Release, and adds a combined `dist/SHA256SUMS.txt`

Note: The macOS job requires a macOS 26+ Apple silicon runner. GitHub-hosted runners may lag behind new macOS major versions, so expect to use a self-hosted runner (labels: `self-hosted`, `macOS`, `ARM64`) until `macos-latest` reaches 26+.

### Required GitHub secrets (macOS signing/notarization)

The macOS release job expects these repository secrets:

- `MACOS_SIGNING_CERT_P12_BASE64`: base64 of a Developer ID Application `.p12`
- `MACOS_SIGNING_CERT_PASSWORD`: password for that `.p12`
- `MACOS_SIGNING_TEAM_ID`: 10-character Team ID
- `MACOS_CODESIGN_IDENTITY`: codesign identity for CLI/plugin signing (SHA-1 or name)
- `MACOS_XCODE_CODE_SIGN_IDENTITY`: usually `Developer ID Application`
- `MACOS_BUNDLE_IDENTIFIER`: bundle identifier for the helper (defaults to the Xcode project value if unset)
- `AC_NOTARY_KEY_ID`: App Store Connect API key id
- `AC_NOTARY_ISSUER_ID`: App Store Connect issuer id
- `AC_NOTARY_PRIVATE_KEY_BASE64`: base64 of the `.p8` private key

## Homebrew

This repo contains a tap layout (for a dedicated tap repo):

- `Formula/kage.rb` (CLI + daemon + age plugin)
- `Casks/kage-helper.rb` (KageHelper.app + LaunchAgent)

### Dedicated tap repo

Homebrew expects taps to live in a repo named `homebrew-<tap>`. For this project:

- Tap name: `willmortimer/kage`
- Tap repo: `willmortimer/homebrew-kage`

Create the tap repo once (recommended: public):

- Create `willmortimer/homebrew-kage` on GitHub with default branch `main`
- The release workflow will populate/update `Formula/` and `Casks/` there on tag releases

Users install via:

```
brew tap willmortimer/kage
brew install kage
brew install --cask kage-helper
```

### Tap automation (recommended)

The tag release workflow will update the tap repo automatically if you set:

- `HOMEBREW_TAP_TOKEN`: PAT with write access to the tap repo
- `HOMEBREW_TAP_REPO` (optional): defaults to `<owner>/homebrew-kage`

If you don’t set those secrets, update `version` + `sha256` manually in the tap repo from the GitHub Release assets (or the `SHA256SUMS*.txt` files).

## Homebrew QA (recommended)

The cask installs a per-user LaunchAgent and runs `launchctl` during install/uninstall.
If you hit issues, run Homebrew from Terminal.app (not tmux/SSH).

### Smoke installs

```
brew untap willmortimer/kage || true
brew tap willmortimer/kage

# Formula
brew install --build-from-source willmortimer/kage/kage
kage --help
brew uninstall kage

# Cask
brew install --cask willmortimer/kage/kage-helper
launchctl print gui/$UID/com.kage.daemon
brew uninstall --cask kage-helper
```

### LaunchAgent recovery

If the agent didn’t load (or is wedged):

```
launchctl bootout gui/$UID ~/Library/LaunchAgents/com.kage.daemon.plist || true
launchctl bootstrap gui/$UID ~/Library/LaunchAgents/com.kage.daemon.plist
launchctl kickstart -k gui/$UID/com.kage.daemon
launchctl print gui/$UID/com.kage.daemon
```

### Linting (tap repo)

Run these from the tap checkout:

```
brew audit --strict --online ./Formula/kage.rb
brew audit --new --cask ./Casks/kage-helper.rb
brew style ./Formula/kage.rb ./Casks/kage-helper.rb
```
