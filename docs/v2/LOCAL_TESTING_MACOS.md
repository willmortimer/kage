Kage v2: Local Testing on macOS

This guide is for validating the macOS path end-to-end: `kage` (Rust) → XPC transport → `KageHelper.app` mach service (`com.kage.daemon`) → Secure Enclave backed unwrap → age stanza wrap/unwrap.

## Prereqs

- macOS 26+ on Apple silicon (arm64)
- `mise` installed
- Xcode installed
- 1Password CLI (`op`) authenticated (needed for `kage setup`)

## Quick Start (Recommended)

1) Trust config + install tools:

- `mise trust --all --yes`
- `mise install`

2) Build + run checks:

- `MISE_JOBS=4 MISE_TASK_OUTPUT=prefix mise run ci`

3) Enroll this machine (creates `~/.kage/v2/config.toml` and your first env record):

- `./target/release/kage setup --org <org> --env <env> --1p-vault "<vault>"`

4) Run the end-to-end smoke (unsigned local dev mode):

- `mise run macos-smoke`
- `mise run install-macos` (alias)

This task:

- Installs `target/release/KageHelper.app` to `/Applications/KageHelper.app`
- Loads + restarts the LaunchAgent for `com.kage.daemon`
- Sets `KAGE_LOCAL_DEV=1` for the LaunchAgent (bypasses Team ID enforcement)
- Runs `./target/release/kage doctor`
- Runs a `sops` encrypt/decrypt using `SOPS_AGE_KEY_CMD="kage identity"`

By default it uses the `prod` environment if present (otherwise the first env from `kage list`).
Override with `KAGE_SMOKE_ENV=<env>`.

## Local dev mode (unsigned)

During local development you can bypass Team ID enforcement by running the XPC daemon in local dev mode:

- `launchctl setenv KAGE_LOCAL_DEV 1`
- `launchctl kickstart -k gui/$(id -u)/com.kage.daemon`

## Codesigning (required for Team ID enforcement)

The daemon enforces that the caller’s Apple Team ID matches its own. Ensure the app and the Rust binaries are signed with the same Team ID.

- Create `.env.local` from `.env.example` and set:
  - `KAGE_DEVELOPMENT_TEAM` (your Apple Team ID)
  - `KAGE_BUNDLE_IDENTIFIER` (optional; if you need a unique bundle id for your local Apple team)
  - `KAGE_CODESIGN_IDENTITY` (e.g. `Apple Development: ... (TEAMID)` or the SHA-1 from `security find-identity -v -p codesigning`)
- Build + sign + run the end-to-end smoke:
  - `mise run macos-smoke-signed`
  - `mise run install-macos-signed` (alias)

The signed smoke also asserts the security contract that an unsigned client binary is rejected by the daemon.

- Check the daemon Team ID: `codesign -dv --verbose=4 /Applications/KageHelper.app 2>&1 | rg TeamIdentifier`
- Check the CLI Team ID: `codesign -dv --verbose=4 target/release/kage 2>&1 | rg TeamIdentifier`
- Check the plugin Team ID: `codesign -dv --verbose=4 target/release/age-plugin-kage 2>&1 | rg TeamIdentifier`

## Smoke test

If you want to run it manually instead of `mise run macos-smoke`:

- `./target/release/kage doctor`
- `./target/release/kage list`
- Encrypt/decrypt via sops (using mise-managed `sops`):
  - `RECIPIENT="$(./target/release/kage list | awk 'NR==1 {print $2}')"`
  - `export PATH="$PWD/target/release:$PATH"`
  - `export SOPS_AGE_KEY_CMD="$PWD/target/release/kage identity"`
  - `printf "secret\n" | mise exec -- sops -e --age "$RECIPIENT" /dev/stdin > /tmp/kage-test.sops`
  - `mise exec -- sops -d /tmp/kage-test.sops`

## Strong policy

- Without an unlock session, `policy=strong` will prompt per operation.
- For batch operations (avoid repeated prompts), start a short unlock session:
  - `./target/release/kage unlock --env <env> --duration 60`

## Debugging

- LaunchAgent status: `launchctl print gui/$(id -u)/com.kage.daemon`
- Helper logs: `tail -f ~/.kage/agent.log`
- Live logs: `log stream --predicate 'process == "KageHelper"' --style compact`
