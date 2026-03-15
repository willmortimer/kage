# Transition Guide (v1 -> v2)

Kage v2 is not wire-compatible with v1. There is no in-place migration: you must decrypt with v1 and re-encrypt with v2 (“nuke and pave”).

See also: `docs/v2/REKEYING_GUIDE.md`.

## 1. Decrypt with v1

Use your existing v1 setup to obtain plaintext.

```bash
sops -d secrets/dev.yaml > secrets/dev.plain.yaml
sops -d secrets/prod.yaml > secrets/prod.plain.yaml
```

## 2. Remove v1 integration

- Remove any `AGE_IDENTITIES_COMMAND` / `SOPS_AGE_KEY` exports pointing at v1.
- Remove v1 configs and cached data (locations vary by platform).

## 3. Install and enroll v2

From the repo:

```bash
mise install
just build
```

Start the daemon and enroll:

```bash
./target/release/kaged
./target/release/kage setup --org my-org --env dev --env prod --1p-vault "Private"
```

## 4. Update `.sops.yaml` recipients

Run:

```bash
./target/release/kage list
```

Replace old recipients with the new `age1kage1...` recipients.

## 5. Re-encrypt with v2

Ensure `age-plugin-kage` is on `PATH`, then encrypt and verify:

```bash
export PATH="$PWD/target/release:$PATH"
sops -e --age "age1kage1..." secrets/dev.plain.yaml > secrets/dev.yaml
sops -d secrets/dev.yaml
```

If decryption succeeds, securely delete plaintext files and commit the updated `.sops.yaml` + encrypted secrets.

