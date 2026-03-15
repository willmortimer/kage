# Age Plugin Protocol Reference (Kage v2)

Kage v2 integrates with `age` / `rage` / `sops` via the `age` plugin protocol, implemented using the Rust `age-plugin` crate.

## Plugin Naming

- Plugin name: `kage`
- Recipient HRP: `age1kage...` (Bech32)
- Plugin binary name: `age-plugin-kage` (must be on `PATH`)
- Identity HRP: `AGE-PLUGIN-KAGE-...` (Bech32, uppercase)

## State Machines

Age clients launch the plugin with:

- `--age-plugin=recipient-v1` during encryption
- `--age-plugin=identity-v1` during decryption

The plugin must support both to work with tools like `sops`.

## Kage v2 Recipient Encoding

Kage recipients are Bech32-encoded 16-byte Key IDs (KIDs):

- HRP: `age1kage`
- Data: 16-byte raw KID

## Kage v2 Stanza Format

Kage writes recipient stanzas in the age header:

```
-> kage {KID_Base64} {Nonce_Base64}
{Ciphertext_Base64}
```

- `KID_Base64`: base64 of the 16-byte raw KID
- `Nonce_Base64`: base64 of the 24-byte XChaCha20 nonce
- `Ciphertext_Base64`: base64 of the encrypted age file key

## Daemon Bridging

The plugin is stateless: it forwards wrap/unwrap operations to the per-OS daemon using the `DaemonTransport` trait described in `docs/v2/IPC_PROTOCOL.md`.

