Kage v2: Security & Cryptography

This document specifies the cryptographic primitives and security invariants for Kage v2.

## 1. Cryptographic Primitives

| Component | Primitive | Rationale |
|-----------|-----------|-----------|
| KDF | HKDF-SHA256 | Industry standard for key derivation. |
| Symmetric Encryption | XChaCha20-Poly1305 | 24-byte nonce eliminates collision risk for random nonces. |
| Recipients | BLAKE3 (Truncated) | High performance; 128-bit collision resistance sufficient for handles. |
| ID Encoding | Bech32 | Error detection; distinct look from hex/base64. |

## 2. Key Derivation

### 2.1 Canonicalization

To ensure consistent hashes, input strings are canonicalized using length-prefixing:

```
LE_U64(len(str)) || str
```

### 2.2 $K_{env}$ (The Hardware Key)

The persistent environment key derived from the root:

$$K_{env} = \text{HKDF-SHA256}(\text{salt}=\varnothing, \text{ikm}=K_{org}, \text{info}=\text{Info}_{env})$$

Where $\text{Info}_{env}$ is:

```
"kage-v2-env" || Canonical(org) || Canonical(env)
```

### 2.3 $K_{wrap}$ (The Encryption Subkey)

We NEVER use $K_{env}$ to encrypt data directly. We derive a specific subkey:

$$K_{wrap} = \text{HKDF-SHA256}(\text{salt}=\varnothing, \text{ikm}=K_{env}, \text{info}=\text{"kage-v2-wrap"})$$

## 3. Stanza Integrity (AAD)

To prevent "Splicing Attacks" (where a valid ciphertext from one file is pasted into another file's stanza), we bind the encryption to the Key ID.

Algorithm:

```
XChaCha20Poly1305_Encrypt(Key=K_wrap, Nonce=Rand(24), Plaintext=FileKey, AAD=Context)
```

AAD Construction:

```
0x02 (Protocol Version) || 16-byte raw KID
```

If the AAD does not match during decryption, Poly1305 will reject the ciphertext.

## 4. Policy Enforcement (The "Zero Cache" Rule)

The Daemon is the enforcement point.

### 4.1 "Strong" Policy

If policy = "strong":

Default: The Daemon MUST NOT store $K_{env}$ or $K_{wrap}$ in memory after an operation completes. Every request triggers a hardware unwrap -> User Prompt.

Explicit Unlock: If the user calls kage unlock, the Daemon creates an UnlockSession with a hard expiry (max 5 minutes). The key is wiped from memory when the timer expires.

### 4.2 "Presence" Policy

Default: Daemon maintains an LRU Cache.

Behavior: First access prompts user. Subsequent accesses within the TTL (5m) use cached key.