Kage v2: IPC Protocol Specification

This document defines the interface between the Client (age-plugin-kage, kage-cli) and the Daemon.

## 1. Transport Abstraction

The Rust client defines a trait that bridges the OS difference:

```rust
#[async_trait]
pub trait DaemonTransport: Send + Sync {
    /// Resolve org/env string to a public Key ID (KID)
    async fn resolve_identity(&self, org: &str, env: &str) -> Result<String, Error>;
    
    /// Encrypt a file key (Client -> Daemon)
    async fn wrap_key(&self, kid: &str, file_key: &[u8]) -> Result<Stanza, Error>;
    
    /// Decrypt a file key (Daemon -> Client)
    async fn unwrap_key(&self, stanza: &Stanza) -> Result<Vec<u8>, Error>;
    
    /// Explicitly start a session (for Strong policy)
    async fn unlock(&self, kid: &str, duration_seconds: u32) -> Result<(), Error>;
    
    /// Diagnostics
    async fn ping(&self) -> Result<String, Error>;
}
```

### 1.1 macOS Transport (XPC)

Service Name: `com.kage.daemon`

Protocol: Defined in Swift/ObjC.

Serialization: Native NSDictionary / NSData.

Security: NSXPCConnection validates the client's Code Signature (Team ID must match Daemon).

### 1.2 Linux Transport (JSON-RPC)

Socket: `~/.kage/kaged.sock` (AF_UNIX).

Protocol: JSON-RPC 2.0.

Security: SO_PEERCRED checks (Client UID must match Daemon UID).

## 2. API Methods & Data

### 2.1 ResolveIdentity

Purpose: Get the public KID for an environment (used by kage list).

In: org, env

Out: kid (Bech32 string)

### 2.2 WrapKey

Purpose: Encrypt a file key.

In: kid (Bech32), file_key (32 bytes)

Out: stanza { kid, nonce (24 bytes), payload }

### 2.3 UnwrapKey

Purpose: Decrypt a file key.

In: stanza

Out: file_key (32 bytes)

Behavior: Triggers User Prompt if session not active.

### 2.4 Unlock

Purpose: Explicitly start a cached session for "Strong" environments.

In: kid, duration (seconds)

Out: success (bool)

## 3. Error Codes

All transports must map errors to these standard codes for the Client to handle gracefully.

| Code | Name | Description | Client Action |
|------|------|-------------|---------------|
| -32001 | KeyNotFound | KID not found in local config. | Fail hard. |
| -32002 | AuthCancelled | User clicked Cancel on prompt. | Retry possible. |
| -32003 | AuthFailed | Biometry mismatch / Wrong PIN. | Retry possible. |
| -32004 | PolicyViolation | Client signature check failed. | Fail hard. |
| -32005 | ConfigError | Daemon config is corrupt. | Fail hard. |
| -32006 | DaemonBusy | Hardware is currently handling a request. | Retry with backoff. |