Kage Roadmap & Moonshot Features

This document outlines the trajectory for Kage post-v2.0. These features focus on elevating Kage from a developer tool to a compliance platform.

## v2.1: The "Break Glass" Protocol

Objective: Prevent coerced or compromised decryption of critical secrets (Production).

Concept:
Decrypting env=prod requires real-time remote approval in addition to local biometrics.

Workflow:

User runs sops -d prod.yaml.

Daemon detects policy=critical.

Daemon pauses and generates a Request Token (signed by device key).

Daemon pushes notification to 1Password / Slack / PagerDuty.

Alert: "User 'Will' requests decryption of 'prod.yaml' on 'MacBook-Pro'."

Security Admin clicks "Approve".

Server returns a time-bound Approval Certificate.

Daemon validates certificate + prompts user for Touch ID.

Decryption proceeds.

Why: Mitigates the "Developer Laptop Compromise" threat vector entirely for production data.

## v2.2: Cryptographically Verifiable Audit Logs

Objective: Tamper-evident logging for compliance.

Concept:
Current logs are plain text files that can be edited by a malicious user to hide access. v2.2 introduces a Merkle Chain for logs.

Implementation:

Each log entry is a JSON object containing:

```
{
  "prev_hash": "sha256_of_previous_entry",
  "timestamp": "ISO8601",
  "operation": "Decrypt",
  "target": "prod",
  "signature": "Sign(Device_SecureEnclave_Key, hash(this_entry))"
}
```


The chain acts as a local blockchain.

Sync: The CLI periodically pushes the "Head Hash" to a central transparency log (Git repo or S3 bucket).

Verification: kage audit verify checks the signature chain integrity.

## v2.3: SSH Agent Injection

Objective: Unified identity for Secrets and Infrastructure.

Concept:
Stop managing separate SSH keys. Kage derives an Ed25519 SSH keypair from K_env (using a unique HKDF info string).

Implementation:

kaged implements the SSH Agent protocol on a separate socket.

```
export SSH_AUTH_SOCK=~/.kage/ssh.sock
```

Accessing a server (ssh prod-server) triggers the same Touch ID prompt and policy as decrypting a file.

Result: Single Sign-On for Terminal.

## v2.4: Dynamic "Just-In-Time" Secrets

Objective: Eliminate static long-lived keys (K_org).

Concept:
Instead of storing K_org in 1Password, Kage authenticates to a central Vault (HashiCorp Vault / AWS KMS) to request a short-lived ephemeral key.

The age-plugin receives an ephemeral key valid for 1 hour.

If the device is reported lost, the central authority revokes access immediately.

No key rotation required, as keys expire automatically.