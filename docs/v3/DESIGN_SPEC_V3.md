# Kage v3 Final Design Specification
## Local Trust Runtime with First-Class Capability Adapters
### Consolidated Design After Review, with Windows + WSL2 Implementation Plan

**Date:** March 14, 2026  
**Status:** Final v3 design specification for implementation planning  
**Predecessors:**  
- Kage v1: hardware-backed age/SOPS key derivation shim  
- Kage v2 (implemented): native hardware-backed age plugin with daemon-enforced policy  
- Kage v3 draft: generalized local trust runtime vision  
- Post-review addendum: implementation constraints and engineering refinements

---

## 1. Executive Summary

Kage v3 evolves the current implemented v2 system from a specialized hardware-backed age plugin into a broader **local trust runtime** for developer workflows.

The existing v2 implementation already proved the hardest thing:

> A resident local daemon, backed by native platform security, can enforce policy and perform narrow cryptographic operations on behalf of standard developer tooling.

v3 generalizes this without destroying the working v2 architecture.

Kage v3 is built around the following concrete priorities:

1. Preserve and harden the existing age plugin as the flagship adapter.
2. Build `kage run` as the second flagship adapter.
3. Establish an explicit, crash-tolerant audit subsystem.
4. Build a generic signing API using hardware-sealed but software-generated asymmetric keys.
5. Use the signing substrate for Git signing, local auth assertions, and artifact signing.
6. Bring Windows and WSL2 to first-class status without faking bare-metal Linux semantics inside WSL.

The product-level shift is:

### v2 framing
Kage is a hardware-backed age plugin with an admin CLI.

### v3 framing
Kage is a local trust runtime whose first shipping adapter is the age plugin.

That is the final synthesis.

---

## 2. What Kage v3 Is

Kage v3 is a **local capability security runtime** for developer systems.

It provides:

- a resident daemon/agent
- hardware-backed or OS-backed protection of local state
- policy-gated, scope-bound trust operations
- explicit user session/unlock semantics
- adapter-driven integrations with developer tools

The daemon is the product.  
Adapters are clients of the daemon.

---

## 3. What Kage v3 Is Not

Kage v3 is not:

- a hosted enterprise secret manager
- a full password manager
- a full SSH suite
- a full GPG replacement
- a full PKI platform
- a cloud IAM replacement
- a package registry or artifact trust ecosystem

Kage owns **local trust execution**.

---

## 4. Core Architectural Principles

1. **The daemon is the authority**
   - All sensitive operations flow through the daemon.

2. **Adapters are clients**
   - Tool-specific behavior lives in adapters, not in the core trust model.

3. **Narrow capability materialization**
   - Kage should materialize only what is needed for the current operation, for the shortest time possible.

4. **Stable v2 age path first**
   - The working age plugin remains the flagship adapter and reference implementation.

5. **Pragmatic generalization**
   - No giant transport or schema rewrite until at least two materially different adapters are shipping.

6. **One session model, one policy model, one audit model**
   - Every new adapter must reuse these.

7. **Advisory context is not authoritative security**
   - Repo path, cwd, process tree, and similar metadata are useful, but not strong trust anchors in early phases.

---

## 5. High-Level Runtime Lifecycle

The final generalized internal runtime lifecycle is:

**Trust Anchor -> Scope Resolution -> Policy Evaluation -> Capability Materialization -> Adapter Execution -> Audit**

This is the core v3 loop.

### 5.1 Trust Anchor

A trust anchor is the root local or imported material from which Kage operations are authorized or derived.

Examples:
- team bootstrap secret in 1Password
- solo local root
- imported recovery material
- hardware-sealed local enrollment state
- future wrapped signing root

### 5.2 Scope Resolution

Every operation resolves scope before any capability is materialized.

### 5.3 Policy Evaluation

The daemon decides whether the operation may proceed given:
- requested scope
- policy level
- session state
- protector availability
- adapter type

### 5.4 Capability Materialization

Kage materializes the minimal required capability:
- wrapping key
- plaintext secret release
- signing operation
- short-lived assertion

### 5.5 Adapter Execution

The adapter performs the tool-specific step:
- unwrap age file key
- launch process with secrets
- sign bytes
- issue local assertion
- sign artifact digest

### 5.6 Audit

Every meaningful operation is auditable with no secret leakage.

---

## 6. Scope Model

Every operation must resolve a scope.

To avoid weak or spoofable local metadata becoming a false security anchor, v3 splits scope into **authoritative** and **advisory** dimensions.

### 6.1 Authoritative Scope

These are the real security boundaries evaluated by the daemon:

- `project`
- `environment`
- `adapter`
- `capability_class`

These are the inputs that determine whether Kage is allowed to proceed.

### 6.2 Advisory Scope

These are contextual signals that may be useful but are not authoritative in early phases:

- `cwd`
- `repo_root`
- `process_tree`
- `target_service_name`
- `invoked_command`
- `artifact_path`

These may be used for:
- richer audit trails
- soft warnings
- future advisory allowlists
- UI context

They must **not** be treated as the root of trust in Phase 1 or Phase 2.

---

## 7. Capability Classes

Kage v3 introduces explicit capability classes. This is the core internal generalization of v2.

### 7.1 `WrapUnwrap`

Purpose:
- protect or recover encrypted material for another system

Examples:
- current age file-key wrapping/unwrapping
- future encrypted envelope operations

Primary adapter:
- age plugin

### 7.2 `SecretRelease`

Purpose:
- release scoped plaintext secrets/config into a runtime context

Examples:
- `kage run`
- future devcontainer handoff
- future WSL-local process secret release

Primary adapter:
- runtime adapter

### 7.3 `Sign`

Purpose:
- sign bytes or structured payloads under a scoped identity

Examples:
- generic sign
- Git commit or tag signing
- artifact digest signing
- future signed metadata flows

Primary adapters:
- generic signing adapter
- Git signing adapter
- artifact signing adapter

### 7.4 `Assert`

Purpose:
- produce short-lived trust assertions for local or developer workflows

Examples:
- local admin CLI auth to local API
- short-lived role assertion for a privileged dev operation
- future local mTLS/cert-style issuance

Primary adapter:
- local auth assertion adapter

### 7.5 `SessionGrant`

Purpose:
- represent temporary approval windows for repeated operations

Examples:
- `kage unlock --env prod --duration 60s`
- future capability-scoped unlocks
- future adapter-specific batch grants

This is a shared system capability, not a user-facing adapter.

---

## 8. Session and Policy Model

The existing v2 policy model is correct in spirit and should be preserved.

### 8.1 Policy Levels

Human-facing policy remains:

- `none`
- `presence`
- `strong`

### 8.2 Early v3 Session Behavior (Phases 1 and 2)

For early v3, keep the session model close to v2:

- unlock binds to **project/environment**
- session applies to all currently implemented capabilities for that scope
- strong policy remains zero-cache by default unless explicitly unlocked
- unlocks are bounded by explicit duration

This keeps complexity under control while `kage run` is introduced.

### 8.3 Later v3 Session Behavior (Phase 3+)

Only after generic signing exists and multiple capability classes are real should Kage add:

- capability-scoped unlocks
- adapter-scoped unlocks
- narrower session grants like:
  - “sign only”
  - “artifact only”
  - “runtime secret release only”

This is explicitly deferred.

---

## 9. Cryptographic Strategy

## 9.1 Symmetric Operations

For `WrapUnwrap` and `SecretRelease`, Kage continues to rely on the proven v2 derivation strategy:

- HKDF-SHA256 for derivation
- XChaCha20-Poly1305 for wrapping/sealing where applicable

This preserves the v2 age plugin’s security model.

## 9.2 Asymmetric Signing Strategy

Asymmetric signing introduces platform fragmentation.  
Secure Enclave, TPM2, and Windows crypto stacks do not all map neatly to the same modern signing key types.

### Final v3 Strategy for Early Signing

Early v3 will **not** require native hardware generation of the final public key type.

Instead:

1. Kage generates signing key material in software.
2. The signing key is sealed/wrapped under the platform protector.
3. The daemon governs unsealing and signing usage under policy.
4. Reusable signing keys are not exported by default.

This gives:
- cross-platform consistency
- strong local protection
- simpler implementation
- consistent developer UX

It matches the spirit of v2: the hardware root protects and gates use, even if the downstream key type is not natively generated by the hardware module.

---

## 10. Subsystems

## 10.1 Core Runtime Subsystems

Kage v3 consists of the following core subsystems:

1. **Protector subsystem**
   - hardware-backed or OS-backed sealing/unsealing

2. **Policy subsystem**
   - evaluates policy level, session state, and scope

3. **Session subsystem**
   - tracks unlock state and expiry

4. **Capability subsystem**
   - materializes requested capabilities

5. **Adapter registry**
   - dispatches operations to adapter implementations

6. **Transport subsystem**
   - IPC between clients and daemon

7. **Audit subsystem**
   - append-only operation logging

## 10.2 Transitional IPC Strategy

The review feedback was correct: do not over-generalize transport too early.

### Step A — Transitional Envelope

Add a small versioned envelope that routes by:
- adapter
- capability class
- operation

But allow the age adapter to keep its optimized internal request shape while the runtime adapter is being introduced.

### Step B — Stable General Core

Once both:
- age adapter
- runtime adapter

successfully use the generalized routing layer, promote it into the stable daemon contract.

### Formal IDL

A formal IDL such as Protobuf or Cap'n Proto is explicitly deferred until:
- Rust/Swift duplication becomes painful
- more than two real adapters exist
- schema maintenance becomes a real bottleneck

Do not front-load this.

## 10.3 Audit Subsystem

Audit is now a required subsystem.

### Minimum audit goals

- append-only NDJSON or equivalent structured log
- atomic append where practical
- event schema versioning
- crash-tolerant best-effort write semantics
- no secrets or plaintext values
- session creation, reuse, and expiry explicitly logged
- authoritative and advisory scope recorded separately

Audit must cover:
- age operations
- runtime secret release
- unlock/lock/session events
- signing operations
- assertion issuance
- policy denials
- errors

Tamper-evidence can be future scope.
Append-only operational logging is enough for the initial system.

---

## 11. First-Class Adapters

## 11.1 age Adapter (Flagship)

This remains the flagship adapter and the reference implementation for v3 design discipline.

Responsibilities:
- current stanza wrapping/unwrapping
- age plugin protocol integration
- explicit unlock behavior for repeated operations
- adapter reference for `WrapUnwrap`

v3 must preserve this path and harden it, not replace it.

## 11.2 Runtime Adapter (`kage run`)

This is the second flagship adapter.

Responsibilities:
- gather scoped secrets/config
- release them to child process or process tree
- support multiple delivery modes
- cleanup temp artifacts
- audit runtime secret release

Primary secret sources:
1. repo-shared encrypted config
2. scope-specific overlays
3. machine-local sealed overrides
4. optional imported bootstrap values

Initial delivery modes:
- environment variables
- temp files

Later delivery modes:
- stdin/pipe
- inherited FD
- local session socket
- container/devcontainer handoff

## 11.3 Generic Signing Adapter

This is the foundational signing substrate.

Responsibilities:
- sign bytes
- sign structured payloads
- expose public signing identity
- keep signing policy and session logic in the daemon

## 11.4 Git Signing Adapter

Built on top of the generic signing adapter.

Responsibilities:
- sign commit payloads
- sign tag payloads
- expose Git-appropriate public identity
- later support richer advisory repo context and UX warnings

## 11.5 Local Auth Assertion Adapter

Built on top of signing.

Responsibilities:
- issue short-lived local assertions
- support local CLI → local service trust
- support role- or purpose-scoped assertions
- later support richer dev infra trust patterns

## 11.6 Artifact Signing Adapter

Built on top of signing.

Responsibilities:
- sign artifact digests
- sign release manifests
- sign provenance/SBOM-style payloads
- bridge to standard external verification paths rather than inventing a new verification ecosystem

---

## 12. Windows Architecture for v3

Windows is now an immediate implementation target, not an afterthought.

The correct Windows design is:

- Rust remains canonical for core/runtime logic
- the Windows daemon remains the authority
- the Windows GUI is a thin native shell over the daemon
- WSL2 is treated as a first-class client of the Windows daemon

## 12.1 Windows Process Model

### `kage-agent.exe`
Per-user background daemon.

Responsibilities:
- named pipe server
- protector integration
- policy/session/capability logic
- adapter registry
- audit writing
- runtime secret release coordination
- future signing/assertion operations

### `kage.exe`
Canonical CLI on Windows.

Responsibilities:
- admin commands
- unlock/lock/session commands
- runtime invocation
- diagnostics
- future signing/assertion commands

### `KageUI.exe`
Native Windows GUI shell.

Responsibilities:
- user-facing status
- unlock prompts and session management
- diagnostics
- bootstrap/setup
- project/env visibility
- runtime secret and adapter visibility
- audit viewer
- settings and policy UX

The GUI is not the authority. The daemon is.

## 12.2 Windows Protector Strategy

For immediate Windows development, the protector strategy should be staged.

### Stage 1 — Windows software-backed + OS-protected baseline
Use:
- DPAPI for sealing local state
- CNG for signing operations where needed
- Windows Hello integration for presence/strong prompts where practical

This is enough to begin development and testing on Windows now.

### Stage 2 — TPM-backed protector
Add:
- TPM-backed sealing for stronger local root semantics
- policy-aware use of Hello/PIN/biometric auth
- parity with the macOS/Linux trust model where practical

Do not block Windows bring-up on full TPM integration if DPAPI-backed sealing gets the core architecture moving sooner.

## 12.3 Windows IPC

Use:
- named pipes for daemon IPC
- versioned envelope matching the v3 transitional IPC strategy

The Windows daemon should be treated as equivalent in authority to:
- XPC-based macOS daemon
- Unix-socket Linux daemon

## 12.4 Windows Immediate Development Stack

### Core
- Rust for core crates, agent, and CLI

### GUI
Recommended first implementation:
- **C# + WPF**

Why WPF first:
- fast to build tray-heavy utility UI
- stable for desktop utility workflows
- easy interop with named pipes and Windows Hello UI glue
- lower friction than jumping directly into a more aesthetic but more involved shell

Future option:
- WinUI 3 shell or settings surface later, if desired

But for immediate development and testing, WPF is the right call.

---

## 13. WSL2 Architecture for v3

WSL2 should not be treated as a fake bare-metal Linux peer with direct TPM semantics.

The correct design is:

**WSL2 is a first-class client of the Windows Kage daemon.**

That is the key architectural decision.

## 13.1 Why

This gives:
- one trust anchor model on Windows hosts
- one authoritative daemon
- one session model
- one audit stream
- no fragile fantasy TPM passthrough assumptions

## 13.2 WSL2 Process Model

### Windows side
- `kage-agent.exe` remains authoritative

### WSL side
Ship a Linux-side `kage` bridge client whose job is to:
- speak to the Windows daemon
- translate Linux execution semantics into Windows daemon requests
- perform Linux-local process spawning for `kage run`

This is crucial:
the Windows daemon should authorize and materialize the capability,
but the WSL bridge should spawn the Linux child process inside WSL.

That gives:
- Windows-controlled trust
- Linux-native runtime behavior

## 13.3 WSL2 Bridge Responsibilities

The WSL bridge should support:

- `kage doctor`
- `kage unlock`
- `kage lock`
- `kage age-*` interactions that need daemon approval
- `kage run` for Linux-local process spawning
- later `kage sign` and `kage assert`

### For `kage run`
The flow should be:

1. WSL CLI resolves user intent locally.
2. WSL bridge sends a scoped request to Windows daemon.
3. Windows daemon evaluates policy/session and resolves secret material.
4. Windows daemon returns approved runtime release payload or stream.
5. WSL bridge injects secrets into the Linux child process using WSL-local delivery mode.
6. WSL bridge performs cleanup and emits final status back to daemon for audit completion where needed.

This is the clean model.

## 13.4 WSL2 Delivery Modes

Immediate support:
- env vars
- temp files inside the Linux filesystem

Do not start with:
- `/mnt/c` storage
- shared Windows filesystem temp artifacts
- fake Windows-side spawn of Linux child process

Keep WSL temp/runtime state inside Linux filesystem space.

## 13.5 WSL2 Immediate Development Plan

Stage 1:
- simple Linux shim that shells to `kage.exe` for non-runtime operations

Stage 2:
- real WSL bridge binary with structured daemon communication
- Linux-local `kage run`
- Linux-local cleanup and audit correlation

Stage 3:
- integrate with future signing and assertion surfaces

This lets you start immediately while still converging on the right architecture.

---

## 14. GUI Design for v3

The GUI needs to evolve from “helper/tray prompt shell” into a real but still lightweight **control surface for the local trust runtime**.

It should remain thin.  
It should not become the real business logic owner.

## 14.1 GUI Goals

The GUI should let the user:

- understand what Kage is doing now
- see which adapters are active
- see which projects/environments are enrolled
- unlock and revoke sessions
- inspect audit activity
- manage local runtime secrets and overrides
- diagnose protector/backend issues
- perform first-run bootstrap and recovery actions
- later inspect signing identities and assertion policies

## 14.2 GUI Information Architecture

The GUI should be designed around v3 capability classes and adapters.

### A. Home / Status
Show:
- daemon running or not
- protector backend in use
- active sessions
- last policy prompt
- adapter activity summary
- warnings or degraded mode banners

### B. Projects & Environments
Show:
- enrolled projects
- environments per project
- policy level per environment
- last-used timestamps
- whether local overrides exist
- whether unlock is currently active

### C. Sessions
Show:
- active sessions
- scope bound to each session
- expiry
- whether session came from explicit unlock
- revoke button

### D. Adapters
Show:
- age adapter status
- runtime adapter status
- signing adapter status
- Git signing availability
- artifact signing availability
- assertion adapter availability

Each adapter page should show:
- current capability status
- recent usage
- settings and diagnostics relevant to that adapter

### E. Runtime Secrets
Show:
- local overrides per project/env
- source metadata
- edit/import/delete actions
- whether repo-shared sources are configured
- default delivery mode

This is especially important once `kage run` exists.

### F. Signing
Show:
- signing identities
- enabled signing scopes
- whether signing keys are sealed and available
- future Git/artifact/assert usage status

### G. Audit
Show:
- recent events
- filter by project/env/adapter/capability/result
- session creation/use/revocation
- warnings and denials

### H. Setup / Recovery / Settings
Show:
- bootstrap references
- protector backend config
- audit/log settings
- import/export recovery
- transport diagnostics
- WSL integration state on Windows
- update channel or version info later if needed

## 14.3 GUI Interaction Patterns

The GUI should support:

- tray icon with status color/state
- quick actions:
  - unlock
  - lock
  - open audit
  - open projects
  - open settings
- focused unlock prompts
- toast/notification integration for:
  - policy prompts
  - session expiry
  - audit-worthy warnings
  - protector failures

## 14.4 Windows-Specific GUI Plan

For immediate Windows development:

Use **WPF** with:
- tray integration
- named pipe client to daemon
- Windows Hello prompt glue where needed
- structured MVVM layout so the shell stays thin

Do not bury security logic in the GUI.
The GUI should call daemon APIs and render state.

---

## 15. Immediate Implementation Plan

This section is intentionally practical.

The goal is to get you building and testing on Windows now, while keeping the design aligned with final v3.

## Immediate Track A — Core v3 Refactor Without Breaking age

### Step A1
Refactor current daemon internals to introduce:
- capability class enum
- adapter registry
- explicit authoritative vs advisory scope structs
- generic audit event envelope

Do not change age behavior yet.

### Step A2
Wrap current age operations behind:
- `WrapUnwrap`
- age adapter interface

Keep current transport and plugin behavior stable.

### Step A3
Add append-only audit subsystem:
- NDJSON file
- schema version
- adapter + capability + scope fields
- session lifecycle events

### Step A4
Introduce transitional request envelope internally:
- operation
- adapter
- capability class
- scope
- advisory context

Do not force every transport path to fully flatten into one generic schema yet.

## Immediate Track B — Windows Bring-Up

### Step B1 — Windows Rust scaffold
Create:
- `kage-agent.exe`
- `kage.exe`
- shared named pipe transport layer
- Windows-specific protector abstraction

### Step B2 — Protector stage 1
Implement first Windows protector with:
- DPAPI sealing/unsealing
- software-generated local material
- Hello-aware auth hooks stubbed or partially integrated

This gets you real Windows testing without waiting for TPM.

### Step B3 — WPF tray shell
Build a minimal GUI with:
- status page
- sessions page
- projects/env page
- audit page
- settings page
- unlock/lock actions

### Step B4 — Windows integration tests
Add tests for:
- daemon launch
- named pipe request/response
- DPAPI seal/unseal
- unlock + session state
- audit write path
- GUI/daemon status sync where practical

## Immediate Track C — WSL2 Bring-Up

### Step C1 — Simple bridge
Ship a minimal WSL-side shim that forwards:
- `kage doctor`
- `kage unlock`
- `kage lock`
- simple age-related commands

to Windows `kage.exe`.

### Step C2 — Real bridge protocol
Add a structured WSL bridge client that can:
- connect to Windows daemon
- request scoped operations
- return runtime release data safely

### Step C3 — Linux-local `kage run`
Inside WSL:
- receive approved release payload from Windows daemon
- spawn Linux child process locally
- inject env vars or temp files in Linux FS
- cleanup after exit

### Step C4 — Audit correlation
Ensure WSL-originated requests are audited with:
- platform = wsl
- authoritative scope
- advisory Linux context
- result + cleanup outcome

## Immediate Track D — `kage run`

### Step D1
Implement secret source layering:
- repo-shared encrypted config
- scope overlays
- local sealed overrides

### Step D2
Implement initial delivery modes:
- env
- temp-file

### Step D3
Add GUI support:
- runtime configuration panel
- secret override management
- per-project delivery defaults

---

## 16. Phased Roadmap

## Phase 1 — Core Generalization
- preserve age plugin behavior
- capability classes
- adapter registry
- authoritative/advisory scope split
- audit subsystem
- transitional IPC routing
- Windows daemon/CLI/WPF bring-up
- WSL shim bring-up

## Phase 2 — Runtime Secret Release
- `kage run`
- Windows-native process injection
- WSL Linux-local process injection
- runtime GUI sections
- local override management
- stable audit for runtime operations

## Phase 3 — Generic Signing API
- software-generated, hardware-sealed signing keys
- generic sign command
- public identity surface
- introduce narrower session options only if warranted

## Phase 4 — Git Signing + Local Assertions
- Git commit/tag signing
- local signed assertions
- richer advisory repo UX
- signing management UI

## Phase 5 — Artifact Signing
- artifact signing adapter
- artifact verification bridges
- release-focused policy and audit UX

---

## 17. Risks and Controls

### Risk: Over-generalization destabilizes age
Control:
- age remains reference implementation
- transitional IPC first
- extract abstractions from working code

### Risk: Weak metadata becomes fake security
Control:
- authoritative vs advisory scope split
- early hard policy bound only to authoritative scope

### Risk: Windows TPM complexity delays real progress
Control:
- start with DPAPI-backed protector
- add TPM as stage 2

### Risk: WSL becomes awkward or second-class
Control:
- define WSL as first-class daemon client
- Linux-local runtime execution
- Windows-owned trust authority

### Risk: GUI becomes logic-heavy
Control:
- GUI is render/control shell only
- daemon remains source of truth

---

## 18. Final Recommendation

The final v3 synthesis is:

- keep the implemented v2 age plugin as the flagship adapter
- add explicit capability classes
- add `kage run` next
- add a real audit subsystem now
- add generic signing after runtime release
- build Git signing, local assertions, and artifact signing on top of the same signing substrate
- bring Windows up immediately with Rust core + named pipe daemon + WPF shell
- treat WSL2 as a first-class client of the Windows daemon, not as a fake bare-metal Linux peer

That is the most ambitious version of Kage that still stays coherent.

It preserves what is already strong, fixes what was too abstract, and gives you a concrete path to start building on Windows immediately.
