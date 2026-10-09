## Context

Reviewed 2026-09-28. `src/main.rs::Config` contains one workspace and store. `src/join.rs` rejects multi-board invitations and an existing state directory, generating fresh identity seeds per join. `src/lib.rs::MatchLighthouseHost` rejects other scopes; catalog merge rejects nonempty revocations and ownership changes. HTTP currently exposes health, challenge and intake only. Cargo pins dependencies by Git revision; README's submodule statement is stale. Match's tests run its own legacy executable, not this repository's production binary.

## Goals / Non-Goals

**Goals:** A container or binary anyone can deploy, accepting N explicitly admitted integrations with M scopes each; reliable native replication, authenticated administration and recovery; bounded work and independent failures.

**Non-Goals:** Billing, anonymous open relay/storage, untrusted encrypted mailbox hosting, distributed service clustering, proof of remote deletion, or additional product adapters beyond Match in v1.

## Decisions

### 1. Domain model and trust boundary

Service: stable public identity, running device certificate/key, transport node and operator configuration.
Integration: opaque ID, app/protocol version, controller person ID, admitted controller device chain/revocations, policy revision, quotas and lifecycle.
Scope: integration ID + workspace ID, immutable genesis anchor, current authority/grants, local handshake, document/chat/blob state and durable coverage.
Automation binding: explicit integration ID + scope ID + permitted action set.

Use one service identity and one Iroh node for v1, with many scoped sessions. No identity per board. A process/store lock enforces a single writer; identical volume replicas cannot run concurrently. Integration isolation is logical authorization/storage isolation within a trusted operator process, not protection against that operator or process compromise.

Scope IDs are tenant-qualified internally. Opaque incoming IDs never become unchecked filesystem paths. If the same workspace is requested by another integration, v1 rejects it with a conflict rather than ambiguously routing it; intentional handover requires current authority and an explicit move. Scope secrets, receipts and route state are never looked up by endpoint alone. Revoking a route in one scope cannot close valid sessions in another.

### 2. Registry, lifecycle and independent scheduling

Replace singleton config with a durable versioned registry and scope stores:
- private service identity/device material;
- integrations and admission policies;
- per-integration scopes and evidence;
- per-integration automation inbox/results;
- recovery envelope and monotonic route/state metadata.

Transactions or a durable journal bind registry activation to validated staged scope files. Crash recovery resumes one recorded operation; temporary files never become active by discovery. Runtime scopes attach/detach without restarting HTTP or the shared Iroh node. Each scope has bounded work queues and independent retry state; a dead peer cannot sequentially block every scope for a 12-second timeout.

Protocol/auth failures quarantine the affected operation/scope with structured diagnostics. Transport failure retries with bounded backoff. Node death has a supervised restart and reattachment path for every active scope. Full disk denies new durable ACKs and pauses intake without busy loops or discarding queues.

### 3. Independent approvals

The service operator permits resource usage by a controller; workspace owners grant access to their data. Pinning a controller is not proof that it owns any given workspace. Use [protocol.md](protocol.md) for discovery and signed administrative requests, then existing MetaMesh workspace join for data-plane admission.

Operator UI lives under /admin. A high-entropy bootstrap secret supplied via file/container secret establishes an authenticated operator session; do not publish it in logs, URL query strings, discovery or public startup output. Use secure HttpOnly SameSite cookies, CSRF protection and rate-limited login. Closing/reopening the page preserves pending decisions; unattended operation never auto-accepts the first requester.

An operator can approve multiple unrelated controllers. Each controller can inspect/manage only its own integration. Operator access permits pause, capacity changes and deletion; it never lets the service forge an owner's grants.

### 4. Identity and recovery

Initialize a service identity before the first workspace join. Produce a versioned MetaMesh recovery envelope; use 24 generated words by default and document that both envelope and words are required. Reuse core crypto. Recovery restores identity, not board contents. Normal requests never contain recovery words.

Provision root material in an explicit operator recovery/setup flow; the daemon receives a certified working device key, not a plaintext root seed. Do not give that device unrestricted authority to mint replacements if the intended compromise response relies on root-only recovery. Store the envelope durably; allow authenticated export. Words are shown/exported during provisioning and are not retained as recoverable server text.

Server replacement from a backup can retain device material only after the old instance is stopped and a single-writer condition holds. Lost/compromised-device replacement uses offline root authorization to certify a new device and revoke the old one; admission/control-plane and workspace peers must verify and propagate the update. If current MetaMesh lacks a required recovery transition, implement it there and test end to end. No promise of immediate revocation at partitioned peers. Root compromise requires a new service identity and explicit reauthorization of integrations.

### 5. Replication and automation

Replicate mode uses visitor access if transport authorization allows forwarding other authors' signed changes; receiving peers validate original authorship and authority. Never silently upgrade to editor to bypass a failing check. Editor is an explicit per-scope choice for bots/intake writers.

Implement full signed authority catalog merge using shared Rust rules, including ownership transitions, membership/access epochs, departures and device revocation. A read-only service must accept valid editor-authored changes, persist them, and forward them to an offline returning peer while remaining unable to author edits.

Document, write proof, authority and checkpoint persistence precede success acknowledgements. Chat and blob coverage are separately tracked. Content-addressed bytes use mesh-blob primitives; authorization and retention are scope-aware even when storage later deduplicates bytes.

Existing HTTP intake binds explicitly to one integration/workspace. A newly added integration never becomes an implicit default destination. Disable writers on downgraded/revoked scopes, preserve failed jobs with a clear reason, and keep unrelated replication running. Replicas alone do not protect against replicated logical deletion; optional versioned backups are separate work.

### 6. Bounded self-hosting

Expose configured ceilings for integrations, scopes, total/per-integration storage, pending pairings, payload size, concurrent dials, blob transfers and automation queues. Enforce admission before allocating unbounded state. HTTP 429/Retry-After handles temporary saturation; capacity conflicts use structured errors and preserve existing scopes. Schedule fairly across integrations.

Provide one documented container entrypoint with persistent volume, public HTTPS origin, advertised metadata, allowed Match origins, operator bootstrap secret file and resource limits. Include compose example and existing Kamal wiring. No hardcoded personal domain, board, owner or compulsory Jev key. Intake/automation is optional; replication works without it.

Liveness means the process is running; readiness requires identity/store/runtime availability, not every offline peer being connected. Status/metrics expose queue depths, persisted coverage, bytes, reconnects and quota usage without secrets or customer document content.

## Risks / Trade-offs

- One service identity/device has a shared compromise radius → separate deployments for stronger tenant isolation; keep root offline and expose per-integration disable.
- One Iroh node failure affects all sessions → supervised restart and multi-scope convergence test.
- Old singleton data includes root material → explicit offline import, backup first, confirmed envelope export, then remove plaintext root from active service storage; backup handling remains operator responsibility.
- Native/browser dependency pins diverge → test the exact standalone binary against Match; update shared protocol fixtures together.

## Migration Plan

1. Add versioned registry and a dry-run singleton import that reports public IDs and target scopes only.
2. Stop existing writer, back up volume and import preserving service/person/device/workspace IDs, grants, authority, chat and inbox/results. Require operator binding of the existing integration controller.
3. Atomically activate new registry after validation; keep original backup read-only. Interrupted import is resumable and idempotent.
4. Deploy multi-scope service, then Match UI; confirm existing intake target remains unchanged.
5. Rollback uses stopped service and a matching backup/binary pair. Never run old singleton writer on new-format storage or overwrite newer accepted authority. No perpetual legacy runtime path.

## Open Questions

Choose the registry persistence mechanism during implementation and demonstrate crash consistency; a JSON file split alone is not sufficient evidence. Determine capacity defaults from a measured test profile. Visitor relay, authority updates and recovery revocation are release gates even if they require shared MetaMesh work. Twang remains a future adapter, not claimed support.
