## 1. Registry and runtime foundations

- [ ] 1.1 Add failing native scenarios for multiple scopes/controllers and record current singleton/authority limitations.
- [ ] 1.2 Implement versioned service/integration/scope registry with crash-consistent activation and a single-writer lock.
- [ ] 1.3 Add dry-run/idempotent singleton import preserving IDs, authority, chat, inbox/results and original backup.
- [ ] 1.4 Replace singleton host dispatch with tenant-qualified scope lookup and independent sessions/retry queues.
- [ ] 1.5 Add scope attach/detach without restart and node supervision that reattaches all active scopes.
- [ ] 1.6 Implement monotonic signed authority catalog/revocation merge through MetaMesh core; remove blanket rejection of authority changes.

## 2. Provisioning identity and administration

- [ ] 2.1 Implement offline-root setup with certified daemon device, 24-word encrypted-envelope export and no plaintext runtime root.
- [ ] 2.2 Implement operator bootstrap-secret login, secure sessions, CSRF controls and pairing administration UI.
- [ ] 2.3 Implement HTTPS discovery, configured CORS/origin, version/capability reporting and signed control request validation.
- [ ] 2.4 Implement durable mutual-approval state machine and shared transcript fixtures in MetaMesh; expose native/WASM adapters.
- [ ] 2.5 Extend existing join to multi-board staging using the existing service identity, exact approved scopes and resumable commit.
- [ ] 2.6 Add tenant-authenticated status, revisioned scope/policy updates, cancellation and admission-policy handling.
- [ ] 2.7 Prove certified device replacement/revocation propagation with offline recovery envelope; document root compromise boundaries.

## 3. Replication, quotas and automation

- [ ] 3.1 Implement/prove visitor relay preserving original author proofs; require explicit editor mode for local writers.
- [ ] 3.2 Persist document/proof/authority before complete ACK; expose authenticated document/chat coverage with crash/retry tests.
- [ ] 3.3 Add authorized hash-verified blob storage/transfer, missing-blob status and scoped retention.
- [ ] 3.4 Add admission, storage, queue, dial and transfer limits plus fair scheduling and structured errors.
- [ ] 3.5 Bind optional intake/automation to explicit integration/workspace and enforce current writer permissions.
- [ ] 3.6 Add pause/disconnect/local-delete semantics and test revoke isolation between scopes sharing a route.

## 4. Packaging and acceptance

- [ ] 4.1 Provide generic container/compose configuration, persistent volume, operator setup and optional Jev-free replication mode.
- [ ] 4.2 Update entrypoint, Kamal config, liveness/readiness and non-sensitive per-integration operational diagnostics.
- [ ] 4.3 Update stale README dependency/provisioning instructions and document install, pairing, recovery, limits, backup and safe rollback.
- [ ] 4.4 Run actual standalone binary against Match for two integrations × two scopes, owner-offline delivery and partial provisioning recovery.
- [ ] 4.5 Test storage failure → retry → ACK, crash after ACK, repeated node loss, stale grant/revoke and cross-tenant access attempts.
- [ ] 4.6 Measure a declared capacity profile with noisy/slow peers; record hardware, limits and observed memory/latency rather than claiming unbounded N.
- [ ] 4.7 Back up/import existing production state explicitly, deploy service through Kamal, verify old intake plus a disposable new integration, then enable Match UI.
