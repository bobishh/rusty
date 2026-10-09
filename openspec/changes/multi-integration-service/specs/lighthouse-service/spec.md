## ADDED Requirements

### Requirement: Multi-integration registry
Lighthouse SHALL serve N admitted integrations with independently authorized scopes, persistence, quotas and lifecycle through one service identity and transport node.

#### Scenario: Independent controllers
- **WHEN** two controllers connect different board sets
- **THEN** both integrations replicate and neither can enumerate, mutate or export the other's settings/data.

#### Scenario: Overlapping workspace
- **WHEN** another integration requests a workspace already assigned elsewhere
- **THEN** the service returns an explicit scope conflict without replacing its genesis or routing.

#### Scenario: Add scope while running
- **WHEN** an authorized integration adds a board
- **THEN** the scope starts without restarting unrelated scopes, intake or the transport node.

### Requirement: Authenticated admission
Lighthouse MUST require authenticated operator approval and valid controller approval bound to one expiring transcript before obtaining board access.

#### Scenario: Pending public request
- **WHEN** a remote client posts a pairing request
- **THEN** only bounded pending state is created; no board import or auto-claim occurs.

#### Scenario: Unauthenticated approval
- **WHEN** a caller knows a request ID or transcript code but lacks an operator session
- **THEN** operator approval is denied.

#### Scenario: Replay or changed payload
- **WHEN** a stale, altered, replayed or cross-service signed operation arrives
- **THEN** the service rejects it or returns the original idempotent result without repeating side effects.

### Requirement: Persistent identity and recovery
Lighthouse SHALL reuse MetaMesh identity/recovery primitives, export an encrypted envelope with generated recovery words, and keep the root private key out of normal daemon storage.

#### Scenario: Provisioning
- **WHEN** the operator initializes a service
- **THEN** the service receives a certified working device and the operator can save the recovery envelope and 24-word phrase separately.

#### Scenario: Words without envelope
- **WHEN** the operator attempts recovery with words alone
- **THEN** the UI explains that the encrypted envelope is required and does not claim data recovery.

#### Scenario: Restart
- **WHEN** the service restarts with its durable volume
- **THEN** identity, integration IDs, scope data and monotonic route metadata are preserved.

#### Scenario: Device compromise recovery
- **WHEN** the operator uses the offline root to replace a device
- **THEN** shared core verifies replacement and revocation evidence; peers reject the old device once the revocation is accepted.

### Requirement: Read-only store and forward
Lighthouse SHALL replicate verified author-signed changes as a visitor and SHALL author changes only with explicit current editor permission.

#### Scenario: Owner offline delivery
- **WHEN** an editor writes, the visitor keeper persists, and another authorized peer later returns while the owner is offline
- **THEN** the returning peer receives and validates the original change through the keeper.

#### Scenario: Forged visitor edit
- **WHEN** the keeper device signs a new board edit under visitor access
- **THEN** the change is rejected by both native and browser admission.

#### Scenario: Automation downgrade
- **WHEN** a scope's editor access is removed
- **THEN** pending writes for that scope stop with an authorization reason while independent replication continues.

### Requirement: Authority updates and revocation
Lighthouse MUST apply verified ownership, access-epoch, device-revocation and departure transitions monotonically using shared Rust rules.

#### Scenario: Delayed grant after revoke
- **WHEN** a revoked participant presents an older validly signed grant
- **THEN** access is denied and authority is not rolled back.

#### Scenario: Transfer during replication
- **WHEN** a valid owner transition reaches the service
- **THEN** the service updates authority and accepts only actions authorized by the resulting state.

#### Scenario: Scope-local revocation
- **WHEN** a peer loses access to one of two scopes on the same route
- **THEN** only the revoked scope loses admission; the other remains usable.

### Requirement: Durable coverage and retry
Lighthouse MUST acknowledge only durably persisted validated data and MUST report separate document, chat and attachment coverage.

#### Scenario: Storage failure
- **WHEN** persisting a received batch fails
- **THEN** no success receipt is issued, pending changes retry after storage recovery, and the final ACK covers all accepted changes.

#### Scenario: Crash after ACK
- **WHEN** the process is killed after confirming a batch
- **THEN** the same validated changes and authority are recoverable after restart.

#### Scenario: Missing blob
- **WHEN** a descriptor arrives before its bytes
- **THEN** document coverage advances but attachment coverage stays pending until hash-verified bytes persist.

#### Scenario: Malformed scope message
- **WHEN** one scope receives an invalid protocol or authorization frame
- **THEN** the affected operation is diagnosed without restarting the shared node or unrelated scopes.

### Requirement: Capacity and fairness
Lighthouse SHALL enforce configured limits before unbounded allocation and schedule work fairly between integrations.

#### Scenario: Saturated admission
- **WHEN** pending requests or scope capacity reaches its configured limit
- **THEN** new requests receive a bounded actionable error without damaging active integrations.

#### Scenario: Noisy integration
- **WHEN** one tenant exhausts its queue/storage/transfer budget
- **THEN** its work is throttled while another admitted integration progresses.

#### Scenario: Repeated node closure
- **WHEN** the transport node fails repeatedly under eventual network availability
- **THEN** the supervisor recreates it and scopes converge without browser reload; obsolete sessions/timers are cleaned up.

### Requirement: Deployable and observable service
Lighthouse SHALL provide a documented standalone container deployment with persistent storage, operator setup, optional automation and distinct liveness/readiness.

#### Scenario: Fresh generic deployment
- **WHEN** an operator launches the documented configuration on a non-personal hostname without Jev credentials
- **THEN** discovery, operator pairing and replication work with automation disabled.

#### Scenario: Offline peer
- **WHEN** an otherwise healthy service has no online peers
- **THEN** readiness remains healthy while per-scope connectivity reports offline.

#### Scenario: Unavailable storage
- **WHEN** durable storage fails
- **THEN** readiness fails or reports the documented degraded policy, durable ACKs stop, and public diagnostics contain no secrets.

### Requirement: Migration and intake routing
Lighthouse SHALL explicitly import existing singleton state once and route every automation job to a configured integration and scope.

#### Scenario: Existing production state
- **WHEN** an operator imports a stopped singleton installation
- **THEN** public identities, grants, documents, chat and inbox/results are preserved and import is idempotent.

#### Scenario: Interrupted import
- **WHEN** the process crashes before registry activation
- **THEN** startup recovers staging or the old consistent state without reporting partial activation as success.

#### Scenario: Second integration
- **WHEN** a new integration is added beside the job-intake scope
- **THEN** existing intake still targets the original explicit binding and never broadcasts to all boards.
