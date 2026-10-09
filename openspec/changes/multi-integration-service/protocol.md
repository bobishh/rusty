# Lighthouse integration HTTP contract v1 (proposed)

This is the canonical cross-repository control-plane contract for this change.
Match links here instead of maintaining a second definition. Implement signature
encoding, transcript binding and transition verification once in MetaMesh Rust,
with shared WASM/native fixtures. HTTPS control-plane admission composes the
existing workspace invitation protocol; it does not replace its data verification.

## Entities and identifiers

- Service: person ID/public key, running device certificate chain, transport endpoint.
- Controller: Match person ID and a currently authorized device/certificate chain.
- Integration: server-generated opaque ID; binds controller + service + app ID.
- Scope: workspace ID + immutable genesis anchor, within one integration.
- Operation: caller-generated random 128-bit-or-stronger ID and expected revision.
- Policy: finite capacity envelope, allowed application, permitted modes and
  explicit future-board authorization. Absence means no future-board authorization.

All routes below use JSON except the operator UI. Error bodies are
`{code, message, retryable, operationId?, scopeId?, retryAfterSeconds?}`.
No raw invitation, envelope secret, document body or private key appears in errors
or audit logs. GET health/discovery reveal no tenant names, board lists or credentials.

## Discovery

`GET /.well-known/mesh-lighthouse` returns:
`{protocolVersions:[1], service:{personId,publicKey,deviceId,certificates},
displayName, capabilities, publicOrigin, managementPath:"/admin"}`.
The configured origin must match the HTTPS origin used for subsequent requests.
The first trust decision compares the authenticated challenge below; a self-signed
discovery descriptor alone proves no prior ownership of the service.

Capabilities name supported product/protocol versions and read-only/document/chat/
blob coverage. Missing required capabilities block complete-replica setup or are
explicitly presented as partial coverage before approval. Redirects cannot silently
change origin or pinned identity. Plain HTTP is development-loopback-only.
CORS is an explicit operator-configured allowlist and is never authentication.

## Signed request format

Use MetaMesh's existing canonical signed envelope serialization under a dedicated
versioned Lighthouse control domain. The signed payload includes action, protocol
version, service person ID, service origin, controller person ID/device ID,
operation ID, expected integration revision where applicable, issuedAt, expiresAt
and the complete action-specific body. Certificate chains accompany the envelope.
The body itself is signed; there is no second ad hoc JSON hashing implementation.

Server validation checks the device chain, known revocations, pinned identity,
action permissions, time window (maximum 10 minutes, documented bounded clock
skew), operation replay and revision. Identical retries return the recorded result;
same operation ID with different payload is a conflict. Consumed operation IDs
remain remembered through expiration plus allowed skew. Management operations
after pairing also require a current server challenge obtained via an authenticated
request, preventing pre-generated batches from being used indefinitely.

## Pairing lifecycle

`POST /v1/pairings`: signed controller offer containing requested board IDs,
titles, genesis anchors, modes, policy and nonce. Return 202 with pairing ID,
expiry, authenticated operator URL, and a service-signed challenge binding the
offer, service identity, fresh nonce and assigned integration ID. No workspace
credentials or data are included at this stage. Bound rate, request size and
pending pairings before persistence/allocation.

A six-digit comparison code is derived in shared Rust from the full offer/challenge
transcript with a versioned domain separator. It is a human cross-check, not an
access token or a replacement for signatures. Display identical code, service/
controller fingerprints, scope list and modes in Match and authenticated /admin.

`POST /v1/pairings/{id}/decision`: signed controller approve/decline of exact
transcript. Operator approve/decline uses authenticated cookie+CSRF routes under
`/admin/api/pairings/{id}/decision`; knowing a public pairing ID cannot approve.
`POST /v1/pairings/{id}/status` accepts a signed controller status request and
returns the service-signed current state.

States:
`pending` (two independent approval flags) → `approved` →
`provisioning` → `active`.
Decline/expiry → `rejected`/`expired`.
Cancellation before active → `cancelling` → `cancelled` after cleanup of any
issued grants; unresolved revocation remains visible.
A recoverable provisioning failure keeps `provisioning` plus structured per-scope
errors. Restart never invents approvals or converts a partial install to active.

Once approved, Match creates an ordinary short-lived multi-workspace invitation
for the exact approved set. `POST /v1/pairings/{id}/provision` delivers that
invitation in a signed authenticated body. It is never placed in a URL, referrer,
browser analytics or access log. Lighthouse joins using its existing service
identity. Match binds approval to that identity and verifies the exact scopes/
modes; there is no blanket auto-approve of every guest reaching the invitation.
Normal WorkspaceJoinHandshake performs owner grant, authority and document
verification. Match suppresses only the duplicate human prompt already satisfied
by the exact transcript; protocol checks are unchanged.

Each scope is staged and verified before registry activation. A durable registry
commit activates the selected set only after every initial scope is ready.
Partial installation stays inaccessible to replication/automation and is resumable.
If an ACK/HTTP response is lost, recorded operation state makes retries idempotent.
Issued grants and their cancellation obligations remain tracked until settled.

## Active management

Signed controller endpoints:
- `POST /v1/integrations/{id}/status`: integration policy and scope health.
- `POST /v1/integrations/{id}/scopes`: add a revisioned set via the same
  provisioning validation. Existing admission policy replaces operator reapproval
  only within its explicit capacity/mode limits. Owner authority is always checked.
- `POST /v1/integrations/{id}/policy`: update future-board policy/limits;
  expansions beyond operator admission become pending operator decisions.
- `POST /v1/integrations/{id}/disconnect`: stop serving selected/all scopes.
  Match also issues normal workspace revocations; stopping service storage alone
  is not a cryptographic revocation. Track both effects separately.
- `POST /v1/integrations/{id}/delete-data`: separate confirmed retention action
  permitted by service policy; report local deletion, never remote-erasure guarantees.

Controller requests are scoped to its own integration. Operator routes can pause
or delete integrations but cannot manufacture owner signatures. The operator
bootstrap credential only establishes local operator access; there is no public
“first requester owns the server” endpoint. Same-identity device updates require
verified certificate/revocation evidence; a different person ID requires explicit
new authorization. Scope and integration revisions use compare-and-set.

## Replica coverage

A signed status response binds integration ID, scope ID, service/device identity,
authority revision, request challenge and persistence evidence:
document accepted frontier/heads, chat coverage, required/persisted blob hashes
(or authenticated paginated manifest references), lastPersistedAt and errors.
Evidence for another scope, stale challenge or revoked device is rejected.
Report sizes and manifest paging are bounded; unknown coverage is not complete.

Match determines coverage of its current changes, including frontier ancestry.
Health, HTTP 202, connection presence and received-but-uncommitted batches do not
qualify as durable evidence. Reuse the core durable batch ACK protocol for
data-plane delivery; the status API summarizes persisted evidence without
weakening ACK completeness requirements.

## Abuse and operational constraints

Reject unadmitted payloads, unsupported versions, invalid signatures and conflicts
before dialing. Invitation endpoints use validated Iroh IDs/addresses; arbitrary
HTTP callback URLs or redirects are not fetched by the pairing worker. Any future
remote fetch feature needs explicit destination validation and bounded responses.
Authenticate status as well as mutations; unguessable IDs alone are insufficient.

429 with Retry-After means temporary admission/queue saturation. 409 means
revision/scope conflict, 403 denied authorization, 410 expired pairing, 413 oversized
payload, 503 unavailable durable storage/runtime. Retryable transport failures
remain recoverable; stale grants do not trigger infinite retries. No global node
restart occurs merely because one scope received invalid data.

## Shared conformance fixtures

Before either release, test matching code/transcript bytes in Rust and WASM;
tampered scope/mode/identity/origin; expired/replayed decisions; concurrent revision
updates; lost provisioning ACK; cross-integration status/data access; same-service
new-device proof; stale device after revoke; partial-store crash and resumption.
The browser suite must launch this standalone repository's binary. Fixtures use
generated disposable identities and never include real production secrets.
