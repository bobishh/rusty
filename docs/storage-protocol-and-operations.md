This reference documents the current blind-storage service, its authorization and storage protocols, operations, verification, and deployment behavior. The [README](../README.md) contains the short overview and local start command.

## Contents

- [Storage protocol](#storage-protocol)
  - [Resource management policy](#resource-management-policy)
  - [Writer compatibility and attachment policy](#writer-compatibility-and-attachment-policy)
  - [Private attachment object namespace](#private-attachment-object-namespace)
  - [Read-only blob coverage](#read-only-blob-coverage)
  - [Private history archive objects and coverage](#private-history-archive-objects-and-coverage)
  - [Confirmed snapshot retention](#confirmed-snapshot-retention)
- [Migration](#migration)
- [Diagnostics](#diagnostics)
- [Verification](#verification)
  - [Deployment and rollback](#deployment-and-rollback)


Rusty stores and serves immutable encrypted objects over HTTP. It does not load Automerge documents, receive readable invitations, participate as a board Editor, classify submissions, fetch job pages, write cards, or process email. Its service signing key authenticates durable storage receipts; it cannot decrypt stored objects or authorize application changes.

Rusty also supports a separate public-board publication namespace. Authorized clients
send a strictly validated, selected-board projection and separate public file copies
after confirming source-board owner rights locally. Rusty verifies each resource owner’s
root/device proof, resource-management authority, challenge-bound signatures, expected revision and snapshot
hash; it does not claim to inspect private workspace history. Public copies include
selected-board/card discussions and attachments, plus allowlisted visitor display
settings (preset bindings, column accents, stage labels and aging). The
`publicBoardPublication.presentationVersion: 1` capability advertises support; older
projections remain valid. `fieldConfigurationVersion: 1` additionally advertises generic
card field bindings and explicit plain/Markdown/JSON/code text formats. Owner-controlled access determines whether a board is
available for anonymous reads; accepted deliveries from currently authorized
writers advance its public revision. Disabling access stops future reads but
cannot recall bytes already received. Configure the public frontend origin in `RUSTY_CORS_ORIGINS`
and `VITE_PUBLIC_BOARD_ORIGIN`. Never put private storage tokens, workspace reading
keys or user board content in service configuration.

```sh
cargo build --release --locked
RUSTY_PUBLIC_ORIGIN='https://rusty.example' \
RUSTY_CORS_ORIGINS='https://tincanban.example' \
./target/release/mesh-lighthouse /fresh-private-directory 0.0.0.0:8080
```

Rusty accepts independently authenticated owners; no deployment-wide owner identity or controller-device allowlist is required. Each device proves its identity with its root-signed certificate chain and a signed, scoped request. Existing person, scope and board policies remain bound to their recorded owner. Another identity cannot read management capabilities, replace policies or rotate another owner's storage access. Current person/resource capabilities and cumulative device revocations still apply. Rusty never receives a root private key. Keep private keys on authorized client devices only. For local development, use `127.0.0.1:8080`; the default origin is then loopback HTTP. Public hosting requires HTTPS, normally through the deployment proxy. CORS accepts a comma-separated allowlist of exact frontend origins and defaults to none. `LIGHTHOUSE_PUBLIC_ORIGIN` and `LIGHTHOUSE_CORS_ORIGINS` remain configuration aliases.

In tincanban, connect by entering the Rusty address. The owner device proves its identity with a short-lived Rusty challenge and a device-signed authorization. The browser creates a random opaque scope, separate read/write storage tokens, and a 32-byte AES-GCM reading key. It sends only scope and storage tokens to Rusty; Rusty stores keyed token hashes. The service never returns bearer tokens. The browser pins the service public key and verifies signed policy and upload receipts before saving access locally or marking a snapshot replicated. Access transfer to additional already-enrolled devices requires a separate encrypted device-settings channel and is not part of this protocol.

Board history, authorization proofs, and workspace chat are encrypted together.
A receiving client verifies AES-GCM authentication, scope/epoch and signed causal
authorization before merging changes. Normal replica push schedules encrypted
attachment upload and cold coverage confirmation. Completion requires verified
blob receipts, locator-index merge and an acknowledged current snapshot; a local
locator alone is insufficient. The client uses durable bounded encryption journals
and a verified local streaming sink. Preview/download may materialize the final
verified file within the application limit. Current Chromium and WebKit acceptance
covers a cold recipient reading and downloading exact attachment bytes after the
source closes, plus interrupted peer transfers without partial-cache publication.
Storage access does not grant board editing permission. Rusty stores encrypted
snapshots and archive objects; it never runs the readable Automerge sync protocol.

**Export private access** saves a JSON file containing the reading key and storage
tokens. Transfer it privately to an authorized device that already has the board,
then choose **Import private Rusty access**. These credentials stay in private local
IndexedDB, outside shared board state. Same-person enrollment and authenticated
device-state exchange transfer portable access while retaining each device's own
cursor. The normal client loop can add a separate identity scope for a previously
board-only Rusty origin. Native HTTP acceptance covers person-policy setup,
same-person devices and independent owners without server identity pins and cold photo
delivery. Desktop-to-mobile WebKit acceptance covers cold reopening after a photo
change without another upload. A device that never received access still needs a
current key holder or recovery package. **Disconnect locally** stops that device;
it does not revoke server tokens. Removing a board grant cannot erase plaintext
or keys already obtained. Local acceptance does not establish a production rollout.

## Storage protocol

Publications retain their verified owner root identity in a service-signed,
board-bound record under `management/publication-owners`. Authorized editor and
automation deliveries use that identity after restart even when the board has no
resource-management policy. The identity is retained only after the entire signed
publication command passes validation; it cannot be supplied by a delivery writer.
Owner evidence and every new parent directory are confirmed durable before the
publication record commits. Retries preserve the exact owner record and reconfirm
its durability. Existing publication and management-policy schemas are unchanged.
For older publications without this record, a verified board or person policy can
supply the original owner's public identity. If neither retains the root key, the
original owner must confirm a publication command before editor delivery resumes;
the requesting editor cannot become the owner.

Signed publication challenges include `deliveryPolicyContentHash` for the current
verified policy. It hashes canonical JSON containing `policy.payload`,
`policy.signerKeyId`, and `ownerCertificates`, excluding only the policy's signature.
Clients compare it to detect changed permissions without assuming deterministic
signature bytes. `deliveryPolicyHash` still binds the complete signed evidence in
publication commands; signature verification and revision checks remain required.

Scope enrollment advertises `capabilities.scopeEnrollmentRetry.version: 1`.
The latest completed signed receipt and a hash of the exact normalized request
commit atomically with the scope's token MACs. An identical request can recover
that receipt after a lost response, consumed challenge or restart without
advancing policy again. Current person/resource/device authorization and original
signatures still apply; changed requests and superseded policies cannot reuse it.
Two still-valid owner requests can also confirm the same immediate policy result:
the stored revision must be exactly the requested revision plus one, and owner,
read/write token commitments, revocation flag and explicit writer floor must all
match. Rusty signs a receipt for each exact authorization without rewriting the
policy or advancing its revision. Different targets and older revisions still
conflict; this confirmation does not bypass challenge expiry or authorization.
An explicit floor-2 request may also reaffirm the exact current floor-2 policy:
when owner, token commitments and revocation state already match, a fresh signed
receipt keeps the current revision. It does not rewrite policy or replace the
last completed mutation receipt. Current device/resource authorization and the
fresh challenge still apply. A real token, revocation or floor change retains
normal revision compare-and-set semantics; legacy requests keep their previous
revision behavior. New board scopes can start at floor 2 without an intermediate
upgrade visible to another device.
Bearer tokens remain absent from durable storage. Older scope-policy readers
reject the new optional receipt field, so rollback must use a compatible reader.
The client retains the exact enrollment request and signed receipt in a durable
transition journal; a lost confirmation is retried without generating another key
or silently adopting an unrelated policy revision.

### Resource management policy

Discovery advertises `capabilities.personManagement.version: 1` separately from
scope management. `PUT /v2/management/person/{personId}` stores person policy under
resource ID equal to `personId`. Its service-signed
`rusty-person-management-capability@1` allows only `management.update` and
`resource.create` and carries a monotonically increasing revision and cumulative
revoked-device list. The first person update requires a valid device certificate chain and signed request for that same person; later person-policy updates require the current person capability. After confirmation,
scope and board policy creation use the exact parent capability and revision, not
controller ancestry. The service persists
immutable signed policy evidence before atomically publishing the current pointer.

Creating a scope or board policy sends `personManagementCapability` with the
resource update and signs the exact `personManagementRevision` into its
authorization. A stale, missing or substituted parent capability cannot create a
resource. Each new resource receives its own capability and operation set; person
authority does not widen later operations on that resource. After initial person
policy confirmation, any valid non-revoked device of that person can create
resources without a server-side controller-device pin.

Confirmed person revocation gates resource-policy and status requests, publication
challenges and staged files, checkpoints, and scope enrollment even when the
presented resource capability remains otherwise valid. Pending person-policy
updates block resource operations; an authenticated, currently authorized device
can read person status and retry the exact saved update. These rules revoke
management authorization only: they do not themselves rotate storage bearer
tokens or erase downloaded plaintext.

Tincanban implements a separate explicit Owner action to remove another registered
device from all connected scopes at one pinned Rusty origin. It freezes ordinary
writers, discovers and freezes approved Workers, drains exact saved ciphertext,
confirms cumulative person revocation, rotates scope tokens and future content
keys through signed policy compare-and-set, updates Workers without widening their
grants, then atomically activates portable settings and confirms a fresh snapshot.
Durable intent and old keys survive interrupted confirmations. Conflicting stored
credentials require explicit recovery: every historical key variant is retained
and a fresh active epoch is proposed above all observed epochs. No timestamp or
arbitrary variant chooses an authority winner.

Focused client tests cover freeze/CAS failures, exact original outbox retries,
signed receipt bindings, retained same-epoch key variants and activation only after
required confirmations. Server HTTP tests cover current authorization, revocation,
retries, policy conflicts and writer-floor enforcement. UI scenarios cover the
explicit removal/recovery controls and their pending/failure states; they are not
a claim that every distributed rotation fault has been exercised in a browser.
Previously downloaded plaintext remains readable by its holder.

Discovery advertises `capabilities.scopeManagement.version: 1`.
`POST /v2/management/{kind}/{id}/status` returns `capability` (or null),
`migrationPending` and a service-signed status receipt. It requires a complete
owner device proof and a `MATCH/1` signature over `rusty-management-policy-status`
version 1: exact service/origin/person/device/resource, nonce-like request ID,
issuance and expiry. Current non-revoked owner devices may query without a server-side identity pin. Unsigned reads, invalid signatures, other identities and revoked
devices receive no capability. Status nonces are single-use, persisted through
restart and bounded to 128 live requests. A lost response requires a fresh signed
status request. Status receipts bind request ID/full authorization hash,
capability hash, revision and pending state. Responses prohibit caching and never
return storage tokens or content keys. `kind` is `scope`, `board` or `person`.
For `person`, `id` must equal the requesting identity’s exact `personId`; scope and board IDs are
exact opaque resources.

`PUT /v2/management/{kind}/{id}` takes `{version:1, identity, deviceId,
certificates, managementCapability, authorization}`. Authorization is a `MATCH/1`
device-signed `rusty-management-policy-update` version 1, binding service ID,
configured origin, person/device, resource kind/ID, expected revision, sorted
operations, sorted cumulative revoked-device IDs, request ID, issuance and expiry.
Expiry is at most 120 seconds after issuance; future issuance is bounded to 30
seconds. First policy creation verifies the requesting owner and any existing scope/publication owner binding. Later
updates require the exact current capability and `management.update`.

The confirmed `RUSTY/2` capability binds those resource/person/service rights,
positive revision, request ID and full authorization hash. Scope operations are
`scope.policy` and `snapshot.checkpoint`; board operations are
`publication.status`, `publication.publish`, `publication.update`,
`publication.unpublish` and `publication.stage-file`. Each policy includes
`management.update`. Device revocations are cumulative and cannot be undone by
a later policy. Migrated enrollment, publication, asset and checkpoint requests
must include `managementCapability`; missing or stale evidence cannot fall back
to pre-policy certificate authority. Management revocation is separate from rotating previously
disclosed storage tokens and future content keys.

Original signed policy evidence is immutable under `management/records`. Current
resource pointers publish atomically only after that evidence is durable. A
separate pending marker preserves interrupted intent; pending first migrations
deny ordinary legacy management until an explicit authorized retry completes.
The exact latest completed retry returns the same capability, even after expiry,
while still requiring a currently authorized, non-revoked signer. Replaying an
older completed request does not clear a newer pending update. Historical policy
evidence is retained, so total audit storage grows with policy updates; the current
index is bounded to 256 resources and each evidence record to 512 KiB.

Reader compatibility: binaries predating this namespace cannot reopen a migrated
volume. Coordinated release/rollback readers must support the management schema;
preserve the service key, pending markers, current pointers and immutable records.

Discovery: `GET /.well-known/mesh-lighthouse`, protocol 2, mode `blind`, `applicationWrites: false`, `classification: false`. No person/device certificate or application grant is advertised. The signed enrollment flow is distinct from workspace pairing; it never sends workspace grants or content keys.

- `POST /v2/enrollment/challenge`: `{version, scopeId, identity, deviceId, certificates}`. Returns a Rusty-signed, 120-second challenge bound to service identity, configured origin, owner, controller device, scope, and current policy revision. Up to 8 pending challenges per owner/scope and 128 globally; expired challenges are removed.
- `PUT /v2/scopes/{opaqueScope}`: `{challenge, identity, deviceId, certificates, readToken, writeToken, revoked, authorization}`. Authorization is a `MATCH/1` device-signed envelope binding the challenge, origin/service/scope, revision, revocation state, and SHA-256 commitments to both storage tokens. Rusty checks current controller authority and consumes the challenge when changing policy, returning a `RUSTY/2` signed receipt. Exact completed retries and unchanged floor-2 confirmations follow the rules above. Policy revision compare-and-set prevents stale updates. Revocation uses the same signed flow with `revoked: true`; clients must verify the receipt before reporting success.
- `PUT /v2/scopes/{scope}/objects/{id}`: write bearer token; `X-Rusty-Request-Id` fresh challenge; encrypted object JSON. ID is base64url SHA-256 of canonical JSON. Returns Ed25519 envelope under `RUSTY/2`, binding service, scope, epoch, object hash, durable sequence, policy revision, and challenge.
- `GET /v2/scopes/{scope}/objects?after=0`: read bearer token; ordered inventory, maximum 128 entries per page.
- `GET /v2/scopes/{scope}/objects/{id}`: read bearer token; encrypted object JSON.
- `GET /health`: reports blind mode.

### Writer compatibility and attachment policy

Discovery advertises `capabilities.writerPolicy` as `{version: 1,
maximumWriterVersion: 2}`. Existing scopes load with minimum writer version 1.
The scope enrollment authorization may include the signed field
`minimumWriterVersion: 2`; it is part of the device-signed authorization, not an
outer request field. Omitting it keeps the current minimum. The minimum is
monotonic: an explicit request for version 1 cannot lower a scope already at
version 2, and unsupported versions are rejected. A signed policy receipt includes
`minimumWriterVersion` when the request explicitly sets it or the active minimum
is above 1; legacy version-1 receipts keep their previous shape.

Snapshot object `PUT` and encrypted blob `PUT` negotiate with the URL query
`writerVersion=2`. An absent query means legacy writer version 1. Once a scope's
minimum is 2, an older snapshot or blob writer receives HTTP 426 with
`code: writer_upgrade_required`; the rejected write creates no receipt or stored
object. Reads remain available to older clients. Encrypted blob writes also
require the scope minimum to be 2: a version-1 scope returns HTTP 409 with
`code: writer_policy_required`, even when the client sends `writerVersion=2`.

Checkpoint authorization may include the signed payload field `writerVersion: 2`;
omission means version 1. Rusty checks this version against the current scope
minimum before retry completion or checkpoint cleanup. An older writer receives
HTTP 426 with `code: writer_upgrade_required`; the rejected checkpoint does not
append an object, issue a receipt, or prune retained snapshots.

### Private attachment object namespace

Discovery advertises `capabilities.encryptedBlobs` with `version: 1` and
`maximumCiphertextBytes: 1048592`. `PUT/GET
/v2/scopes/{scope}/blobs/{ciphertextId}` uses the existing scope write/read bearer
tokens, respectively, and the same strict opaque encrypted-object-v1 body. The
ID is SHA-256 of canonical ciphertext-object JSON. Filename, media type, plaintext
digest, content keys and file contents must remain inside client encryption.
The server cannot validate attachment meaning or workspace editing permission.

PUT requires `X-Rusty-Request-Id` and returns a `RUSTY/2` signed
`blind-blob-storage-receipt@1`: `serviceId`, `scopeId`, `keyEpoch`, `objectId`,
`policyRevision`, `requestId`. It contains no snapshot sequence. Identical retries
verify stored bytes and directory durability before issuing a receipt. First
creation fsyncs both the namespace link and committed object. GET validates the
stored object's scope and ciphertext hash. Successful responses use `no-store`.
Denied access returns 403, an authorized missing object 404, capacity exhaustion
507, and storage/integrity failure 503. Neither endpoint lists plaintext metadata.

Blob objects never enter snapshot inventory and are never deleted by snapshot
checkpoint cleanup. Snapshot, blob, and archive namespaces share
`RUSTY_MAX_SCOPE_BYTES`; retained blob and archive bytes count toward checkpoint
capacity and scratch accounting. The blob namespace
allows at most 16,384 objects per scope and each ciphertext at most 1 MiB plus a
16-byte GCM tag. No automatic blob deletion is implemented. Old servers do not
advertise this capability; clients must retain pending uploads and report upgrade
required rather than claiming complete attachment coverage. A server receipt
attests opaque object durability; the client must additionally verify the encrypted
manifest/chunk bindings and current workspace access before reporting completion.

### Read-only blob coverage

Discovery may separately advertise `capabilities.blobCoverage` as
`{version: 1, maximumObjects: 33}`. This is distinct from `encryptedBlobs`: a
server can store opaque blobs without supporting a durable coverage proof.

`POST /v2/scopes/{scope}/blob-coverage` uses the scope read bearer. Its exact
version-1 JSON request contains a URL-safe `requestId` (20–64 characters) and
1–33 `{objectId,keyEpoch}` entries, strictly sorted by unique ciphertext
`objectId`; the body is bounded to 16 KiB. Rusty validates each committed object's
hash and epoch and fsyncs the namespace before returning a signed
`RUSTY/2` `blind-blob-coverage-receipt`. The receipt binds the service, scope,
current policy revision, request ID and exact requested object set. This is
read-only: no blob data or plaintext metadata is returned or changed, and no
application grant is consulted. A client must verify the service pin and every
receipt binding. A private locator by itself does not establish durable presence
of its manifest and chunks. Servers without the advertised capability cannot
prove cold coverage; clients must report coverage as unsupported or incomplete.

Protocol tests cover malformed batches, missing/corrupt objects, wrong epochs,
read denial, policy/revocation and injected namespace-fsync failure. The client
coverage adapter authenticates the manifest, derives the exact chunk set, verifies
signed coverage without downloading chunk payloads and rechecks live guards.
Application replication schedules upload and coverage confirmation. Real
source-closed attachment preview/download passes in Chromium and WebKit. Bounded
peer-read and cancellation checks include interrupted transfer/reconnect without
publishing partial bytes. Reload tabs onto the coordinated current frontend/WASM
cohort: an older cached adapter may ignore the optional stream read bound.

### Private history archive objects and coverage

Discovery advertises `capabilities.encryptedArchives` as
`{version: 1, maximumCiphertextBytes: 262160}` and
`capabilities.archiveCoverageBatches` as `{version: 1, maximumObjects: 64}` and
`capabilities.archiveCoverageAggregates` as
`{version: 1, maximumChildren: 8, maximumHeight: 31}`.
These server capabilities store and attest opaque archive objects; they do not
enable a workspace baseline protocol.

`PUT /v2/scopes/{scope}/archives/{ciphertextId}?writerVersion=2` uses the scope
write token and accepts the strict encrypted-object-v1 body, with at most 256 KiB
plus the 16-byte GCM tag. Scope policy must require writer version 2. The object
ID is SHA-256 of canonical ciphertext-object JSON. PUT requires
`X-Rusty-Request-Id` (20–64 URL-safe characters) and returns a signed
`RUSTY/2` `blind-archive-storage-receipt` binding service, scope, key epoch,
ciphertext ID, policy revision and request ID. An exact retry checks the stored
bytes and directory durability before returning a receipt. GET uses the scope
read token and returns the opaque object with `no-store`; neither method exposes
workspace IDs, filenames, plaintext hashes or archive content.

`POST /v2/scopes/{scope}/archive-coverage` uses the read token and a version-1
request containing a 20–64 character request ID and 1–64 `{objectId,keyEpoch}`
entries sorted by unique ciphertext ID. Rusty verifies each named object and its
key epoch, fsyncs the scope and archive directory, then signs a
`blind-archive-coverage-batch-receipt` binding the exact requested batch, service,
scope, policy revision and request ID. This receipt covers that batch only; it
does not itself bind a complete archive root or prove baseline-wide coverage.

`POST /v2/scopes/{scope}/archive-coverage/aggregate` uses the read token and an
exact version-1 request with a 20–64 character request ID, an opaque archive-root
ciphertext ID and 1–8 signed leaf or aggregate receipts. Children must share the
current service pin, scope and policy revision; aggregate children must bind the
same root. Rusty verifies signatures, strict non-overlapping ciphertext-ID ranges,
equal child heights, safe object-count sums and depth below 32, then signs a
`blind-archive-coverage-aggregate-receipt` with `no-store`. Leaf receipts remain
unchanged: root coverage is derived from their actual object IDs. This composes
durable batch attestations without rereading each underlying archive object, so it
does not prove bytes remain available after later corruption or authorize baseline
activation.

Archives are independent of snapshot inventory and checkpoint pruning. The
shared scope quota includes snapshots, blobs and archives; checkpoint retained
capacity and scratch accounting include archive bytes. Archive storage currently
limits each scope to 1,048,576 objects. First use after process start scans the
archive directory for byte/count accounting. A warm in-memory accounting cache
is invalidated before uncertain writes and refreshed after a durable write. This
is not a durable bounded accounting index: restart accounting still requires a
directory scan.

The shared captured/archived/covered preparation journal has SDK, private
IndexedDB and Worker Durable Object adapters. Tincanban's live WASM producer
consumes Native-verified preparation, emits the original encrypted catalogue,
confirms exact data/directory coverage and signs an Owner-attested compact basis.
The compact basis byte tree has its own exact-set coverage receipt. Current
Workers have explicit prepare/activate history phases: original pending writes
are drained before freezing, and Native verifies the published basis and covered
local heads before activation. Rusty only stores opaque objects and signs storage
receipts; it cannot create the Owner attestation or expand a Worker's grant.

Native HTTP acceptance exercises real capture/rebase/storage/coverage through the
WASM sink and application journal, exact ciphertext retry after a lost reply and
Rusty restart, and cold original control/proof/pending-change reads. Frozen legacy
fixtures retain their original admission policy and bytes. Current Chromium and
WebKit acceptance covers archive publication, a credential-free Editor's bounded
historical read, complete private export, incomplete export after both sources
close, fresh identity/workspace recovery and an offline version restore as a new
currently authorized command. Encrypted Rusty readers verify storage correspondence;
authorized direct-peer readers verify Owner authority and content-addressed
plaintext proof paths without claiming equivalent ciphertext evidence.

Application activation uses a staged journal and exact source/revision guards;
original history and prior baselines remain available. Export includes unavailable
objects as incomplete coverage rather than deleting or inventing originals. These
results prove the tested local paths, not an activated production revision.
Rusty's own CI and deployment receipts identify its actual deployed artifacts.

### Confirmed snapshot retention

Discovery advertises `capabilities.snapshotCheckpoints` as
`{version: 1, observedSequence: true}`. An owner
device may replace already merged snapshots with one complete encrypted
checkpoint. Ordinary writers, including scoped automation, retain append-only
storage access; a write token alone cannot prune a scope.

`POST /v2/scopes/{scope}/checkpoint` takes the write bearer token and
`{object, identity, deviceId, certificates, authorization}`. The `MATCH/1`
device-signed authorization payload contains `kind: rusty-snapshot-checkpoint`,
`version: 1`, `serviceId`, `origin`, `scopeId`, `keyEpoch`, `policyRevision`,
`expectedSequence`, `objectId`, `requestId`, `issuedAt`, and `expiresAt`.
Times are epoch milliseconds; expiry may be at most 120 seconds after issuance,
and issuance may be at most 30 seconds ahead of server time. Rusty verifies the
requesting owner’s root/device certificate chain and the scope policy's owner.

The device must first durably merge the full inventory and confirm that its
current raw Automerge document has no pending or quarantined changes, retaining
all required authorization evidence. It encrypts the admitted compact basis and
active tail (or the original document before archiving), archive references and
current chat state, including signed records. Earlier archived originals stay in
the separate archive namespace. Chat follows tincanban's existing local retention
policy (2000 messages / 4 MiB); this is not an archive of all historical chat.
Ephemeral typing is excluded. Rusty remains blind and trusts the certified
owner's checkpoint attestation rather than inspecting plaintext.

Under the storage lock, `expectedSequence=N` must equal the current inventory
frontier. A conflict returns HTTP 409 with `code: checkpoint_conflict`; the client
must pull and admit new objects before preparing another checkpoint. Rusty fsyncs
the new object at `N+1`, atomically fsyncs `compaction.json` with retained floor
`N`, then removes older objects and fsyncs their directory. A bounded replacement
object can use temporary scratch space while an old scope is full, but the
retained object must fit the configured quota. Old objects are never deleted
before the new checkpoint is durable.

Snapshot uploads include `observedSequence`, the admitted inventory cursor saved
with their original outbox ciphertext and request. After a checkpoint, a new
object prepared before its sequence receives HTTP 409
`checkpoint_generation_required` before storage changes. An omitted field means
zero. A byte-identical object already retained remains idempotent after current
authorization checks. Clients must preserve the original sequence on retries;
a later cursor cannot reauthorize an older prepared snapshot. This storage
ordering fence keeps the existing writer policy unchanged.

The `RUSTY/2` signed receipt has `kind: rusty-snapshot-checkpoint-receipt`,
`version: 1`, `serviceId`, `scopeId`, `keyEpoch`, `objectId`, `sequence`,
`supersedesThrough`, `policyRevision`, `requestId`, and `authorizationHash`.
The hash is base64url SHA-256 of canonical JSON of the full authorization
envelope. Exact completed retries return this receipt even after expiry, while
still requiring current write access, policy revision and valid owner proof;
they never prune newer writes. A durable object bearing the original checkpoint
marker may finish its manifest after a crash while keeping every later sequence;
it never lowers an already newer retained floor. Fresh owner proof can renew the
same incomplete ciphertext after expiry. Clients retain ciphertext and
authorization across uncertain delivery.

Inventory retains its existing pagination fields and adds `compactedThrough`,
`checkpointSequence` (null before the first checkpoint), `maxSequence`, and
`objectCount`. Sequences never reset. Older clients and workers can still read
the retained checkpoint and append later snapshots. A download that races
pruning retries inventory on its next pass. Startup validates the manifest,
checkpoint hash/path and contiguous retained range before completing cleanup.
Back up the volume before rollout: an older Rusty binary cannot read a compacted
volume because it expects object sequences to start at 1.

Public publication API (requires scoped owner/device authorization; anonymous readers use only
the GET endpoints):

- `POST /v1/public/challenges`: controller identity, device certificate chain and
  board entity ID. Returns a signed, short-lived challenge carrying the controller-
  bound current revision/withdrawal state.
- `PUT /v1/public/boards/{boardId}/files`: authenticated idempotent staging of one
  bounded public file copy, with a challenge-bound SHA-256 and size. Staged files
  remain unreadable until included in a confirmed board manifest.
- `PUT /v1/public/boards/{boardId}`: signed publish, update or unpublish command with
  exact projection hash and expected revision. Rusty verifies every referenced staged
  file before durably activating the snapshot or withdrawal tombstone and signing a
  receipt.
- `GET /v1/public/boards/{boardId}`: anonymous no-store snapshot read. Withdrawn or
  unknown boards return 404.
- `GET /v1/public/boards/{boardId}/files/{revision}/{sha256}`: anonymous binary read
  only when that exact revision remains active and references the digest. Responses
  use safe attachment disposition and `nosniff`.

Encrypted objects contain exactly `version`, `scopeId`, `keyEpoch`, `nonce`, and `ciphertext`. AES-GCM uses a random 12-byte nonce, 128-bit tag, and authenticated binding `RUSTY/2/object\0{scopeId}\0{keyEpoch}`. Server accepts at most 16 MiB ciphertext per object, 10,000 objects and approximately 1 GiB encoded storage per scope by default. Set `RUSTY_MAX_SCOPE_BYTES` to a positive byte count in deployment configuration to change the per-scope budget; the 10,000-object ceiling remains. Raising the budget preserves existing objects and permits retries without migration. Ordinary uploads remain append-only; an eligible tincanban owner client requests a confirmed checkpoint once eight retained objects have been fully admitted, as described above. The browser uploads only changed snapshots, retries identical ciphertext after uncertain delivery, and polls every 15 seconds while open. No client online is required for Rusty to retain data.

Files use private permissions; atomic rename, file/directory fsync precede receipts. Tokens are stored as keyed hashes. Pending enrollment and publication challenges are persisted for replay protection and expire after 120 seconds. A filesystem lock excludes another Rusty writer on the same directory. Public snapshots and withdrawal tombstones survive restart. Public assets are separate from blind ciphertext; active revisions alone authorize their download, and stale orphan cleanup is bounded. Back up the service key, policies, challenges, objects and publication records together. Losing the service key prevents authorization and invalidates the pinned identity. Inventory retains object metadata in memory, not all ciphertext.

## Migration

Use a **fresh durable directory/volume**. Startup rejects legacy configs, inboxes, results, and unknown files without deleting them. Existing plaintext volumes are not converted or erased automatically. Keep old volumes private, export boards/inbox/results through an authorized migration process, and remove old Keeper Editor/Visitor grants in each board before retiring the old service. Do not hand old invitations or workspace content keys to new Rusty.

The container invokes the same blind binary. `RUSTY_STATE_DIR` defaults to `/data`; `RUSTY_HTTP_BIND` defaults to `0.0.0.0:8080`. An old readable `/data` volume fails closed; existing blind volumes retain their service key and encrypted scopes. Cloudflare Worker + Clef website intake, forwarded-mail correlation, and scoped automation remain a separate implementation tracked in tincanban's `blind-keeper-and-scoped-automation` OpenSpec. Old ingestion and plaintext authority modules have been removed.

## Diagnostics

`RUSTY_LOG` selects `off`, `error`, `warn`, `info` (default), `debug` or `trace`.
Errors include quota exhaustion and failed requests; info records confirmed new
objects and startup; debug adds immutable retries, inventory and downloads;
trace adds routine service requests. Records always go to stderr at the selected
level. Configure `RUSTY_TELEMETRY_URL`, `RUSTY_TELEMETRY_TOKEN` and optional
`RUSTY_TELEMETRY_PROJECT` (default `rusty`) to send a copy to TinSink's v2 intake.
The token is a server write key, stored only in private deployment configuration.

Delivery uses a bounded 256-event queue and 25-event batches, a two-second
request timeout and at most three attempts with stable event IDs. Sink failures
never block storage; queue overflow and final delivery failure remain in stderr.
Headers, tokens, ciphertext and decrypted board contents are excluded.
`storage.object.stored` reports `stored_bytes_before`, `stored_bytes`,
`object_count`, `scope_limit_bytes` and encoded object `bytes`.
`storage.object.reused` identifies unchanged immutable retries;
`storage.quota.exceeded` records the actual refused budget. Distinct ciphertext
does not prove distinct application data: correlate client `mesh.rusty.upload.*`
diagnostics by opaque scope to inspect initial/change/retry decisions.

`storage.checkpoint.requested`, `.completed` and `.rejected` report retention
attempts; completion includes `freed_bytes`, `pruned_count` and remaining
`object_count`. HTTP diagnostics accept optional `X-Rusty-Client` (`tincanban` or
`automation`) and `X-Rusty-Build` (40 or 64 hexadecimal characters) labels.
These labels are untrusted diagnostic metadata and grant no permissions. Tokens,
signed proofs, encrypted snapshots and readable board contents remain excluded.

The domain root shows independent service availability and read-only board status.
Choose **View my boards** to open an allowed Tincanban frontend in the same browser.
Tincanban asks before sharing names and checked sync outcomes for boards configured
on that exact Rusty origin. Confirmation is bound to the original popup, exact
origins, a fresh request ID, a two-minute deadline and the approving identity/device.
Keys, tokens, board contents and management capabilities remain in Tincanban.
Results stay in that Rusty page's memory, display their check time and require a
new confirmation to refresh. They describe this browser's exchanges, not every
offline participant. No backend login session or anonymous private-board listing
is created. Allowed frontends come from `RUSTY_CORS_ORIGINS`; with none configured,
inspection remains disabled with an operator configuration explanation.

The root also retains connection instructions and a link to the protected logs.
Its robot, header and Fira Code/Caveat typography preserve the original Rusty UI.
Styles, fonts and artwork are embedded in the service binary and served from
`/assets/`; rendering does not depend on TinSink being available. The asset handler
serves an explicit embedded allowlist, never files from the storage directory.

`src/ui/design-system.css` contains the unmodified, flattened tincanban design
system from `7a60c9b3d82a9a766aadc5ba77e9a49cf27e3a2d` (`src/styles/design-system/index.css`
and its imports). Rusty typography, robot, favicon, font/paint files and font
licenses come from Rusty's original UI at
`4c0d15dc06ec5d2c0b93fc02ed91a67eb52f262e` (`frontend/src/typography.css`,
`frontend/src/assets/rusty-logo.webp`, `frontend/public/brand/` and
`frontend/public/assets/`). Updating these assets does not restore retired readable
Keeper controls.

## Verification

```sh
cargo test --locked
python3 scripts/smoke_service.py target/debug/mesh-lighthouse
node scripts/service-ui.mjs target/debug/mesh-lighthouse
```

The tests cover two HTTP clients, opaque replication, signed durable receipts, retry, restart, concurrent-writer exclusion, read/write separation, revoked storage, and refusal of plaintext state. Tincanban's `e2e/rusty-connection.spec.ts` and `e2e/repeated-rusty-poll.spec.ts` use an actual service binary with isolated temporary state and unused ports. Attachment and history acceptance live in `e2e/attachments-rusty.spec.ts` and `e2e/attachment-session-recovery.spec.ts`.

The service UI browser check uses the adjacent tincanban checkout's installed
Playwright. It starts an isolated Rusty process on an unused port, verifies loaded
local fonts and the original robot/header on desktop and mobile, and exercises an
unavailable Sink link. Screenshots are written under ignored `target/`.

GitHub Actions checks formatting, storage/publication protocols, formal models,
and discovery/durable identity across real service-process restarts. Rusty CI
seals the exact executable hash, immutable image digest and SDK revision as build
provenance. Rusty's own protected deployment workflow consumes that artifact,
pulls the public image by immutable digest with an isolated anonymous Docker
configuration and verifies it on the host before the single-writer storage handoff,
boots that prepared image without another registry pull, and confirms the live
image digest and reader floors. Image preparation failures leave the previous
writer running; failed activation restores it. This bounds the handoff to service
activation but does not provide simultaneous blue/green writers on one volume. Its rollback selects an earlier sealed Rusty artifact;
it does not activate tincanban or change the retained volume.

Container builds reuse the dependency layer through the GitHub Actions v2 cache,
using one stable `rusty-release-linux-amd64` scope. `mode=max` includes the Rust
builder stage; source changes still rebuild the service with the current build
and SDK revisions. Cache export is limited to three minutes and cannot fail the
release. Docker build-record artifact uploads are disabled. Cache uses GitHub's
separate repository allowance and eviction policy, not release artifact storage;
the workflow does not raise the repository cache limit. The loaded image still
passes service-label verification, push, executable extraction and release sealing.

Actions diagnostics expire after one day. Sealed source releases and deployment
copies have a 90-day expiry. `Prune Actions artifacts` runs daily and after main
CI/deployment completion; manual runs default to preview. Cleanup verifies seals
and executable bytes before protecting the active `/health` identity, the previous
compatible deployed release, and the latest successful main push CI. It preserves
in-flight work and pauses release deletion during pending deployments. Missing
health or required recovery artifacts aborts cleanup before deletion. Runtime
health and active runs are rechecked before every delete; a change stops the
remaining plan. Older completed releases have a one-hour grace period; diagnostics keep their first
24 hours. Runtime data, container images and caches are untouched. The 90-day
GitHub expiry still applies even to a protected artifact; cleanup cannot extend it.

### Deployment and rollback

`Deploy Rusty` runs after a successful push build on `main`. It downloads the
artifact from that exact CI run and attempt, verifies the signed-by-hash manifest
and executable bytes, then deploys the immutable image through the existing
Kamal service. The production environment should require its normal reviewer
approval. Deployment variables/secrets belong only to this repository:
`RUSTY_DEPLOY_SPEC` (same pinned service/host JSON contract used before the
release split), `RUSTY_DEPLOY_SSH_KEY`, `RUSTY_DEPLOY_KNOWN_HOSTS`,
`RUSTY_TELEMETRY_TOKEN` and `CLICKHOUSE_PASSWORD`.
`release/deployment-config.json` pins the public infrastructure repository and
commit. Optional telemetry endpoint/project values are configuration, not
deployment gates.

To roll back, run `Deploy Rusty` from `main` with the exact successful source run
and attempt for the previously sealed artifact. The same digest verification,
single-writer storage handoff and live receipt checks apply. Never rebuild an old
source revision or select a mutable image tag for rollback. This operation
changes Rusty only; it does not activate product Workers or alter the volume.
Artifacts predating the current public-board publication reader floor are refused
before the storage handoff, because their strict reader cannot open current
publication records.
The retired readable Keeper runtime, pairing console and application grants are
not reactivated by retaining their Git history.

[Blind-storage TLA+ models](../formal/tla/README.md) run in CI alongside native tests.
Duplicate upload and recovered checkpoint retries confirm directory durability
before issuing a receipt or pruning prior objects, including after a failed rename
commit. Object IDs, sequences and encrypted storage format remain unchanged.
