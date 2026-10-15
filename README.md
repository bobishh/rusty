# Rusty blind storage

Rusty stores and serves immutable encrypted objects over HTTP. It does not load Automerge documents, receive readable invitations, participate as a board Editor, classify submissions, fetch job pages, write cards, or process email. Its service signing key authenticates durable storage receipts; it cannot decrypt stored objects or authorize application changes.

Rusty also supports a separate public-board publication namespace. Authorized clients
send a strictly validated, selected-board projection and separate public file copies
after confirming source-board owner rights locally. Rusty verifies its configured
owner root/device proof, resource-management authority, challenge-bound signatures, expected revision and snapshot
hash; it does not claim to inspect private workspace history. Public copies include
selected-board/card discussions and attachments, and remain unchanged until explicit
update or withdrawal. Configure the public frontend origin in `RUSTY_CORS_ORIGINS`
and `VITE_PUBLIC_BOARD_ORIGIN`. Never put private storage tokens, workspace reading
keys or user board content in service configuration.

```sh
cargo build --release --locked
RUSTY_TRUSTED_OWNER='{"identity":{"personId":"…","publicKey":"…","displayName":"Owner"},"allowedControllerDeviceIds":["…"]}' \
RUSTY_PUBLIC_ORIGIN='https://rusty.example' \
RUSTY_CORS_ORIGINS='https://tincanban.example' \
./target/release/mesh-lighthouse /fresh-private-directory 0.0.0.0:8080
```

`RUSTY_TRUSTED_OWNER` is public trust configuration, not a secret. It pins the owner's root identity. The optional `allowedControllerDeviceIds` list authorizes legacy provisioning and one initial migration of person management policy. Before that person policy is confirmed, only devices with configured legacy controller ancestry can bootstrap management. After confirmation, scope and board policy creation requires the exact person capability and its signed revision; later owner devices need only a valid certificate chain for the same person, not the original controller ancestry. Legacy controller pins may then be empty. They cannot bypass a removed operation or current person/device revocation. Resource capabilities remain separately scoped, and Rusty never receives the root private key. Missing or invalid owner trust disables provisioning. Keep private keys on authorized client devices only. For local development, use `127.0.0.1:8080`; the default origin is then loopback HTTP. Public hosting requires HTTPS, normally through the deployment proxy. CORS accepts a comma-separated allowlist of exact frontend origins and defaults to none. `LIGHTHOUSE_PUBLIC_ORIGIN` and `LIGHTHOUSE_CORS_ORIGINS` remain configuration aliases.

In tincanban, connect by entering the Rusty address. The owner device proves its identity with a short-lived Rusty challenge and a device-signed authorization. The browser creates a random opaque scope, separate read/write storage tokens, and a 32-byte AES-GCM reading key. It sends only scope and storage tokens to Rusty; Rusty stores keyed token hashes. The service never returns bearer tokens. The browser pins the service public key and verifies signed policy and upload receipts before saving access locally or marking a snapshot replicated. Access transfer to additional already-enrolled devices requires a separate encrypted device-settings channel and is not part of this protocol.

Board history, authorization proofs, and workspace chat are encrypted together. A receiving client verifies AES-GCM authentication, scope/epoch, and the existing signed causal authorization before merging changes. Normal replica push now discovers workspace file descriptors and schedules encrypted Rusty upload or cold-coverage confirmation. Completion follows blob receipts, locator-index merge and an acknowledged current snapshot; a local locator alone is insufficient. Status stays in the active local session with separate upload, missing-source, availability, access, unsupported and capacity phases. The reader uses current workspace/device authorization and verifies complete file bytes. Production scheduling and cold-read confirmation pass native HTTP acceptance from a source-closed snapshot; browser acceptance remains unrun. The current client prepares encrypted chunks through a durable bounded journal and receives them through a verified local streaming sink; preview/download callers may materialize the final verified file. Per-stream cancellation and bounded peer reads now have native/core and SDK evidence. Service-credential migration, browser acceptance and app-level session-replacement behavior remain unverified. Storage access does not grant board edit permissions. Rusty stores snapshots containing Automerge history, rather than implementing the readable Automerge sync protocol.

**Export private access** saves a JSON file containing the reading key and storage tokens. Transfer it privately to an authorized device that already has the board through the normal signed invitation/import flow, then choose **Import private Rusty access**. These credentials remain in private local IndexedDB, outside shared board state. The current tincanban working tree transfers portable access during authenticated same-person enrollment and device-state exchange; each device retains its own cursor. Its normal device-sync loop can provision a separate identity scope for a previously board-only Rusty origin. Focused native HTTP tests cover person-policy setup, a same-person root-issued device after controller pins are removed, and cold photo delivery with source capture unavailable. Browser and deployed-device acceptance remain unverified. Older enrollments need a current key holder or recovery package once. **Disconnect locally** stops this device; it does not revoke storage tokens on Rusty. Removing a member's board grant does not remove previously obtained plaintext or reading keys.

## Storage protocol

### Resource management policy

Discovery advertises `capabilities.personManagement.version: 1` separately from
scope management. `PUT /v2/management/person/{personId}` stores person policy under
resource ID equal to `personId`. Its service-signed
`rusty-person-management-capability@1` allows only `management.update` and
`resource.create` and carries a monotonically increasing revision and cumulative
revoked-device list. The first update is the one-time explicit legacy-controller
migration; later person-policy updates require the current person capability. This
legacy proof is not a recurring first-resource requirement: after confirmation,
scope and board policy creation use the exact parent capability and revision, not
controller ancestry. The service persists
immutable signed policy evidence before atomically publishing the current pointer.

Creating a scope or board policy sends `personManagementCapability` with the
resource update and signs the exact `personManagementRevision` into its
authorization. A stale, missing or substituted parent capability cannot create a
resource. Each new resource receives its own capability and operation set; person
authority does not widen later operations on that resource. After initial person
policy confirmation, any valid non-revoked device of the pinned person can create
resources even when the legacy controller pins are empty and that controller is
offline.

Confirmed person revocation gates resource-policy and status requests, publication
challenges and staged files, checkpoints, and scope enrollment even when the
presented resource capability remains otherwise valid. Pending person-policy
updates block resource operations; an authenticated, currently authorized device
can read person status and retry the exact saved update. These rules revoke
management authorization only: they do not revoke storage bearer tokens already
disclosed or erase downloaded plaintext. Future content-key and token rotation is
separate. Root-reported current checks: 58 Rust tests plus formatting/build, three
native HTTP integration cases, six focused app client files / 63 tests, 14
management-capability verifier tests and 6 discovery tests passed. These focused
results do not establish product migration/recovery UI, global revocation UI,
future key/token rotation, full browser acceptance or coordinated old-reader
rollback; those remain unverified.

Discovery advertises `capabilities.scopeManagement.version: 1`.
`POST /v2/management/{kind}/{id}/status` returns `capability` (or null),
`migrationPending` and a service-signed status receipt. It requires a complete
owner device proof and a `MATCH/1` signature over `rusty-management-policy-status`
version 1: exact service/origin/person/device/resource, nonce-like request ID,
issuance and expiry. Current non-revoked owner devices may query without a legacy
controller pin. Unsigned reads, invalid signatures, other identities and revoked
devices receive no capability. Status nonces are single-use, persisted through
restart and bounded to 128 live requests. A lost response requires a fresh signed
status request. Status receipts bind request ID/full authorization hash,
capability hash, revision and pending state. Responses prohibit caching and never
return storage tokens or content keys. `kind` is `scope`, `board` or `person`.
For `person`, `id` must equal the exact pinned `personId`; scope and board IDs are
exact opaque resources.

`PUT /v2/management/{kind}/{id}` takes `{version:1, identity, deviceId,
certificates, managementCapability, authorization}`. Authorization is a `MATCH/1`
device-signed `rusty-management-policy-update` version 1, binding service ID,
configured origin, person/device, resource kind/ID, expected revision, sorted
operations, sorted cumulative revoked-device IDs, request ID, issuance and expiry.
Expiry is at most 120 seconds after issuance; future issuance is bounded to 30
seconds. First migration requires legacy operator-approved authority. Later
updates require the exact current capability and `management.update`.

The confirmed `RUSTY/2` capability binds those resource/person/service rights,
positive revision, request ID and full authorization hash. Scope operations are
`scope.policy` and `snapshot.checkpoint`; board operations are
`publication.status`, `publication.publish`, `publication.update`,
`publication.unpublish` and `publication.stage-file`. Each policy includes
`management.update`. Device revocations are cumulative and cannot be undone by
a later policy. Migrated enrollment, publication, asset and checkpoint requests
must include `managementCapability`; missing or stale evidence cannot fall back
to legacy ancestry. Management revocation is separate from rotating previously
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
- `PUT /v2/scopes/{opaqueScope}`: `{challenge, identity, deviceId, certificates, readToken, writeToken, revoked, authorization}`. Authorization is a `MATCH/1` device-signed envelope binding the challenge, origin/service/scope, revision, revocation state, and SHA-256 commitments to both storage tokens. Rusty checks the configured root and allowed device list, consumes each challenge once, and returns a `RUSTY/2` signed policy receipt. Policy revision compare-and-set prevents stale updates. Revocation uses the same signed flow with `revoked: true`; clients must verify the receipt before reporting success.
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
required rather than claiming complete attachment coverage. This server increment
does not establish client delivery, encrypted manifest/chunk formats, product UI,
browser acceptance or a deployed release.

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

Rusty's full suite passes 72 tests, including malformed-batch, missing/corrupt
object, wrong-epoch, read-denial, live-policy/revocation and injected namespace
fsync-failure coverage cases. The durability fault reproduced premature receipt
issuance and now requires both scope-link and blob-directory durability. Five
focused client suites pass 42 tests. The production client coverage adapter has
five focused cases and a native HTTP confirmation test before cold-recipient
download: it authenticates the manifest, derives the exact chunk set, requests
signed coverage without downloading chunk payloads, and rechecks live guards.
Normal application replication now schedules attachment upload and coverage
confirmation. Product/browser acceptance and compatible-client rollout of the
bounded peer-read limit remain unfinished; older cached adapters may ignore the
optional read bound.

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
directory scan. The durable captured/archived/covered preparation repository now
has SDK, private IndexedDB and Worker Durable Object storage adapters. It is caller-
fed: it does not consume the native `VerifiedHistoryPreparation` token or capture
the authenticated archive catalogue. No ordinary host scheduler, signed Owner
transition, atomic baseline activation, restore/export or capability rollout is
implemented.

Tincanban's targeted native-client test now uses the durable private IndexedDB
preparation repository. After a lost upload reply and Rusty restart, a fresh handle
reopens captured/archived state, retries exact ciphertext without resealing, then
confirms signed complete coverage. It retains and cold-recovers a real signed
Automerge change with an absent dependency and repeated-content parts, checking the
original hash, dependencies and author signature. This caller-fed repository is
not connected to the native verified preparation token, ordinary host scheduling
or baseline activation. The combined native client suite now passes eight cases,
including a Native-derived catalogue generated by `VerifiedHistoryArchiveCapture`.
That case stages the exact Native objects through the app journal, confirms real
signed coverage, then cold-downloads original control, proof and compressed pending
change bytes. SDK replay of the same vector preserves admitted/pending/quarantined
classifications through actual WASM. This is fixture/transport integration; a live
WASM capture handle and ordinary producer integration remain absent. The retained
Workerd result is 125 runtime cases. Browser acceptance, automatic host
scheduling, native baseline authority and deployment verification remain open.

### Confirmed snapshot retention

Discovery advertises `capabilities.snapshotCheckpoints.version: 1`. An owner
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
configured root/controller certificate chain and the scope policy's owner.

The device must first durably merge the full inventory and confirm that its raw
Automerge history has no pending or quarantined changes, retaining all required
authorization evidence. It encrypts the resulting full history and current chat
state, including signed records. Chat follows tincanban's existing local retention
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

Public publication API (requires `RUSTY_TRUSTED_OWNER`; anonymous readers use only
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

The domain root serves connection instructions and a link to the protected logs.
Its robot, header and Fira Code/Caveat typography preserve the original Rusty UI.
Styles, fonts and artwork are embedded in the service binary and served from
`/assets/`; rendering does not depend on TinSink being available. The asset handler
serves an explicit embedded allowlist, never files from the storage directory.

`src/ui/design-system.css` contains the unmodified, flattened tincanban design
system from `7f546526bfcc7610f25f771a2288df3784e2abc6` (`src/styles/design-system/index.css`
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

The tests cover two HTTP clients, opaque replication, signed durable receipts, retry, restart, concurrent-writer exclusion, read/write separation, revoked storage, and refusal of plaintext state. Tincanban's `e2e/blind-keeper.spec.ts` starts the standalone debug binary with its own temporary directory/port and checks actual browser encryption, native signature verification, restart settings, and unavailable-server behavior.

The service UI browser check uses the adjacent tincanban checkout's installed
Playwright. It starts an isolated Rusty process on an unused port, verifies loaded
local fonts and the original robot/header on desktop and mobile, and exercises an
unavailable Sink link. Screenshots are written under ignored `target/`.

`main` is the canonical blind-storage and public-publication release. GitHub Actions
checks formatting, the storage/publication protocol suite, and discovery and durable
identity across real service-process restarts. Tincanban CI pins a commit from this
branch and exercises its publication lifecycle with browsers. The former readable
Keeper runtime, pairing console and application grants are superseded; merging their
history does not reactivate them or change existing encrypted storage.

[Blind-storage TLA+ models](formal/tla/README.md) run in CI alongside native tests.
Duplicate upload and recovered checkpoint retries confirm directory durability
before issuing a receipt or pruning prior objects, including after a failed rename
commit. Object IDs, sequences and encrypted storage format remain unchanged.
