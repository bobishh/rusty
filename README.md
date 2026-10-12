# Rusty blind storage

Rusty stores and serves immutable encrypted objects over HTTP. It does not load Automerge documents, receive readable invitations, participate as a board Editor, classify submissions, fetch job pages, write cards, or process email. Its service signing key authenticates durable storage receipts; it cannot decrypt stored objects or authorize application changes.

Rusty also supports a separate public-board publication namespace. Authorized clients
send a strictly validated, selected-board projection and separate public file copies
after confirming source-board owner rights locally. Rusty verifies its configured
controller root/device, challenge-bound signatures, expected revision and snapshot
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

`RUSTY_TRUSTED_OWNER` is public trust configuration, not a secret. It pins the owner's root identity and an explicit allowlist of controller device IDs. Rusty validates the submitted device-certificate chain to that root. Missing or invalid trust configuration disables provisioning. Keep the corresponding private keys on authorized client devices only. For local development, use `127.0.0.1:8080`; the default origin is then loopback HTTP. Public hosting requires HTTPS, normally through the deployment proxy. CORS accepts a comma-separated allowlist of exact frontend origins and defaults to none. `LIGHTHOUSE_PUBLIC_ORIGIN` and `LIGHTHOUSE_CORS_ORIGINS` remain configuration aliases.

In tincanban, connect by entering the Rusty address. The owner device proves its identity with a short-lived Rusty challenge and a device-signed authorization. The browser creates a random opaque scope, separate read/write storage tokens, and a 32-byte AES-GCM reading key. It sends only scope and storage tokens to Rusty; Rusty stores keyed token hashes. The service never returns bearer tokens. The browser pins the service public key and verifies signed policy and upload receipts before saving access locally or marking a snapshot replicated. Access transfer to additional already-enrolled devices requires a separate encrypted device-settings channel and is not part of this protocol.

Board history, authorization proofs, and workspace chat are encrypted together. A receiving client verifies AES-GCM authentication, scope/epoch, and the existing signed causal authorization before merging changes. Attachments continue through existing device sync; blind blob replication is not implemented. Storage access does not grant board edit permissions. Rusty stores snapshots containing Automerge history, rather than implementing the readable Automerge sync protocol.

**Export private access** saves a JSON file containing the reading key and storage tokens. Transfer it privately to an authorized device that already has the board through the normal signed invitation/import flow, then choose **Import private Rusty access**. These credentials remain in private local IndexedDB, outside shared board state. They are not automatically synchronized with identity enrollment. **Disconnect locally** stops this device; it does not revoke storage tokens on Rusty. Removing a member's board grant does not remove previously obtained plaintext or reading keys.

## Storage protocol

Discovery: `GET /.well-known/mesh-lighthouse`, protocol 2, mode `blind`, `applicationWrites: false`, `classification: false`. No person/device certificate or application grant is advertised. The signed enrollment flow is distinct from workspace pairing; it never sends workspace grants or content keys.

- `POST /v2/enrollment/challenge`: `{version, scopeId, identity, deviceId, certificates}`. Returns a Rusty-signed, 120-second challenge bound to service identity, configured origin, owner, controller device, scope, and current policy revision. Up to 8 pending challenges per owner/scope and 128 globally; expired challenges are removed.
- `PUT /v2/scopes/{opaqueScope}`: `{challenge, identity, deviceId, certificates, readToken, writeToken, revoked, authorization}`. Authorization is a `MATCH/1` device-signed envelope binding the challenge, origin/service/scope, revision, revocation state, and SHA-256 commitments to both storage tokens. Rusty checks the configured root and allowed device list, consumes each challenge once, and returns a `RUSTY/2` signed policy receipt. Policy revision compare-and-set prevents stale updates. Revocation uses the same signed flow with `revoked: true`; clients must verify the receipt before reporting success.
- `PUT /v2/scopes/{scope}/objects/{id}`: write bearer token; `X-Rusty-Request-Id` fresh challenge; encrypted object JSON. ID is base64url SHA-256 of canonical JSON. Returns Ed25519 envelope under `RUSTY/2`, binding service, scope, epoch, object hash, durable sequence, policy revision, and challenge.
- `GET /v2/scopes/{scope}/objects?after=0`: read bearer token; ordered inventory, maximum 128 entries per page.
- `GET /v2/scopes/{scope}/objects/{id}`: read bearer token; encrypted object JSON.
- `GET /health`: reports blind mode.

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

Encrypted objects contain exactly `version`, `scopeId`, `keyEpoch`, `nonce`, and `ciphertext`. AES-GCM uses a random 12-byte nonce, 128-bit tag, and authenticated binding `RUSTY/2/object\0{scopeId}\0{keyEpoch}`. Server accepts at most 16 MiB ciphertext per object, 10,000 objects and approximately 1 GiB encoded storage per scope by default. Set `RUSTY_MAX_SCOPE_BYTES` to a positive byte count in deployment configuration to change the per-scope budget; the 10,000-object ceiling remains. Raising the budget preserves existing objects and permits retries without migration. No automatic retention/compaction exists. The browser uploads only changed snapshots, retries identical ciphertext after uncertain delivery, and polls every 15 seconds while open. No client online is required for Rusty to retain data.

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
