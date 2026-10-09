# Rusty blind storage

Rusty stores and serves immutable encrypted objects over HTTP. It does not load Automerge documents, receive readable invitations, participate as a board Editor, classify submissions, fetch job pages, write cards, or process email. Its service signing key authenticates durable storage receipts; it cannot decrypt stored objects or authorize application changes.

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

Encrypted objects contain exactly `version`, `scopeId`, `keyEpoch`, `nonce`, and `ciphertext`. AES-GCM uses a random 12-byte nonce, 128-bit tag, and authenticated binding `RUSTY/2/object\0{scopeId}\0{keyEpoch}`. Server accepts at most 16 MiB ciphertext per object, 10,000 objects and approximately 1 GiB encoded storage per scope. No automatic retention/compaction exists. The browser uploads only changed snapshots, retries identical ciphertext after uncertain delivery, and polls every 15 seconds while open. No client online is required for Rusty to retain data.

Files use private permissions; atomic rename, file/directory fsync precede receipts. Tokens are stored as keyed hashes. Pending enrollment challenges are persisted for replay protection and expire after 120 seconds. A filesystem lock excludes another Rusty writer on the same directory. Back up the service key, policies, challenges, and objects together. Losing the service key prevents authorization and invalidates the pinned identity. Inventory retains object metadata in memory, not all ciphertext.

## Migration

Use a **fresh durable directory/volume**. Startup rejects legacy configs, inboxes, results, and unknown files without deleting them. Existing plaintext volumes are not converted or erased automatically. Keep old volumes private, export boards/inbox/results through an authorized migration process, and remove old Keeper Editor/Visitor grants in each board before retiring the old service. Do not hand old invitations or workspace content keys to new Rusty.

The container invokes the same blind binary. `RUSTY_STATE_DIR` defaults to `/data`; `RUSTY_HTTP_BIND` defaults to `0.0.0.0:8080`. An old `/data` volume fails closed. Cloudflare Worker + Clef website intake, forwarded-mail correlation, and scoped automation remain a separate implementation tracked in tincanban's `blind-keeper-and-scoped-automation` OpenSpec. Old ingestion and plaintext authority modules have been removed. Existing uncommitted `keeper.rs` and `replication.rs` changes are preserved outside the module graph; they are not compiled into Rusty.

## Verification

```sh
cargo test --locked
```

The tests cover two HTTP clients, opaque replication, signed durable receipts, retry, restart, concurrent-writer exclusion, read/write separation, revoked storage, and refusal of plaintext state. Tincanban's `e2e/blind-keeper.spec.ts` starts the standalone debug binary with its own temporary directory/port and checks actual browser encryption, native signature verification, restart settings, and unavailable-server behavior.
