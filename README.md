# Rusty blind storage

Rusty is an optional HTTP service for storing and serving immutable encrypted objects. Clients encrypt and authorize workspace history; Rusty stores opaque bytes and signs durable storage receipts. Its service key cannot decrypt objects or authorize board edits.

Rusty also exposes a separate public-board publication API. Authorized clients send a selected, readable board projection for anonymous visitors. Rusty verifies the configured owner proof and signed command, but does not inspect the private workspace history behind that projection. Current public-board and private-storage capabilities remain bound to the identity and resource policies recorded by Rusty. There is no deployment-wide owner identity pin.

## Start a local service

Requirements: Rust toolchain available for the locked project dependencies.

```sh
cargo build --release --locked
./target/release/mesh-lighthouse /tmp/rusty-local 127.0.0.1:8080
```

This starts loopback HTTP with an empty CORS allowlist. Configure exact public origins only when integrating a client or hosting the service; see the [protocol and operations reference](docs/storage-protocol-and-operations.md).

## Relationship to the product

Tincanban is a client of Rusty; MetaMesh handles peer identity and readable replication. Rusty does not join the board's Automerge sync, act as a board Editor, classify job submissions, fetch job pages, or process email. Storage access does not grant board access. Removing a board grant does not erase plaintext or keys already obtained; disconnecting one device does not revoke stored credentials.

## Protocol, verification, and operations

The [storage protocol and operations reference](docs/storage-protocol-and-operations.md) documents storage formats, authorization, attachment and archive handling, migrations, diagnostics, tests, and deployment behavior. Repository tests and production rollout are separate evidence.
