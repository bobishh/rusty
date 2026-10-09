## Why

Lighthouse currently has one workspace config, one store and a CLI-only join flow. It must become a deployable service accepting N independently authorized integrations, each with multiple boards, without manual container access for normal pairing.

## What Changes

- Run one persistent service identity/device and Iroh node, dispatching to isolated integration/scope state.
- Expose versioned discovery and signed pairing/management APIs plus an authenticated operator UI.
- Require both service admission and workspace-owner approval before activating integration scopes.
- Support read-only replication, explicit editor automation, authority updates/revocation, durable acknowledgements and attachment replication.
- Add bounded capacity, fair scheduling, recovery provisioning, readiness and a documented self-hosted container deployment.
- Replace singleton assumptions with a registry; preserve the existing production integration through an explicit one-time import.
- Reuse MetaMesh protocols and Match authority; keep product adapters separate from service admission.

## Capabilities

### New Capabilities
- `lighthouse-service`: Multi-integration lifecycle, operator administration, identity recovery, isolation, scheduling, replication and deployment.

### Modified Capabilities
None. There is no existing published Lighthouse capability specification in this repository.

## Impact

`src/main.rs`, `src/join.rs`, `src/lib.rs`, `src/http.rs`, entrypoint, container/docs and shared MetaMesh dependencies. Existing intake must route to an explicit integration/workspace instead of a singleton store. Companion: [tincanban integration UI](../../../../tincanban/openspec/changes/lighthouse-integrations/proposal.md). The shared version-1 HTTP contract lives in this change's `protocol.md`; these are proposed requirements, not deployed behavior.
