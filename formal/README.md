# Keeper integration lifecycle model

`IntegrationLifecycle.tla` models one Config-backed integration, two selected
workspace replicas, and one unrelated active scope. Pairing history is
independent from current registry/runtime status. Invitation role and signed
grant role are separate; both must be Editor for new activation. The bounded
model covers two-party approval, revision compare-and-swap, per-scope grant
epochs, immediate local routing block, tombstones, partial cleanup failure,
restart reconstruction, operation-bound removal receipt, future-board policy,
and ambiguous JobSearch routing.

The model abstracts cryptographic signatures, owner/person/device/service
binding, expiry, and exact workspace IDs into `ValidDisconnectProof`, separate
owner and keeper approval bits, and a fixed two-scope request. It does not
prove signature verification, filesystem path selection, disk atomicity,
network delivery, or multi-integration enumeration. Receipt operation ID must
match the disconnect tombstone. The unrelated-scope bit checks that removal
does not affect another integration. Disk presence is independent of
authority: bytes may remain during pending cleanup but cannot keep runtime
routing active. A removed receipt requires both selected files cleaned up.

`FailureRestartReAdd.cfg` witnesses partial cleanup, process restart, retry,
signed removal receipt, and fresh activation with a higher grant epoch.
`ConcurrentCAS.cfg` checks that concurrent owner updates cannot commit a stale
staged revision. `FutureEnabled.cfg` witnesses future provisioning with an
Editor invitation and Editor grant. `FutureOfferLifecycle.tla` starts from an
already-active Editor integration, then models a separately owner-signed future
board offer; it does not require a second pairing approval. Its normal config
checks Editor invitation and grant independently, its Visitor-only gate mutant
checks offer liveness, and its Visitor grant mutant checks role safety. The
disabled-consent config checks that no board can stage when `futureBoards` is
false. The owner signature itself is abstracted as `OwnerProofValid`; signature
verification remains covered by Rust tests.

| Requirement | Check |
| --- | --- |
| Editor invitation and signed Editor grant required | `EditorRoleProofs`; `VisitorActivation.cfg` mutant |
| Valid Editor pairing eventually activates | `EditorActivationCompletes`; `VisitorOnlyGate.cfg` liveness mutant |
| Pairing receipt cannot claim active after detach | `ActiveReceiptHasCurrentCommit`; `StalePairingStatus.cfg` mutant |
| Revocation immediately blocks routing; ACK waits for cleanup | `RemovedNeverRoutes`, `CleanupBeforeRemovedAck`; `EarlyAck.cfg` mutant |
| Receipt matches disconnect operation; unrelated scope stays active | `RemovedReceiptMatchesDisconnect`, `ExactScopeRevocation`; `UnsignedDisconnect.cfg` and `WidenedRevoke.cfg` mutants |
| Partial selected-scope cleanup retries across restart | `FullRetryReAdd`; `FailureRestartReAdd.cfg` witness |
| Tombstoned activation cannot replay; fresh higher-epoch Editor can re-add | `NoStaleActivationResurrection`, `FreshGrantEpoch`; `StaleActivation.cfg` mutant |
| Concurrent owner revision cannot commit stale stage | `CommitUsesCurrentRevision`; `ConcurrentCAS.cfg` and `StaleCAS.cfg` |
| Future-board consent plus Editor invite/grant are enforced independently | `FuturePolicyBlocksAutoPairing`; `FutureConsent.cfg` mutant; `FutureOfferLifecycle.tla` configs `FutureEditorOffer.cfg` witness, `FutureVisitorOnlyOfferGate.cfg` liveness mutant, `FutureVisitorGrant.cfg` role mutant, `FutureConsentDisabled.cfg` consent check |
| Ambiguous JobSearch routing is blocked | `AmbiguousRouteBlocked`; `AmbiguousRouteMutation.cfg` mutant |

Source mapping:

- Config-backed integration registry and cleanup reconciliation:
  `src/main.rs`, `src/keeper.rs` (`reconcile_registry`,
  `finish_disconnect_cleanup`).
- Two-sided approval, role validation, and signed status/disconnect envelopes:
  `src/pairing.rs`, `src/http.rs`.
- Activation, revision checks, disconnect tombstones, and scoped deletion:
  `src/keeper.rs` (`activate_provisioned_scopes`,
  `disconnect_integration`, `unsubscribe`).
- JobSearch target selection and ambiguity rejection: `src/keeper.rs`.

Run `python3 formal/run_models.py --jar /path/to/tla2tools.jar`. TLC logs and
state directories stay outside checkout by default. CI downloads official TLC
1.7.4 and verifies its pinned SHA-256.
