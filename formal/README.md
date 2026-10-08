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
checks offer liveness, its Visitor grant mutant checks role safety, and its
omitted-ledger mutant checks that a runtime-attached scope also enters the
canonical registry. It also starts with an existing owned board in the captured
inventory but outside the explicitly approved initial scope list; the sweep
mutant demonstrates that future-board consent cannot add that unselected board
to this integration. Its preexisting standalone runtime attachment remains
active and outside the integration ledger; the model does not require every
local scope to belong to an integration. A subsequently created board is absent
from that captured inventory and may be offered under consent. The disabled-
consent config checks that no board can stage when `futureBoards` is false. The
owner signature itself is abstracted as `OwnerProofValid`; signature
verification remains covered by Rust tests.

`DisconnectReplay.tla` preserves a completed signed removal receipt as history.
After a fresh higher-epoch re-add, replay of that old removal operation must
return conflict instead of presenting the historical receipt as current
removal confirmation. Its mutant returns the archived receipt while the scope
is active and violates `RemovedResponseMatchesCurrentScope`.

`LegacyOfflineRemoval.tla` covers older keeper records that identify the keeper
and owner-selected boards but have no Rusty integration descriptor. Owner
authorization and current ownership of selected boards permit persisting a
pending removal intent before local sync revocation. Without a descriptor, no
remote request or completion is possible; a later supplied address is usable
only after matching the known keeper device and validating signed status. Local
and remote failures retain pending state for retry. Removal clears only after
cleanup and exact signed receipt, while board data and unrelated scopes remain.
The normal trace includes local revoke failure, retry, later descriptor
discovery, remote request failure, retry, and receipt. A no-descriptor config
checks durable pending behavior; a mutant permits new owner offers during that
pending interval.

`SessionCookieIsolation.tla` abstracts operator and Tincanban identity
sessions as distinct server-validated tokens in separate cookie slots. The
normal config checks that identity exchange preserves operator access, each
logout clears only its own session, and operator approval remains reachable.
The collision mutant writes the identity token into the operator slot and must
violate `OperatorCookieSlotIsOperatorOnly`. The model does not prove HTTP cookie
attributes, token entropy, CSRF validation, or browser storage; Rust router and
Playwright tests cover those behaviors.

`LocalProjectionCleanup.tla` checks the client-side tail after a valid Rusty
removed receipt: persist that receipt in the integration reference, fail to
delete the local OwnerKeeper record, restart, and retry the local deletion. The
normal trace retains enough receipt data for retry. `LocalProjectionCleanupDropsReceipt.cfg`
models clearing that data too early and must violate cleanup liveness. This is
a cross-repository state contract, not a proof of Tincanban storage behavior;
the corresponding implementation is `tincanban/src/sync/deviceSyncKeeper.ts`
(`persistRemovalReceipt`, `finishAlreadyRemoved`).

`PairingWithdrawal.tla` covers a controller-signed withdrawal fence while
provisioning may be in flight. A grant may already have been issued before
activation; cancellation therefore requires either no provisioning attempt or
verified owner revocation beyond the issued grant. Rusty cannot revoke grants
itself. The model checks late activation, retry fencing, cleanup/restart, and
the case where detached service files are incorrectly treated as proof that
the owner grant was revoked. That mutant violates `CancelledHasNoGrant`. The
model abstracts envelope signatures and grant epochs to booleans; Rust tests
cover signed owner proof and strict epoch comparison.

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
| Future-board consent applies only to genuinely new boards; Editor invite/grant and registry commit enforced | `FuturePolicyBlocksAutoPairing`; `FutureConsent.cfg` mutant; `FutureOfferLifecycle.tla` configs `FutureEditorOffer.cfg` witness, `FutureVisitorOnlyOfferGate.cfg` liveness mutant, `FutureVisitorGrant.cfg` role mutant, `FutureLedgerOmitted.cfg` registry mutant, `FutureSweepsUnselected.cfg` baseline-consent mutant, `FutureConsentDisabled.cfg` consent check |
| A completed removal receipt remains historical after fresh re-add; stale replay cannot claim current removal | `RemovedResponseMatchesCurrentScope`; `DisconnectReplayStaleReceipt.cfg` mutant; `DisconnectReplay.cfg` conflict-after-readd witness |
| Legacy offline removal persists local intent, blocks sync/offers, and waits for exact signed remote completion | `LegacyOfflineRemoval.cfg` retry witness; `LegacyOfflineNoDescriptor.cfg` pending witness; `LegacyOfferDuringPending.cfg` mutant |
| Operator and identity sessions survive independent sign-in and logout | `SessionCookieIsolation.cfg`; `SessionCookieCollision.cfg` models the overwrite defect |
| Local OwnerKeeper projection cleanup retries after a verified removal receipt and restart | `LocalProjectionCleanup.cfg`; `LocalProjectionCleanupDropsReceipt.cfg` models lost retry evidence |
| Pairing withdrawal fences late provision/retry and waits for owner revocation beyond issued grants | `PairingWithdrawal.cfg`; `PairingLateActivation.cfg`, `PairingRetryAfterWithdrawal.cfg`, and `PairingUnverifiedCompletion.cfg` are expected counterexamples |
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
- Future-board import must update runtime scopes and the Config-backed
  integration registry and must exclude boards outside pairing baseline:
  `src/keeper.rs` (`merge_owner_offer`, `record_activated_integration`) and
  Tincanban's captured owner workspace baseline.
- JobSearch target selection and ambiguity rejection: `src/keeper.rs`.

Run `python3 formal/run_models.py --jar /path/to/tla2tools.jar`. TLC logs and
state directories stay outside checkout by default. CI downloads official TLC
1.7.4 and verifies its pinned SHA-256.
