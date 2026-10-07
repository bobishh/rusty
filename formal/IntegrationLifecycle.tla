---------------- MODULE IntegrationLifecycle ----------------
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS AllowVisitorActivation, AllowStaleActivation,
          IgnoreFuturePolicy, AckBeforeCleanup, IgnoreRevisionCAS,
          WidenRevocation, ValidDisconnectProof, IgnoreDisconnectProof,
          RequireVisitorGate, StalePairingStatus
CONSTANT InitialFutureBoards, UnrelatedIsJobSearch, PickAmbiguousTarget
CONSTANT RequireRestartAfterFailure, RequireFailureBeforeAck
CONSTANT OnlyValidOffers
CONSTANT SimulateConcurrentWriter

Roles == {"editor", "visitor"}
PairState == {"idle", "pending", "approved", "staged", "committed"}
Ops == 0..5
Epochs == 0..3
CleanupStates == {"none", "pending", "retry", "restarted", "complete"}

VARIABLES lifecycle, role, grantEpoch, activationOp, tombstoneEpoch,
          tombstoneOp, cleanup, runtime, futureBoards, revision,
          pairState, operationId, ownerApproved, keeperApproved,
          offeredRole, offeredGrantRole, offeredAuto, stagedEpoch, stagedOp,
          receiptState, receiptOp, cleanupFailed, casExpected, diskPresent, secondDiskPresent, partialCleanupObserved,
          legacyVisitor, unrelatedScopeActive

vars == <<lifecycle, role, grantEpoch, activationOp, tombstoneEpoch,
          tombstoneOp, cleanup, runtime, futureBoards, revision,
          pairState, operationId, ownerApproved, keeperApproved,
          offeredRole, offeredGrantRole, offeredAuto, stagedEpoch, stagedOp,
          receiptState, receiptOp, cleanupFailed, casExpected, diskPresent, secondDiskPresent, partialCleanupObserved,
          legacyVisitor, unrelatedScopeActive>>

Init ==
  /\ lifecycle = "absent"
  /\ role = "visitor"
  /\ grantEpoch = 0
  /\ activationOp = 0
  /\ tombstoneEpoch = 0
  /\ tombstoneOp = 0
  /\ cleanup = "none"
  /\ runtime = FALSE
  /\ futureBoards = InitialFutureBoards
  /\ revision = 0
  /\ pairState = "idle"
  /\ operationId = 0
  /\ ownerApproved = FALSE
  /\ keeperApproved = FALSE
  /\ offeredRole = "visitor"
  /\ offeredGrantRole = "visitor"
  /\ offeredAuto = FALSE
  /\ stagedEpoch = 0
  /\ stagedOp = 0
  /\ receiptState = "none"
  /\ receiptOp = 0
  /\ cleanupFailed = FALSE
  /\ casExpected = 0
  /\ diskPresent = FALSE
  /\ secondDiskPresent = FALSE
  /\ partialCleanupObserved = FALSE
  /\ legacyVisitor = FALSE
  /\ unrelatedScopeActive = TRUE

BeginPairing(invite, grant, auto, nextOp) ==
  /\ lifecycle \in {"absent", "removed"}
  /\ pairState \in {"idle", "committed"}
  /\ (~OnlyValidOffers \/ (invite = "editor" /\ grant = "editor"))
  /\ nextOp \in Ops
  /\ nextOp = operationId + 1
  /\ (auto => (futureBoards \/ IgnoreFuturePolicy))
  /\ pairState' = "pending"
  /\ operationId' = nextOp
  /\ offeredRole' = invite
  /\ offeredGrantRole' = grant
  /\ offeredAuto' = auto
  /\ ownerApproved' = FALSE
  /\ keeperApproved' = FALSE
  /\ casExpected' = revision
  /\ receiptState' = "none"
  /\ UNCHANGED <<lifecycle, role, grantEpoch, activationOp, tombstoneEpoch,
       tombstoneOp, cleanup, runtime, futureBoards, revision, stagedEpoch,
       stagedOp, cleanupFailed, diskPresent, legacyVisitor,
       receiptOp, unrelatedScopeActive, secondDiskPresent, partialCleanupObserved>>

ApproveOwner ==
  /\ pairState = "pending"
  /\ ownerApproved' = TRUE
  /\ pairState' = IF keeperApproved THEN "approved" ELSE "pending"
  /\ UNCHANGED <<lifecycle, role, grantEpoch, activationOp, tombstoneEpoch,
       tombstoneOp, cleanup, runtime, futureBoards, revision, operationId,
       keeperApproved, offeredRole, offeredGrantRole, offeredAuto, stagedEpoch, stagedOp,
       receiptState, receiptOp, cleanupFailed, casExpected, diskPresent, legacyVisitor,
       unrelatedScopeActive, secondDiskPresent, partialCleanupObserved>>

ApproveKeeper ==
  /\ pairState = "pending"
  /\ keeperApproved' = TRUE
  /\ pairState' = IF ownerApproved THEN "approved" ELSE "pending"
  /\ UNCHANGED <<lifecycle, role, grantEpoch, activationOp, tombstoneEpoch,
       tombstoneOp, cleanup, runtime, futureBoards, revision, operationId,
       ownerApproved, offeredRole, offeredGrantRole, offeredAuto, stagedEpoch, stagedOp,
       receiptState, receiptOp, cleanupFailed, casExpected, diskPresent, legacyVisitor,
       unrelatedScopeActive, secondDiskPresent, partialCleanupObserved>>

StageProvision ==
  /\ pairState = "approved"
  /\ ownerApproved /\ keeperApproved
  /\ ((offeredRole = "editor" /\ offeredGrantRole = "editor" /\ ~RequireVisitorGate)
       \/ AllowVisitorActivation)
  /\ (offeredAuto => (futureBoards \/ IgnoreFuturePolicy))
  /\ stagedEpoch' = tombstoneEpoch + 1
  /\ stagedEpoch' \in Epochs
  /\ stagedOp' = operationId
  /\ lifecycle' = "staged"
  /\ pairState' = "staged"
  /\ UNCHANGED <<role, grantEpoch, activationOp, tombstoneEpoch, tombstoneOp,
       cleanup, runtime, futureBoards, revision, operationId, ownerApproved,
       keeperApproved, offeredRole, offeredGrantRole, offeredAuto, receiptState, receiptOp, cleanupFailed,
       casExpected, diskPresent, legacyVisitor, unrelatedScopeActive, secondDiskPresent, partialCleanupObserved>>

CommitActivation ==
  /\ pairState = "staged"
  /\ lifecycle = "staged"
  /\ stagedOp = operationId
  /\ (casExpected = revision \/ IgnoreRevisionCAS)
  /\ stagedEpoch > tombstoneEpoch
  /\ ((offeredRole = "editor" /\ offeredGrantRole = "editor" /\ ~RequireVisitorGate)
       \/ AllowVisitorActivation)
  /\ lifecycle' = "active"
  /\ role' = offeredGrantRole
  /\ grantEpoch' = stagedEpoch
  /\ activationOp' = operationId
  /\ runtime' = TRUE
  /\ diskPresent' = TRUE
  /\ secondDiskPresent' = TRUE
  /\ legacyVisitor' = FALSE
  /\ revision' = revision + 1
  /\ pairState' = "committed"
  /\ receiptState' = "active"
  /\ UNCHANGED <<tombstoneEpoch, tombstoneOp, cleanup, futureBoards, operationId,
       ownerApproved, keeperApproved, offeredRole, offeredGrantRole, offeredAuto, stagedEpoch,
       stagedOp, cleanupFailed, casExpected, unrelatedScopeActive, receiptOp, partialCleanupObserved>>

LocalRevoke ==
  /\ lifecycle = "active"
  /\ operationId < 5
  /\ (ValidDisconnectProof \/ IgnoreDisconnectProof)
  /\ lifecycle' = "revoking"
  /\ runtime' = FALSE
  /\ unrelatedScopeActive' = IF WidenRevocation THEN FALSE ELSE unrelatedScopeActive
  /\ tombstoneEpoch' = grantEpoch
  /\ tombstoneOp' = operationId + 1
  /\ operationId' = operationId + 1
  /\ cleanup' = "pending"
  /\ cleanupFailed' = FALSE
  /\ futureBoards' = FALSE
  /\ revision' = revision + 1
  /\ casExpected' = revision
  /\ receiptState' = "pending"
  /\ UNCHANGED <<role, grantEpoch, activationOp, pairState,
       ownerApproved, keeperApproved, offeredRole, offeredGrantRole, offeredAuto, stagedEpoch,
       stagedOp, diskPresent, legacyVisitor, receiptOp, secondDiskPresent, partialCleanupObserved>>

CleanupFails ==
  /\ ~RequireFailureBeforeAck
  /\ lifecycle = "revoking"
  /\ cleanup = "pending"
  /\ cleanup' = "retry"
  /\ cleanupFailed' = TRUE
  /\ UNCHANGED <<lifecycle, role, grantEpoch, activationOp, tombstoneEpoch,
       tombstoneOp, runtime, futureBoards, revision, pairState,
       operationId, ownerApproved, keeperApproved, offeredRole, offeredGrantRole, offeredAuto,
       stagedEpoch, stagedOp, receiptState, receiptOp, casExpected, diskPresent,
       legacyVisitor, unrelatedScopeActive, secondDiskPresent, partialCleanupObserved>>

CleanupPartialFails ==
  /\ RequireFailureBeforeAck
  /\ lifecycle = "revoking"
  /\ cleanup = "pending"
  /\ diskPresent
  /\ secondDiskPresent
  /\ diskPresent' = FALSE
  /\ cleanup' = "retry"
  /\ cleanupFailed' = TRUE
  /\ partialCleanupObserved' = TRUE
  /\ UNCHANGED <<lifecycle, role, grantEpoch, activationOp, tombstoneEpoch,
       tombstoneOp, runtime, futureBoards, revision, pairState, operationId,
       ownerApproved, keeperApproved, offeredRole, offeredGrantRole, offeredAuto,
       stagedEpoch, stagedOp, receiptState, receiptOp, casExpected,
       secondDiskPresent, legacyVisitor, unrelatedScopeActive>>

CleanupSucceeds ==
  /\ lifecycle = "revoking"
  /\ cleanup \in {"pending", "retry", "restarted"}
  /\ (~RequireFailureBeforeAck \/ cleanup \in {"retry", "restarted"})
  /\ (~RequireRestartAfterFailure \/ cleanup # "retry")
  /\ cleanup' = "complete"
  /\ cleanupFailed' = FALSE
  /\ diskPresent' = FALSE
  /\ secondDiskPresent' = FALSE
  /\ UNCHANGED <<lifecycle, role, grantEpoch, activationOp, tombstoneEpoch,
       tombstoneOp, runtime, futureBoards, revision, pairState, operationId,
       ownerApproved, keeperApproved, offeredRole, offeredGrantRole, offeredAuto, stagedEpoch,
       stagedOp, receiptState, receiptOp, casExpected, legacyVisitor,
       unrelatedScopeActive, partialCleanupObserved>>

AckRemoved ==
  /\ lifecycle = "revoking"
  /\ (cleanup = "complete" \/ AckBeforeCleanup)
  /\ lifecycle' = "removed"
  /\ cleanup' = cleanup
  /\ receiptState' = "removed"
  /\ receiptOp' = operationId
  /\ revision' = revision + 1
  /\ UNCHANGED <<role, grantEpoch, activationOp, tombstoneEpoch, tombstoneOp,
       runtime, futureBoards, pairState, operationId, ownerApproved,
       keeperApproved, offeredRole, offeredGrantRole, offeredAuto, stagedEpoch, stagedOp,
       cleanupFailed, casExpected, diskPresent, legacyVisitor,
       unrelatedScopeActive, secondDiskPresent, partialCleanupObserved>>

Restart ==
  /\ runtime' = (lifecycle = "active")
  /\ cleanup' = IF lifecycle = "revoking" /\ cleanup = "retry"
                  THEN "restarted" ELSE cleanup
  /\ UNCHANGED <<lifecycle, role, grantEpoch, activationOp, tombstoneEpoch,
       tombstoneOp, futureBoards, revision, pairState, operationId,
       ownerApproved, keeperApproved, offeredRole, offeredGrantRole, offeredAuto, stagedEpoch,
       stagedOp, receiptState, cleanupFailed, casExpected, diskPresent,
       legacyVisitor, unrelatedScopeActive, receiptOp, secondDiskPresent, partialCleanupObserved>>

ReplayOldActivation ==
  /\ lifecycle = "removed"
  /\ activationOp < tombstoneOp
  /\ AllowStaleActivation
  /\ lifecycle' = "active"
  /\ runtime' = TRUE
  /\ receiptState' = "active"
  /\ revision' = revision + 1
  /\ UNCHANGED <<role, grantEpoch, activationOp, tombstoneEpoch, tombstoneOp,
       cleanup, futureBoards, pairState, operationId, ownerApproved,
       keeperApproved, offeredRole, offeredGrantRole, offeredAuto, stagedEpoch, stagedOp,
       cleanupFailed, casExpected, diskPresent, legacyVisitor,
       unrelatedScopeActive, receiptOp, secondDiskPresent, partialCleanupObserved>>

ReplayStalePairingStatus ==
  /\ lifecycle = "removed"
  /\ pairState = "committed"
  /\ StalePairingStatus
  /\ receiptState' = "active"
  /\ UNCHANGED <<lifecycle, role, grantEpoch, activationOp, tombstoneEpoch,
       tombstoneOp, cleanup, runtime, futureBoards, revision, pairState,
       operationId, ownerApproved, keeperApproved, offeredRole, offeredGrantRole,
       offeredAuto, stagedEpoch, stagedOp, cleanupFailed, casExpected,
       diskPresent, legacyVisitor, unrelatedScopeActive, receiptOp, secondDiskPresent, partialCleanupObserved>>

ConcurrentConfigUpdate ==
  /\ pairState = "staged"
  /\ SimulateConcurrentWriter
  /\ revision < 5
  /\ revision' = revision + 1
  /\ UNCHANGED <<lifecycle, role, grantEpoch, activationOp, tombstoneEpoch,
       tombstoneOp, cleanup, runtime, futureBoards, pairState, operationId,
       ownerApproved, keeperApproved, offeredRole, offeredGrantRole, offeredAuto, stagedEpoch,
       stagedOp, receiptState, cleanupFailed, casExpected, diskPresent,
       legacyVisitor, unrelatedScopeActive, receiptOp, secondDiskPresent, partialCleanupObserved>>

RefreshStagedCAS ==
  /\ pairState = "staged"
  /\ casExpected # revision
  /\ casExpected' = revision
  /\ UNCHANGED <<lifecycle, role, grantEpoch, activationOp, tombstoneEpoch,
       tombstoneOp, cleanup, runtime, futureBoards, revision, pairState,
       operationId, ownerApproved, keeperApproved, offeredRole, offeredGrantRole,
       offeredAuto, stagedEpoch, stagedOp, receiptState, cleanupFailed,
       diskPresent, legacyVisitor, unrelatedScopeActive, receiptOp, secondDiskPresent, partialCleanupObserved>>

ImportLegacyVisitor ==
  /\ lifecycle = "absent"
  /\ pairState = "idle"
  /\ lifecycle' = "active"
  /\ role' = "visitor"
  /\ grantEpoch' = 1
  /\ activationOp' = 1
  /\ revision' = 1
  /\ runtime' = TRUE
  /\ diskPresent' = TRUE
  /\ secondDiskPresent' = TRUE
  /\ legacyVisitor' = TRUE
  /\ receiptState' = "active"
  /\ UNCHANGED <<tombstoneEpoch, tombstoneOp, cleanup, futureBoards,
       pairState, operationId, ownerApproved, keeperApproved, offeredRole,
       offeredGrantRole, offeredAuto, stagedEpoch, stagedOp, cleanupFailed, casExpected,
       unrelatedScopeActive, receiptOp, partialCleanupObserved>>

Next ==
  \/ \E invite, grant \in {"editor", "visitor"}, auto \in BOOLEAN, op \in Ops :
       BeginPairing(invite, grant, auto, op)
  \/ ApproveOwner
  \/ ApproveKeeper
  \/ StageProvision
  \/ CommitActivation
  \/ LocalRevoke
  \/ CleanupFails
  \/ CleanupPartialFails
  \/ CleanupSucceeds
  \/ AckRemoved
  \/ Restart
  \/ ReplayOldActivation
  \/ ReplayStalePairingStatus
  \/ ConcurrentConfigUpdate
  \/ RefreshStagedCAS
  \/ ImportLegacyVisitor
  \/ UNCHANGED vars

Spec == Init /\ [][Next]_vars

RuntimeOnlyFromActiveRegistry == runtime => lifecycle = "active"
RemovedNeverRoutes == lifecycle \in {"revoking", "removed"} => ~runtime
EditorGrantRequired == lifecycle = "active" => role = "editor" \/ legacyVisitor
EditorInviteRequired == lifecycle = "active" => offeredRole = "editor" \/ legacyVisitor
EditorRoleProofs == lifecycle = "active" => legacyVisitor \/ (role = "editor" /\ offeredRole = "editor")
FreshGrantEpoch == lifecycle = "active" => grantEpoch > tombstoneEpoch
ActiveReceiptHasCurrentCommit == receiptState = "active" =>
  lifecycle = "active" /\ runtime /\ (legacyVisitor \/ activationOp = operationId)
CleanupBeforeRemovedAck == receiptState = "removed" =>
  lifecycle = "removed" /\ cleanup = "complete" /\ ~runtime /\ ~diskPresent /\ ~secondDiskPresent
NoStaleActivationResurrection == lifecycle = "removed" =>
  ~(runtime /\ activationOp < tombstoneOp)
FuturePolicyBlocksAutoPairing == pairState \in {"pending", "approved", "staged"} /\ offeredAuto => futureBoards
ApprovalRequiredForStage == pairState \in {"staged", "committed"} => ownerApproved /\ keeperApproved
CommitUsesCurrentRevision == lifecycle = "active" => revision = casExpected + 1
PendingRevokeUsesOperation == lifecycle = "revoking" => operationId = tombstoneOp
RemovedReceiptMatchesDisconnect == receiptState = "removed" =>
  receiptOp = operationId /\ receiptOp = tombstoneOp /\ ~diskPresent /\ ~secondDiskPresent
ExactScopeRevocation == unrelatedScopeActive
RetainedDataHasNoAuthority == lifecycle \in {"revoking", "removed"} => ~runtime
FailedCleanupStaysPending == cleanupFailed =>
  lifecycle = "revoking" /\ cleanup \in {"retry", "restarted"} /\
    receiptState = "pending" /\ ~runtime
IntakeRoute ==
  IF runtime /\ lifecycle = "active" /\ role = "editor"
  THEN IF unrelatedScopeActive /\ UnrelatedIsJobSearch /\ ~PickAmbiguousTarget
       THEN "ambiguous" ELSE "target"
  ELSE "blocked"
AmbiguousRouteBlocked ==
  runtime /\ lifecycle = "active" /\ role = "editor" /\
    unrelatedScopeActive /\ UnrelatedIsJobSearch
  => IntakeRoute = "ambiguous"
RevocationRequiresExactSignedProof ==
  lifecycle \in {"revoking", "removed"} => ValidDisconnectProof
RevokeEventuallyAcknowledged == lifecycle = "revoking" ~> lifecycle = "removed"
EditorActivationCompletes == pairState = "approved" ~> lifecycle = "active"
BeginEditorPairing == \E op \in Ops : BeginPairing("editor", "editor", FALSE, op)
BeginAutoPairing == \E op \in Ops : BeginPairing("editor", "editor", TRUE, op)
FutureAutoOfferCompletes == futureBoards ~> (pairState = "committed" /\ offeredAuto)
AutoPolicyNext ==
  \/ BeginAutoPairing
  \/ ApproveOwner
  \/ ApproveKeeper
  \/ StageProvision
  \/ CommitActivation
  \/ UNCHANGED vars
FuturePolicySpec ==
  /\ Init
  /\ [][AutoPolicyNext]_vars
  /\ WF_vars(BeginAutoPairing)
  /\ WF_vars(ApproveOwner)
  /\ WF_vars(ApproveKeeper)
  /\ WF_vars(StageProvision)
  /\ WF_vars(CommitActivation)
FairSpec ==
  /\ Init /\ [][Next]_vars
  /\ WF_vars(BeginEditorPairing)
  /\ WF_vars(ApproveOwner)
  /\ WF_vars(ApproveKeeper)
  /\ WF_vars(StageProvision)
  /\ WF_vars(CommitActivation)
  /\ WF_vars(LocalRevoke)
  /\ WF_vars(CleanupFails)
  /\ WF_vars(CleanupPartialFails)
  /\ WF_vars(Restart)
  /\ WF_vars(CleanupSucceeds)
  /\ WF_vars(AckRemoved)
  /\ WF_vars(RefreshStagedCAS)
  /\ WF_vars(BeginAutoPairing)
FullRetryReAdd ==
  /\ <> partialCleanupObserved
  /\ <> (cleanup = "retry")
  /\ <> (cleanup = "restarted")
  /\ <> (receiptState = "removed")
  /\ <> (lifecycle = "active" /\ tombstoneEpoch > 0 /\ grantEpoch > tombstoneEpoch)
TypeOK ==
  /\ lifecycle \in {"absent", "staged", "active", "revoking", "removed"}
  /\ role \in {"editor", "visitor"}
  /\ grantEpoch \in Epochs /\ tombstoneEpoch \in Epochs /\ stagedEpoch \in Epochs
  /\ activationOp \in Ops /\ tombstoneOp \in Ops /\ operationId \in Ops /\ stagedOp \in Ops
  /\ revision \in 0..12 /\ casExpected \in 0..12
  /\ cleanup \in CleanupStates
  /\ pairState \in {"idle", "pending", "approved", "staged", "committed"}
  /\ receiptState \in {"none", "active", "pending", "removed"}
  /\ runtime \in BOOLEAN /\ futureBoards \in BOOLEAN /\ cleanupFailed \in BOOLEAN
  /\ ownerApproved \in BOOLEAN /\ keeperApproved \in BOOLEAN /\ offeredAuto \in BOOLEAN
  /\ offeredRole \in {"editor", "visitor"} /\ diskPresent \in BOOLEAN
  /\ offeredGrantRole \in {"editor", "visitor"}
  /\ legacyVisitor \in BOOLEAN /\ unrelatedScopeActive \in BOOLEAN
  /\ secondDiskPresent \in BOOLEAN /\ partialCleanupObserved \in BOOLEAN

=============================================================
