---------------- MODULE LegacyOfflineRemoval ----------------
EXTENDS Naturals, TLC

CONSTANTS OwnerAuthorized, SelectedScopeOwned, ServiceAddressAvailable,
          KnownKeeperDevice, SignedStatusValid, SignedReceiptValid,
          ReceiptScopesExact, AllowOfferDuringPending

VARIABLES removalStarted, pending, keeperSyncAllowed, localRevokeApplied,
          localFailureObserved, descriptorKnown, requestSent,
          remoteFailureObserved, cleanupComplete, removedReceipt,
          ownerOfferDuringPending, ownedDataPresent, unrelatedScopeActive

vars == <<removalStarted, pending, keeperSyncAllowed, localRevokeApplied,
         localFailureObserved, descriptorKnown, requestSent,
         remoteFailureObserved, cleanupComplete, removedReceipt,
         ownerOfferDuringPending, ownedDataPresent, unrelatedScopeActive>>

Init ==
  /\ removalStarted = FALSE
  /\ pending = FALSE
  /\ keeperSyncAllowed = TRUE
  /\ localRevokeApplied = FALSE
  /\ localFailureObserved = FALSE
  /\ descriptorKnown = FALSE
  /\ requestSent = FALSE
  /\ remoteFailureObserved = FALSE
  /\ cleanupComplete = FALSE
  /\ removedReceipt = FALSE
  /\ ownerOfferDuringPending = FALSE
  /\ ownedDataPresent = TRUE
  /\ unrelatedScopeActive = TRUE

PersistRemovalIntent ==
  /\ ~removalStarted
  /\ OwnerAuthorized
  /\ SelectedScopeOwned
  /\ removalStarted' = TRUE
  /\ pending' = TRUE
  /\ UNCHANGED <<keeperSyncAllowed, localRevokeApplied,
                  localFailureObserved, descriptorKnown, requestSent,
                  remoteFailureObserved, cleanupComplete, removedReceipt,
                  ownerOfferDuringPending, ownedDataPresent, unrelatedScopeActive>>

LocalRevokeFails ==
  /\ pending
  /\ keeperSyncAllowed
  /\ ~localFailureObserved
  /\ localFailureObserved' = TRUE
  /\ UNCHANGED <<removalStarted, pending, keeperSyncAllowed,
                  localRevokeApplied, descriptorKnown, requestSent,
                  remoteFailureObserved, cleanupComplete, removedReceipt,
                  ownerOfferDuringPending, ownedDataPresent, unrelatedScopeActive>>

RetryLocalRevoke ==
  /\ pending
  /\ keeperSyncAllowed
  /\ localFailureObserved
  /\ keeperSyncAllowed' = FALSE
  /\ localRevokeApplied' = TRUE
  /\ UNCHANGED <<removalStarted, pending, localFailureObserved,
                  descriptorKnown, requestSent, remoteFailureObserved,
                  cleanupComplete, removedReceipt, ownerOfferDuringPending,
                  ownedDataPresent, unrelatedScopeActive>>

ProvideAddressAndValidateStatus ==
  /\ pending
  /\ localRevokeApplied
  /\ ~descriptorKnown
  /\ ServiceAddressAvailable
  /\ KnownKeeperDevice
  /\ SignedStatusValid
  /\ descriptorKnown' = TRUE
  /\ UNCHANGED <<removalStarted, pending, keeperSyncAllowed,
                  localRevokeApplied, localFailureObserved, requestSent,
                  remoteFailureObserved, cleanupComplete, removedReceipt,
                  ownerOfferDuringPending, ownedDataPresent, unrelatedScopeActive>>

SubmitSignedDisconnect ==
  /\ pending
  /\ localRevokeApplied
  /\ descriptorKnown
  /\ ~requestSent
  /\ requestSent' = TRUE
  /\ UNCHANGED <<removalStarted, pending, keeperSyncAllowed,
                  localRevokeApplied, localFailureObserved, descriptorKnown,
                  remoteFailureObserved, cleanupComplete, removedReceipt,
                  ownerOfferDuringPending, ownedDataPresent, unrelatedScopeActive>>

RemoteRequestFailsOnce ==
  /\ requestSent
  /\ ~remoteFailureObserved
  /\ requestSent' = FALSE
  /\ remoteFailureObserved' = TRUE
  /\ UNCHANGED <<removalStarted, pending, keeperSyncAllowed,
                  localRevokeApplied, localFailureObserved, descriptorKnown,
                  cleanupComplete, removedReceipt, ownerOfferDuringPending,
                  ownedDataPresent, unrelatedScopeActive>>

CompleteRemoteCleanup ==
  /\ requestSent
  /\ remoteFailureObserved
  /\ cleanupComplete' = TRUE
  /\ requestSent' = FALSE
  /\ UNCHANGED <<removalStarted, pending, keeperSyncAllowed,
                  localRevokeApplied, localFailureObserved, descriptorKnown,
                  remoteFailureObserved, removedReceipt, ownerOfferDuringPending,
                  ownedDataPresent, unrelatedScopeActive>>

AcceptSignedRemovedReceipt ==
  /\ pending
  /\ cleanupComplete
  /\ SignedReceiptValid
  /\ ReceiptScopesExact
  /\ pending' = FALSE
  /\ removedReceipt' = TRUE
  /\ UNCHANGED <<removalStarted, keeperSyncAllowed, localRevokeApplied,
                  localFailureObserved, descriptorKnown, requestSent,
                  remoteFailureObserved, cleanupComplete, ownerOfferDuringPending,
                  ownedDataPresent, unrelatedScopeActive>>

IssueOwnerOffer ==
  /\ (~pending \/ AllowOfferDuringPending)
  /\ IF pending
        THEN ownerOfferDuringPending' = TRUE
        ELSE UNCHANGED ownerOfferDuringPending
  /\ UNCHANGED <<removalStarted, pending, keeperSyncAllowed,
                  localRevokeApplied, localFailureObserved, descriptorKnown,
                  requestSent, remoteFailureObserved, cleanupComplete,
                  removedReceipt, ownedDataPresent, unrelatedScopeActive>>

Next ==
  \/ PersistRemovalIntent
  \/ LocalRevokeFails
  \/ RetryLocalRevoke
  \/ ProvideAddressAndValidateStatus
  \/ SubmitSignedDisconnect
  \/ RemoteRequestFailsOnce
  \/ CompleteRemoteCleanup
  \/ AcceptSignedRemovedReceipt
  \/ IssueOwnerOffer
  \/ UNCHANGED vars

TypeOK ==
  /\ removalStarted \in BOOLEAN
  /\ pending \in BOOLEAN
  /\ keeperSyncAllowed \in BOOLEAN
  /\ localRevokeApplied \in BOOLEAN
  /\ localFailureObserved \in BOOLEAN
  /\ descriptorKnown \in BOOLEAN
  /\ requestSent \in BOOLEAN
  /\ remoteFailureObserved \in BOOLEAN
  /\ cleanupComplete \in BOOLEAN
  /\ removedReceipt \in BOOLEAN
  /\ ownerOfferDuringPending \in BOOLEAN
  /\ ownedDataPresent \in BOOLEAN
  /\ unrelatedScopeActive \in BOOLEAN

PendingIntentRetainedUntilReceipt == removalStarted /\ ~removedReceipt => pending
LocalRevokeAppliedBeforeRemoteRequest == requestSent => localRevokeApplied
DescriptorRequiredForDisconnect == requestSent => descriptorKnown
MissingDescriptorCannotComplete == ~descriptorKnown => ~cleanupComplete
PendingBlocksNewOwnerOffers == pending => ~ownerOfferDuringPending
RemovedRequiresExactSignedCleanupReceipt == removedReceipt =>
  removalStarted /\ cleanupComplete /\ SignedReceiptValid /\ ReceiptScopesExact
LocalRevokeBelongsToAuthorizedOwner == localRevokeApplied =>
  removalStarted /\ OwnerAuthorized /\ SelectedScopeOwned
OwnedBoardDataRetained == ownedDataPresent
UnrelatedScopeUnaffected == unrelatedScopeActive
PendingRemovalBlocksKeeperSync == localRevokeApplied => ~keeperSyncAllowed

RemovalEventuallyAcknowledged == removalStarted ~> removedReceipt

Spec ==
  /\ Init
  /\ [][Next]_vars
  /\ WF_vars(PersistRemovalIntent)
  /\ WF_vars(LocalRevokeFails)
  /\ WF_vars(RetryLocalRevoke)
  /\ WF_vars(ProvideAddressAndValidateStatus)
  /\ WF_vars(SubmitSignedDisconnect)
  /\ WF_vars(RemoteRequestFailsOnce)
  /\ WF_vars(CompleteRemoteCleanup)
  /\ WF_vars(AcceptSignedRemovedReceipt)

=============================================================
