---------------- MODULE LocalProjectionCleanup ----------------
EXTENDS TLC

CONSTANT DiscardReceipt

VARIABLES remoteReceiptVerified, descriptorSaved, receiptRetained,
          ownerKeeperPresent, localDeleteFailed, restarted, localCleanupDone

vars == <<remoteReceiptVerified, descriptorSaved, receiptRetained,
         ownerKeeperPresent, localDeleteFailed, restarted, localCleanupDone>>

Init ==
  /\ remoteReceiptVerified = FALSE
  /\ descriptorSaved = FALSE
  /\ receiptRetained = FALSE
  /\ ownerKeeperPresent = TRUE
  /\ localDeleteFailed = FALSE
  /\ restarted = FALSE
  /\ localCleanupDone = FALSE

AcceptVerifiedRemoteReceipt ==
  /\ ~remoteReceiptVerified
  /\ remoteReceiptVerified' = TRUE
  /\ UNCHANGED <<descriptorSaved, receiptRetained, ownerKeeperPresent,
       localDeleteFailed, restarted, localCleanupDone>>

PersistRemovedDescriptor ==
  /\ remoteReceiptVerified
  /\ ~descriptorSaved
  /\ descriptorSaved' = TRUE
  /\ receiptRetained' = ~DiscardReceipt
  /\ UNCHANGED <<remoteReceiptVerified, ownerKeeperPresent,
       localDeleteFailed, restarted, localCleanupDone>>

OwnerKeeperDeleteFails ==
  /\ descriptorSaved
  /\ ownerKeeperPresent
  /\ ~localDeleteFailed
  /\ localDeleteFailed' = TRUE
  /\ UNCHANGED <<remoteReceiptVerified, descriptorSaved, receiptRetained,
       ownerKeeperPresent, restarted, localCleanupDone>>

RestartAndReloadDescriptor ==
  /\ localDeleteFailed
  /\ ~restarted
  /\ restarted' = TRUE
  /\ UNCHANGED <<remoteReceiptVerified, descriptorSaved, receiptRetained,
       ownerKeeperPresent, localDeleteFailed, localCleanupDone>>

RetryOwnerKeeperDelete ==
  /\ restarted
  /\ descriptorSaved
  /\ receiptRetained
  /\ ownerKeeperPresent
  /\ ownerKeeperPresent' = FALSE
  /\ localCleanupDone' = TRUE
  /\ UNCHANGED <<remoteReceiptVerified, descriptorSaved, receiptRetained,
       localDeleteFailed, restarted>>

Next ==
  \/ AcceptVerifiedRemoteReceipt
  \/ PersistRemovedDescriptor
  \/ OwnerKeeperDeleteFails
  \/ RestartAndReloadDescriptor
  \/ RetryOwnerKeeperDelete
  \/ UNCHANGED vars

TypeOK ==
  /\ remoteReceiptVerified \in BOOLEAN
  /\ descriptorSaved \in BOOLEAN
  /\ receiptRetained \in BOOLEAN
  /\ ownerKeeperPresent \in BOOLEAN
  /\ localDeleteFailed \in BOOLEAN
  /\ restarted \in BOOLEAN
  /\ localCleanupDone \in BOOLEAN

LocalMetadataRemovalRequiresVerifiedReceipt ==
  ~ownerKeeperPresent => remoteReceiptVerified /\ receiptRetained /\ localCleanupDone
ReceiptPersistsUntilProjectionCleanup ==
  descriptorSaved /\ ownerKeeperPresent =>
    remoteReceiptVerified /\ receiptRetained

ProjectionCleanupEventuallyRetryable ==
  (remoteReceiptVerified /\ localDeleteFailed) ~> localCleanupDone

Spec ==
  /\ Init
  /\ [][Next]_vars
  /\ WF_vars(AcceptVerifiedRemoteReceipt)
  /\ WF_vars(PersistRemovedDescriptor)
  /\ WF_vars(OwnerKeeperDeleteFails)
  /\ WF_vars(RestartAndReloadDescriptor)
  /\ WF_vars(RetryOwnerKeeperDelete)

=============================================================
