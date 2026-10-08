---------------- MODULE PairingWithdrawal ----------------
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS AllowLateActivation, IgnoreWithdrawalFence, AllowUnverifiedCompletion

VARIABLES withdrawal, provisioning, scopeActive, cleanup, grantIssued,
          verifiedOwnerRevocation,
          unrelatedScopeActive, activationAfterFence, retryAfterFence

vars == <<withdrawal, provisioning, scopeActive, cleanup,
         grantIssued, verifiedOwnerRevocation,
         unrelatedScopeActive, activationAfterFence, retryAfterFence>>

Init ==
  /\ withdrawal = "none"
  /\ provisioning = "none"
  /\ scopeActive = FALSE
  /\ cleanup = "none"
  /\ grantIssued = FALSE
  /\ verifiedOwnerRevocation = FALSE
  /\ unrelatedScopeActive = TRUE
  /\ activationAfterFence = FALSE
  /\ retryAfterFence = FALSE

StartProvision ==
  /\ withdrawal = "none"
  /\ provisioning = "none"
  /\ provisioning' = "running"
  /\ UNCHANGED <<withdrawal, scopeActive, cleanup, grantIssued,
                  verifiedOwnerRevocation, unrelatedScopeActive,
                  activationAfterFence, retryAfterFence>>

IssueGrant ==
  /\ provisioning = "running"
  /\ withdrawal = "none"
  /\ grantIssued' = TRUE
  /\ UNCHANGED <<withdrawal, provisioning, scopeActive, cleanup,
                  verifiedOwnerRevocation, unrelatedScopeActive,
                  activationAfterFence, retryAfterFence>>

RetryProvision ==
  /\ provisioning = "failed"
  /\ (withdrawal = "none" \/ IgnoreWithdrawalFence)
  /\ provisioning' = "running"
  /\ retryAfterFence' = (retryAfterFence \/ withdrawal # "none")
  /\ UNCHANGED <<withdrawal, scopeActive, cleanup, grantIssued,
                  verifiedOwnerRevocation, unrelatedScopeActive,
                  activationAfterFence>>

Activate ==
  /\ provisioning = "running"
  /\ (withdrawal = "none" \/ AllowLateActivation)
  /\ provisioning' = "active"
  /\ scopeActive' = TRUE
  /\ grantIssued' = TRUE
  /\ activationAfterFence' = (activationAfterFence \/ withdrawal # "none")
  /\ UNCHANGED <<withdrawal, cleanup, verifiedOwnerRevocation,
                  unrelatedScopeActive, retryAfterFence>>

AbortProvision ==
  /\ provisioning = "running"
  /\ withdrawal = "pending"
  /\ provisioning' = "failed"
  /\ UNCHANGED <<withdrawal, scopeActive, cleanup, grantIssued,
                  verifiedOwnerRevocation, unrelatedScopeActive,
                  activationAfterFence, retryAfterFence>>

Withdraw ==
  /\ withdrawal = "none"
  /\ withdrawal' = IF provisioning = "none" THEN "cancelled" ELSE "pending"
  /\ UNCHANGED <<provisioning, scopeActive, cleanup, grantIssued,
                  verifiedOwnerRevocation, unrelatedScopeActive,
                  activationAfterFence, retryAfterFence>>

DisconnectScope ==
  /\ withdrawal = "pending"
  /\ scopeActive
  /\ scopeActive' = FALSE
  /\ grantIssued' = FALSE
  /\ verifiedOwnerRevocation' = TRUE
  /\ cleanup' = "pending"
  /\ UNCHANGED <<withdrawal, provisioning, unrelatedScopeActive,
                  activationAfterFence, retryAfterFence>>

CleanupFails ==
  /\ cleanup = "pending"
  /\ cleanup' = "retry"
  /\ UNCHANGED <<withdrawal, provisioning, scopeActive, grantIssued,
                  verifiedOwnerRevocation, unrelatedScopeActive,
                  activationAfterFence, retryAfterFence>>

CleanupSucceeds ==
  /\ cleanup \in {"pending", "retry"}
  /\ cleanup' = "complete"
  /\ provisioning' = "detached"
  /\ UNCHANGED <<withdrawal, scopeActive, grantIssued,
                  verifiedOwnerRevocation, unrelatedScopeActive,
                  activationAfterFence, retryAfterFence>>

OwnerCleanupVerified ==
  /\ withdrawal = "pending"
  /\ provisioning = "failed"
  /\ ~scopeActive
  /\ provisioning' = "detached"
  /\ grantIssued' = FALSE
  /\ verifiedOwnerRevocation' = TRUE
  /\ cleanup' = "complete"
  /\ UNCHANGED <<withdrawal, scopeActive, unrelatedScopeActive,
                  activationAfterFence, retryAfterFence>>

UnsafeDetachWithoutRevocation ==
  /\ AllowUnverifiedCompletion
  /\ withdrawal = "pending"
  /\ provisioning = "failed"
  /\ ~scopeActive
  /\ provisioning' = "detached"
  /\ cleanup' = "complete"
  /\ UNCHANGED <<withdrawal, scopeActive, grantIssued,
                  verifiedOwnerRevocation, unrelatedScopeActive,
                  activationAfterFence, retryAfterFence>>

Finalize ==
  /\ withdrawal = "pending"
  /\ provisioning \in {"none", "detached"}
  /\ ~scopeActive
  /\ ((~grantIssued
       /\ (provisioning = "none" \/ verifiedOwnerRevocation))
      \/ AllowUnverifiedCompletion)
  /\ cleanup \in {"none", "complete"}
  /\ withdrawal' = "cancelled"
  /\ UNCHANGED <<provisioning, scopeActive, cleanup, grantIssued,
                  verifiedOwnerRevocation, unrelatedScopeActive,
                  activationAfterFence, retryAfterFence>>

Restart == UNCHANGED vars

Next == StartProvision \/ IssueGrant \/ RetryProvision \/ Activate \/ AbortProvision
        \/ Withdraw \/ DisconnectScope \/ CleanupFails \/ CleanupSucceeds
        \/ OwnerCleanupVerified \/ UnsafeDetachWithoutRevocation
        \/ Finalize \/ Restart

TypeOK ==
  /\ withdrawal \in {"none", "pending", "cancelled"}
  /\ provisioning \in {"none", "running", "active", "failed", "detached"}
  /\ scopeActive \in BOOLEAN
  /\ cleanup \in {"none", "pending", "retry", "complete"}
  /\ grantIssued \in BOOLEAN
  /\ verifiedOwnerRevocation \in BOOLEAN
  /\ unrelatedScopeActive = TRUE
  /\ activationAfterFence \in BOOLEAN
  /\ retryAfterFence \in BOOLEAN

CancelledHasNoScope == withdrawal = "cancelled" => ~scopeActive
CancelledHasDurableCleanup == withdrawal = "cancelled" => cleanup \in {"none", "complete"}
CancelledHasNoGrant == withdrawal = "cancelled" => ~grantIssued
AttemptedGrantRequiresProof ==
  withdrawal = "cancelled" /\ provisioning # "none" => verifiedOwnerRevocation
NoLateActivation == ~activationAfterFence
NoRetryAfterFence == ~retryAfterFence
RemovalPreservesUnrelatedScope == unrelatedScopeActive

FairSpec == Init /\ [][Next]_vars
            /\ WF_vars(Activate)
            /\ WF_vars(AbortProvision)
            /\ WF_vars(Withdraw)
            /\ WF_vars(DisconnectScope)
            /\ WF_vars(CleanupSucceeds)
            /\ WF_vars(OwnerCleanupVerified)
            /\ WF_vars(Finalize)

WithdrawalEventuallyCompletes == (withdrawal = "pending") ~> (withdrawal = "cancelled")

=============================================================================
