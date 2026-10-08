---------------- MODULE PairingCompletionOrdering ----------------
EXTENDS Naturals, TLC

CONSTANTS IgnoreActiveCompletionFence, IgnoreCleanupCompletionFence

VARIABLES hostStatus, pairingStatus, activeObserved, cleanupObserved

vars == <<hostStatus, pairingStatus, activeObserved, cleanupObserved>>

Init ==
  /\ hostStatus = "provisioning"
  /\ pairingStatus = "provisioning"
  /\ activeObserved = FALSE
  /\ cleanupObserved = FALSE

ObserveDurableActivation ==
  /\ hostStatus = "provisioning"
  /\ hostStatus' = "active"
  /\ pairingStatus' = "active"
  /\ activeObserved' = TRUE
  /\ UNCHANGED cleanupObserved

LateFailedCompletion ==
  /\ activeObserved
  /\ pairingStatus = "active"
  /\ pairingStatus' = IF IgnoreActiveCompletionFence
                         THEN "provisioning"
                         ELSE "active"
  /\ UNCHANGED <<hostStatus, activeObserved, cleanupObserved>>

BeginCleanup ==
  /\ hostStatus = "active"
  /\ hostStatus' = "pending_cleanup"
  /\ pairingStatus' = "pending_cleanup"
  /\ cleanupObserved' = TRUE
  /\ UNCHANGED activeObserved

FinishCleanup ==
  /\ hostStatus = "pending_cleanup"
  /\ hostStatus' = "detached"
  /\ pairingStatus' = "detached"
  /\ UNCHANGED <<activeObserved, cleanupObserved>>

LateSuccessfulCompletion ==
  /\ cleanupObserved
  /\ pairingStatus \in {"pending_cleanup", "detached"}
  /\ pairingStatus' = IF IgnoreCleanupCompletionFence
                         THEN "active"
                         ELSE pairingStatus
  /\ UNCHANGED <<hostStatus, activeObserved, cleanupObserved>>

Next == ObserveDurableActivation \/ LateFailedCompletion \/ BeginCleanup
        \/ FinishCleanup \/ LateSuccessfulCompletion

TypeOK ==
  /\ hostStatus \in {"provisioning", "active", "pending_cleanup", "detached"}
  /\ pairingStatus \in {"provisioning", "active", "pending_cleanup", "detached"}
  /\ activeObserved \in BOOLEAN
  /\ cleanupObserved \in BOOLEAN

DurableActiveDoesNotRegress ==
  activeObserved /\ hostStatus = "active" => pairingStatus = "active"

CleanupDoesNotReactivate ==
  cleanupObserved => pairingStatus \in {"pending_cleanup", "detached"}

Spec == Init /\ [][Next]_vars

=============================================================================
