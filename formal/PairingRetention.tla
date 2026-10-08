---------------- MODULE PairingRetention ----------------
EXTENDS Naturals, TLC

CONSTANT TerminalRetention

VARIABLES recordPresent, state, terminalAge
vars == <<recordPresent, state, terminalAge>>

Init ==
  /\ recordPresent = TRUE
  /\ state = "pending"
  /\ terminalAge = 0

Expire ==
  /\ recordPresent
  /\ state = "pending"
  /\ state' = "expired"
  /\ terminalAge' = 0
  /\ UNCHANGED recordPresent

StartWithdrawal ==
  /\ recordPresent
  /\ state \in {"pending", "expired", "active"}
  /\ state' = "cancel_pending"
  /\ UNCHANGED <<recordPresent, terminalAge>>

BeginProvisioning ==
  /\ recordPresent
  /\ state = "pending"
  /\ state' = "provisioning"
  /\ UNCHANGED <<recordPresent, terminalAge>>

Activate ==
  /\ recordPresent
  /\ state = "provisioning"
  /\ state' = "active"
  /\ UNCHANGED <<recordPresent, terminalAge>>

CleanupPending ==
  /\ recordPresent
  /\ state = "active"
  /\ state' = "pending_cleanup"
  /\ UNCHANGED <<recordPresent, terminalAge>>

CleanupCompletes ==
  /\ recordPresent
  /\ state \in {"cancel_pending", "pending_cleanup"}
  /\ state' = "cancelled"
  /\ terminalAge' = 0
  /\ UNCHANGED recordPresent

TickTerminal ==
  /\ recordPresent
  /\ state \in {"expired", "cancelled"}
  /\ terminalAge < TerminalRetention
  /\ terminalAge' = terminalAge + 1
  /\ UNCHANGED <<recordPresent, state>>

PruneTerminal ==
  /\ recordPresent
  /\ state \in {"expired", "cancelled"}
  /\ terminalAge >= TerminalRetention
  /\ recordPresent' = FALSE
  /\ UNCHANGED <<state, terminalAge>>

Restart == UNCHANGED vars

Next == Expire \/ StartWithdrawal \/ BeginProvisioning \/ Activate
        \/ CleanupPending \/ CleanupCompletes \/ TickTerminal
        \/ PruneTerminal \/ Restart

TypeOK ==
  /\ recordPresent \in BOOLEAN
  /\ state \in {"pending", "expired", "provisioning", "active",
                 "pending_cleanup", "cancel_pending", "cancelled"}
  /\ terminalAge \in Nat

CleanupObligationRetained ==
  state \in {"provisioning", "active", "pending_cleanup", "cancel_pending"}
  => recordPresent

TerminalReceiptRetainedUntilExpiry ==
  state = "cancelled" /\ terminalAge < TerminalRetention
  => recordPresent

NoActiveOrPendingTerminalPrune ==
  ~recordPresent => state \in {"expired", "cancelled"}

Spec == Init /\ [][Next]_vars

=============================================================================
