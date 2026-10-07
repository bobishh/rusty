---------------- MODULE FutureOfferLifecycle ----------------
EXTENDS Naturals, TLC

CONSTANTS InitialFutureBoards, RequireVisitorOnlyGate,
          IgnoreEditorGrantCheck, InviteRole, GrantRole, OwnerProofValid

Roles == {"editor", "visitor"}
ScopeStates == {"absent", "staged", "active"}

VARIABLES baseActive, baseRole, futureBoards, newScope,
          stagedInviteRole, stagedGrantRole, activeInviteRole,
          activeGrantRole, stagedEpoch, grantEpoch

vars == <<baseActive, baseRole, futureBoards, newScope,
         stagedInviteRole, stagedGrantRole, activeInviteRole,
         activeGrantRole, stagedEpoch, grantEpoch>>

Init ==
  /\ baseActive = TRUE
  /\ baseRole = "editor"
  /\ futureBoards = InitialFutureBoards
  /\ newScope = "absent"
  /\ stagedInviteRole = "visitor"
  /\ stagedGrantRole = "visitor"
  /\ activeInviteRole = "visitor"
  /\ activeGrantRole = "visitor"
  /\ stagedEpoch = 1
  /\ grantEpoch = 0

AcceptOwnerOffer ==
  /\ baseActive
  /\ baseRole = "editor"
  /\ futureBoards
  /\ OwnerProofValid
  /\ newScope = "absent"
  /\ InviteRole = "editor"
  /\ (GrantRole = "editor" \/ IgnoreEditorGrantCheck)
  /\ (~RequireVisitorOnlyGate \/ (InviteRole = "visitor" /\ GrantRole = "visitor"))
  /\ newScope' = "staged"
  /\ stagedInviteRole' = InviteRole
  /\ stagedGrantRole' = GrantRole
  /\ stagedEpoch' = 1
  /\ UNCHANGED <<baseActive, baseRole, futureBoards, activeInviteRole,
                  activeGrantRole, grantEpoch>>

CommitScope ==
  /\ newScope = "staged"
  /\ baseActive
  /\ baseRole = "editor"
  /\ futureBoards
  /\ OwnerProofValid
  /\ stagedInviteRole = "editor"
  /\ (stagedGrantRole = "editor" \/ IgnoreEditorGrantCheck)
  /\ stagedEpoch > 0
  /\ newScope' = "active"
  /\ activeInviteRole' = stagedInviteRole
  /\ activeGrantRole' = stagedGrantRole
  /\ grantEpoch' = stagedEpoch
  /\ UNCHANGED <<baseActive, baseRole, futureBoards, stagedInviteRole,
                  stagedGrantRole, stagedEpoch>>

Next == AcceptOwnerOffer \/ CommitScope \/ UNCHANGED vars

BaseEditorScopePreserved == baseActive /\ baseRole = "editor"
FutureConsentRequired == newScope \in {"staged", "active"} => futureBoards
OwnerProofRequired == newScope \in {"staged", "active"} => OwnerProofValid
FutureScopeRequiresEditorRoles == newScope = "active" =>
  activeInviteRole = "editor" /\ activeGrantRole = "editor"
FutureScopeUsesSignedGrantEpoch == newScope = "active" => grantEpoch > 0
TypeOK ==
  /\ baseActive \in BOOLEAN
  /\ baseRole \in Roles
  /\ futureBoards \in BOOLEAN
  /\ newScope \in ScopeStates
  /\ stagedInviteRole \in Roles
  /\ stagedGrantRole \in Roles
  /\ activeInviteRole \in Roles
  /\ activeGrantRole \in Roles
  /\ stagedEpoch \in 1..2
  /\ grantEpoch \in 0..2

AuthorizedFutureOfferCompletes ==
  (futureBoards /\ baseActive /\ OwnerProofValid
    /\ InviteRole = "editor" /\ GrantRole = "editor")
    ~> newScope = "active"

Spec ==
  /\ Init
  /\ [][Next]_vars
  /\ WF_vars(AcceptOwnerOffer)
  /\ WF_vars(CommitScope)

=============================================================
