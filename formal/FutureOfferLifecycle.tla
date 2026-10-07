---------------- MODULE FutureOfferLifecycle ----------------
EXTENDS Naturals, TLC

CONSTANTS InitialFutureBoards, RequireVisitorOnlyGate,
          IgnoreEditorGrantCheck, OmitFutureLedgerCommit,
          ScanAllOwnedScopes,
          InviteRole, GrantRole, OwnerProofValid

Roles == {"editor", "visitor"}
ScopeStates == {"absent", "staged", "active"}

VARIABLES baseActive, baseRole, futureBoards, newScope,
          stagedInviteRole, stagedGrantRole, activeInviteRole,
          activeGrantRole, stagedEpoch, grantEpoch,
          runtimeAttached, ledgerActive, unselectedOwned,
          unselectedInCapturedBaseline, unselectedSelectedAtPairing,
          preexistingStandaloneActive, unselectedIntegrationMember,
          unselectedLedgerActive

vars == <<baseActive, baseRole, futureBoards, newScope,
         stagedInviteRole, stagedGrantRole, activeInviteRole,
         activeGrantRole, stagedEpoch, grantEpoch,
         runtimeAttached, ledgerActive, unselectedOwned,
         unselectedInCapturedBaseline, unselectedSelectedAtPairing,
         preexistingStandaloneActive, unselectedIntegrationMember,
         unselectedLedgerActive>>

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
  /\ runtimeAttached = FALSE
  /\ ledgerActive = FALSE
  /\ unselectedOwned = TRUE
  /\ unselectedInCapturedBaseline = TRUE
  /\ unselectedSelectedAtPairing = FALSE
  /\ preexistingStandaloneActive = TRUE
  /\ unselectedIntegrationMember = FALSE
  /\ unselectedLedgerActive = FALSE

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
                  activeGrantRole, grantEpoch, runtimeAttached, ledgerActive,
                  unselectedOwned, unselectedInCapturedBaseline,
                  unselectedSelectedAtPairing, preexistingStandaloneActive,
                  unselectedIntegrationMember, unselectedLedgerActive>>

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
  /\ runtimeAttached' = TRUE
  /\ ledgerActive' = ~OmitFutureLedgerCommit
  /\ UNCHANGED <<baseActive, baseRole, futureBoards, stagedInviteRole,
                  stagedGrantRole, stagedEpoch, unselectedOwned,
                  unselectedInCapturedBaseline, unselectedSelectedAtPairing,
                  preexistingStandaloneActive, unselectedIntegrationMember,
                  unselectedLedgerActive>>

AutoAddUnselectedOwnedScope ==
  /\ ScanAllOwnedScopes
  /\ baseActive
  /\ baseRole = "editor"
  /\ futureBoards
  /\ OwnerProofValid
  /\ unselectedOwned
  /\ unselectedInCapturedBaseline
  /\ ~unselectedSelectedAtPairing
  /\ ~unselectedIntegrationMember
  /\ unselectedIntegrationMember' = TRUE
  /\ unselectedLedgerActive' = TRUE
  /\ UNCHANGED <<baseActive, baseRole, futureBoards, newScope,
                  stagedInviteRole, stagedGrantRole, activeInviteRole,
                  activeGrantRole, stagedEpoch, grantEpoch, runtimeAttached,
                  ledgerActive, unselectedOwned, unselectedInCapturedBaseline,
                  unselectedSelectedAtPairing, preexistingStandaloneActive>>

Next == AcceptOwnerOffer \/ CommitScope \/ AutoAddUnselectedOwnedScope \/ UNCHANGED vars

BaseEditorScopePreserved == baseActive /\ baseRole = "editor"
FutureConsentRequired == newScope \in {"staged", "active"} => futureBoards
OwnerProofRequired == newScope \in {"staged", "active"} => OwnerProofValid
FutureScopeRequiresEditorRoles == newScope = "active" =>
  activeInviteRole = "editor" /\ activeGrantRole = "editor"
FutureScopeUsesSignedGrantEpoch == newScope = "active" => grantEpoch > 0
FutureRuntimeAttachedHasLedger == runtimeAttached => ledgerActive
UnselectedIntegrationMemberRequiresInvitationConsent ==
  unselectedIntegrationMember =>
    (~unselectedInCapturedBaseline \/ unselectedSelectedAtPairing)
UnselectedStandalonePreserved == preexistingStandaloneActive
UnselectedIntegrationMemberHasLedger ==
  unselectedIntegrationMember => unselectedLedgerActive
TypeOK ==
  /\ baseActive \in BOOLEAN
  /\ baseRole \in Roles
  /\ futureBoards \in BOOLEAN
  /\ newScope \in ScopeStates
  /\ stagedInviteRole \in Roles
  /\ stagedGrantRole \in Roles
  /\ activeInviteRole \in Roles
  /\ activeGrantRole \in Roles
  /\ runtimeAttached \in BOOLEAN
  /\ ledgerActive \in BOOLEAN
  /\ unselectedOwned \in BOOLEAN
  /\ unselectedInCapturedBaseline \in BOOLEAN
  /\ unselectedSelectedAtPairing \in BOOLEAN
  /\ preexistingStandaloneActive \in BOOLEAN
  /\ unselectedIntegrationMember \in BOOLEAN
  /\ unselectedLedgerActive \in BOOLEAN
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
