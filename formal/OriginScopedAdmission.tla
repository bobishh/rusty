---------------- MODULE OriginScopedAdmission ----------------
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS LegacyOffer, OwnerProofValid, ControllerDeviceTranscriptValid,
          ScopeProofValid, OriginAllowed, OriginMatches, AllScopeGrants,
          ManualOperatorConsent

VARIABLES controllerApproved, serviceApproved, admissionSource, attached,
          attachmentCount

vars == <<controllerApproved, serviceApproved, admissionSource, attached,
          attachmentCount>>

Init ==
  /\ controllerApproved = FALSE
  /\ serviceApproved = FALSE
  /\ admissionSource = "none"
  /\ attached = {}
  /\ attachmentCount = 0

OwnerOriginDecision ==
  /\ ~LegacyOffer
  /\ OwnerProofValid
  /\ ControllerDeviceTranscriptValid
  /\ ScopeProofValid
  /\ OriginAllowed
  /\ OriginMatches
  /\ controllerApproved' = TRUE
  /\ serviceApproved' = TRUE
  /\ admissionSource' = "owner_origin"
  /\ UNCHANGED <<attached, attachmentCount>>

LegacyOwnerDecision ==
  /\ LegacyOffer
  /\ OwnerProofValid
  /\ ControllerDeviceTranscriptValid
  /\ ScopeProofValid
  /\ controllerApproved' = TRUE
  /\ UNCHANGED <<serviceApproved, admissionSource, attached, attachmentCount>>

LegacyOperatorDecision ==
  /\ LegacyOffer
  /\ ManualOperatorConsent
  /\ serviceApproved' = TRUE
  /\ admissionSource' = "operator"
  /\ UNCHANGED <<controllerApproved, attached, attachmentCount>>

ProvisionAllOrNone ==
  /\ controllerApproved
  /\ serviceApproved
  /\ OwnerProofValid
  /\ ControllerDeviceTranscriptValid
  /\ ScopeProofValid
  /\ AllScopeGrants
  /\ attached' = {"all-requested-scopes"}
  /\ attachmentCount' = 1
  /\ UNCHANGED <<controllerApproved, serviceApproved, admissionSource>>

Next == OwnerOriginDecision \/ LegacyOwnerDecision \/ LegacyOperatorDecision \/ ProvisionAllOrNone

Spec == Init /\ [][Next]_vars

TypeOK ==
  /\ controllerApproved \in BOOLEAN
  /\ serviceApproved \in BOOLEAN
  /\ admissionSource \in {"none", "owner_origin", "operator"}
  /\ attached \subseteq {"all-requested-scopes"}
  /\ attachmentCount \in 0..1

OwnerOriginAdmissionIsBound ==
  admissionSource = "owner_origin" =>
    /\ ~LegacyOffer
    /\ OwnerProofValid
    /\ ControllerDeviceTranscriptValid
    /\ ScopeProofValid
    /\ OriginAllowed
    /\ OriginMatches
    /\ controllerApproved
    /\ serviceApproved

NoOriginOnlyAdmission ==
  serviceApproved /\ ~LegacyOffer =>
    /\ OwnerProofValid
    /\ ControllerDeviceTranscriptValid
    /\ ScopeProofValid
    /\ OriginAllowed
    /\ OriginMatches

LegacyNeedsOperatorConsent ==
  LegacyOffer /\ serviceApproved => ManualOperatorConsent

NoPartialAttachment == attachmentCount = 0 \/ attachmentCount = 1

NoAttachWithoutVerifiedWholeGrant ==
  attached # {} =>
    /\ controllerApproved
    /\ serviceApproved
    /\ OwnerProofValid
    /\ ControllerDeviceTranscriptValid
    /\ ScopeProofValid
    /\ AllScopeGrants

THEOREM Spec => []TypeOK
===============================================================
