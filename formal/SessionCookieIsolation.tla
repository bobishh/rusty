---------------- MODULE SessionCookieIsolation ----------------
EXTENDS TLC

CONSTANT OverwriteOperatorCookie

VARIABLES adminCookie, identityCookie, operatorLoggedIn,
          identityExchanged, identityLoggedOut, operatorLoggedOut,
          approvalDone

vars == <<adminCookie, identityCookie, operatorLoggedIn,
         identityExchanged, identityLoggedOut, operatorLoggedOut,
         approvalDone>>

NoCookie == "none"
OperatorToken == "operator-session"
IdentityToken == "identity-session"

Init ==
  /\ adminCookie = NoCookie
  /\ identityCookie = NoCookie
  /\ operatorLoggedIn = FALSE
  /\ identityExchanged = FALSE
  /\ identityLoggedOut = FALSE
  /\ operatorLoggedOut = FALSE
  /\ approvalDone = FALSE

OperatorLogin ==
  /\ ~operatorLoggedIn
  /\ adminCookie' = OperatorToken
  /\ operatorLoggedIn' = TRUE
  /\ UNCHANGED <<identityCookie, identityExchanged, identityLoggedOut,
       operatorLoggedOut, approvalDone>>

IdentityExchange ==
  /\ operatorLoggedIn
  /\ ~identityExchanged
  /\ identityCookie' = IdentityToken
  /\ adminCookie' = IF OverwriteOperatorCookie
                       THEN IdentityToken ELSE adminCookie
  /\ identityExchanged' = TRUE
  /\ UNCHANGED <<operatorLoggedIn, identityLoggedOut,
       operatorLoggedOut, approvalDone>>

Approve ==
  /\ adminCookie = OperatorToken
  /\ operatorLoggedIn
  /\ ~operatorLoggedOut
  /\ ~approvalDone
  /\ approvalDone' = TRUE
  /\ UNCHANGED <<adminCookie, identityCookie, operatorLoggedIn,
       identityExchanged, identityLoggedOut, operatorLoggedOut>>

IdentityLogout ==
  /\ identityExchanged
  /\ ~identityLoggedOut
  /\ identityCookie' = NoCookie
  /\ identityLoggedOut' = TRUE
  /\ UNCHANGED <<adminCookie, operatorLoggedIn, identityExchanged,
       operatorLoggedOut, approvalDone>>

OperatorLogout ==
  /\ approvalDone
  /\ ~operatorLoggedOut
  /\ adminCookie' = NoCookie
  /\ operatorLoggedOut' = TRUE
  /\ UNCHANGED <<identityCookie, operatorLoggedIn, identityExchanged,
       identityLoggedOut, approvalDone>>

Next ==
  \/ OperatorLogin
  \/ IdentityExchange
  \/ Approve
  \/ IdentityLogout
  \/ OperatorLogout
  \/ UNCHANGED vars

TypeOK ==
  /\ adminCookie \in {NoCookie, OperatorToken, IdentityToken}
  /\ identityCookie \in {NoCookie, IdentityToken}
  /\ operatorLoggedIn \in BOOLEAN
  /\ identityExchanged \in BOOLEAN
  /\ identityLoggedOut \in BOOLEAN
  /\ operatorLoggedOut \in BOOLEAN
  /\ approvalDone \in BOOLEAN

OperatorCookieSlotIsOperatorOnly == adminCookie # IdentityToken
OperatorSessionSurvivesIdentityExchange ==
  identityExchanged /\ ~operatorLoggedOut => adminCookie = OperatorToken
IdentityLogoutIsScoped ==
  identityLoggedOut /\ ~operatorLoggedOut => adminCookie = OperatorToken
OperatorLogoutIsScoped ==
  operatorLoggedOut /\ identityExchanged /\ ~identityLoggedOut =>
    identityCookie = IdentityToken
ApprovalRequiresOperatorSession ==
  approvalDone => operatorLoggedIn

ApprovalAfterIdentityExchange ==
  []((operatorLoggedIn /\ identityExchanged /\ ~operatorLoggedOut)
     ~> approvalDone)

Spec ==
  /\ Init
  /\ [][Next]_vars
  /\ WF_vars(OperatorLogin)
  /\ WF_vars(IdentityExchange)
  /\ WF_vars(Approve)
  /\ WF_vars(IdentityLogout)
  /\ WF_vars(OperatorLogout)

=============================================================
