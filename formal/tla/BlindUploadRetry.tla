---------------- MODULE BlindUploadRetry ----------------
EXTENDS Naturals, TLC
CONSTANTS SkipDirectoryConfirmation, SkipCurrentPolicy
VARIABLES visible, durable, stage, attempts, writes, authority, receipt, badReceipt, lostReply
vars == <<visible, durable, stage, attempts, writes, authority, receipt, badReceipt, lostReply>>
Init == /\ visible = FALSE /\ durable = FALSE /\ stage = "idle" /\ attempts = 0
        /\ writes = 0 /\ authority = TRUE /\ receipt = FALSE /\ badReceipt = FALSE /\ lostReply = FALSE
Start ==
  /\ stage = "idle" /\ attempts < 2 /\ (authority \/ SkipCurrentPolicy)
  /\ stage' = (IF visible THEN "duplicate" ELSE "writing") /\ attempts' = attempts + 1
  /\ UNCHANGED <<visible, durable, writes, authority, receipt, badReceipt, lostReply>>
Rename ==
  /\ stage = "writing" /\ visible' = TRUE /\ writes' = writes + 1 /\ stage' = "directory-sync"
  /\ UNCHANGED <<durable, attempts, authority, receipt, badReceipt, lostReply>>
SyncDirectory ==
  /\ stage \in {"directory-sync", "duplicate"} /\ durable' = TRUE /\ stage' = "reply"
  /\ UNCHANGED <<visible, attempts, writes, authority, receipt, badReceipt, lostReply>>
DirectoryFailure ==
  /\ stage \in {"directory-sync", "duplicate"} /\ ~durable /\ stage' = "idle"
  /\ UNCHANGED <<visible, durable, attempts, writes, authority, receipt, badReceipt, lostReply>>
Reply ==
  /\ stage = "reply" \/ (stage = "duplicate" /\ SkipDirectoryConfirmation)
  /\ receipt' = TRUE /\ badReceipt' = (~durable \/ ~authority)
  /\ stage' = "idle"
  /\ UNCHANGED <<visible, durable, attempts, writes, authority, lostReply>>
LoseReply ==
  /\ stage = "reply" /\ ~lostReply /\ lostReply' = TRUE /\ stage' = "idle"
  /\ UNCHANGED <<visible, durable, attempts, writes, authority, receipt, badReceipt>>
Revoke ==
  /\ stage = "idle" /\ authority /\ authority' = FALSE
  /\ UNCHANGED <<visible, durable, stage, attempts, writes, receipt, badReceipt, lostReply>>
Next == Start \/ Rename \/ SyncDirectory \/ DirectoryFailure \/ Reply \/ LoseReply \/ Revoke
TypeOK == /\ visible \in BOOLEAN /\ durable \in BOOLEAN /\ authority \in BOOLEAN
          /\ receipt \in BOOLEAN /\ badReceipt \in BOOLEAN /\ lostReply \in BOOLEAN
          /\ attempts \in 0..2 /\ writes \in 0..2
          /\ stage \in {"idle", "writing", "directory-sync", "duplicate", "reply"}
Spec == Init /\ [][Next]_vars
ReceiptIsDurableAndCurrentlyAuthorized == ~badReceipt
IdenticalRetryDoesNotRewrite == writes <= 1
=========================================================
