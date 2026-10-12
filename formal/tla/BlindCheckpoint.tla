---------------- MODULE BlindCheckpoint ----------------
EXTENDS Naturals, FiniteSets, TLC
CONSTANTS EarlyReceipt, EarlyPrune, RewriteRetry
Candidates == {"C", "E"}
Objects == {"A", "B", "C", "E", "D"}
VARIABLES retained, manifest, winner, candidate, stage, crashed, lateWrite,
          writes, receipts, unsafeReceipt, unsafePrune, currentAuthority, unauthorizedReceipt
vars == <<retained, manifest, winner, candidate, stage, crashed, lateWrite,
          writes, receipts, unsafeReceipt, unsafePrune, currentAuthority, unauthorizedReceipt>>
Init == /\ retained = {"A", "B"} /\ manifest = "none" /\ winner = "none"
        /\ candidate = "C" /\ stage = "idle" /\ crashed = FALSE /\ lateWrite = FALSE
        /\ writes = [o \in Objects |-> IF o \in {"A", "B"} THEN 1 ELSE 0]
        /\ receipts = {} /\ unsafeReceipt = FALSE /\ unsafePrune = FALSE
        /\ currentAuthority = TRUE /\ unauthorizedReceipt = FALSE
Start(c) ==
  /\ stage = "idle" /\ currentAuthority
  \* Exact completed retry or matching durable orphan may recover after a later append.
  /\ (manifest = c \/ (manifest = "none" /\
       ((retained = {"A", "B"}) \/ (c \in retained /\ retained \cap Candidates = {c}))))
  /\ candidate' = c /\ stage' = "object"
  /\ UNCHANGED <<retained, manifest, winner, crashed, lateWrite, writes, receipts,
                 unsafeReceipt, unsafePrune, currentAuthority, unauthorizedReceipt>>
WriteObject ==
  /\ stage = "object" /\ writes[candidate] < 2
  /\ writes' = IF candidate \in retained /\ ~RewriteRetry THEN writes
                ELSE [writes EXCEPT ![candidate] = @ + 1]
  /\ retained' = retained \cup {candidate} /\ stage' = "manifest"
  /\ UNCHANGED <<manifest, winner, candidate, crashed, lateWrite, receipts,
                 unsafeReceipt, unsafePrune, currentAuthority, unauthorizedReceipt>>
WriteManifest ==
  /\ stage = "manifest" /\ candidate \in retained
  /\ manifest' = candidate /\ winner' = candidate /\ stage' = "prune"
  /\ UNCHANGED <<retained, candidate, crashed, lateWrite, writes, receipts,
                 unsafeReceipt, unsafePrune, currentAuthority, unauthorizedReceipt>>
Prune ==
  /\ stage = "prune" \/ (EarlyPrune /\ stage = "object")
  /\ unsafePrune' = (unsafePrune \/ ~(manifest = candidate /\ candidate \in retained))
  /\ retained' = retained \ {"A", "B"} /\ stage' = "receipt"
  /\ UNCHANGED <<manifest, winner, candidate, crashed, lateWrite, writes, receipts,
                 unsafeReceipt, currentAuthority, unauthorizedReceipt>>
Receipt ==
  /\ stage = "receipt" \/ (EarlyReceipt /\ stage \in {"object", "manifest"})
  /\ receipts' = receipts \cup {candidate}
  /\ unsafeReceipt' = (unsafeReceipt \/ ~(manifest = candidate /\ candidate \in retained))
  /\ unauthorizedReceipt' = (unauthorizedReceipt \/ ~currentAuthority)
  /\ currentAuthority /\ stage' = "idle"
  /\ UNCHANGED <<retained, manifest, winner, candidate, crashed, lateWrite, writes, unsafePrune, currentAuthority>>
Crash ==
  /\ stage # "idle" /\ ~crashed /\ crashed' = TRUE /\ stage' = "idle"
  /\ UNCHANGED <<retained, manifest, winner, candidate, lateWrite, writes, receipts,
                 unsafeReceipt, unsafePrune, currentAuthority, unauthorizedReceipt>>
Append ==
  /\ stage = "idle" /\ ~lateWrite /\ currentAuthority
  /\ lateWrite' = TRUE /\ retained' = retained \cup {"D"}
  /\ writes' = [writes EXCEPT !["D"] = 1]
  /\ UNCHANGED <<manifest, winner, candidate, stage, crashed, receipts,
                 unsafeReceipt, unsafePrune, currentAuthority, unauthorizedReceipt>>
Revoke ==
  /\ stage = "idle" /\ currentAuthority /\ currentAuthority' = FALSE
  /\ UNCHANGED <<retained, manifest, winner, candidate, stage, crashed, lateWrite,
                 writes, receipts, unsafeReceipt, unsafePrune, unauthorizedReceipt>>
Next == (\E c \in Candidates : Start(c)) \/ WriteObject \/ WriteManifest \/ Prune \/ Receipt \/ Crash \/ Append \/ Revoke
TypeOK == /\ retained \subseteq Objects /\ receipts \subseteq Candidates
          /\ manifest \in Candidates \cup {"none"} /\ winner \in Candidates \cup {"none"}
          /\ candidate \in Candidates /\ writes \in [Objects -> 0..2]
          /\ stage \in {"idle", "object", "manifest", "prune", "receipt"}
          /\ crashed \in BOOLEAN /\ lateWrite \in BOOLEAN /\ currentAuthority \in BOOLEAN
          /\ unsafeReceipt \in BOOLEAN /\ unsafePrune \in BOOLEAN /\ unauthorizedReceipt \in BOOLEAN
Spec == Init /\ [][Next]_vars
ReceiptRequiresDurableCheckpoint == ~unsafeReceipt
PruneRequiresDurableReplacement == ~unsafePrune
ExactRetryWritesOnce == \A c \in Candidates : writes[c] <= 1
LateAppendSurvives == lateWrite => "D" \in retained
OneWinnerPerFrontier == Cardinality(retained \cap Candidates) <= 1 /\ Cardinality(receipts) <= 1
CurrentAuthorityRequired == ~unauthorizedReceipt
=========================================================
