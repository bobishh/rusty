---------------- MODULE DisconnectReplay ----------------
EXTENDS Naturals, TLC

CONSTANT ReplayHistoricalWhenActive

VARIABLES active, epoch, tombstoneEpoch, removalIssued, readded,
          historicalReceipt, historicalReceiptEpoch,
          retryResponse, retryResponseEpoch

vars == <<active, epoch, tombstoneEpoch, removalIssued, readded,
         historicalReceipt, historicalReceiptEpoch,
         retryResponse, retryResponseEpoch>>

Init ==
  /\ active = TRUE
  /\ epoch = 1
  /\ tombstoneEpoch = 0
  /\ removalIssued = FALSE
  /\ readded = FALSE
  /\ historicalReceipt = FALSE
  /\ historicalReceiptEpoch = 0
  /\ retryResponse = "none"
  /\ retryResponseEpoch = 0

Disconnect ==
  /\ active
  /\ ~removalIssued
  /\ active' = FALSE
  /\ tombstoneEpoch' = epoch
  /\ removalIssued' = TRUE
  /\ historicalReceipt' = TRUE
  /\ historicalReceiptEpoch' = epoch
  /\ retryResponse' = "removed"
  /\ retryResponseEpoch' = epoch
  /\ UNCHANGED <<epoch, readded>>

FreshReAdd ==
  /\ ~active
  /\ removalIssued
  /\ ~readded
  /\ epoch' = tombstoneEpoch + 1
  /\ active' = TRUE
  /\ readded' = TRUE
  /\ retryResponse' = "none"
  /\ retryResponseEpoch' = 0
  /\ UNCHANGED <<tombstoneEpoch, removalIssued,
                  historicalReceipt, historicalReceiptEpoch>>

RetryCompletedDisconnect ==
  /\ historicalReceipt
  /\ IF active /\ ReplayHistoricalWhenActive
        THEN /\ retryResponse' = "removed"
             /\ retryResponseEpoch' = historicalReceiptEpoch
        ELSE IF active
          THEN /\ retryResponse' = "conflict"
               /\ retryResponseEpoch' = 0
          ELSE /\ retryResponse' = "removed"
               /\ retryResponseEpoch' = historicalReceiptEpoch
  /\ UNCHANGED <<active, epoch, tombstoneEpoch, removalIssued, readded,
                  historicalReceipt, historicalReceiptEpoch>>

Next == Disconnect \/ FreshReAdd \/ RetryCompletedDisconnect \/ UNCHANGED vars

TypeOK ==
  /\ active \in BOOLEAN
  /\ epoch \in 1..2
  /\ tombstoneEpoch \in 0..1
  /\ removalIssued \in BOOLEAN
  /\ readded \in BOOLEAN
  /\ historicalReceipt \in BOOLEAN
  /\ historicalReceiptEpoch \in 0..1
  /\ retryResponse \in {"none", "removed", "conflict"}
  /\ retryResponseEpoch \in 0..1

RemovedResponseMatchesCurrentScope ==
  retryResponse = "removed" =>
    ~active /\ retryResponseEpoch = tombstoneEpoch

HistoricalReceiptPreserved ==
  historicalReceipt => historicalReceiptEpoch = 1

RetryAfterFreshReAddResolves ==
  (readded /\ retryResponse = "none") ~> retryResponse = "conflict"

Spec ==
  /\ Init
  /\ [][Next]_vars
  /\ WF_vars(RetryCompletedDisconnect)

=============================================================
