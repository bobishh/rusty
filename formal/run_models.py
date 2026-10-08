#!/usr/bin/env python3
"""Run lifecycle safety models and require each deliberate mutant to fail."""
import argparse
import os
from pathlib import Path
import re
import subprocess
import tempfile

CASES = [
    ("IntegrationLifecycle", "RevokeEventuallyAcknowledged", None),
    ("FailureRestartReAdd", "FullRetryReAdd", None),
    ("ConcurrentCAS", "EditorActivationCompletes", None),
    ("VisitorOnlyGate", "EditorActivationCompletes", "TEMPORAL"),
    ("StalePairingStatus", None, "ActiveReceiptHasCurrentCommit"),
    ("FutureEnabled", "RevokeEventuallyAcknowledged", None),
    ("AmbiguousScopes", None, None),
    ("VisitorActivation", None, "EditorRoleProofs"),
    ("StaleActivation", None, "FreshGrantEpoch"),
    ("FutureConsent", None, "FuturePolicyBlocksAutoPairing"),
    ("EarlyAck", None, "CleanupBeforeRemovedAck"),
    ("StaleCAS", None, "CommitUsesCurrentRevision"),
    ("WidenedRevoke", None, "ExactScopeRevocation"),
    ("UnsignedDisconnect", None, "RevocationRequiresExactSignedProof"),
    ("AmbiguousRouteMutation", None, "AmbiguousRouteBlocked"),
    ("FutureEditorOffer", "AuthorizedFutureOfferCompletes", None, "FutureOfferLifecycle"),
    ("FutureVisitorOnlyOfferGate", "AuthorizedFutureOfferCompletes", "TEMPORAL", "FutureOfferLifecycle"),
    ("FutureVisitorGrant", None, "FutureScopeRequiresEditorRoles", "FutureOfferLifecycle"),
    ("FutureLedgerOmitted", None, "FutureRuntimeAttachedHasLedger", "FutureOfferLifecycle"),
    ("FutureSweepsUnselected", None, "UnselectedIntegrationMemberRequiresInvitationConsent", "FutureOfferLifecycle"),
    ("FutureConsentDisabled", None, None, "FutureOfferLifecycle"),
    ("DisconnectReplay", "RetryAfterFreshReAddResolves", None, "DisconnectReplay"),
    ("DisconnectReplayStaleReceipt", None, "RemovedResponseMatchesCurrentScope", "DisconnectReplay"),
    ("LegacyOfflineRemoval", "RemovalEventuallyAcknowledged", None, "LegacyOfflineRemoval"),
    ("LegacyOfflineNoDescriptor", None, None, "LegacyOfflineRemoval"),
    ("LegacyOfferDuringPending", None, "PendingBlocksNewOwnerOffers", "LegacyOfflineRemoval"),
    ("SessionCookieIsolation", "ApprovalAfterIdentityExchange", None, "SessionCookieIsolation"),
    ("SessionCookieCollision", None, "OperatorCookieSlotIsOperatorOnly", "SessionCookieIsolation"),
    ("LocalProjectionCleanup", "ProjectionCleanupEventuallyRetryable", None, "LocalProjectionCleanup"),
    ("LocalProjectionCleanupDropsReceipt", "ProjectionCleanupEventuallyRetryable", "TEMPORAL", "LocalProjectionCleanup"),
    ("PairingWithdrawal", "WithdrawalEventuallyCompletes", None, "PairingWithdrawal"),
    ("PairingLateActivation", None, "NoLateActivation", "PairingWithdrawal"),
    ("PairingRetryAfterWithdrawal", None, "NoRetryAfterFence", "PairingWithdrawal"),
    ("PairingUnverifiedCompletion", None, "CancelledHasNoGrant", "PairingWithdrawal"),
]


def run_case(java, jar, logs, config, property_name, expected_invariant, timeout, module):
    with tempfile.TemporaryDirectory(prefix="rusty-tlc-states-") as state_dir:
        result = subprocess.run(
            [
                java,
                "-XX:+UseParallelGC",
                "-Xmx1g",
                "-cp",
                jar,
                "tlc2.TLC",
                "-workers",
                "1",
                "-config",
                f"{config}.cfg",
                "-metadir",
                state_dir,
                f"{module}.tla",
            ],
            cwd=Path(__file__).resolve().parent,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            check=False,
        )
    (logs / f"{config}.log").write_text(result.stdout)
    states = re.search(r"(\d+) states generated, (\d+) distinct states found", result.stdout)
    state_count = f"{states[1]} generated/{states[2]} distinct" if states else "state count unavailable"
    if expected_invariant == "TEMPORAL":
        passed = result.returncode != 0 and "Temporal properties were violated." in result.stdout
        status = f"expected {property_name} liveness counterexample"
    elif expected_invariant:
        passed = (
            result.returncode != 0
            and f"Error: Invariant {expected_invariant} is violated." in result.stdout
        )
        status = f"expected {expected_invariant} counterexample"
    else:
        passed = (
            result.returncode == 0
            and "Model checking completed. No error has been found." in result.stdout
        )
        status = "safety/liveness checked"
    if property_name and f"Property {property_name} is violated" in result.stdout:
        passed = False
        status = f"unexpected {property_name} violation"
    print(f"{'PASS' if passed else 'FAIL'} {config}: {status}; {state_count}")
    if not passed:
        summary = next(
            (line.strip() for line in reversed(result.stdout.splitlines())
             if "Error:" in line or "Exception" in line or "Property" in line),
            "TLC exited without recognized result",
        )
        print(f"  {summary}")
    return passed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--java", default=os.environ.get("JAVA", "java"))
    parser.add_argument("--jar", default=os.environ.get("TLC_JAR"))
    parser.add_argument(
        "--logs",
        type=Path,
        default=Path(os.environ.get("TLC_LOGS", tempfile.mkdtemp(prefix="rusty-tlc-"))),
    )
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()
    if not args.jar or not Path(args.jar).is_file():
        parser.error("Supply --jar PATH or TLC_JAR pointing to official tla2tools.jar")
    logs = args.logs.resolve()
    logs.mkdir(parents=True, exist_ok=True)
    jar = str(Path(args.jar).resolve())
    results = [
        run_case(
            args.java,
            jar,
            logs,
            config,
            prop,
            invariant,
            args.timeout,
            case[3] if len(case) == 4 else "IntegrationLifecycle",
        )
        for case in CASES
        for config, prop, invariant in (case[:3],)
    ]
    print(f"Formal result: {sum(results)}/{len(results)} cases passed")
    print(f"TLC logs: {logs}")
    raise SystemExit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
