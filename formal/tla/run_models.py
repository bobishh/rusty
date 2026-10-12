#!/usr/bin/env python3
"""Check safety, fair liveness, and specifically expected counterexamples."""
import argparse
import os
from pathlib import Path
import re
import subprocess
import tempfile

MODELS = [
    ("BlindUploadRetry", "BlindUploadRetry", None),
    ("BlindUploadRetryVisibleOnly", "BlindUploadRetry", "Invariant ReceiptIsDurableAndCurrentlyAuthorized is violated"),
    ("BlindUploadRetrySkipsPolicy", "BlindUploadRetry", "Invariant ReceiptIsDurableAndCurrentlyAuthorized is violated"),
    ("BlindCheckpoint", "BlindCheckpoint", None),
    ("BlindCheckpointEarlyReceipt", "BlindCheckpoint", "Invariant ReceiptRequiresDurableCheckpoint is violated"),
    ("BlindCheckpointEarlyPrune", "BlindCheckpoint", "Invariant PruneRequiresDurableReplacement is violated"),
    ("BlindCheckpointRewriteRetry", "BlindCheckpoint", "Invariant ExactRetryWritesOnce is violated"),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--java", default=os.environ.get("JAVA", "java"))
    parser.add_argument("--jar", default=os.environ.get("TLC_JAR"))
    parser.add_argument("--logs", type=Path)
    args = parser.parse_args()
    if not args.jar or not Path(args.jar).is_file():
        parser.error("Supply --jar PATH or TLC_JAR pointing to official tla2tools.jar")
    jar = str(Path(args.jar).resolve())
    logs = args.logs or Path(tempfile.mkdtemp(prefix="match-tlc-"))
    logs.mkdir(parents=True, exist_ok=True)
    root = Path(__file__).resolve().parent
    failed = False
    for config, module, expected in MODELS:
        with tempfile.TemporaryDirectory(prefix="match-tlc-states-") as state_dir:
            result = subprocess.run(
                [args.java, "-XX:+UseParallelGC", "-Xmx1g", "-cp", jar, "tlc2.TLC",
                 "-workers", "1", "-config", f"{config}.cfg", "-metadir", state_dir,
                 f"{module}.tla"],
                cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                timeout=60,
            )
        (logs / f"{config}.log").write_text(result.stdout)
        if expected:
            ok = result.returncode != 0 and f"Error: {expected}" in result.stdout
        else:
            ok = result.returncode == 0 and "Model checking completed. No error has been found." in result.stdout
        counts = re.search(r"(\d+) states generated, (\d+) distinct states found", result.stdout)
        detail = f"{counts[1]} generated / {counts[2]} distinct" if counts else "no state counts"
        outcome = "expected counterexample" if expected else "checked"
        print(f"{'PASS' if ok else 'FAIL'} {config}: {outcome}; {detail}")
        if not ok:
            failed = True
            print(result.stdout[-3000:])
    print(f"Full TLC logs: {logs.resolve()}")
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
