"""Given durable storage, verify a blind/public service preserves its identity on restart."""
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request


def run_once(binary, directory):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    origin = f"http://127.0.0.1:{port}"
    environment = {
        key: value for key, value in os.environ.items()
        if not key.startswith(("RUSTY_", "LIGHTHOUSE_"))
    }
    environment["RUSTY_PUBLIC_ORIGIN"] = origin
    with tempfile.TemporaryFile() as logs:
        child = subprocess.Popen(
            [str(binary), str(directory), f"127.0.0.1:{port}"],
            env=environment, stdout=logs, stderr=logs,
        )
        try:
            deadline = time.monotonic() + 15
            while True:
                if child.poll() is not None:
                    raise AssertionError("Service exited before readiness")
                try:
                    with urllib.request.urlopen(origin + "/health", timeout=1) as response:
                        health = json.load(response)
                    break
                except (OSError, urllib.error.URLError):
                    if time.monotonic() >= deadline:
                        raise AssertionError("Service readiness timed out")
                    time.sleep(0.05)
            assert health["mode"] == "blind", health
            with urllib.request.urlopen(origin + "/.well-known/mesh-lighthouse", timeout=2) as response:
                descriptor = json.load(response)
            capabilities = descriptor["capabilities"]
            assert capabilities["modes"] == ["blind"], capabilities
            assert capabilities["applicationWrites"] is False, capabilities
            assert capabilities["classification"] is False, capabilities
            assert capabilities["publicBoardPublication"]["version"] == 1, capabilities
            assert descriptor["publicOrigin"] == origin, descriptor
            return descriptor["service"]
        except BaseException:
            logs.seek(0)
            sys.stderr.write(logs.read().decode("utf-8", errors="replace"))
            raise
        finally:
            if child.poll() is None:
                child.send_signal(signal.SIGINT)
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
            if child.returncode != 0:
                raise AssertionError(f"Service shutdown failed: {child.returncode}")


if __name__ == "__main__":
    binary = Path(sys.argv[1]).resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="rusty-process-smoke-") as directory:
        first = run_once(binary, Path(directory))
        second = run_once(binary, Path(directory))
        assert first == second, "Restart changed the durable service identity"
    print("Blind storage, public publication and durable restart passed")
