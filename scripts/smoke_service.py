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
            # Given a fresh Rusty, its original branding must be self-contained.
            with urllib.request.urlopen(origin + "/", timeout=2) as response:
                page = response.read().decode("utf-8")
            assert 'class="topbar"' in page and 'class="rusty-mark"' in page, page
            assert 'href="/assets/design-system.css"' in page, page
            assert "https://analytics.meta-uber-engineer.dev/admin.css" not in page
            for asset, mime in (
                ("design-system.css", "text/css"),
                ("typography.css", "text/css"),
                ("rusty-logo.webp", "image/webp"),
                ("rusty-head-32.png", "image/png"),
                ("fira-code-latin-wght.woff2", "font/woff2"),
                ("caveat-latin-wght.woff2", "font/woff2"),
                ("ink-surface-0.svg", "image/svg+xml"),
            ):
                with urllib.request.urlopen(origin + "/assets/" + asset, timeout=2) as response:
                    assert response.headers.get_content_type() == mime, asset
                    assert response.headers["X-Content-Type-Options"] == "nosniff", asset
                    assert response.read(), asset
            try:
                urllib.request.urlopen(origin + "/assets/service-key.json", timeout=2)
                raise AssertionError("Unknown assets must not expose storage files")
            except urllib.error.HTTPError as error:
                assert error.code == 404, error
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
