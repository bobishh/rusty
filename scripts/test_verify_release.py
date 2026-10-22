import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from verify_release import verify


class VerifyReleaseTests(unittest.TestCase):
    def fixture(self, root):
        data = b"sealed executable"
        digest = hashlib.sha256(data).hexdigest()
        body = {"kind": "tincanban-component-artifact", "version": 1, "component": "rusty",
                "sourceSha": "a" * 40, "sdkSha": "b" * 40, "candidateId": "12-1",
                "readers": {"scopePolicy": 2, "managementPolicy": 2, "archiveStorage": 1,
                            "publicBoardPublication": 1}, "writerVersion": 2,
                "files": {"mesh-lighthouse": digest},
                "image": "ghcr.io/bobishh/rusty@sha256:" + "c" * 64, "binarySha256": digest}
        body["artifactSha256"] = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        (root / "mesh-lighthouse").write_bytes(data)
        (root / "artifact.json").write_text(json.dumps(body))

    def test_accepts_exact_sealed_native_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.fixture(root)
            self.assertEqual(verify(root)["component"], "rusty")

    def test_rejects_artifact_without_current_reader_floors(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.fixture(root)
            artifact_path = root / "artifact.json"
            artifact = json.loads(artifact_path.read_text())
            artifact["readers"] = {"scopePolicy": 2}
            body = {key: value for key, value in artifact.items() if key != "artifactSha256"}
            artifact["artifactSha256"] = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
            artifact_path.write_text(json.dumps(artifact))
            with self.assertRaisesRegex(ValueError, "reader floors"):
                verify(root)

    def test_rejects_rollback_artifact_without_public_publication_reader(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.fixture(root)
            artifact_path = root / "artifact.json"
            artifact = json.loads(artifact_path.read_text())
            artifact["readers"].pop("publicBoardPublication")
            body = {key: value for key, value in artifact.items() if key != "artifactSha256"}
            artifact["artifactSha256"] = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
            artifact_path.write_text(json.dumps(artifact))
            with self.assertRaisesRegex(ValueError, "reader floors"):
                verify(root)

    def test_rejects_changed_executable_and_mutated_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.fixture(root)
            (root / "mesh-lighthouse").write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "executable differs"):
                verify(root)
            self.fixture(root)
            data = json.loads((root / "artifact.json").read_text())
            data["image"] = "ghcr.io/attacker/rusty@sha256:" + "c" * 64
            (root / "artifact.json").write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError, "seal does not match"):
                verify(root)


if __name__ == "__main__":
    unittest.main()
