import tempfile
import unittest
from pathlib import Path
from seal_release import seal_release


class ReleaseSealTests(unittest.TestCase):
    def test_same_source_with_changed_executable_has_distinct_artifact_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "mesh-lighthouse"
            image = "ghcr.io/bobishh/rusty@sha256:" + "a" * 64
            executable.write_bytes(b"first executable")
            first = seal_release(directory, image, "b" * 40, "c" * 40, "run-1")
            executable.write_bytes(b"second executable")
            second = seal_release(directory, image, "b" * 40, "c" * 40, "run-1")
            self.assertNotEqual(first["artifactSha256"], second["artifactSha256"])

    def test_mutable_image_tag_cannot_be_a_release_identity(self):
        with self.assertRaisesRegex(ValueError, "immutable"):
            seal_release("unused", "ghcr.io/bobishh/rusty:main", "b" * 40, "c" * 40, "run-1")


if __name__ == "__main__":
    unittest.main()
