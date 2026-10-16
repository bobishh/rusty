"""Verify the exact immutable Rusty artifact downloaded from its CI run."""
import hashlib
import json
from pathlib import Path
import re
import sys

REQUIRED_READER_FLOORS = {"scopePolicy": 2, "managementPolicy": 1, "archiveStorage": 1,
                          "publicBoardPublication": 1}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def verify(directory):
    root = Path(directory)
    artifact = json.loads((root / "artifact.json").read_text())
    seal = artifact.pop("artifactSha256", None)
    if artifact.get("kind") != "tincanban-component-artifact" or artifact.get("version") != 1 or artifact.get("component") != "rusty":
        raise ValueError("Unexpected Rusty release artifact")
    if not re.fullmatch(r"[a-f0-9]{64}", seal or "") or hashlib.sha256(canonical(artifact)).hexdigest() != seal:
        raise ValueError("Rusty release seal does not match")
    if not re.fullmatch(r"ghcr\.io/bobishh/rusty@sha256:[a-f0-9]{64}", artifact.get("image", "")):
        raise ValueError("Rusty release image is not immutable")
    readers = artifact.get("readers")
    if not isinstance(readers, dict) or any(
        isinstance(readers.get(schema), bool)
        or not isinstance(readers.get(schema), int)
        or readers[schema] < floor
        for schema, floor in REQUIRED_READER_FLOORS.items()
    ):
        raise ValueError("Rusty release artifact is missing compatible reader floors")
    if isinstance(artifact.get("writerVersion"), bool) or not isinstance(artifact.get("writerVersion"), int) or artifact["writerVersion"] < 2:
        raise ValueError("Rusty release artifact is missing the current writer floor")
    if set(artifact.get("files", {})) != {"mesh-lighthouse"}:
        raise ValueError("Unexpected Rusty release file set")
    binary_hash = hashlib.sha256((root / "mesh-lighthouse").read_bytes()).hexdigest()
    if artifact["files"]["mesh-lighthouse"] != binary_hash or artifact.get("binarySha256") != binary_hash:
        raise ValueError("Rusty executable differs from its sealed image artifact")
    return artifact


if __name__ == "__main__":
    verify(sys.argv[1])
