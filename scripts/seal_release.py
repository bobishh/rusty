"""Seal the executable extracted from the exact pushed image, without rebuilding it."""
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tomllib


def seal_release(directory, image, source_sha, sdk_sha, candidate_id):
    if not re.fullmatch(r"ghcr\.io/bobishh/rusty@sha256:[a-f0-9]{64}", image):
        raise ValueError("An immutable pushed Rusty image digest is required")
    if not all(re.fullmatch(r"[a-f0-9]{40}", value) for value in [source_sha, sdk_sha]):
        raise ValueError("Full source and SDK revisions are required")
    binary = (Path(directory) / "mesh-lighthouse").read_bytes()
    binary_sha = hashlib.sha256(binary).hexdigest()
    body = {
        "kind": "tincanban-component-artifact", "version": 1, "component": "rusty",
        "sourceSha": source_sha, "sdkSha": sdk_sha, "candidateId": candidate_id,
        "readers": {"scopePolicy": 2, "managementPolicy": 2, "archiveStorage": 1,
                    "publicBoardPublication": 1},
        "writerVersion": 2, "files": {"mesh-lighthouse": binary_sha},
        "image": image, "binarySha256": binary_sha,
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return {**body, "artifactSha256": hashlib.sha256(canonical.encode()).hexdigest()}


if __name__ == "__main__":
    artifact_directory, immutable_image = sys.argv[1:]
    sdk = tomllib.loads(Path("Cargo.toml").read_text())["dependencies"]["meta-mesh-core"]["rev"]
    manifest = seal_release(artifact_directory, immutable_image, os.environ["GITHUB_SHA"], sdk,
                            f'{os.environ["GITHUB_RUN_ID"]}-{os.environ["GITHUB_RUN_ATTEMPT"]}')
    (Path(artifact_directory) / "artifact.json").write_text(json.dumps(manifest, separators=(",", ":")))
