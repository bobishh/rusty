"""Transfer Rusty's single-writer volume without deleting containers or stored data."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

SERVICE = "mesh-lighthouse"
VOLUME = "mesh_lighthouse_blind_20261008"


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True).strip()


def checked_container(container_id):
    container = json.loads(docker("inspect", container_id))[0]
    labels = container["Config"]["Labels"]
    if (labels.get("service") != SERVICE or labels.get("role") != "web"
            or labels.get("destination", "") != ""
            or not any(m.get("Name") == VOLUME and m["Destination"] == "/data"
                       for m in container["Mounts"])):
        raise RuntimeError("Storage handoff encountered another service or volume")
    name = container["Name"].removeprefix("/mesh-lighthouse-web-")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
        raise RuntimeError("Storage handoff encountered an unexpected container name")
    return container, name


def handoff(action, cohort, directory):
    if action not in ("stop", "restore") or not re.fullmatch(r"[a-f0-9]{64}", cohort):
        raise ValueError("Invalid storage handoff request")
    record = directory / f"storage-handoff-{cohort}.json"
    if record.exists():
        previous = json.loads(record.read_text())["containerId"]
    elif action == "stop":
        table = re.sub(r"\x1b\[[0-9;]*m", "", docker("exec", "kamal-proxy", "kamal-proxy", "list"))
        rows = [line.split() for line in table.splitlines() if line.split()[:1] == ["mesh-lighthouse-web"]]
        if len(rows) != 1 or len(rows[0]) != 6 or rows[0][4] != "running":
            raise RuntimeError("Cannot establish the currently routed Rusty container")
        target = rows[0][3].removesuffix(":8080")
        if not re.fullmatch(r"[a-f0-9]{12,64}", target):
            raise RuntimeError("Unexpected Rusty proxy target")
        previous = checked_container(target)[0]["Id"]
        directory.mkdir(parents=True, exist_ok=True)
        with record.open("x") as output:
            json.dump({"containerId": previous}, output)
            output.flush()
            os.fsync(output.fileno())
        descriptor = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    else:
        raise RuntimeError("No captured Rusty writer to restore")
    if not re.fullmatch(r"[a-f0-9]{64}", previous):
        raise RuntimeError("Invalid captured Rusty container identity")
    _, version = checked_container(previous)
    # Include restarting failed candidates: any of them could acquire the lock next.
    ids = docker("ps", "-q", "--filter", "label=service=mesh-lighthouse",
                 "--filter", "label=role=web", "--filter", f"volume={VOLUME}").split()
    for container_id in ids:
        container, _ = checked_container(container_id)
        if container["Id"] != previous:
            docker("stop", "--time", "30", container_id)
    if action == "stop":
        docker("stop", "--time", "30", previous)
    else:
        docker("start", previous)
    return {"version": version}


if __name__ == "__main__":
    print(json.dumps(handoff(sys.argv[1], sys.argv[2], Path.home() / ".kamal/apps/mesh-lighthouse")))
