#!/usr/bin/env python3
"""Read Docker's actual port bindings on the host and publish an advisory snapshot.

Run on the Docker host after container start and periodically thereafter. The
server container does not receive the Docker socket or any host privileges.
"""
import argparse
import datetime
import json
import os
import pathlib
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument("--container", required=True, help="Docker container name or ID")
parser.add_argument("--data-dir", required=True, type=pathlib.Path, help="Host directory mounted as /data")
args = parser.parse_args()
raw = subprocess.check_output(["docker", "inspect", "--type=container", args.container], timeout=10)
items = json.loads(raw)
if len(items) != 1:
    raise SystemExit("expected one Docker container")
item = items[0]
ports = []
for key, bindings in (item.get("NetworkSettings", {}).get("Ports") or {}).items():
    text, protocol = key.split("/", 1)
    if protocol != "tcp" or not bindings:
        continue
    container_port = int(text)
    for binding in bindings:
        ports.append({
            "container_port": container_port,
            "host_ip": binding["HostIp"],
            "host_port": int(binding["HostPort"]),
        })
if len(ports) > 1024:
    raise SystemExit("too many published ports")
body = {
    "container_id": item["Id"],
    "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
    "ports": ports,
}
args.data_dir.mkdir(parents=True, exist_ok=True)
with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=args.data_dir, prefix=".publication-", delete=False) as output:
    path = pathlib.Path(output.name)
    json.dump(body, output, separators=(",", ":"))
    output.flush()
    os.fsync(output.fileno())
try:
    path.chmod(0o644)
    path.replace(args.data_dir / "deployment-publication.json")
finally:
    path.unlink(missing_ok=True)
print("Docker publication snapshot refreshed")
