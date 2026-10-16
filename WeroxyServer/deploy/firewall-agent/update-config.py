#!/usr/bin/env python3
"""Root-only scope replacement: revoke old rules before changing authorization."""
import argparse
import json
import os
import pathlib
import socket
import struct
import subprocess
import tempfile
import time

from importlib.util import module_from_spec, spec_from_file_location

ROOT = pathlib.Path(__file__).resolve().parent
spec = spec_from_file_location("agent_installer", ROOT / "install.py")
installer = module_from_spec(spec)
spec.loader.exec_module(installer)
CONFIG = pathlib.Path("/etc/weroxy/firewall-agent.json")
STATE = pathlib.Path("/var/lib/weroxy-firewall/state.json")
BINARY = "/usr/local/lib/weroxy/weroxy-Server"


def request(body):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(15)
        conn.connect("/run/weroxy-firewall/agent.sock")
        _, uid, _ = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != 0:
            raise RuntimeError("agent peer must be root")
        conn.sendall(json.dumps(body).encode() + b"\n")
        result = bytearray()
        while not result.endswith(b"\n"):
            chunk = conn.recv(8192)
            if not chunk:
                raise RuntimeError("incomplete agent response")
            result.extend(chunk)
            if len(result) > 1024 * 1024:
                raise RuntimeError("agent response exceeds budget")
        return json.loads(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=pathlib.Path)
    parser.add_argument("--enable-apply", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError("scope replacement requires root")
    if not args.config.is_file() or args.config.is_symlink() or args.config.stat().st_size > 256 * 1024:
        raise RuntimeError("bounded ordinary config required")
    cfg = json.loads(args.config.read_text())
    cfg["allow_apply"] = bool(args.enable_apply)
    new = json.dumps(cfg, indent=2).encode() + b"\n"
    with tempfile.TemporaryDirectory(dir="/etc/weroxy") as temp:
        candidate = pathlib.Path(temp) / "config.json"
        installer.atomic_file(candidate, new, 0o600)
        subprocess.run([BINARY, "firewall-agent", "--config", str(candidate), "--check"], check=True, timeout=10)
    if CONFIG.is_symlink() or CONFIG.stat().st_size > 256 * 1024:
        raise RuntimeError("unsafe installed config")
    subprocess.run([BINARY, "firewall-agent", "--config", str(CONFIG), "--check"], check=True, timeout=10, stdout=subprocess.DEVNULL)
    old = CONFIG.read_bytes()
    current = request({"operation": "query"})
    if current.get("status") != "ok":
        raise RuntimeError("agent query failed")
    generation = int(current["generation"]) + 1
    if STATE.exists():
        if STATE.is_symlink() or STATE.stat().st_size > 32768:
            raise RuntimeError("unsafe agent journal")
        generation = max(generation, int(json.loads(STATE.read_text())["generation"]) + 1)
    if generation >= 2**64:
        raise RuntimeError("generation exhausted")
    if json.loads(old).get("allow_apply"):
        revoked = request({"operation": "revoke", "generation": generation, "rules": []})
        if revoked.get("status") != "applied":
            raise RuntimeError("old rule revocation failed; scope unchanged")
    elif STATE.exists():
        raise RuntimeError("recover and revoke old journal before disabling writes")
    subprocess.run(["systemctl", "stop", "weroxy-firewall-agent.service"], check=True, timeout=30)
    archive = STATE.with_name("state.previous-" + str(time.time_ns()) + ".json")
    if STATE.exists():
        STATE.rename(archive)
    try:
        installer.atomic_file(CONFIG, new, 0o600)
        subprocess.run(["systemctl", "start", "weroxy-firewall-agent.service"], check=True, timeout=30)
        # systemctl start alone does not prove the agent accepted its config.
        deadline = time.monotonic() + 15
        while True:
            try:
                if request({"operation": "query"}).get("status") == "ok":
                    break
                raise RuntimeError("new agent query rejected")
            except (OSError, RuntimeError):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(1)
    except Exception:
        subprocess.run(["systemctl", "stop", "weroxy-firewall-agent.service"], check=False, timeout=30)
        installer.atomic_file(CONFIG, old, 0o600)
        if archive.exists():
            archive.replace(STATE)
        subprocess.run(["systemctl", "start", "weroxy-firewall-agent.service"], check=True, timeout=30)
        raise
    print("Scope replaced; prior rules revoked. Server policy synchronization must apply the new batch.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print("Scope replacement failed: " + (str(error) if isinstance(error, RuntimeError) else type(error).__name__))
        raise SystemExit(1)
