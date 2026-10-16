#!/usr/bin/env python3
"""Refresh operator-approved Docker scope; no unprivileged process edits it."""
import argparse
import json
import os
import pathlib
import subprocess
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent
APPROVED_FLAGS = {"--container", "--network", "--public-ip", "--management-source", "--management-port", "--client-uid", "--backend", "--listen-host"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope-args", required=True, type=pathlib.Path)
    parser.add_argument("--enable-apply", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError("watcher requires root")
    info = args.scope_args.lstat()
    if args.scope_args.is_symlink() or not args.scope_args.is_file() or info.st_uid != 0 or info.st_mode & 0o077 or info.st_size > 8192:
        raise RuntimeError("scope arguments must be root-owned 0600 JSON")
    argv = json.loads(args.scope_args.read_text())
    if not isinstance(argv, list) or len(argv) > 128 or len(argv) % 2:
        raise RuntimeError("bounded argument pairs required")
    for index in range(0, len(argv), 2):
        if argv[index] not in APPROVED_FLAGS or not isinstance(argv[index + 1], str) or len(argv[index + 1]) > 256:
            raise RuntimeError("unsupported scope argument")
    while True:
        try:
            result = subprocess.run(["/usr/bin/python3", str(ROOT / "docker-config.py"), *argv],
                                    check=True, capture_output=True, timeout=30)
            if len(result.stdout) > 256 * 1024:
                raise RuntimeError("generated scope exceeds budget")
            cfg = json.loads(result.stdout)
            cfg["allow_apply"] = bool(args.enable_apply)
            current = pathlib.Path("/etc/weroxy/firewall-agent.json")
            if current.is_symlink() or current.stat().st_size > 256 * 1024:
                raise RuntimeError("invalid installed scope")
            if cfg != json.loads(current.read_text()):
                with tempfile.TemporaryDirectory(dir="/etc/weroxy") as temp:
                    candidate = pathlib.Path(temp) / "scope.json"
                    candidate.write_text(json.dumps(cfg))
                    candidate.chmod(0o600)
                    command = ["/usr/bin/python3", str(ROOT / "update-config.py"), "--config", str(candidate)]
                    if args.enable_apply:
                        command.append("--enable-apply")
                    subprocess.run(command, check=True, timeout=120)
                print("Docker scope updated", flush=True)
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
            # Keep old approved scope, but make failure observable in host logs.
            print("Docker scope refresh failed; existing scope retained", flush=True)
        time.sleep(30)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError) as error:
        print("Watcher failed: " + (str(error) if isinstance(error, RuntimeError) else type(error).__name__))
        raise SystemExit(1)
