#!/usr/bin/env python3
"""Install the reviewed host agent without applying kernel rules or starting it."""
import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent


def atomic_file(destination, body, mode):
    if destination.is_symlink():
        raise RuntimeError("refusing symlink destination")
    with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as output:
        temp = pathlib.Path(output.name)
        output.write(body)
        output.flush()
        os.fsync(output.fileno())
    try:
        temp.chmod(mode)
        os.chown(temp, 0, 0)
        temp.replace(destination)
    finally:
        temp.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=pathlib.Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--config", required=True, type=pathlib.Path)
    parser.add_argument("--enable-apply", action="store_true", help="Explicitly permit later authenticated rule mutations")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError("installer requires root")
    if args.binary.is_symlink() or not args.binary.is_file() or args.binary.stat().st_size > 128 * 1024 ** 2:
        raise RuntimeError("bounded ordinary executable required")
    binary = args.binary.read_bytes()
    if hashlib.sha256(binary).hexdigest() != args.sha256.lower():
        raise RuntimeError("binary SHA-256 mismatch")
    if args.config.is_symlink() or not args.config.is_file() or args.config.stat().st_size > 256 * 1024:
        raise RuntimeError("bounded ordinary config required")
    cfg = json.loads(args.config.read_text())
    cfg["allow_apply"] = bool(args.enable_apply)
    for directory in [pathlib.Path("/etc/weroxy"), pathlib.Path("/usr/local/lib/weroxy")]:
        directory.mkdir(mode=0o755, parents=True, exist_ok=True)
        # Check every ancestor before copying a privileged executable/config.
        for parent in [directory, *directory.parents]:
            info = parent.lstat()
            if parent.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
                raise RuntimeError("installation ancestors must be protected root-owned directories")
    # Validate the root-owned staged config without creating socket/rules.
    with tempfile.TemporaryDirectory(dir="/etc/weroxy") as temp:
        stage = pathlib.Path(temp)
        executable, configuration = stage / "weroxy-Server", stage / "config.json"
        atomic_file(executable, binary, 0o755)
        atomic_file(configuration, json.dumps(cfg).encode(), 0o600)
        subprocess.run([str(executable), "firewall-agent", "--config", str(configuration), "--check"],
                       check=True, timeout=10, stdout=subprocess.DEVNULL)
    destination = pathlib.Path("/usr/local/lib/weroxy/weroxy-Server")
    conf = pathlib.Path("/etc/weroxy/firewall-agent.json")
    if destination.exists() or conf.exists():
        raise RuntimeError("existing installation: use an explicit reviewed replacement procedure")
    unit = ROOT / "weroxy-firewall-agent.service"
    content = unit.read_text().replace("/usr/local/bin/weroxy-Server", str(destination))
    atomic_file(destination, binary, 0o755)
    atomic_file(conf, json.dumps(cfg, indent=2).encode() + b"\n", 0o600)
    atomic_file(pathlib.Path("/etc/systemd/system/weroxy-firewall-agent.service"), content.encode(), 0o644)
    for name in ("install.py", "docker-config.py", "update-config.py", "watch-docker.py"):
        atomic_file(pathlib.Path("/usr/local/lib/weroxy") / name, (ROOT / name).read_bytes(), 0o755)
    atomic_file(pathlib.Path("/etc/systemd/system/weroxy-firewall-scope.service"), (ROOT / "weroxy-firewall-scope.service").read_bytes(), 0o644)
    subprocess.run(["systemctl", "daemon-reload"], check=True, timeout=15)
    print("Installed. Agent is not started or enabled. Review config, then start/enable the service explicitly.")
    print("Kernel mutation permission: " + ("enabled" if args.enable_apply else "disabled"))


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        print("Installation failed: " + (str(error) if isinstance(error, RuntimeError) else type(error).__name__))
        raise SystemExit(1)
