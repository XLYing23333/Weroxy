#!/usr/bin/env python3
"""Host-side Docker lifecycle; never exposes the Docker socket to Server."""
import argparse
import contextlib
import json
import os
import pathlib
import shutil
import sqlite3
import socket
import struct
import stat
import subprocess
import sys
import tempfile
import time
import re
import hashlib
import shlex

import port_plan

ROOT = pathlib.Path(__file__).resolve().parent
DATA = ROOT / "data"
STATE = ROOT / ".deployment-state.json"
LOCK = ROOT / ".deployment.lock"
PUBLICATION = ROOT / "publication.compose.yaml"


def command(argv, *, capture=False, timeout=120, env=None, pass_fds=()):
    return subprocess.run(argv, cwd=ROOT, env=env, check=True, timeout=timeout,
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.PIPE if capture else None,
                          text=True, pass_fds=pass_fds).stdout


def compose(*args, image=None, capture=False, timeout=120):
    env = os.environ.copy()
    if image:
        env["WEROXY_IMAGE"] = image
    files = [item for item in env.get("COMPOSE_FILE", "compose.yaml").split(os.pathsep) if item]
    if PUBLICATION.exists() and str(PUBLICATION) not in files:
        files.append(str(PUBLICATION))
    flags = [part for file in files for part in ("-f", file)]
    return command(["docker", "compose", *flags, *args], capture=capture, timeout=timeout, env=env)


def state():
    if not STATE.exists():
        return {"image": os.environ.get("WEROXY_IMAGE", "weroxy-server:local")}
    return json.loads(STATE.read_text())


def save(value):
    with tempfile.NamedTemporaryFile(mode="w", dir=ROOT, delete=False) as output:
        path = pathlib.Path(output.name)
        json.dump(value, output)
        output.flush()
        os.fsync(output.fileno())
    path.chmod(0o600)
    path.replace(STATE)


def refresh(image):
    cid = compose("ps", "-q", "weroxy", image=image, capture=True, timeout=10).strip()
    if not cid or "\n" in cid:
        raise RuntimeError("one running Weroxy container required")
    command([sys.executable, str(ROOT / "refresh-publication.py"),
             "--container", cid, "--data-dir", str(DATA)], timeout=20)


def ready(image):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            # Use the same HTTP endpoint as the Compose liveness check.
            cid = compose("ps", "-q", "weroxy", image=image, capture=True, timeout=10).strip()
            raw = command(["docker", "inspect", cid], capture=True, timeout=5)
            check = json.loads(raw)[0]["Config"]["Healthcheck"]["Test"][1:]
            check[check.index("--check") + 1] = "ready"
            command(["docker", "exec", cid, *check], capture=True, timeout=5)
            refresh(image)
            return
        except (subprocess.SubprocessError, RuntimeError, KeyError, ValueError, IndexError):
            time.sleep(2)
    raise RuntimeError("readiness did not succeed within 60 seconds")


def owned_copy(source, destination):
    result = shutil.copy2(source, destination)
    info = os.stat(source, follow_symlinks=False)
    os.chown(destination, info.st_uid, info.st_gid)
    return result


def verify_data(path):
    if path.is_symlink() or not path.is_dir():
        raise RuntimeError("ordinary data directory required")
    total = 0
    for item in path.rglob("*"):
        mode = item.lstat().st_mode
        if not stat.S_ISREG(mode) and not stat.S_ISDIR(mode):
            raise RuntimeError("data may contain only ordinary files and directories")
        if stat.S_ISREG(mode):
            total += item.stat().st_size
        if total > 4 * 1024 ** 3:
            raise RuntimeError("offline snapshot exceeds 4 GiB budget")
    return total


def verify_old_certificates(path):
    """Accept Certbot's relative live-to-archive links only within this tree."""
    if path.is_symlink() or not path.is_dir():
        raise RuntimeError('ordinary certificate directory required')
    base = path.resolve()
    total = 0
    for item in path.rglob('*'):
        mode = item.lstat().st_mode
        if stat.S_ISLNK(mode):
            try:
                target = item.resolve(strict=True)
            except (OSError, RuntimeError) as exc:
                raise RuntimeError('invalid certificate link') from exc
            if os.path.isabs(os.readlink(item)) or not target.is_relative_to(base) or not target.is_file():
                raise RuntimeError('certificate link must resolve to a file within its directory')
        elif stat.S_ISREG(mode):
            total += item.stat().st_size
        elif not stat.S_ISDIR(mode):
            raise RuntimeError('unexpected certificate file type')
        if total > 4 * 1024 ** 3:
            raise RuntimeError('certificate snapshot exceeds 4 GiB budget')
    return total


def quarantine_restore(path):
    # Same credential safety boundary as Server RestoreFile. Do not resurrect
    # sessions, tokens, or device access from an older database snapshot.
    dbfile = path / "weroxy.db"
    if not dbfile.is_file() or dbfile.is_symlink():
        raise RuntimeError("rollback database missing")
    with contextlib.closing(sqlite3.connect(dbfile, timeout=5)) as db:
        db.execute("PRAGMA busy_timeout=5000")
        result = db.execute("PRAGMA quick_check").fetchall()
        if result != [("ok",)]:
            raise RuntimeError("rollback database integrity failed")
        db.execute("UPDATE admin_sessions SET revoked=1")
        db.execute("UPDATE quick_tokens SET revoked=1")
        db.execute("UPDATE weroxy_devices SET revoked=1,paused=1")
        db.execute("UPDATE legacy_devices SET paused=1")
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='firewall_sync'").fetchone():
            db.execute("UPDATE firewall_sync SET enabled=0,managed=0,status='revoked',failure_reason='' WHERE id=1")
        db.commit()
    for suffix in ("", "-wal", "-shm"):
        item = pathlib.Path(str(dbfile) + suffix)
        if item.exists():
            os.chown(item, 10001, 10001)
            item.chmod(0o600)
    (path / "deployment-publication.json").unlink(missing_ok=True)


def revoke_managed_firewall():
    # Server has stopped: it cannot race this revoke with a new policy batch.
    dbfile = DATA / "weroxy.db"
    with contextlib.closing(sqlite3.connect("file:" + str(dbfile) + "?mode=ro", uri=True, timeout=5)) as db:
        if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='firewall_sync'").fetchone():
            return
        row = db.execute("SELECT enabled,managed FROM firewall_sync WHERE id=1").fetchone()
        if not row or not any(row):
            return
    def submit(body):
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
            connection.settimeout(15)
            connection.connect("/run/weroxy-firewall/agent.sock")
            _,uid,_=struct.unpack("3i",connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            if uid!=0:raise RuntimeError("rollback firewall peer must be root")
            connection.sendall(json.dumps(body).encode()+b"\n")
            result=bytearray()
            while not result.endswith(b"\n"):
                chunk=connection.recv(8192)
                if not chunk:raise RuntimeError("incomplete firewall response")
                result.extend(chunk)
                if len(result)>1024*1024:raise RuntimeError("firewall response exceeds budget")
            return json.loads(result)
    current=submit({"operation":"query"})
    if current.get("status")!="ok":raise RuntimeError("cannot query managed firewall before rollback")
    generation=max(int(current["generation"]),int(current.get("pending_generation",0)))+1
    if generation>=2**64:raise RuntimeError("firewall generation exhausted")
    response=submit({"operation":"revoke","generation":generation,"rules":[]})
    if response.get("status")!="applied":raise RuntimeError("managed firewall revocation failed; rollback blocked")


def rollback(saved):
    if os.geteuid() != 0 or not saved.get("rollback_available"):
        raise RuntimeError("root and an offline rollback snapshot required")
    old = saved["previous_image"]
    command(["docker", "image", "inspect", old], capture=True)
    compose("stop", "weroxy", image=saved["image"])
    if not saved.get("rollback_prepared"):
        revoke_managed_firewall()
    backup = ROOT / "rollback-data"
    failed = pathlib.Path(saved.get("rollback_failed_data", str(ROOT / ("failed-data-" + str(time.time_ns())))))
    if not saved.get("rollback_prepared"):
        verify_data(backup)
        quarantine_restore(backup)
        marker = backup / ".rollback-prepared"
        marker.write_text("credential quarantine complete\n")
        marker.chmod(0o600)
        saved = {**saved, "rollback_prepared": True, "rollback_failed_data": str(failed)}
        save(saved)
    # Recorded intent permits resuming after either directory rename.
    if not failed.exists():
        if DATA.exists():
            DATA.rename(failed)
        else:
            raise RuntimeError("current data directory missing")
    if backup.exists():
        if DATA.exists():
            raise RuntimeError("unexpected data directory during rollback")
        backup.rename(DATA)
    if not (DATA / ".rollback-prepared").is_file():
        raise RuntimeError("rollback snapshot marker missing")
    DATA.chmod(0o750)
    prepare_publication(old)
    save({"image": old})
    if saved.get("previous_running", True):
        compose("up", "-d", "--no-build", "weroxy", image=old)
        ready(old)
    else:
        pause_tasks()
    print("Rollback complete. Admin sessions are invalidated; devices require explicit recovery.")


def own_published_ports(image):
    try:
        cid = compose("ps", "-q", "weroxy", image=image, capture=True, timeout=10).strip()
        if not cid or "\n" in cid:
            return set()
        item = json.loads(command(["docker", "inspect", cid], capture=True, timeout=5))[0]
        return {int(row["HostPort"]) for bindings in (item.get("NetworkSettings", {}).get("Ports") or {}).values()
                for row in (bindings or [])}
    except (subprocess.SubprocessError, ValueError, KeyError):
        return set()


def prepare_publication(image):
    port_plan.check_firewall()
    host = os.environ.get("WERXY_PUBLISH_IP", "0.0.0.0")
    value = port_plan.plan(DATA / "weroxy.db", host, own_published_ports(image))
    port_plan.write_plan(value, DATA, PUBLICATION)
    return value


def initialize(args, image):
    if os.geteuid() != 0:
        raise RuntimeError("init requires root to prepare UID 10001 files")
    if (DATA / "weroxy.db").exists():
        raise RuntimeError("existing database: use the existing deployment, not init")
    if DATA.is_symlink():
        raise RuntimeError("deployment data directory must not be a symlink")
    DATA.mkdir(mode=0o750, exist_ok=True)
    os.chown(DATA, 10001, 10001)
    compose("run", "--rm", "--no-deps", "weroxy", "weroxy", "pool", "set",
            "--data", "/data", "--forward-pool", args.forward_pool,
            "--data-pool", args.data_pool, "--reserved", str(args.reserved),
            "--bind-host", "0.0.0.0", image=image)
    save({"image": image})


def install_publication_timer(systemd=None):
    """Keep the bounded Docker inspect evidence fresh without a Docker socket in the container."""
    if os.geteuid() != 0:
        raise RuntimeError("publication timer requires root")
    project = os.environ.get("COMPOSE_PROJECT_NAME", "")
    if project and not re.fullmatch(r"[A-Za-z0-9_-]+", project):
        raise RuntimeError("invalid Compose project name for publication timer")
    suffix = hashlib.sha256(str(ROOT).encode()).hexdigest()[:12]
    name = f"weroxy-publication-{suffix}"
    systemd = pathlib.Path("/etc/systemd/system") if systemd is None else pathlib.Path(systemd)
    service = systemd / f"{name}.service"
    timer = systemd / f"{name}.timer"
    old = {path: path.read_bytes() if path.exists() else None for path in (service, timer)}
    environment = f"Environment=COMPOSE_PROJECT_NAME={project}\n" if project else ""
    try:
        service.write_text("[Unit]\nDescription=Refresh Weroxy Docker port evidence\n"
                           "[Service]\nType=oneshot\nWorkingDirectory=" + str(ROOT) + "\n" + environment +
                           "ExecStart=/usr/bin/python3 " + shlex.quote(str(ROOT / "manage.py")) + " refresh\n")
        timer.write_text("[Unit]\nDescription=Refresh Weroxy Docker port evidence every minute\n"
                         "[Timer]\nOnCalendar=*-*-* *:*:00\nPersistent=true\n"
                         "[Install]\nWantedBy=timers.target\n")
        service.chmod(0o644)
        timer.chmod(0o644)
        command(["systemctl", "daemon-reload"], timeout=15)
        command(["systemctl", "enable", "--now", timer.name], timeout=15)
        command(["systemctl", "is-active", "--quiet", timer.name], timeout=10)
    except Exception:
        with contextlib.suppress(Exception):
            command(["systemctl", "disable", "--now", timer.name], timeout=10)
        for path, body in old.items():
            restore_file(path, body)
        with contextlib.suppress(Exception):
            command(["systemctl", "daemon-reload"], timeout=15)
        if old[timer] is not None:
            with contextlib.suppress(Exception):
                command(["systemctl", "enable", "--now", timer.name], timeout=15)
        raise


def restore_file(path, body):
    if body is None:
        path.unlink(missing_ok=True)
    else:
        path.write_bytes(body)

def deployment_tasks():
    suffix = hashlib.sha256(str(ROOT).encode()).hexdigest()[:12]
    return [f"weroxy-{kind}-{suffix}" for kind in ("publication",)]


def pause_tasks():
    """Only touch units belonging to this deployment. Stop timers before services."""
    names = [name for name in deployment_tasks()
             if pathlib.Path('/etc/systemd/system', name + '.timer').is_file()]
    enabled = []
    for name in names:
        try:
            command(['systemctl', 'is-enabled', '--quiet', name + '.timer'], capture=True, timeout=10)
            enabled.append(name)
        except subprocess.CalledProcessError:
            pass
    if names:
        command(['systemctl', 'disable', '--now', *(name + '.timer' for name in names)], timeout=30)
        command(['systemctl', 'stop', *(name + '.service' for name in names)], timeout=30)
    return enabled


def resume_tasks(names):
    if names:
        command(['systemctl', 'enable', '--now', *(name + '.timer' for name in names)], timeout=30)


def offline_backup(image):
    required = verify_data(DATA)
    certificates = ROOT / 'https-data'
    if certificates.exists():
        required += verify_old_certificates(certificates)
    if shutil.disk_usage(ROOT).free < required + 256 * 1024 ** 2:
        raise RuntimeError('insufficient space for backup and reserve')
    path = ROOT / 'backups' / str(time.time_ns())
    path.parent.mkdir(mode=0o700, exist_ok=True)
    path.parent.chmod(0o700)
    running = bool(own_published_ports(image))
    services = ['weroxy']
    tasks = pause_tasks()
    try:
        if running:
            compose('stop', *services, image=image)
        path.mkdir(mode=0o700)
        shutil.copytree(DATA, path / 'data', copy_function=owned_copy)
        for source in [DATA, *(p for p in DATA.rglob('*') if p.is_dir())]:
            target = path / 'data' / source.relative_to(DATA)
            info = source.stat()
            os.chown(target, info.st_uid, info.st_gid)
        if STATE.exists():
            shutil.copy2(STATE, path / STATE.name)
        for name in ('publication.compose.yaml', 'https.compose.yaml', '.https-settings.json',
                     '.https-host.json', '.https-agent-state.json', 'Caddyfile.generated'):
            source = ROOT / name
            if source.exists():
                if source.is_symlink() or not source.is_file():
                    raise RuntimeError('ordinary host configuration file required')
                shutil.copy2(source, path / name)
        if certificates.exists():
            shutil.copytree(certificates, path / 'https-data', symlinks=True, copy_function=owned_copy)
        print('Backup: ' + str(path))
    except Exception:
        shutil.rmtree(path, ignore_errors=True)
        raise
    finally:
        try:
            if running:
                compose('up', '-d', '--no-build', *services, image=image)
                ready(image)
        finally:
            resume_tasks(tasks)


def retire_old_https():
    """One-time retirement of integrations explicitly owned by this deployment."""
    obsolete = ['https.compose.yaml', '.https-settings.json', '.https-host.json',
                '.https-agent-state.json', 'Caddyfile.generated', 'https-data']
    material = [ROOT / name for name in obsolete if (ROOT / name).exists()]
    suffix = hashlib.sha256(str(ROOT).encode()).hexdigest()[:12]
    units = []
    for kind in ('https-agent', 'https'):
        service = pathlib.Path('/etc/systemd/system') / f'weroxy-{kind}-{suffix}.service'
        timer = service.with_suffix('.timer')
        if service.exists():
            if service.is_symlink() or str(ROOT) not in service.read_text():
                raise RuntimeError('Cannot verify ownership of old HTTPS task')
            if timer.exists() and (timer.is_symlink() or service.stem not in timer.read_text() and 'Description=' not in timer.read_text()):
                raise RuntimeError('Cannot verify ownership of old HTTPS timer')
            units.extend([timer, service])
    if not material and not units and not any((DATA / name).exists() for name in ("weroxy-tls.crt", "weroxy-tls.key")):
        return
    backup = ROOT / 'backups' / ('retired-https-' + str(time.time_ns()))
    backup.mkdir(parents=True, mode=0o700)
    backup.parent.chmod(0o700)
    for item in material:
        if item.is_symlink():
            raise RuntimeError('Old HTTPS material must not be symlinked')
        if item.is_dir():
            verify_old_certificates(item)
            shutil.copytree(item, backup / item.name, symlinks=True, copy_function=owned_copy)
        else:
            shutil.copy2(item, backup / item.name)
    # Read a fixed old integration receipt; never discover or manage other sites.
    receipt = ROOT / '.https-host.json'
    if receipt.exists():
        info = receipt.stat()
        if info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > 65536:
            raise RuntimeError('Untrusted old HTTPS integration receipt')
        host = json.loads(receipt.read_text())
        directory = host.get('nginx_dir', '')
        binary = host.get('nginx_binary', '')
        if directory:
            allowed = {'/etc/nginx/conf.d', '/etc/nginx/sites-enabled', '/www/server/panel/vhost/nginx'}
            if directory not in allowed or binary not in {'/usr/sbin/nginx', '/usr/local/nginx/sbin/nginx', '/www/server/nginx/sbin/nginx'}:
                raise RuntimeError('Old integration falls outside the supported retirement scope')
            site = pathlib.Path(directory) / ('weroxy-' + suffix + '.conf')
            if site.exists():
                if site.is_symlink() or site.stat().st_uid != 0 or site.stat().st_mode & 0o022 or not site.read_text().startswith('# Managed by Weroxy deployment ' + str(ROOT) + '\n'):
                    raise RuntimeError('Cannot verify ownership of old domain site')
                body = site.read_bytes()
                (backup / 'owned-domain-site.conf').write_bytes(body)
                site.unlink()
                try:
                    command([binary, '-t'], capture=True, timeout=10)
                    command([binary, '-s', 'reload'], capture=True, timeout=10)
                except Exception:
                    site.write_bytes(body)
                    raise
    for unit in units:
        if unit.exists():
            shutil.copy2(unit, backup / unit.name)
            command(['systemctl', 'disable', '--now', unit.name], capture=True, timeout=30)
            unit.unlink()
    if units:
        command(['systemctl', 'daemon-reload'], timeout=15)
    raw = command(['docker', 'ps', '-a', '--filter', 'label=com.docker.compose.service=caddy', '--format', '{{.ID}}'], capture=True)
    for cid in raw.splitlines():
        item = json.loads(command(['docker', 'inspect', cid], capture=True))[0]
        labels = item['Config'].get('Labels') or {}
        if labels.get('com.docker.compose.project.working_dir') == str(ROOT):
            command(['docker', 'rm', '-f', cid], capture=True)
    for item in material:
        if item.is_dir(): shutil.rmtree(item)
        else: item.unlink(missing_ok=True)
    # Retire only known Server-generated certificate filenames.
    for name in ('weroxy-tls.crt', 'weroxy-tls.key', 'https-status.json', 'https-received.json'):
        item = DATA / name
        if item.exists():
            if item.is_symlink() or not item.is_file(): raise RuntimeError('Unexpected old certificate file type')
            shutil.copy2(item, backup / name)
            item.unlink()
    print('Old HTTPS integration archived privately: ' + str(backup))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["build", "init", "up", "stop", "backup", "status", "refresh", "watch", "upgrade", "rollback"])
    parser.add_argument("--image")
    parser.add_argument("--lock-fd", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--forward-pool", default="29000-29099")
    parser.add_argument("--data-pool", default="29100-29199")
    parser.add_argument("--reserved", type=int, default=10)
    args = parser.parse_args(argv)
    # Serialize lifecycle operations, including publication refresh.
    import fcntl
    if args.lock_fd is not None:
        inherited = os.fstat(args.lock_fd)
        actual = LOCK.stat()
        if (inherited.st_dev, inherited.st_ino) != (actual.st_dev, actual.st_ino) or not stat.S_ISREG(inherited.st_mode):
            raise RuntimeError('invalid inherited deployment lock')
        lock_context = os.fdopen(os.dup(args.lock_fd), 'a')
    else:
        lock_context = LOCK.open('a')
    with lock_context as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        saved = state()
        image = args.image or saved["image"]
        if args.action == "build":
            compose("build", "weroxy", image=image, timeout=1800)
        elif args.action == "init":
            initialize(args, image)
        elif args.action == "up":
            retire_old_https()
            if STATE.exists() and image != saved["image"]:
                raise RuntimeError("use upgrade to change the deployment image")
            was_running = bool(own_published_ports(image))
            old = {p: p.read_bytes() if p.exists() else None for p in (PUBLICATION, DATA / "host-port-plan.json")}
            print('Check entry and pool ports / 检查入口与端口池', flush=True)
            publication = prepare_publication(image)
            services = ("weroxy",)
            opened = []
            try:
                compose("up", "-d", "--no-build", *services, image=image)
                ready(image)
                print('Verify firewall and Docker ingress / 验证防火墙与 Docker 入站', flush=True)
                opened = port_plan.open_firewall(publication)
                port_plan.verify_ingress(publication, DATA)
                install_publication_timer()

            except Exception:
                with contextlib.suppress(Exception):
                    port_plan.close_firewall(opened)
                for path, body in old.items():
                    restore_file(path, body)
                with contextlib.suppress(Exception):
                    if was_running:
                        compose("up", "-d", "--no-build", *services, image=image)
                    else:
                        compose("stop", *services, image=image)
                raise
            save({**saved, "image": image})
        elif args.action == "status":
            compose("ps", image=image)
        elif args.action == "stop":
            pause_tasks()
            compose('stop', image=image)
        elif args.action == "backup":
            offline_backup(image)
        elif args.action == "refresh":
            refresh(image)
        elif args.action == "watch":
            # Release the lifecycle lock between bounded snapshots.
            fcntl.flock(lock, fcntl.LOCK_UN)
            while True:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    refresh(state()["image"])
                except (BlockingIOError, subprocess.SubprocessError, RuntimeError):
                    print("publication refresh unavailable", file=sys.stderr)
                finally:
                    fcntl.flock(lock, fcntl.LOCK_UN)
                time.sleep(30)
        elif args.action == "upgrade":
            if not args.image or image == saved["image"]:
                raise RuntimeError("upgrade requires a different immutable image tag or digest")
            target = json.loads(command(["docker", "image", "inspect", image], capture=True))[0]["Id"]
            cid = compose("ps", "-a", "-q", "weroxy", image=saved["image"], capture=True).strip()
            if not cid or "\n" in cid:
                raise RuntimeError("upgrade requires one existing Weroxy container")
            previous_info = json.loads(command(["docker", "inspect", cid], capture=True))[0]
            previous = previous_info["Image"]
            was_running = bool(previous_info.get("State", {}).get("Running"))
            if target == previous:
                raise RuntimeError("target is the current image")
            image = target
            saved = {**saved, "image": previous}
            compose("config", "--quiet", image=image)
            if os.geteuid() != 0:
                raise RuntimeError("upgrade requires root to preserve snapshot ownership")
            backup = ROOT / "rollback-data"
            if backup.exists():
                raise RuntimeError("archive rollback-data before upgrading")
            required = verify_data(DATA)
            if shutil.disk_usage(ROOT).free < required + 256 * 1024 ** 2:
                raise RuntimeError("insufficient space for snapshot and reserve")
            publication_files = {p: p.read_bytes() if p.exists() else None
                                 for p in (PUBLICATION, DATA / "host-port-plan.json")}
            compose("stop", "weroxy", image=saved["image"])
            # Database migrations can prevent old binaries reading upgraded data.
            # Keep a complete offline data snapshot and the old image identity.
            try:
                shutil.copytree(DATA, backup, copy_function=owned_copy)
                for source in [DATA, *(p for p in DATA.rglob("*") if p.is_dir())]:
                    target = backup / source.relative_to(DATA)
                    info = source.stat()
                    os.chown(target, info.st_uid, info.st_gid)
                backup.chmod(0o700)
            except Exception:
                if was_running:
                    compose("up", "-d", "--no-build", "weroxy", image=saved["image"])
                raise
            save({"image": image, "previous_image": saved["image"], "previous_running": was_running, "rollback_available": True})
            opened = []
            replacement_started = False
            try:
                retire_old_https()
                publication = prepare_publication(image)
                services = ("weroxy",)
                replacement_started = True
                compose("up", "-d", "--no-build", *services, image=image)
                ready(image)
                print('Verify firewall and Docker ingress / 验证防火墙与 Docker 入站', flush=True)
                opened = port_plan.open_firewall(publication)
                port_plan.verify_ingress(publication, DATA)
                install_publication_timer()

            except Exception:
                with contextlib.suppress(Exception):
                    port_plan.close_firewall(opened)
                if not replacement_started:
                    # No new executable has opened SQLite. Restore the original
                    # deployment without revoking untouched device credentials.
                    for path, body in publication_files.items():
                        restore_file(path, body)
                    backup.rename(ROOT / ("aborted-upgrade-snapshot-" + str(time.time_ns())))
                    save({"image": saved["image"]})
                    if was_running:
                        compose("up", "-d", "--no-build", "weroxy", image=saved["image"])
                        ready(saved["image"])
                    print("upgrade preflight failed; original image and unchanged data restored", file=sys.stderr)
                else:
                    print("upgrade failed; restoring old image and quarantined offline data", file=sys.stderr)
                    rollback(state())
                raise
        elif args.action == "rollback":
            rollback(saved)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit(130)
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as error:
        # Do not print subprocess output, passwords, or file contents.
        print("Deployment operation failed: " + (str(error) if isinstance(error, RuntimeError) else type(error).__name__), file=sys.stderr)
        raise SystemExit(1)
