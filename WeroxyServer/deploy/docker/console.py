#!/usr/bin/env python3
"""Single command/TUI entry point for verified, host-managed deployments."""
import argparse
import contextlib
import fcntl
import getpass
import hashlib
import ipaddress
import functools
import urllib.request
import json
import locale
import os
import pathlib
import platform
import re
import shutil
import signal
import sqlite3
import stat
import subprocess
import sys
import tarfile
import threading
import time

import manage as core

ROOT = pathlib.Path(__file__).resolve().parent
PACKAGE = ROOT.parent
LOCK_FD = None
DEPLOY_FILES = ('compose.yaml', 'manage.py', 'console.py', 'tui.py', 'port_plan.py',
                'refresh-publication.py', 'firewall.compose.yaml',
                'weroxy-publication.service', 'README.md')
REQUIRED = {'manage', 'BUILD.json', 'README.md', 'README-CN.md', 'LICENSE', 'THIRD_PARTY_NOTICES', 'assets/BarLOGO.png',
            *('deploy/' + name for name in DEPLOY_FILES)}


def ordinary_file(base, name):
    parts = pathlib.PurePosixPath(name)
    if parts.is_absolute() or any(part in ('', '.', '..') for part in name.split('/')):
        raise RuntimeError('Unsafe release path / 发布包路径不合法')
    path = base
    for part in parts.parts:
        path = path / part
        if path.is_symlink():
            raise RuntimeError('Release symlinks are not allowed / 发布包不能包含符号链接')
    if not path.is_file():
        raise RuntimeError('Missing release file / 发布包文件缺失: ' + name)
    return path


def checksum(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def verify(package=PACKAGE):
    package = pathlib.Path(package).absolute()
    if package.is_symlink() or not package.is_dir():
        raise RuntimeError('An ordinary extracted package directory is required / 请提供已解压的普通目录')
    manifest = ordinary_file(package, 'SHA256SUMS')
    if manifest.stat().st_size > 65536:
        raise RuntimeError('Release manifest too large / 校验清单过大')
    names = set()
    for row in manifest.read_text().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([^\r\n]+)', row)
        if not match or match[2] in names or len(names) >= 64:
            raise RuntimeError('Invalid release manifest / 校验清单无效')
        digest, name = match.groups()
        path = ordinary_file(package, name)
        if checksum(path) != digest:
            raise RuntimeError('SHA-256 mismatch / SHA-256 不匹配: ' + name)
        names.add(name)
    if not REQUIRED <= names:
        raise RuntimeError('Incomplete release manifest / 校验清单不完整')
    build = json.loads(ordinary_file(package, 'BUILD.json').read_text())
    version = build.get('version', '')
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?', version):
        raise RuntimeError('Invalid release version / 发布版本无效')
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
    if build.get('architecture') != 'linux/' + str(arch):
        raise RuntimeError('Release architecture differs from host / 发布包架构与宿主机不同')
    image = build.get('image_config_digest', '')
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', image):
        raise RuntimeError('Invalid image identity / 镜像标识无效')
    archive = build.get('image_archive', 'weroxy-server_' + version + '_linux_' + str(arch) + '.docker.tar')
    if archive not in names or not archive.endswith('.docker.tar'):
        raise RuntimeError('Image missing from release manifest / 校验清单缺少镜像')
    build['image_archive'] = archive
    # Ignore runtime files outside this allowlist; all distributed code is checked.
    allowed = REQUIRED | {'SOURCE_SHA256SUMS', archive}
    if not names <= allowed:
        raise RuntimeError('Unexpected release files / 发布包包含不支持的文件')
    return build


def normalize_locale():
    """SSH locale names need not exist on the destination host."""
    for candidate in ('', 'C.UTF-8', 'C.utf8', 'C'):
        try:
            selected = locale.setlocale(locale.LC_ALL, candidate)
            # LC_ALL may describe several categories. Obtain a portable name.
            if candidate:
                os.environ['LC_ALL'] = candidate
                os.environ['LANG'] = candidate
            else:
                # Preserve the valid environment, including mixed categories.
                return selected
            return selected
        except locale.Error:
            continue
    raise RuntimeError('No usable locale found; check the Python/system locale installation')


def secure_release_permissions(package=None):
    """Repair only a verified standalone release, never source or live data."""
    package = pathlib.Path(package or PACKAGE).absolute()
    if os.geteuid() != 0:
        raise RuntimeError('Run sudo ./manage / 请使用 sudo ./manage')
    verify(package)
    # Never chown a home/source parent. A writable ancestor would allow the
    # root-managed deployment to be replaced after this check.
    for parent in package.parents:
        info = parent.lstat()
        sticky_root = info.st_uid == 0 and bool(info.st_mode & 0o1000)
        if parent.is_symlink() or info.st_uid != 0 or (info.st_mode & 0o022 and not sticky_root):
            raise RuntimeError('Unsafe parent directory: ' + str(parent) +
                               '. Extract the release into /opt/weroxy with sudo tar; parent directories are not modified.')
    names = [row.split('  ', 1)[1] for row in (package / 'SHA256SUMS').read_text().splitlines()]
    names.append('SHA256SUMS')
    files = [ordinary_file(package, name) for name in names]
    if any(path.lstat().st_nlink != 1 for path in files):
        raise RuntimeError('Release files must not be hard-linked; extract a fresh release')
    directories = {package}
    for path in files:
        directories.update(parent for parent in path.parents if parent == package or package in parent.parents)
    changed = False
    # Seal directories before touching individual files; do not traverse data,
    # backups, unknown files or any symlink.
    for path in sorted(directories, key=lambda item: len(item.parts)):
        mode = 0o700 if path == package else 0o755
        info = path.lstat()
        if path.is_symlink() or not path.is_dir():
            raise RuntimeError('Release directory changed during permission repair')
        if info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o7777 != mode:
            os.chown(path, 0, 0, follow_symlinks=False)
            os.chmod(path, mode)
            changed = True
    for path in files:
        mode = 0o755 if path == package / 'manage' else 0o644
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise RuntimeError('Ordinary release file required')
            if info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o7777 != mode:
                os.fchown(stream.fileno(), 0, 0)
                os.fchmod(stream.fileno(), mode)
                changed = True
    verify(package)
    return changed


def prerequisites(network=True):
    if os.geteuid() != 0:
        raise RuntimeError('Run sudo ./manage / 请使用 sudo ./manage')
    if sys.version_info < (3, 10):
        raise RuntimeError('Python 3.10+ required / 需要 Python 3.10 或以上')
    for name in ('docker', 'systemctl', 'ss'):
        if not shutil.which(name):
            raise RuntimeError('Missing host capability; see README / 缺少主机组件，请参阅 README: ' + {'docker': 'container runtime', 'systemctl': 'service manager', 'ss': 'port inspection'}[name])
    try:
        core.command(['docker', 'info'], capture=True, timeout=20)
    except subprocess.SubprocessError:
        raise RuntimeError('Container runtime unavailable; see README / 容器运行环境不可用，请参阅 README') from None
    try:
        core.command(['docker', 'compose', 'version'], capture=True, timeout=10)
    except subprocess.SubprocessError:
        raise RuntimeError('Install the required container orchestration plugin; see README / 请参阅 README 安装容器编排组件') from None
    try:
        core.command(['systemctl', 'show', '--property=Version'], capture=True, timeout=10)
    except subprocess.SubprocessError:
        raise RuntimeError('A running system service manager is required / 需要运行系统服务管理器的宿主机') from None
    if network:
        core.port_plan.check_firewall()
    # Automatic host integration must not be writable by the Server user.
    for path in (PACKAGE, ROOT):
        info = path.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError('Deployment directory is unsafe: ' + str(path) + '; use a verified release under /opt/weroxy / 请将正式发布包解压到 /opt/weroxy')
    if os.environ.get('COMPOSE_FILE', 'compose.yaml') not in ('compose.yaml',):
        raise RuntimeError('Managed deployment requires COMPOSE_FILE=compose.yaml / 请移除直接发布的 Compose 覆盖配置')
    if (ROOT / '.env').exists():
        raise RuntimeError('Remove legacy .env before managed installation / 请先归档旧的 .env，避免覆盖管理配置')


def invoke(action, *args):
    flags = [] if LOCK_FD is None else ['--lock-fd', str(LOCK_FD)]
    core.command([sys.executable, str(ROOT / 'manage.py'), action, *args, *flags],
                 capture=True, timeout=1800, pass_fds=() if LOCK_FD is None else (LOCK_FD,))


def archive_identity(package, build):
    with tarfile.open(package / build['image_archive']) as archive:
        def read(name, limit):
            if pathlib.PurePosixPath(name).is_absolute() or '..' in pathlib.PurePosixPath(name).parts:
                raise RuntimeError('Unsafe image archive / 镜像归档路径不合法')
            member = archive.getmember(name)
            if not member.isfile() or member.size > limit:
                raise RuntimeError('Invalid image metadata / 镜像元数据无效')
            return archive.extractfile(member).read()
        manifest = json.loads(read('manifest.json', 65536))
        if len(manifest) != 1:
            raise RuntimeError('Exactly one release image required / 发布包须包含单个镜像')
        config_bytes = read(manifest[0]['Config'], 1024 * 1024)
        if 'sha256:' + hashlib.sha256(config_bytes).hexdigest() != build['image_config_digest']:
            raise RuntimeError('Archive config identity differs / 归档 config 摘要与构建记录不同')
        config = json.loads(config_bytes)
        if config['architecture'] != build['architecture'].split('/')[1]:
            raise RuntimeError('Archive architecture differs / 镜像归档架构不符')
        tags = manifest[0].get('RepoTags') or []
        if not tags or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9./:_-]{0,255}', tags[0]):
            raise RuntimeError('Invalid archive image tag / 镜像归档标签无效')
        return tags[0], config


def load_image(package, build):
    reference, config = archive_identity(package, build)
    print('Import container image', flush=True)
    core.command(['docker', 'load', '-i', str(package / build['image_archive'])], capture=True, timeout=600)
    info = json.loads(core.command(['docker', 'image', 'inspect', reference], capture=True))[0]
    # Classic graphdriver uses config IDs; containerd uses manifest IDs. Both
    # are recorded, and actual runtime layers/config must also agree.
    identities = {build['image_config_digest'], build.get('image_manifest_digest')}
    if (info['Id'] not in identities or info['Architecture'] != config['architecture']
            or info['RootFS']['Layers'] != config['rootfs']['diff_ids']
            or any(info['Config'].get(key) != value for key, value in config['config'].items())):
        raise RuntimeError('Imported image identity differs / 导入镜像标识不符')
    return info['Id']


@functools.lru_cache(maxsize=1)
def server_ip():
    """Prefer a directly known public address; use a bounded NAT lookup last."""
    local = []
    candidates = [os.environ.get('WERXY_PUBLISH_IP', '')]
    connection = os.environ.get('SSH_CONNECTION', '').split()
    if len(connection) == 4:
        candidates.append(connection[2])
    try:
        interfaces = json.loads(core.command(['ip', '-j', 'address', 'show', 'scope', 'global'], capture=True, timeout=3))
        local = [row['local'] for interface in interfaces for row in interface.get('addr_info', []) if row.get('family') == 'inet']
        candidates.extend(local)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        pass
    for value in candidates:
        try:
            if ipaddress.ip_address(value).is_global:
                return value
        except ValueError:
            pass
    try:
        with urllib.request.urlopen('https://api.ipify.org', timeout=2) as response:
            value = response.read(65).decode('ascii').strip()
        if ipaddress.ip_address(value).is_global:
            return value
    except (OSError, ValueError, UnicodeError):
        pass
    for value in candidates:
        try:
            address = ipaddress.ip_address(value)
            if not address.is_unspecified and not address.is_loopback and not address.is_link_local:
                return value
        except ValueError:
            pass
    # Offline host with no discoverable interface: still use a real local address.
    return '127.0.0.1'


def web_url(port=9415):
    address = server_ip()
    if ':' in address:
        address = '[' + address + ']'
    return 'http://' + address + ':' + str(port)


def summary():
    value = {'version': '?', 'installed': (core.DATA / 'weroxy.db').is_file() and not (ROOT / '.uninstalled').exists(), 'health': '-', 'url': web_url()}
    try:
        value['version'] = json.loads((PACKAGE / 'BUILD.json').read_text())['version']
    except (OSError, ValueError, KeyError):
        pass
    if value['installed']:
        try:
            raw = core.compose('ps', '-q', 'weroxy', capture=True, image=core.state()['image'], timeout=5).strip()
            if raw:
                item = json.loads(core.command(['docker', 'inspect', raw], capture=True, timeout=5))[0]
                value['health'] = item['State'].get('Health', {}).get('Status', item['State']['Status'])
            else:
                value['health'] = 'stopped'
            if (core.DATA / 'host-port-plan.json').exists():
                plan = json.loads((core.DATA / 'host-port-plan.json').read_text())
                port = next(out for out, inside in plan['ports'] if inside == 9415)
                value['url'] = web_url(port)
        except (OSError, ValueError, KeyError, StopIteration, subprocess.SubprocessError):
            value['health'] = 'unavailable'
    return value


def setup_url():
    with sqlite3.connect('file:' + str(core.DATA / 'weroxy.db') + '?mode=ro', uri=True) as db:
        # The secret is a temporary credential; never include it in status or reports.
        if db.execute('SELECT COUNT(*) FROM administrators').fetchone()[0]:
            return
    secret = core.DATA / 'setup.secret'
    if secret.is_file():
        token = secret.read_text().strip()
        if re.fullmatch('[0-9a-f]{64}', token):
            print('Private setup URL: ' + summary()['url'] + '/init' + token)
            print('Open this URL to create your administrator. Do not share it.')


@contextlib.contextmanager
def critical_operation():
    # The TUI owns signal handling on the main thread while its worker executes.
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    previous = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


@contextlib.contextmanager
def lifecycle_lock():
    """Keep one lock across all child stages so timers cannot race restart/install."""
    global LOCK_FD
    with core.LOCK.open('a') as lock:
        deadline = time.monotonic() + 600
        announced = False
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if not announced:
                    print('Waiting for current host task / 等待当前宿主机任务安全完成', flush=True)
                    announced = True
                if time.monotonic() >= deadline:
                    raise RuntimeError('Host task still busy; retry later / 宿主机任务仍忙，请稍后重试')
                time.sleep(.1)
        LOCK_FD = lock.fileno()
        try:
            yield
        finally:
            LOCK_FD = None


def uninstall():
    """Remove this deployment's runtime integration, retaining user data."""
    units = []
    for name in core.deployment_tasks():
        for suffix in ('.timer', '.service'):
            unit = pathlib.Path('/etc/systemd/system') / (name + suffix)
            if unit.exists():
                if unit.is_symlink():
                    raise RuntimeError('Refusing to remove a symlinked deployment unit')
                if suffix == '.service' and str(ROOT) not in unit.read_text():
                    raise RuntimeError('Service ownership does not match this deployment')
                units.append(unit)
    print('Stop deployment tasks')
    core.pause_tasks()
    # Stop the Server first so no new firewall policy can race revocation.
    core.compose('stop', image=core.state()['image'], capture=True)
    if (core.DATA / 'weroxy.db').exists():
        core.revoke_managed_firewall()
    print('Remove deployment containers and network')
    core.compose('down', '--remove-orphans', image=core.state()['image'], capture=True)
    for unit in units:
        core.command(['systemctl', 'disable', '--now', unit.name], capture=True, timeout=30)
        unit.unlink()
    if units:
        core.command(['systemctl', 'daemon-reload'], capture=True, timeout=15)
    # Only delete explicitly tagged Weroxy rules matching this deployment's plan.
    # Shared HTTP/HTTPS rules and ports published by other containers are retained.
    planfile = core.DATA / 'host-port-plan.json'
    if shutil.which('ufw') and planfile.exists():
        plan = json.loads(planfile.read_text())
        ports = {int(port) for port, _ in plan['ports']} - {80, 443}
        other = core.command(['docker', 'ps', '-q'], capture=True).split()
        if other:
            containers = json.loads(core.command(['docker', 'inspect', *other], capture=True))
            for container in containers:
                for bindings in (container.get('NetworkSettings', {}).get('Ports') or {}).values():
                    ports.difference_update(int(row['HostPort']) for row in (bindings or []))
        owned = set(core.port_plan.spans(ports))
        status = core.command(['ufw', 'status', 'numbered'], capture=True, env={**os.environ, 'LC_ALL': 'C'})
        numbers = []
        for line in status.splitlines():
            match = re.match(r'\[\s*(\d+)\]\s+(\d+(?::\d+)?)/tcp(?:\s|$)', line)
            if match and match[2] in owned and line.partition('#')[2].strip() == 'Weroxy':
                numbers.append(int(match[1]))
        for number in sorted(numbers, reverse=True):
            core.command(['ufw', '--force', 'delete', str(number)], capture=True)
    marker = ROOT / '.uninstalled'
    marker.write_text('Runtime removed; data retained.\n')
    marker.chmod(0o600)
    print('Uninstalled. Data retained in ' + str(core.DATA))


def reset_password(username, password=None):
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', username or ''):
        raise RuntimeError('Invalid username / 用户名无效')
    if password is None and not sys.stdin.isatty():
        raise RuntimeError('Password reset requires a terminal / 重置密码需要终端')
    if password is None:
        password = getpass.getpass('New password: ')
    raw = password.encode()
    if not 6 <= len(raw) <= 1024:
        raise RuntimeError('Password must contain 6–1024 bytes')
    # Send via stdin, never through argv, environment or an on-disk credential file.
    result = subprocess.run(['docker', 'compose', '-f', str(ROOT / 'compose.yaml'),
                             'exec', '-T', 'weroxy', '/weroxy-Server', 'admin', 'reset-password',
                             '--data', '/data', '--username', username], cwd=ROOT, input=raw, check=True, timeout=60, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    del password, raw
    return result


ACTIONS = ('install', 'start', 'stop', 'restart', 'status', 'reset-password', 'uninstall', 'notices')


def execute(action, args):
    if action not in ACTIONS:
        raise RuntimeError('Unsupported management action: ' + action)
    if action == 'notices':
        with ordinary_file(PACKAGE, 'THIRD_PARTY_NOTICES').open(encoding='utf-8', newline='') as stream:
            text = stream.read()
        print(text, end='')
        return
    if action == 'status':
        state = summary()
        print('Version: ' + state['version'])
        print('Installation: ' + ('Installed' if state['installed'] else 'Not installed'))
        print('Container: ' + state['health'])
        print('Web: ' + state['url'])
        if (core.DATA / 'host-port-plan.json').exists():
            plan = json.loads((core.DATA / 'host-port-plan.json').read_text())
            print('Available ports: Forward ' + str(plan['forward_last']-plan['forward_first']+1-len(plan['unavailable_forward'])) + ' / Data ' + str(plan['data_last']-plan['data_first']+1-len(plan['unavailable_data'])))
        return
    if (PACKAGE / 'BUILD.json').is_file() and (PACKAGE / 'manage').is_file():
        if secure_release_permissions():
            print('Release permissions repaired automatically / 发布包权限已自动修正', flush=True)
    if action != 'install':
        prerequisites(network=action in ('start', 'restart'))
    with (ROOT / '.manage.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('Another management operation is running') from None
        if action == 'reset-password':
            if not (core.DATA / 'weroxy.db').is_file():
                raise RuntimeError('Install first')
            reset_password(args.username, getattr(args, 'password', None))
            print('Password reset successfully.')
            return
        with critical_operation(), lifecycle_lock():
            if action == 'uninstall':
                uninstall()
            elif action == 'install':
                print('Check release integrity', flush=True)
                build = verify()
                prerequisites()
                existing = (core.DATA / 'weroxy.db').exists()
                if existing and not (ROOT / '.uninstalled').exists():
                    raise RuntimeError('Already installed: use Start')
                host = os.environ.get('WERXY_PUBLISH_IP', '0.0.0.0')
                for key, default in [('LEGACY',4900),('CONTROL',29999),('WEB',9415)]:
                    port = int(os.environ.get('WERXY_'+key+'_HOST_PORT', str(default)))
                    if not 1 <= port <= 65535 or not core.port_plan.host_port_free(host, port):
                        raise RuntimeError('Required entry port occupied: ' + str(port))
                image = load_image(PACKAGE, build)
                if not existing:
                    print('Initialize data', flush=True)
                    invoke('init', '--image', image)
                print('Start and check ingress', flush=True)
                invoke('up')
                (ROOT / '.uninstalled').unlink(missing_ok=True)
                print('Installed successfully. Web: ' + summary()['url'])
                setup_url()
            else:
                if not (core.DATA / 'weroxy.db').is_file() or (ROOT / '.uninstalled').exists():
                    raise RuntimeError('Install first')
                if action in ('start', 'restart'):
                    print('Check release integrity', flush=True)
                    build = verify()
                    _, config = archive_identity(PACKAGE, build)
                    info = json.loads(core.command(['docker', 'image', 'inspect', core.state()['image']], capture=True))[0]
                    if (info['Id'] not in {build['image_config_digest'], build.get('image_manifest_digest')}
                            or info['RootFS']['Layers'] != config['rootfs']['diff_ids']
                            or any(info['Config'].get(key) != value for key, value in config['config'].items())):
                        raise RuntimeError('Installed image differs from this release; complete the backed-up upgrade first')
                if action == 'start':
                    invoke('up')
                elif action == 'stop':
                    invoke('stop')
                elif action == 'restart':
                    invoke('stop')
                    invoke('up')
                print(action.capitalize() + ' completed successfully.')
                if action in ('start', 'restart'):
                    print('Web: ' + summary()['url'])
                    setup_url()


def parser():
    value = argparse.ArgumentParser(description='WeroxyServer terminal manager')
    value.add_argument('action', nargs='?', choices=ACTIONS)
    value.add_argument('--username', help='administrator username for password reset')
    value.add_argument('--lang', choices=['en'], default='en')
    return value


def main():
    normalize_locale()
    value = parser()
    args = value.parse_args()
    if not args.action:
        if not sys.stdin.isatty() or not sys.stdout.isatty() or os.environ.get('TERM', '') in ('', 'dumb'):
            value.print_help()
            return
        import tui
        notice = ''
        if (PACKAGE / 'BUILD.json').is_file() and (PACKAGE / 'manage').is_file():
            if secure_release_permissions():
                notice = 'Release ownership and permissions repaired automatically.'
        tui.run(args.lang, notice=notice)
    else:
        execute(args.action, args)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\nCancelled / 已取消', file=sys.stderr)
        raise SystemExit(130)
    except (OSError, RuntimeError, ValueError, KeyError, tarfile.TarError, sqlite3.Error, subprocess.SubprocessError) as error:
        # No subprocess output or sensitive application data in error reports.
        print(str(error) if isinstance(error, RuntimeError) else 'Operation failed / 操作失败: ' + type(error).__name__, file=sys.stderr)
        raise SystemExit(1)
