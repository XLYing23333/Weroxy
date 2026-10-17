"""Bounded public release downloads and transactional managed updates."""
import contextlib
import fcntl
import hashlib
import json
import os
import pathlib
import platform
import re
import shutil
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request

API = 'https://api.github.com/repos/XLYing23333/Weroxy/releases/latest'
PREFIX = 'https://github.com/XLYing23333/Weroxy/releases/download/'


def version(value):
    if not re.fullmatch(r'v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', value):
        raise RuntimeError('Invalid stable release version')
    return tuple(int(n) for n in value.removeprefix('v').split('.'))


class Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urllib.parse.urlsplit(newurl)
        if target.scheme != 'https' or target.username or target.hostname not in {
            'github.com', 'api.github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com'
        }:
            raise RuntimeError('Unsafe release redirect')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def read(url, limit, output=None, timeout=10, cancel=None):
    request = urllib.request.Request(url, headers={'User-Agent': 'Weroxy-update'})
    started = time.monotonic()
    budget = 10 if output is None else 600
    with urllib.request.build_opener(Redirect()).open(request, timeout=timeout) as response:
        chunks = []; size = 0; digest = hashlib.sha256()
        while True:
            if time.monotonic() - started >= budget:
                raise RuntimeError('Release request exceeds time budget')
            if cancel is not None and cancel.is_set():
                raise RuntimeError("Update cancelled before installation")
            block = response.read1(65536)
            if not block:
                break
            size += len(block)
            if size > limit or time.monotonic() - started >= budget:
                raise RuntimeError('Release download exceeds budget')
            digest.update(block)
            if output is None:
                chunks.append(block)
            else:
                output.write(block)
        return (b''.join(chunks) if output is None else size), digest.hexdigest()


def check():
    raw, _ = read(API, 2 * 1024 ** 2)
    result = json.loads(raw)
    version(result['tag_name'])
    if result.get('draft') or result.get('prerelease') or result.get('html_url') != 'https://github.com/XLYing23333/Weroxy/releases/tag/' + result['tag_name']:
        raise RuntimeError('Invalid stable release')
    return result


def asset(release, name):
    matches = [a for a in release['assets'] if a['name'] == name]
    expected = PREFIX + release['tag_name'] + '/' + name
    if len(matches) != 1 or matches[0]['browser_download_url'] != expected or not 0 < matches[0]['size']:
        raise RuntimeError('Required release asset missing or invalid: ' + name)
    return matches[0]


def candidate_name(release):
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
    if arch is None:
        raise RuntimeError('No Server update package for this architecture')
    return 'weroxy-server_' + release['tag_name'].removeprefix('v') + '_linux_' + arch + '.release.tar.gz'


def download(release, target, cancel=None):
    name = candidate_name(release)
    manifest = asset(release, 'SHA256SUMS')
    if manifest['size'] > 1024 ** 2:
        raise RuntimeError('Checksum manifest too large')
    raw, _ = read(manifest['browser_download_url'], 1024 ** 2)
    hashes = {}
    for line in raw.decode().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([^\r\n]+)', line)
        if not match or match[2] in hashes:
            raise RuntimeError('Invalid checksum manifest')
        hashes[match[2]] = match[1]
    item = asset(release, name)
    if item['size'] > 1024 ** 3 or name not in hashes:
        raise RuntimeError('Invalid Server asset size or checksum')
    with target.open('xb') as stream:
        size, digest = read(item['browser_download_url'], 1024 ** 3, stream, timeout=30, cancel=cancel)
        stream.flush(); os.fsync(stream.fileno())
    if digest != hashes[name] or size != item['size']:
        raise RuntimeError('Server release SHA-256 or size mismatch')


def extract(source, target):
    with tarfile.open(source, 'r:gz') as archive:
        members = []; expanded = 0
        for member in archive:
            expanded += member.size
            if len(members) >= 100 or expanded > 2 * 1024 ** 3:
                raise RuntimeError('Expanded release exceeds budget')
            members.append(member)
        names = set()
        for member in members:
            parts = pathlib.PurePosixPath(member.name)
            if parts.is_absolute() or any(p in ('', '.', '..') for p in member.name.split('/')) or member.name in names or not (member.isfile() or member.isdir()):
                raise RuntimeError('Unsafe release archive entry')
            names.add(member.name)
        # Extract only prevalidated ordinary files into this fresh directory.
        for member in members:
            dest = target / member.name
            if member.isdir():
                dest.mkdir(parents=True, exist_ok=True)
            else:
                dest.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(member) as source_file, dest.open('xb') as output:
                    shutil.copyfileobj(source_file, output)
                dest.chmod(0o755 if member.name == 'manage' else 0o644)


def apply(console, release, args=None):
    console.prerequisites(network=False)
    console.secure_release_permissions()
    previous = console.PACKAGE / '.update-previous'
    if previous.exists():
        raise RuntimeError('Archive .update-previous before another update')
    with (console.ROOT / '.manage.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('Another management operation is running') from None
        with tempfile.TemporaryDirectory(prefix='.update-', dir=console.PACKAGE) as work:
            work = pathlib.Path(work)
            download(release, work / 'release.tar.gz', getattr(args, 'update_cancel', None))
            stage = work / 'release'; stage.mkdir()
            extract(work / 'release.tar.gz', stage)
            build = console.verify(stage)
            if version(build['version']) != version(release['tag_name']):
                raise RuntimeError('Release package version mismatch')
            cancel = getattr(args, 'update_cancel', None)
            if cancel is not None and cancel.is_set():
                raise RuntimeError('Update cancelled before installation')
            installing = getattr(args, 'update_installing', None)
            if installing is not None:
                installing.set()
            image = console.load_image(stage, build)
            # Keep the old manager and its manifest intact until all validation
            # has passed. The lifecycle engine separately snapshots offline data.
            files = [p.relative_to(stage) for p in stage.rglob('*') if p.is_file()]
            previous.mkdir(mode=0o700)
            absent = []
            upgraded = False
            try:
                for relative in files:
                    dest = console.PACKAGE / relative
                    if dest.exists():
                        old = previous / relative; old.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(dest, old)
                    else:
                        absent.append(relative)
                with console.critical_operation(), console.lifecycle_lock():
                    for relative in files:
                        dest = console.PACKAGE / relative; dest.parent.mkdir(parents=True, exist_ok=True)
                        pending = dest.with_name(dest.name + '.update-new')
                        shutil.copyfile(stage / relative, pending)
                        pending.chmod(0o755 if relative.as_posix() == 'manage' else 0o644)
                        pending.replace(dest)
                    console.invoke('upgrade', '--image', image)
                    upgraded = True
                    cid = console.core.compose('ps', '-q', 'weroxy', image=image, capture=True, timeout=10).strip()
                    reported = console.core.command(['docker', 'exec', cid, '/weroxy-Server', 'version'], capture=True, timeout=10)
                    if reported.splitlines()[:1] != ['weroxy-Server ' + build['version']]:
                        raise RuntimeError('Post-update Server version check failed')
                    print('Server updated to ' + build['version'] + '. Reopen manage to use the new manager.')
            except BaseException:
                if upgraded:
                    try:
                        with console.critical_operation(), console.lifecycle_lock():
                            console.invoke('rollback')
                    except BaseException as error:
                        raise RuntimeError('Post-update verification failed and rollback failed; retain .update-previous and rollback-data for recovery') from error
                for relative in files:
                    old = previous / relative
                    if old.is_file():
                        shutil.copy2(old, console.PACKAGE / relative)
                    elif relative in absent:
                        (console.PACKAGE / relative).unlink(missing_ok=True)
                shutil.rmtree(previous)
                raise


def execute(console, args):
    current = console.summary()['version']
    release = getattr(args, 'update_release', None) or check()
    print('Current: ' + current + '\nLatest: ' + release['tag_name'] + '\n' + release['html_url'])
    if version(release['tag_name']) <= version(current):
        print('No newer stable release available.'); return
    asset(release, candidate_name(release))
    if not getattr(args, 'update_confirmed', False):
        if input('Update interrupts Weroxy connections. Continue? [y/N] ').strip().lower() != 'y':
            print('Cancelled.'); return
    apply(console, release, args)
