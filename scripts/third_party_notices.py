#!/usr/bin/env python3
"""Generate/check offline notices from pinned dependencies and upstream license texts.

--update reads local Go/npm caches and fetches two missing upstream artifacts.
Default/--check needs no network or dependency installation.
"""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / 'legal/third_party.json'
COMPONENTS = ('WeroxyServer', 'WeroxyClient')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def inputs():
    files = [f'{c}/go.mod' for c in COMPONENTS] + [f'{c}/go.sum' for c in COMPONENTS]
    files += ['WeroxyServer/web/package.json', 'WeroxyServer/web/package-lock.json']
    return {f: digest((ROOT / f).read_bytes()) for f in files}


def go_requirements(component):
    # All declared direct/indirect modules, including platform-specific dependencies.
    return re.findall(r'^\s*(?:require\s+)?([^\s()]+\.[^\s()]+)\s+(v[^\s]+)',
                      (ROOT / component / 'go.mod').read_text(), re.M)


def legal_files(directory):
    found = []
    for p in sorted(directory.iterdir()):
        if p.is_file() and re.match(r'(?i)^(licen[cs]e|copying|copyright|notice|patents|third.?party)', p.name):
            found.append((p.name, p.read_bytes()))
    return found


def fetch(url):
    if not url.startswith(('https://registry.npmjs.org/', 'https://raw.githubusercontent.com/')):
        raise RuntimeError('Unexpected upstream source')
    with urllib.request.urlopen(url, timeout=40) as response:
        return response.read(32 * 1024 * 1024 + 1)


def update():
    go = os.environ.get('GO') or shutil.which('go')
    if not go:
        raise RuntimeError('Set GO to the pinned Go executable')
    env = json.loads(subprocess.check_output([go, 'env', '-json', 'GOMODCACHE', 'GOROOT'], text=True))
    documents, packages = {}, []

    def record(ecosystem, name, version, scopes, files, source, **extra):
        if not files:
            raise RuntimeError(f'No license evidence for {name}@{version}')
        refs = []
        for filename, raw in files:
            # Fail rather than silently replacing invalid bytes in copyright notices.
            text = raw.decode('utf-8-sig')
            key = digest(raw)
            documents[key] = {'text': text, 'sha256_utf8': digest(text.encode())}
            refs.append({'file': filename, 'document': key})
        packages.append(dict(ecosystem=ecosystem, name=name, version=version,
                             scopes=sorted(scopes), source=source, files=refs, **extra))

    mods = {}
    for c in COMPONENTS:
        for name, version in go_requirements(c):
            mods.setdefault((name, version), []).append(c)
    for (name, version), scopes in sorted(mods.items()):
        escaped = ''.join('!' + c.lower() if c.isupper() else c for c in name)
        directory = Path(env['GOMODCACHE']) / (escaped + '@' + version)
        record('go', name, version, scopes, legal_files(directory),
               'https://' + name, license='See upstream license texts', evidence='module-cache')

    goroot = Path(env['GOROOT'])
    version = (goroot / 'VERSION').read_text().splitlines()[0]
    files = [(n, (goroot/n).read_bytes()) for n in ['LICENSE', 'PATENTS']]
    # Vendor licenses cover components in the standard library. Compiler-only
    # dependencies remain in the build toolchain rather than the installed app.
    for p in sorted((goroot/'src/vendor').rglob('*')):
        if p.is_file() and p.name in ('LICENSE', 'PATENTS', 'NOTICE'):
            files.append((p.relative_to(goroot).as_posix(), p.read_bytes()))
    record('toolchain', 'Go runtime and standard library', version, list(COMPONENTS),
           files, 'https://go.dev/LICENSE', license='BSD-3-Clause and bundled notices', evidence='pinned-toolchain')

    web = ROOT / 'WeroxyServer/web'
    locked = json.loads((web/'package-lock.json').read_text())['packages']
    for path, entry in sorted(locked.items()):
        if not path:
            continue
        name = path.split('node_modules/')[-1]
        directory = web / path
        files = legal_files(directory) if directory.is_dir() else []
        evidence = 'locked-package'
        source = entry['resolved']
        if directory.is_dir():
            pkg = json.loads((directory/'package.json').read_text())
            if pkg['version'] != entry['version'] or (pkg['name'] != name and entry.get('name') != pkg['name']):
                raise RuntimeError(f'Installed dependency differs from lock: {name}')
        if not files and name.startswith(('@esbuild/', '@rollup/rollup-')):
            # Platform binary packages omit LICENSE; the same-version parent
            # distribution provides the upstream core and bundled licenses.
            parent = 'esbuild' if name.startswith('@esbuild/') else 'rollup'
            parent_entry = locked['node_modules/'+parent]
            if parent_entry['version'] != entry['version']:
                raise RuntimeError('Platform package version mismatch')
            files = legal_files(web/'node_modules'/parent)
            evidence = 'same-version-parent-license: '+parent+'@'+entry['version']
        if not files and name == '@vue/devtools-api' and entry['version'] == '6.6.4':
            source = 'https://raw.githubusercontent.com/vuejs/devtools-v6/v6.6.4/LICENSE'
            files = [('LICENSE', fetch(source))]
            evidence = 'upstream-release-tag'
        if not files and name == 'fsevents':
            raw = fetch(source)
            algorithm, expected = entry['integrity'].split('-', 1)
            if base64.b64encode(hashlib.new(algorithm, raw).digest()).decode() != expected:
                raise RuntimeError('npm tarball integrity mismatch')
            with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
                for item in archive.getmembers():
                    if item.isfile() and re.match(r'(?i)^(license|notice|copying)', Path(item.name).name):
                        files.append((item.name, archive.extractfile(item).read()))
            evidence = 'lock-integrity-verified-tarball'
        if not files and name in ('lodash-unified', '@napi-rs/lzma-linux-x64-gnu'):
            # These publishers supply an SPDX expression but no full license
            # file. Preserve that evidence; never invent their copyright text.
            if not directory.is_dir():
                raise RuntimeError('Metadata-only package must be installed')
            metadata = {k: pkg[k] for k in ('name','version','license','author','repository') if k in pkg}
            note = ('UPSTREAM LICENSE TEXT NOT PROVIDED\n'
                    'The published package declares the license below but does not supply\n'
                    'a full license/copyright text. This is metadata, not a reconstructed license.\n\n'
                    + json.dumps(metadata, ensure_ascii=False, indent=2)+'\n')
            files = [('PUBLISHER-METADATA', note.encode())]
            evidence = 'metadata-only; full upstream license text missing'
        record('npm', name, entry['version'], ['WeroxyServer'], files, source,
               license=entry['license'], integrity=entry['integrity'], evidence=evidence,
               usage='Web build/platform optional dependency' if entry.get('dev') else 'Web dependency',
               optional=entry.get('optional', False), published_name=entry.get('name', name))

    data = dict(schema=1, inputs=inputs(), packages=packages, documents=documents)
    MANIFEST.write_text(json.dumps(data, ensure_ascii=False, indent=2)+'\n')
    return data


def render(data, component=None):
    packages = [p for p in data['packages'] if component is None or component in p['scopes']]
    title = component or 'Weroxy (all components)'
    chunks = [f'{title} — THIRD-PARTY NOTICES\n',
              'Generated by scripts/third_party_notices.py from pinned dependency versions.\n'
              'Includes direct/indirect Go modules, Go runtime/standard-library notices,\n'
              'and (for Server) every npm lock entry, including build and optional platform packages.\n'
              'Listing a build/platform dependency does not imply it executes in the installed app.\n'
              'Upstream bundled notices are retained; individual source-file headers are not a separate inventory.\n'
              'External OS packages and optional host tools are provided by the operating system.\n'
              'Each license document appears once below, referenced by its identifier.\n'
              'Noise: Flynn® is a trademark of Prime Directive, Inc.\n']
    chunks.append("\nDependency input SHA-256:\n")
    for path, value in sorted(data['inputs'].items()):
        chunks.append(value+"  "+path+"\n")
    used = {}
    for p in packages:
        chunks.append(f'\n[{p["ecosystem"]}] {p["name"]}@{p["version"]}\n'
                      f'Components: {", ".join(p["scopes"])}\n'
                      f'License: {p["license"]}\nSource: {p["source"]}\n'
                      f'Evidence: {p["evidence"]}\n')
        if p.get('published_name', p['name']) != p['name']:
            chunks.append('Published package name: '+p['published_name']+'\n')
        if 'usage' in p:
            chunks.append(f'Usage: {p["usage"]}; optional: {p["optional"]}\n')
        for ref in p['files']:
            key = ref['document']
            chunks.append(f'  {ref["file"]} -> document {key}\n')
            used.setdefault(key, []).append(f'{p["name"]}@{p["version"]}: {ref["file"]}')
    for key, owners in used.items():
        text = data['documents'][key]['text']
        chunks.append('\n'+'='*72+'\nDOCUMENT '+key+'\n'+ '\n'.join(owners)+'\n'+'-'*72+'\n'+text)
        if not text.endswith('\n'):
            chunks.append('\n')
    return ''.join(chunks).encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--update', action='store_true')
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    data = update() if args.update else json.loads(MANIFEST.read_text())
    if data['inputs'] != inputs():
        raise RuntimeError('Dependency locks changed; regenerate and review third-party notices')
    for item in data['documents'].values():
        if item['sha256_utf8'] != digest(item['text'].encode()):
            raise RuntimeError('License evidence hash mismatch')
    outputs = {ROOT/'THIRD_PARTY_NOTICES': render(data)}
    outputs.update({ROOT/c/'THIRD_PARTY_NOTICES': render(data,c) for c in COMPONENTS})
    for p, content in outputs.items():
        if args.update:
            p.write_bytes(content)
        elif p.read_bytes() != content:
            raise RuntimeError('Outdated notices: '+p.relative_to(ROOT).as_posix())
    missing = [p['name'] for p in data['packages'] if p['evidence'].startswith('metadata-only')]
    print(f'Notices checked: {len(data["packages"])} components/packages, {len(data["documents"])} legal evidence documents.')
    if missing:
        print('Upstream full license text missing (publisher metadata preserved): '+', '.join(missing))


if __name__ == '__main__':
    main()
