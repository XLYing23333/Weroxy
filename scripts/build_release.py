#!/usr/bin/env python3
"""Build v0.4.x assets from a clean commit; never deploy or publish them."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run(*args, cwd=ROOT, env=None, capture=False):
    return subprocess.check_output(args, cwd=cwd, env=env, text=True).strip() if capture else subprocess.run(args, cwd=cwd, env=env, check=True)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2)+'\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('version')
    args = parser.parse_args()
    version = args.version
    if not re.fullmatch(r'\d+\.\d+\.\d+',version):
        parser.error('Use a stable semantic version without v')
    if run('git','ls-files','Docs','tests',capture=True):
        raise SystemExit('Docs and tests are user-designated local-only paths; remove them from Git before release')
    if run('git','status','--porcelain',capture=True):
        raise SystemExit('Commit source changes before building a release')
    commit = run('git','rev-parse','HEAD',capture=True)
    epoch = run('git','show','-s','--format=%ct','HEAD',capture=True)
    go = os.environ.get('GO_BIN','go')
    env = dict(os.environ, SOURCE_DATE_EPOCH=epoch, CGO_ENABLED='0', GOTOOLCHAIN='local', GOOS='linux', GOARCH='amd64', GOAMD64='v1')
    output = ROOT/'dist/github'/version
    if output.exists():
        raise SystemExit('Release output already exists: '+str(output))
    output.mkdir(parents=True)
    run(sys.executable,'scripts/third_party_notices.py','--check')
    # Build from npm lock without changing dependencies or using lifecycle scripts.
    run('npm','ci','--ignore-scripts','--no-audit','--no-fund',cwd=ROOT/'WeroxyServer/web')
    run('npm','run','typecheck',cwd=ROOT/'WeroxyServer/web')
    run('npm','run','build',cwd=ROOT/'WeroxyServer/web')
    if run('git','status','--porcelain',capture=True):
        raise SystemExit('Build changed tracked sources; review and commit before releasing')
    names = run('git','ls-files',capture=True).splitlines()
    source = ''.join(sha(ROOT/n)+'  '+n+'\n' for n in names if (ROOT/n).is_file())
    (output/'SOURCE_SHA256SUMS').write_text(source)
    with tempfile.TemporaryDirectory(prefix='weroxy-public-release-') as temp:
        stage = Path(temp)
        run(go,'build','-trimpath','-buildvcs=false','-ldflags',f'-s -w -X weroxy/server/internal/buildinfo.Version={version}',
            '-o',str(stage/'weroxy-Server'),'./cmd/weroxy-Server',cwd=ROOT/'WeroxyServer',env=env)
        shutil.copyfile(ROOT/'WeroxyServer/THIRD_PARTY_NOTICES',stage/'THIRD_PARTY_NOTICES')
        (stage/'Dockerfile').write_text('FROM scratch\nCOPY weroxy-Server /weroxy-Server\nCOPY THIRD_PARTY_NOTICES /THIRD_PARTY_NOTICES\nUSER 10001:10001\nENTRYPOINT ["/weroxy-Server"]\nCMD ["run"]\n')
        image='weroxy-server:'+version
        run('docker','build','--platform=linux/amd64','-t',image,str(stage))
        info=json.loads(run('docker','image','inspect',image,capture=True))[0]
        build=dict(version=version,baseline_commit=commit,includes_uncommitted_changes=False,
                   architecture='linux/amd64',image_config_digest=info['Id'],image_manifest_digest=info['Id'],
                   go_version=run(go,'version',capture=True),node_version=run('node','--version',capture=True),
                   built_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),remote_deployed=False,
                   source_manifest_sha256=sha(output/'SOURCE_SHA256SUMS'),binary_sha256=sha(stage/'weroxy-Server'))
        write_json(stage/'BUILD.json',build)
        run(sys.executable,'WeroxyServer/deploy/package.py','--image',image,'--output',str(stage/'server'),
            '--runtime-build',str(stage/'BUILD.json'),'--runtime-source-manifest',str(output/'SOURCE_SHA256SUMS'))
        for p in (stage/'server').glob('*.release.tar.gz'):
            shutil.copyfile(p,output/p.name)
        shutil.copyfile(stage/'server/BUILD.json',output/'SERVER_BUILD.json')
    run('bash','WeroxyClient/deploy/package.sh',version,env=dict(env,GO_BIN=go))
    client = ROOT/'dist/client'/version
    for p in client.iterdir():
        if p.suffix in ('.deb','.rpm','.zst'):
            shutil.copyfile(p,output/p.name)
    shutil.copyfile(client/'BUILD.json',output/'CLIENT_BUILD.json')
    # Bundles retain package-manager ownership; no parallel tar-based installer.
    for arch in ('amd64','arm64'):
        name=f'weroxy-client_{version}_{arch}.deb'
        with tempfile.TemporaryDirectory(prefix='weroxy-client-bundle-') as temp:
            stage=Path(temp)
            shutil.copyfile(output/name,stage/name)
            for source_name in ('LICENSE','WeroxyClient/THIRD_PARTY_NOTICES','WeroxyClient/deploy/INSTALL.md','INSTALL_AGENT.md'):
                shutil.copyfile(ROOT/source_name,stage/Path(source_name).name)
            (stage/'SHA256SUMS').write_text(''.join(sha(p)+'  '+p.name+'\n' for p in sorted(stage.iterdir())))
            with tarfile.open(output/f'weroxy-client_{version}_linux_{arch}.tar.gz','w:gz') as archive:
                for p in sorted(stage.iterdir()):
                    info=archive.gettarinfo(str(p),arcname=p.name)
                    info.uid=info.gid=0;info.uname=info.gname='root';info.mtime=int(epoch);info.mode=0o644
                    with p.open('rb') as stream:
                        archive.addfile(info,stream)
    shutil.copyfile(ROOT/'INSTALL_AGENT.md',output/'INSTALL_AGENT.md')
    shutil.copyfile(ROOT/'THIRD_PARTY_NOTICES',output/'THIRD_PARTY_NOTICES')
    (output/'SHA256SUMS').write_text(''.join(sha(p)+'  '+p.name+'\n' for p in sorted(output.iterdir()) if p.is_file()))
    print('Built release assets from '+commit+' in '+str(output))


if __name__=='__main__':
    main()
