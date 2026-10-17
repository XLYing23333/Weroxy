#!/usr/bin/env python3
"""Package a built Server Docker image with the verified interactive host manager."""
import argparse
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tarfile
import tempfile

REPO=pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'WeroxyServer/deploy/docker'))
import console


def run(*args):
    return subprocess.check_output(args,text=True).strip()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image',default='weroxy-server:0.5.0')
    parser.add_argument('--output',default=str(REPO/'dist/server/0.5.0'))
    parser.add_argument('--runtime-build',required=True,help='metadata for the already-built image')
    parser.add_argument('--runtime-source-manifest',required=True)
    args=parser.parse_args()
    subprocess.run([sys.executable,str(REPO/"scripts/third_party_notices.py"),"--check"],check=True)
    output=pathlib.Path(args.output).absolute();output.mkdir(parents=True,exist_ok=True)
    build=json.loads(pathlib.Path(args.runtime_build).read_text())
    image=json.loads(run('docker','image','inspect',args.image))[0]
    if image['Id'] not in {build['image_config_digest'],build.get('image_manifest_digest')} or image['Architecture']!=build['architecture'].split('/')[1]:
        raise SystemExit('Runtime build metadata and image identity differ')
    name='weroxy-server_'+build['version']+'_linux_'+image['Architecture']
    with tempfile.TemporaryDirectory(prefix='weroxy-package-',dir='/tmp') as tmp:
        stage=pathlib.Path(tmp)
        for relative in console.REQUIRED-{'BUILD.json'}:
            source=REPO/relative
            if relative=='THIRD_PARTY_NOTICES':source=REPO/'WeroxyServer/THIRD_PARTY_NOTICES'
            elif relative=='manage':source=REPO/'WeroxyServer/deploy/docker/manage'
            elif relative.startswith('deploy/'):source=REPO/'WeroxyServer/deploy/docker'/relative.removeprefix('deploy/')
            target=stage/relative;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,target)
        (stage/'manage').chmod(0o755)
        archive=name+'.docker.tar'
        subprocess.run(['docker','save','-o',str(stage/archive),args.image],check=True)
        with tarfile.open(stage/archive) as image_tar:
            manifest=json.load(image_tar.extractfile('manifest.json'))
            if len(manifest)!=1:raise SystemExit('Exactly one image required')
            config_digest='sha256:'+hashlib.sha256(image_tar.extractfile(manifest[0]['Config']).read()).hexdigest()
        inputs=''.join(console.checksum(stage/path)+'  '+path+'\n' for path in sorted(console.REQUIRED-{'BUILD.json'}))
        build={**build,'image_archive':archive,'package_format':2,
               'image_config_digest':config_digest,'image_manifest_digest':image['Id'],
               'deployment_manifest_sha256':hashlib.sha256(inputs.encode()).hexdigest(),
               'packaging_baseline_commit':run('git','-C',str(REPO),'rev-parse','HEAD'),
               'packaging_includes_uncommitted_changes':bool(run('git','-C',str(REPO),'status','--porcelain')),
               'remote_deployed':False}
        (stage/'BUILD.json').write_text(json.dumps(build,indent=2)+'\n')
        shutil.copyfile(args.runtime_source_manifest,stage/'SOURCE_SHA256SUMS')
        files=sorted(p for p in stage.rglob('*') if p.is_file())
        (stage/'SHA256SUMS').write_text(''.join(console.checksum(p)+'  '+p.relative_to(stage).as_posix()+'\n' for p in files))
        console.verify(stage)
        release=output/(name+'.release.tar.gz');pending=release.with_suffix('.new')
        with tarfile.open(pending,'w:gz') as tar:
            for path in sorted(stage.rglob('*')):
                info=tar.gettarinfo(str(path),arcname=path.relative_to(stage).as_posix())
                info.uid=info.gid=0;info.uname=info.gname='root'
                info.mode = 0o755 if path.is_dir() or path.relative_to(stage).as_posix() == 'manage' else 0o644
                if path.is_file():
                    with path.open('rb') as stream:tar.addfile(info,stream)
                else:tar.addfile(info)
        pending.replace(release)
        for name in ['BUILD.json','SOURCE_SHA256SUMS']:shutil.copyfile(stage/name,output/name)
        (output/'SHA256SUMS').write_text(''.join(console.checksum(output/name)+'  '+name+'\n' for name in ['BUILD.json','SOURCE_SHA256SUMS',release.name]))
        print('Release: '+str(release)+'\nSHA-256: '+console.checksum(release))


if __name__=='__main__':main()
