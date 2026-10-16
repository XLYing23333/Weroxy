#!/usr/bin/env python3
"""Create native packages from static build inputs; only build tooling uses Python."""
import pathlib,subprocess,sys,shutil,os,hashlib,json,tarfile,io
version=sys.argv[1];epoch=int(sys.argv[2]);uid=int(sys.argv[3]);gid=int(sys.argv[4])
root=pathlib.Path('/work');out=pathlib.Path('/out');deploy=pathlib.Path('/deploy')
def run(*args):subprocess.run(args,check=True,stdout=subprocess.DEVNULL)
manifest=[]
for arch,rpmarch in [('amd64','x86_64'),('arm64','aarch64')]:
 stage=root/('stage-'+arch)
 for path in ['usr/bin','usr/lib/systemd/system','usr/share/doc/weroxy-client']: (stage/path).mkdir(parents=True)
 shutil.copy(root/('weroxy-client-'+arch),stage/'usr/bin/weroxy-client')
 shutil.copy(deploy/'weroxycli.service',stage/'usr/lib/systemd/system/weroxycli.service')
 for n in ['INSTALL.md','LICENSE','THIRD_PARTY_NOTICES']:shutil.copy((root if n in ['LICENSE','THIRD_PARTY_NOTICES'] else deploy)/n,stage/'usr/share/doc/weroxy-client'/n)
 for p in stage.rglob('*'):
  p.chmod(0o755 if p.is_dir() or p.name=='weroxy-client' else 0o644);os.utime(p,(epoch,epoch))
 deb=root/('deb-'+arch);shutil.copytree(stage,deb);control=deb/'DEBIAN';control.mkdir()
 (control/'control').write_text(f'Package: weroxy-client\nVersion: {version}\nArchitecture: {arch}\nSection: net\nPriority: optional\nMaintainer: Weroxy contributors\nDepends: systemd, passwd, util-linux\nDescription: Weroxy native TCP tunnel client with terminal configuration\n')
 (control/'postinst').write_text((deploy/'package-postinstall.sh').read_text())
 (control/'prerm').write_text('#!/bin/sh\ncase "$1" in remove|deconfigure)\n'+(deploy/'package-preremove.sh').read_text().split('\n',1)[1]+'\n;; esac\n')
 (control/'postrm').write_text('#!/bin/sh\nif [ -d /run/systemd/system ]; then systemctl daemon-reload; fi\n')
 for p in control.iterdir():p.chmod(0o644 if p.name=='control' else 0o755);os.utime(p,(epoch,epoch))
 run('dpkg-deb','-Zgzip','--build','--root-owner-group',str(deb),str(out/f'weroxy-client_{version}_{arch}.deb'))
 top=root/('rpm-'+arch)
 for p in ['BUILD','BUILDROOT','RPMS','SOURCES','SPECS','SRPMS','DB']:(top/p).mkdir(parents=True)
 rpmver=version.replace('-','.')
 spec=f'''Name: weroxy-client
Version: {rpmver}
Release: 1
Summary: Weroxy native TCP tunnel client
License: Apache-2.0
Requires: systemd, shadow-utils, util-linux
AutoReqProv: no
%description
Native client with terminal configuration. Configuration and credentials are preserved on removal.
%prep
%build
%install
mkdir -p %{{buildroot}}
cp -a {stage}/usr %{{buildroot}}/
%post
{(deploy/'package-postinstall.sh').read_text().split(chr(10),1)[1]}
%preun
if [ "$1" = 0 ]; then
{(deploy/'package-preremove.sh').read_text().split(chr(10),1)[1]}
fi
%postun
if [ -d /run/systemd/system ]; then systemctl daemon-reload; fi
%files
%defattr(-,root,root,-)
/usr/bin/weroxy-client
/usr/lib/systemd/system/weroxycli.service
/usr/share/doc/weroxy-client
'''
 (top/'SPECS/client.spec').write_text(spec)
 run('rpmbuild','--target',rpmarch,'--define',f'_topdir {top}','--define',f'_dbpath {top}/DB','--define','_binary_payload w9.gzdio','--define','_build_id_links none','--define','__os_install_post %{nil}','--define',f'_buildhost weroxy-builder','-bb',str(top/'SPECS/client.spec'))
 for p in (top/'RPMS').rglob('*.rpm'):shutil.copy(p,out/p.name)
 if arch=='amd64':
  pkg=out/f'weroxy-client-{version}-1-x86_64.pkg.tar.zst';work=root/'arch';shutil.copytree(stage,work)
  (work/'.PKGINFO').write_text(f'pkgname = weroxy-client\npkgbase = weroxy-client\npkgver = {version.replace("-",".")}-1\npkgdesc = Weroxy native TCP tunnel client\nbuilddate = {epoch}\npackager = Weroxy contributors\nsize = {sum(p.stat().st_size for p in stage.rglob("*") if p.is_file())}\narch = x86_64\nlicense = Apache\ndepend = systemd\ndepend = shadow\ndepend = util-linux\n')
  # Pacman executes install functions in a shell; share identical package hooks.
  post=(deploy/'package-postinstall.sh').read_text().split('\n',1)[1].replace('set -eu','')
  pre=(deploy/'package-preremove.sh').read_text().split('\n',1)[1].replace('set -eu','')
  (work/'.INSTALL').write_text('post_install() {\n'+post+'\n}\npost_upgrade() { post_install; }\npre_remove() {\n'+pre+'\n}\npost_remove() { [ ! -d /run/systemd/system ] || systemctl daemon-reload; }\n')
  tar=root/'arch.tar'
  with tarfile.open(tar,'w',format=tarfile.PAX_FORMAT) as f:
   for p in sorted(work.rglob('*')):
    info=f.gettarinfo(str(p),str(p.relative_to(work)));info.uid=info.gid=0;info.uname=info.gname='root';info.mtime=epoch
    if p.is_file():
     with p.open('rb') as fp:f.addfile(info,fp)
    else:f.addfile(info)
  run('zstd','-q','-19',str(tar),'-o',str(pkg))
for p in sorted(out.iterdir()):
 if p.suffix not in ['.deb','.rpm','.zst']:continue
 manifest.append({'file':p.name,'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'client_version':version});os.chown(p,uid,gid)
(out/'SHA256SUMS').write_text(''.join(f'{p["sha256"]}  {p["file"]}\n' for p in manifest));(out/'manifest.json').write_text(json.dumps({'version':version,'packages':manifest},indent=2)+'\n')
for p in ['SHA256SUMS','manifest.json']:os.chown(out/p,uid,gid)
