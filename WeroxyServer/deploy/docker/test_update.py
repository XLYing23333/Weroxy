import contextlib
import types
import io
import pathlib
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import update


class UpdateTest(unittest.TestCase):
    def test_versions_and_exact_assets(self):
        self.assertGreater(update.version('v0.10.0'), update.version('0.9.9'))
        for value in ['0.5', 'v01.2.3', '0.5.0-rc1']:
            with self.assertRaises(RuntimeError): update.version(value)
        release = {'tag_name':'v0.5.0','assets':[{'name':'x','size':1,'browser_download_url':update.PREFIX+'v0.5.0/x'}]}
        update.asset(release, 'x')
        release['assets'][0]['browser_download_url']='https://example.com/x'
        with self.assertRaises(RuntimeError): update.asset(release, 'x')

    def test_extract_rejects_links_traversal_and_duplicates(self):
        for name, kind in [('../escape',tarfile.REGTYPE),('link',tarfile.SYMTYPE),('/absolute',tarfile.REGTYPE)]:
            with tempfile.TemporaryDirectory() as work:
                root=pathlib.Path(work); source=root/'a.tar.gz'; target=root/'out';target.mkdir()
                with tarfile.open(source,'w:gz') as tar:
                    info=tarfile.TarInfo(name);info.type=kind;info.linkname='/etc/passwd';tar.addfile(info)
                with self.assertRaises(RuntimeError):update.extract(source,target)
                self.assertEqual(list(target.iterdir()),[])

    def test_bad_checksum_stops_before_install(self):
        release={'tag_name':'v0.5.0','assets':[]}
        name='weroxy-server_0.5.0_linux_amd64.release.tar.gz'
        for n,size in [('SHA256SUMS',80),(name,3)]:release['assets'].append({'name':n,'size':size,'browser_download_url':update.PREFIX+'v0.5.0/'+n})
        def read(url,limit,output=None,timeout=10,cancel=None):
            if output is None:return (('0'*64+'  '+name+'\n').encode(),'')
            output.write(b'bad');return 3,'1'*64
        with tempfile.TemporaryDirectory() as work,patch('update.platform.machine',return_value='x86_64'),patch('update.read',side_effect=read):
            with self.assertRaisesRegex(RuntimeError,'SHA-256'):update.download(release,pathlib.Path(work)/'package')

    def test_failed_lifecycle_restores_manager_and_removes_new_files(self):
        with tempfile.TemporaryDirectory() as work:
            package=pathlib.Path(work);root=package/'deploy';root.mkdir()
            (root/'manage.py').write_text('old manager')
            def extract(source,stage):
                (stage/'deploy').mkdir()
                (stage/'deploy/manage.py').write_text('new manager')
                (stage/'new-only').write_text('candidate')
            def fail(*args):raise RuntimeError('simulated lifecycle failure')
            console=types.SimpleNamespace(PACKAGE=package,ROOT=root,
                prerequisites=lambda **kwargs:None,secure_release_permissions=lambda:None,
                verify=lambda stage:{'version':'0.5.0'},load_image=lambda *args:'sha256:new',
                critical_operation=contextlib.nullcontext,lifecycle_lock=contextlib.nullcontext,invoke=fail)
            with patch('update.download'),patch('update.extract',side_effect=extract):
                with self.assertRaisesRegex(RuntimeError,'lifecycle failure'):
                    update.apply(console,{'tag_name':'v0.5.0'})
            self.assertEqual((root/'manage.py').read_text(),'old manager')
            self.assertFalse((package/'new-only').exists())
            self.assertFalse((package/'.update-previous').exists())

    def test_post_install_version_failure_rolls_back_and_preserves_recovery_on_failure(self):
        for rollback_fails in [False,True]:
            with self.subTest(rollback_fails=rollback_fails),tempfile.TemporaryDirectory() as work:
                package=pathlib.Path(work);root=package/'deploy';root.mkdir()
                (root/'manage.py').write_text('old manager')
                def extract(source,stage):
                    (stage/'deploy').mkdir();(stage/'deploy/manage.py').write_text('new manager')
                actions=[]
                def invoke(action,*args):
                    actions.append(action)
                    if action=='rollback' and rollback_fails:raise RuntimeError('simulated rollback failure')
                core=types.SimpleNamespace(compose=lambda *a,**kw:'cid',command=lambda *a,**kw:'weroxy-Server 0.0.0\n')
                console=types.SimpleNamespace(PACKAGE=package,ROOT=root,core=core,
                    prerequisites=lambda **kwargs:None,secure_release_permissions=lambda:None,
                    verify=lambda stage:{'version':'0.5.0'},load_image=lambda *a:'sha256:new',
                    critical_operation=contextlib.nullcontext,lifecycle_lock=contextlib.nullcontext,invoke=invoke)
                with patch('update.download'),patch('update.extract',side_effect=extract):
                    with self.assertRaisesRegex(RuntimeError,'rollback failed' if rollback_fails else 'version check failed'):
                        update.apply(console,{'tag_name':'v0.5.0'})
                self.assertEqual(actions,['upgrade','rollback'])
                self.assertEqual((root/'manage.py').read_text(),'new manager' if rollback_fails else 'old manager')
                self.assertEqual((package/'.update-previous').exists(),rollback_fails)

    def test_metadata_time_budget_and_archive_entry_budget(self):
        response=types.SimpleNamespace()
        class Opened:
            def __enter__(self):return response
            def __exit__(self,*args):return False
        opener=types.SimpleNamespace(open=lambda *a,**kw:Opened())
        with patch('update.urllib.request.build_opener',return_value=opener),patch('update.time.monotonic',side_effect=[0,11]):
            with self.assertRaisesRegex(RuntimeError,'time budget'):update.read(update.API,1024)
        with tempfile.TemporaryDirectory() as work:
            root=pathlib.Path(work);source=root/'many.tar.gz';target=root/'out';target.mkdir()
            with tarfile.open(source,'w:gz') as archive:
                for i in range(101):archive.addfile(tarfile.TarInfo(str(i)))
            with self.assertRaisesRegex(RuntimeError,'budget'):update.extract(source,target)
            self.assertEqual(list(target.iterdir()),[])

if __name__=='__main__':unittest.main()
