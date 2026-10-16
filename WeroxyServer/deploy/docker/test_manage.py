import os
import pathlib
import tempfile
import unittest
import json
import sys
import shutil
from unittest.mock import patch

import manage


class InitializationTest(unittest.TestCase):
    def test_init_prepares_pool_without_creating_admin(self):
        with tempfile.TemporaryDirectory() as root:
            data=pathlib.Path(root)/"data"
            from types import SimpleNamespace
            args=SimpleNamespace(forward_pool="29000-29099",data_pool="29100-29199",reserved=10)
            with patch.object(manage,"DATA",data), patch("manage.os.geteuid",return_value=0), patch("manage.os.chown"), patch.object(manage,"compose") as compose, patch.object(manage,"save"):
                manage.initialize(args,"test-image")
            self.assertTrue(data.is_dir())
            self.assertEqual(compose.call_count,1)
            self.assertIn("pool",compose.call_args.args)
            self.assertNotIn("admin",compose.call_args.args)
            self.assertFalse((data/"bootstrap.secret").exists())


class PublicationTimerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name) / 'deployment'
        self.units = pathlib.Path(self.tmp.name) / 'systemd'
        self.root.mkdir()
        self.units.mkdir()
        self.root_patch = patch.object(manage, 'ROOT', self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)
        self.uid_patch = patch('manage.os.geteuid', return_value=0)
        self.uid_patch.start()
        self.addCleanup(self.uid_patch.stop)
        self.env_patch = patch.dict(os.environ, {'COMPOSE_PROJECT_NAME': 'weroxy_accept_test'})
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)

    def test_install_uses_host_manager_and_compose_project(self):
        calls = []
        with patch.object(manage, 'command', side_effect=lambda cmd, **kw: calls.append(cmd)):
            manage.install_publication_timer(self.units)
        service = next(self.units.glob('*.service'))
        timer = next(self.units.glob('*.timer'))
        self.assertIn('Environment=COMPOSE_PROJECT_NAME=weroxy_accept_test', service.read_text())
        self.assertIn('manage.py refresh', service.read_text())
        self.assertIn('OnCalendar=*-*-* *:*:00', timer.read_text())
        self.assertTrue(any(c[:3] == ['systemctl', 'enable', '--now'] for c in calls))

    def test_failed_install_restores_unit_files(self):
        def reject_enable(cmd, **_):
            if cmd[:3] == ['systemctl', 'enable', '--now']:
                raise RuntimeError('unit failed')
        with patch.object(manage, 'command', side_effect=reject_enable):
            with self.assertRaisesRegex(RuntimeError, 'unit failed'):
                manage.install_publication_timer(self.units)
        self.assertEqual(list(self.units.iterdir()), [])


class UpgradePreflightTest(unittest.TestCase):
    def test_failed_preflight_keeps_original_database_and_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp);data=root/'data';data.mkdir()
            (data/'weroxy.db').write_bytes(b'original device credentials')
            publication=root/'publication.compose.yaml';publication.write_text('original published ports')
            calls=[];saved=[]
            def compose(*args,**kw):
                calls.append((args,kw))
                return 'cid' if args[0]=='ps' else ''
            def command(args,**kw):return json.dumps([{'Id':'new','Image':'old','State':{'Running':True}}])
            def fail(*_):
                publication.write_text('incomplete plan')
                raise RuntimeError('port collision')
            with patch.object(manage,'ROOT',root),patch.object(manage,'DATA',data),patch.object(manage,'PUBLICATION',publication),patch.object(manage,'LOCK',root/'lock'),patch.object(manage,'state',return_value={'image':'old'}),patch.object(manage,'save',side_effect=saved.append),patch.object(manage,'command',side_effect=command),patch.object(manage,'compose',side_effect=compose),patch.object(manage,'verify_data',return_value=10),patch.object(manage,'owned_copy',side_effect=shutil.copy2),patch.object(manage,'retire_old_https'),patch.object(manage,'prepare_publication',side_effect=fail),patch.object(manage,'ready'),patch.object(manage,'rollback') as rollback,patch('manage.os.geteuid',return_value=0),patch('manage.os.chown'),patch.object(sys,'argv',['manage.py','upgrade','--image','new']):
                with self.assertRaisesRegex(RuntimeError,'port collision'):manage.main()
            rollback.assert_not_called()
            self.assertEqual((data/'weroxy.db').read_bytes(),b'original device credentials')
            self.assertEqual(publication.read_text(),'original published ports')
            self.assertEqual(saved[-1],{'image':'old'})
            self.assertTrue(any(args==('up','-d','--no-build','weroxy') and kw['image']=='old' for args,kw in calls))
            self.assertEqual(len(list(root.glob('aborted-upgrade-snapshot-*'))),1)


if __name__ == '__main__':
    unittest.main()


class HTTPSRetirementTest(unittest.TestCase):
    def test_certbot_relative_links_are_preserved_in_private_backup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp);data=root/'data';data.mkdir()
            certificates=root/'https-data'
            (certificates/'archive'/'example').mkdir(parents=True)
            (certificates/'live'/'example').mkdir(parents=True)
            (certificates/'archive'/'example'/'cert1.pem').write_text('fixture certificate')
            (certificates/'live'/'example'/'cert.pem').symlink_to('../../archive/example/cert1.pem')
            with patch.object(manage,'ROOT',root),patch.object(manage,'DATA',data),patch.object(manage,'command',return_value=''):
                manage.retire_old_https()
            backup=next((root/'backups').glob('retired-https-*'))
            link=backup/'https-data'/'live'/'example'/'cert.pem'
            self.assertTrue(link.is_symlink())
            self.assertEqual(link.read_text(),'fixture certificate')
            self.assertFalse(certificates.exists())

    def test_certificate_escape_is_rejected_before_host_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp);data=root/'data';data.mkdir()
            certificates=root/'https-data';certificates.mkdir()
            (root/'other.pem').write_text('unrelated file')
            (certificates/'cert.pem').symlink_to('../other.pem')
            with patch.object(manage,'ROOT',root),patch.object(manage,'DATA',data),patch.object(manage,'command') as command:
                with self.assertRaisesRegex(RuntimeError,'within its directory'):
                    manage.retire_old_https()
                command.assert_not_called()
            self.assertTrue(certificates.exists())
            self.assertEqual((root/'other.pem').read_text(),'unrelated file')

    def test_no_old_material_performs_no_work(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp);data=root/'data';data.mkdir()
            with patch.object(manage,'ROOT',root),patch.object(manage,'DATA',data),patch.object(manage,'command') as command:
                manage.retire_old_https()
                command.assert_not_called()
                self.assertFalse((root/'backups').exists())

    def test_old_material_saved_privately_then_removed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp);data=root/'data';data.mkdir()
            (root/'https.compose.yaml').write_text('old owned integration')
            (data/'weroxy-tls.key').write_text('fixture only')
            with patch.object(manage,'ROOT',root),patch.object(manage,'DATA',data),patch.object(manage,'command',return_value=''):
                manage.retire_old_https()
            backups=list((root/'backups').glob('retired-https-*'));self.assertEqual(len(backups),1)
            self.assertEqual(backups[0].stat().st_mode & 0o777,0o700)
            self.assertEqual((backups[0]/'weroxy-tls.key').read_text(),'fixture only')
            self.assertFalse((data/'weroxy-tls.key').exists())
            self.assertFalse((root/'https.compose.yaml').exists())

    def test_untrusted_receipt_rejects_before_host_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp);data=root/'data';data.mkdir()
            receipt=root/'.https-host.json';receipt.write_text('{}');receipt.chmod(0o666)
            with patch.object(manage,'ROOT',root),patch.object(manage,'DATA',data),patch.object(manage,'command') as command:
                with self.assertRaisesRegex(RuntimeError,'Untrusted'):
                    manage.retire_old_https()
                command.assert_not_called()
            self.assertTrue(receipt.exists())
