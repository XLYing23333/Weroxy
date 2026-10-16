import argparse
import curses
import contextlib
import hashlib
import io
import json
import pathlib
import os
import tempfile
import time
import unittest
from unittest.mock import patch, Mock

import console
import manage
import tui


class LocaleTest(unittest.TestCase):
    def test_invalid_environment_uses_utf8_fallback(self):
        with patch.dict(os.environ, {'LC_ALL':'invalid', 'LANG':'invalid'}), patch('console.locale.setlocale', side_effect=[console.locale.Error('unsupported'), 'C.UTF-8']) as setting, patch('tui.curses.wrapper') as wrapper:
            tui.run('zh')
            self.assertEqual(os.environ['LC_ALL'],'C.UTF-8')
            self.assertEqual(os.environ['LANG'],'C.UTF-8')
        self.assertEqual([call.args[1] for call in setting.call_args_list], ['', 'C.UTF-8'])
        wrapper.assert_called_once_with(tui.initialize, 'en', '')

    def test_only_c_locale_uses_english(self):
        with patch.dict(os.environ, {'LC_ALL':'invalid'}), patch('console.locale.setlocale', side_effect=[console.locale.Error('unsupported')]*3+['C']), patch('tui.curses.wrapper') as wrapper:
            tui.run('zh')
            self.assertEqual(os.environ['LC_ALL'],'C')
        wrapper.assert_called_once_with(tui.initialize, 'en', '')


class ReleaseTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=pathlib.Path(self.tmp.name)
        for name in console.REQUIRED:
            path=self.path/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('fixture')
        self.build={'version':'0.2.0','architecture':'linux/amd64','image_config_digest':'sha256:'+'a'*64,'image_archive':'test.docker.tar'}
        (self.path/'BUILD.json').write_text(json.dumps(self.build))
        (self.path/'test.docker.tar').write_bytes(b'image')
        self.manifest()
        self.machine=patch('console.platform.machine',return_value='x86_64');self.machine.start();self.addCleanup(self.machine.stop)

    def manifest(self):
        files=sorted(p for p in self.path.rglob('*') if p.is_file() and p.name!='SHA256SUMS')
        (self.path/'SHA256SUMS').write_text(''.join(console.checksum(p)+'  '+p.relative_to(self.path).as_posix()+'\n' for p in files))

    def test_notices_without_installation(self):
        canonical = pathlib.Path(__file__).resolve().parents[3] / 'THIRD_PARTY_NOTICES'
        text = canonical.read_bytes().decode('utf-8')
        (self.path/'THIRD_PARTY_NOTICES').write_bytes(text.encode('utf-8'))
        output = io.StringIO()
        with patch('console.PACKAGE', self.path), patch('console.core.command') as command, contextlib.redirect_stdout(output):
            console.execute('notices', argparse.Namespace())
        self.assertEqual(output.getvalue(), text)
        command.assert_not_called()
        self.assertTrue(tui.available('notices', {'installed':False}))
        self.assertEqual(len(tui.ACTIONS),len(tui.LABELS))
        self.assertEqual(len(tui.ACTIONS),len(tui.DESCRIPTIONS))

    def test_valid_release(self):
        self.assertEqual(console.verify(self.path)['version'],'0.2.0')

    def test_corrupt_image(self):
        (self.path/'test.docker.tar').write_bytes(b'bad')
        with self.assertRaisesRegex(RuntimeError,'mismatch'):console.verify(self.path)

    def test_missing_script(self):
        (self.path/'deploy/manage.py').unlink()
        with self.assertRaisesRegex(RuntimeError,'Missing'):console.verify(self.path)

    def test_missing_required_manifest_entry(self):
        p=self.path/'SHA256SUMS';p.write_text('\n'.join(r for r in p.read_text().splitlines() if not r.endswith('deploy/manage.py'))+'\n')
        with self.assertRaisesRegex(RuntimeError,'Incomplete'):console.verify(self.path)

    def test_traversal_and_absolute_paths(self):
        for name in ('../outside','/etc/passwd','deploy/../manage','deploy//manage.py'):
            with self.subTest(name=name),self.assertRaisesRegex(RuntimeError,'Unsafe'):console.ordinary_file(self.path,name)

    def test_symlink_file_and_directory(self):
        p=self.path/'deploy/manage.py';p.unlink();p.symlink_to('/etc/passwd')
        with self.assertRaisesRegex(RuntimeError,'symlinks'):console.verify(self.path)
        (self.path/'link').symlink_to(self.path/'deploy',target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError,'symlinks'):console.ordinary_file(self.path,'link/console.py')

    def test_architecture_mismatch(self):
        with patch('console.platform.machine',return_value='aarch64'),self.assertRaisesRegex(RuntimeError,'architecture'):console.verify(self.path)

    def test_duplicate_manifest(self):
        p=self.path/'SHA256SUMS';p.write_text(p.read_text()+p.read_text().splitlines()[0]+'\n')
        with self.assertRaisesRegex(RuntimeError,'Invalid'):console.verify(self.path)

    def test_unexpected_file(self):
        (self.path/'surprise').write_text('unexpected');self.manifest()
        with self.assertRaisesRegex(RuntimeError,'Unexpected'):console.verify(self.path)

    def test_archive_identity_and_classic_or_containerd_import(self):
        import tarfile
        config={'architecture':'amd64','rootfs':{'diff_ids':['sha256:layer']},'config':{'Cmd':['run'],'User':'10001:10001'}}
        body=json.dumps(config).encode();digest='sha256:'+hashlib.sha256(body).hexdigest()
        manifest=json.dumps([{'Config':'config.json','RepoTags':['weroxy-server:0.2.0']}]).encode()
        with tarfile.open(self.path/'test.docker.tar','w') as archive:
            for name,data in [('manifest.json',manifest),('config.json',body)]:
                info=tarfile.TarInfo(name);info.size=len(data);archive.addfile(info,io.BytesIO(data))
        build={**self.build,'image_config_digest':digest,'image_manifest_digest':'sha256:'+'b'*64}
        for identity in [digest,build['image_manifest_digest']]:
            info={'Id':identity,'Architecture':'amd64','RootFS':{'Layers':['sha256:layer']},'Config':config['config']}
            with patch('console.core.command',side_effect=['',json.dumps([info])]),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(console.load_image(self.path,build),identity)
        with self.assertRaisesRegex(RuntimeError,'Archive config'):
            console.archive_identity(self.path,self.build)
        info['Config']={'Cmd':['different'],'User':'10001:10001'}
        with patch('console.core.command',side_effect=['',json.dumps([info])]),contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError,'Imported image'):console.load_image(self.path,build)

    def test_internal_verification_does_not_execute_docker(self):
        with patch('console.core.command') as command:
            console.verify(self.path)
        command.assert_not_called()

    def test_release_permission_repair_excludes_data_and_backups(self):
        data=self.path/'deploy/data';data.mkdir();(data/'weroxy.db').write_bytes(b'private')
        backups=self.path/'deploy/backups';backups.mkdir()
        (self.path/'deploy').chmod(0o777)
        # Package parent is the root-owned sticky /tmp, never modified.
        with patch('console.os.geteuid',return_value=0),patch('console.os.chown') as owner,patch('console.os.chmod') as mode,patch('console.os.fchown'),patch('console.os.fchmod'),patch('console.core.command') as command:
            self.assertTrue(console.secure_release_permissions(self.path))
        self.assertEqual({call.args[0] for call in owner.call_args_list},{self.path,self.path/'deploy',self.path/'assets'})
        self.assertTrue(all(call.args[0] not in (data,backups,self.path.parent) for call in mode.call_args_list))
        command.assert_not_called()
        self.assertEqual((data/'weroxy.db').read_bytes(),b'private')

    def test_corrupt_release_cannot_trigger_permission_changes(self):
        (self.path/'test.docker.tar').write_bytes(b'corrupt')
        with patch('console.os.geteuid',return_value=0),patch('console.os.chown') as owner,patch('console.os.chmod') as mode:
            with self.assertRaisesRegex(RuntimeError,'mismatch'):
                console.secure_release_permissions(self.path)
        owner.assert_not_called();mode.assert_not_called()

    def test_unsafe_parent_is_not_modified(self):
        with patch('console.os.geteuid',return_value=0),patch('console.verify'),patch('console.os.chown') as owner:
            parent=self.path/'user-parent';parent.mkdir();parent.chmod(0o777)
            with self.assertRaisesRegex(RuntimeError,'Unsafe parent'):
                console.secure_release_permissions(parent/'release')
        owner.assert_not_called()

    def test_hard_link_cannot_change_files_outside_release(self):
        alias=self.path/'external-copy';os.link(self.path/'README.md',alias)
        with patch('console.os.geteuid',return_value=0),patch('console.os.chown') as owner:
            with self.assertRaisesRegex(RuntimeError,'hard-linked'):
                console.secure_release_permissions(self.path)
        owner.assert_not_called()

    def test_corrupt_install_never_imports_or_initializes(self):
        (self.path/'test.docker.tar').write_bytes(b'bad')
        with patch('console.os.geteuid',return_value=0),patch('console.PACKAGE',self.path),patch('console.ROOT',self.path/'deploy'),patch('console.verify',side_effect=RuntimeError('SHA mismatch')),patch('console.load_image') as load,patch('console.invoke') as invoke,patch('console.lifecycle_lock',return_value=contextlib.nullcontext()),contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError,'SHA mismatch'):console.execute('install',argparse.Namespace())
        load.assert_not_called();invoke.assert_not_called()

    def test_corrupt_start_never_changes_running_deployment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp);data=root/'data';data.mkdir();(data/'weroxy.db').touch()
            with patch('console.ROOT',root),patch('console.core.DATA',data),patch('console.prerequisites'),patch('console.verify',side_effect=RuntimeError('SHA mismatch')),patch('console.invoke') as invoke,patch('console.lifecycle_lock',return_value=contextlib.nullcontext()),contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(RuntimeError,'SHA mismatch'):console.execute('start',argparse.Namespace())
            invoke.assert_not_called()



class LifecycleTest(unittest.TestCase):
    def test_child_reuses_parent_lifecycle_lock_and_timer_cannot_race(self):
        import fcntl,subprocess,sys
        with tempfile.TemporaryDirectory() as tmp:
            path=pathlib.Path(tmp)/'lock'
            child="import sys,pathlib; sys.path.insert(0,sys.argv[1]); import manage; manage.LOCK=pathlib.Path(sys.argv[2]); manage.state=lambda:{'image':'test'}; manage.compose=lambda *a,**k:None; manage.main(sys.argv[3:])"
            with path.open('a') as lock:
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                base=[sys.executable,'-c',child,str(pathlib.Path(manage.__file__).parent),str(path),'status']
                timer=subprocess.run(base,capture_output=True)
                self.assertNotEqual(timer.returncode,0)
                result=subprocess.run(base+['--lock-fd',str(lock.fileno())],pass_fds=(lock.fileno(),),capture_output=True)
                self.assertEqual(result.returncode,0,result.stderr.decode())
                with path.open('a') as probe:
                    with self.assertRaises(BlockingIOError):fcntl.flock(probe,fcntl.LOCK_EX|fcntl.LOCK_NB)

    def test_nonterminal_no_action_only_help(self):
        with patch('sys.argv',['manage']),patch('sys.stdin.isatty',return_value=False),patch('console.execute') as execute,contextlib.redirect_stdout(io.StringIO()) as out:console.main()
        execute.assert_not_called();self.assertIn('install',out.getvalue())

    def test_stop_disables_only_current_deployment_units(self):
        with patch('manage.pathlib.Path.is_file',return_value=True),patch('manage.command') as command:
            names=manage.pause_tasks()
        self.assertEqual(len(names),1)
        self.assertEqual(command.call_args_list[1].args[0][1:4],['disable','--now',names[0]+'.timer'])
        self.assertTrue(all(name in manage.deployment_tasks() for name in names))

    def test_backup_restores_tasks_even_when_ready_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp);data=root/'data';data.mkdir();(data/'weroxy.db').write_bytes(b'snapshot')
            with patch('manage.ROOT',root),patch('manage.DATA',data),patch('manage.own_published_ports',return_value={9415}),patch('manage.pause_tasks',return_value=['task']),patch('manage.resume_tasks') as resume,patch('manage.compose'),patch('manage.ready',side_effect=RuntimeError('not ready')),patch('manage.os.chown'),patch('manage.owned_copy',side_effect=__import__('shutil').copy2),contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(RuntimeError,'not ready'):manage.offline_backup('image')
                resume.assert_called_once_with(['task'])
            snapshot=next((root/'backups').iterdir())
            self.assertEqual((snapshot/'data/weroxy.db').read_bytes(),b'snapshot')
            self.assertEqual(snapshot.stat().st_mode&0o777,0o700)

    def test_menu_disabled_actions_and_wide_characters(self):
        self.assertTrue(tui.available('install',{'installed':False}))
        self.assertFalse(tui.available('start',{'installed':False}))
        self.assertFalse(tui.available('install',{'installed':True}))
        self.assertEqual(tui.clip('设备X',4),'设备')
        self.assertEqual(tui.clip('a\x1bb',4),'ab')

    def test_password_reset_prompts_only_once(self):
        with patch('sys.stdin.isatty',return_value=True),patch('console.getpass.getpass',return_value='abcdef') as prompt,patch('console.subprocess.run'):
            console.reset_password('tester')
        prompt.assert_called_once()

    def test_short_password_rejects(self):
        with patch('sys.stdin.isatty',return_value=True),patch('console.getpass.getpass',return_value='abc'),patch('console.subprocess.run') as command:
            with self.assertRaisesRegex(RuntimeError,'6–1024'):console.reset_password('tester')
        command.assert_not_called()

    def test_password_never_in_argv(self):
        with patch('sys.stdin.isatty',return_value=True),patch('console.getpass.getpass',return_value='not-a-real-password'),patch('console.subprocess.run') as command:
            console.reset_password('tester')
        self.assertNotIn('not-a-real-password',' '.join(command.call_args.args[0]))
        self.assertEqual(command.call_args.kwargs['input'],b'not-a-real-password')

    def test_no_operation_confirmation(self):
        for action in ['stop', 'restart', 'uninstall']:
            with patch('tui.dialog') as dialog:
                self.assertIsNotNone(tui.parameters(Mock(), action))
                dialog.assert_not_called()

    def test_removed_commands_are_rejected_and_default_is_english(self):
        self.assertEqual(console.parser().parse_args([]).lang, 'en')
        for action in ['verify', 'logs', 'backup', 'upgrade', 'rollback', 'https']:
            with self.subTest(action=action), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit): console.parser().parse_args([action])
                with self.assertRaisesRegex(RuntimeError, 'Unsupported'): console.execute(action, argparse.Namespace())

    def test_status_is_readable_and_has_no_json(self):
        with tempfile.TemporaryDirectory() as tmp, patch('console.core.DATA', pathlib.Path(tmp)), patch('console.summary',return_value={'version':'0.2.0','installed':True,'health':'healthy','url':'http://8.8.8.8:9415'}), contextlib.redirect_stdout(io.StringIO()) as out:
            console.execute('status', argparse.Namespace())
        self.assertIn('Container: healthy', out.getvalue())
        self.assertIn('Web: http://8.8.8.8:9415', out.getvalue())
        self.assertNotIn('{', out.getvalue())

    def test_result_stays_in_tui_and_shows_error(self):
        screen = Mock(); screen.getmaxyx.return_value = (25, 100); screen.getch.return_value = 10
        args = argparse.Namespace(password='private')
        with patch('console.execute',side_effect=RuntimeError('entry port occupied')), patch('tui.curses.endwin') as endwin:
            tui.operation(screen, 'start', args)
        endwin.assert_not_called()
        rendered = [call.args[2] for call in screen.addstr.call_args_list]
        self.assertTrue(any('Failed: entry port occupied' in line for line in rendered))
        self.assertIsNone(args.password)

    def test_busy_operation_repaints_on_resize_and_ignores_back_until_done(self):
        screen=Mock();screen.getmaxyx.return_value=(16,64)
        keys=[27,curses.KEY_RESIZE,curses.KEY_UP,curses.KEY_END]
        def read():
            time.sleep(.01)
            return keys.pop(0) if keys else 10
        screen.getch.side_effect=read
        def slow(*_):time.sleep(.08);print('Finished safely')
        with patch('console.execute',side_effect=slow):
            tui.operation(screen,'start',argparse.Namespace(password=None))
        rendered=[call.args[2] for call in screen.addstr.call_args_list]
        self.assertTrue(any('Working' in line for line in rendered))
        self.assertTrue(any('Completed' in line for line in rendered))
        self.assertTrue(any('Finished safely' in line for line in rendered))
        screen.timeout.assert_any_call(100);screen.timeout.assert_any_call(-1)

    def test_cjk_wrap_and_bounded_operation_output(self):
        self.assertEqual(tui.wrap('设备状态X',4),['设备','状态','X'])
        output=tui.OperationOutput();output.write('a'*(output.LIMIT*2))
        self.assertLess(len(output.snapshot()),output.LIMIT+64)
        self.assertTrue(output.snapshot().startswith('[Earlier output omitted]'))

    def test_both_terminal_cursor_key_modes_and_quick_escape(self):
        for codes in ([27,ord('['),ord('B')],[27,ord('O'),ord('B')]):
            screen=Mock();screen.getch.side_effect=codes
            self.assertEqual(tui.read_key(screen),curses.KEY_DOWN)
            screen.timeout.assert_any_call(25);screen.timeout.assert_any_call(-1)
        screen=Mock();screen.getch.side_effect=[27,-1]
        self.assertEqual(tui.read_key(screen),27)

    def test_password_cancel_does_not_run(self):
        with patch('tui.dialog',side_effect=['tester', None]):
            self.assertIsNone(tui.parameters(Mock(), 'reset-password'))

    def test_ssh_public_ip_skips_external_lookup(self):
        console.server_ip.cache_clear()
        with patch.dict('os.environ',{'SSH_CONNECTION':'1.1.1.1 30000 8.8.8.8 22','WERXY_PUBLISH_IP':'0.0.0.0'}), patch('console.core.command',return_value='[]'), patch('console.urllib.request.urlopen') as lookup:
            self.assertEqual(console.web_url(), 'http://8.8.8.8:9415')
            lookup.assert_not_called()
        console.server_ip.cache_clear()

    def test_nat_public_ip_and_offline_fallback(self):
        console.server_ip.cache_clear()
        interfaces = '[{"addr_info":[{"family":"inet","local":"192.168.1.10"}]}]'
        response = Mock(); response.__enter__ = Mock(return_value=response); response.__exit__ = Mock(return_value=False); response.read.return_value = b'8.8.8.8'
        with patch.dict('os.environ',{'SSH_CONNECTION':'','WERXY_PUBLISH_IP':'0.0.0.0'}), patch('console.core.command',return_value=interfaces), patch('console.urllib.request.urlopen',return_value=response):
            self.assertEqual(console.server_ip(), '8.8.8.8')
        console.server_ip.cache_clear()
        with patch.dict('os.environ',{'SSH_CONNECTION':'','WERXY_PUBLISH_IP':'0.0.0.0'}), patch('console.core.command',return_value=interfaces), patch('console.urllib.request.urlopen',side_effect=OSError):
            self.assertEqual(console.server_ip(), '192.168.1.10')
        console.server_ip.cache_clear()

    def test_setup_url_uses_actual_host_port_without_placeholder(self):
        with tempfile.TemporaryDirectory() as tmp:
            data=pathlib.Path(tmp)
            with __import__('sqlite3').connect(data/'weroxy.db') as db:
                db.execute('CREATE TABLE administrators (id INTEGER)')
            (data/'setup.secret').write_text('a'*64)
            with patch('console.core.DATA', data), patch('console.summary',return_value={'url':'http://8.8.8.8:19415'}), contextlib.redirect_stdout(io.StringIO()) as out:
                console.setup_url()
            self.assertIn('http://8.8.8.8:19415/init'+'a'*64,out.getvalue())
            self.assertNotIn('<server-IP>',out.getvalue())

    def test_uninstall_preserves_data_and_marks_removed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp); data=root/'data'; data.mkdir(); (data/'weroxy.db').write_bytes(b'private')
            with patch('console.ROOT',root),patch('console.core.DATA',data),patch('console.core.state',return_value={'image':'image'}),patch('console.core.deployment_tasks',return_value=[]),patch('console.core.pause_tasks'),patch('console.core.compose') as compose,patch('console.core.revoke_managed_firewall'),contextlib.redirect_stdout(io.StringIO()) as out:
                console.uninstall()
            self.assertEqual((data/'weroxy.db').read_bytes(),b'private')
            self.assertTrue((root/'.uninstalled').is_file())
            self.assertEqual(compose.call_args.args, ('down','--remove-orphans'))
            self.assertIn('Data retained',out.getvalue())

    def test_uninstall_only_removes_owned_unshared_ufw_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp); data=root/'data';data.mkdir()
            (data/'host-port-plan.json').write_text(json.dumps({'ports':[[9415,9415],[29000,29000],[443,443]]}))
            other=json.dumps([{'NetworkSettings':{'Ports':{'22/tcp':[{'HostPort':'29000'}]}}}])
            status='[ 1] 9415/tcp ALLOW IN Anywhere # Weroxy\n[ 2] 29000/tcp ALLOW IN Anywhere # Weroxy\n[ 3] 443/tcp ALLOW IN Anywhere # Weroxy\n[ 4] 12345/tcp ALLOW IN Anywhere # Other'
            with patch('console.ROOT',root),patch('console.core.DATA',data),patch('console.core.state',return_value={'image':'image'}),patch('console.core.deployment_tasks',return_value=[]),patch('console.core.pause_tasks'),patch('console.core.compose'),patch('console.shutil.which',return_value='/usr/sbin/ufw'),patch('console.core.command',side_effect=['other',other,status,'']) as command,contextlib.redirect_stdout(io.StringIO()):
                console.uninstall()
            self.assertEqual(command.call_args.args[0],['ufw','--force','delete','1'])
            self.assertEqual(command.call_count,4)

if __name__=='__main__':unittest.main()
