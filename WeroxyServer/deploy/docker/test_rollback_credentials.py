import pathlib
import shutil
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
import manage


def fixture(root):
    root.mkdir()
    with sqlite3.connect(root/'weroxy.db') as db:
        db.executescript('''
        CREATE TABLE administrators(id INTEGER PRIMARY KEY, password_hash BLOB);
        CREATE TABLE admin_sessions(id INTEGER PRIMARY KEY, revoked INTEGER);
        CREATE TABLE quick_tokens(id INTEGER PRIMARY KEY, revoked INTEGER);
        CREATE TABLE weroxy_devices(id INTEGER PRIMARY KEY, key_mac BLOB, revoked INTEGER, paused INTEGER);
        CREATE TABLE legacy_devices(id INTEGER PRIMARY KEY, paused INTEGER);
        CREATE TABLE config_revisions(domain TEXT, desired_revision INTEGER, applied_revision INTEGER);
        CREATE TABLE access_rules(cidr TEXT, action TEXT);
        CREATE TABLE firewall_sync(id INTEGER PRIMARY KEY, enabled INTEGER, managed INTEGER, status TEXT, failure_reason TEXT);
        CREATE TABLE metric_samples(at INTEGER, value INTEGER);
        INSERT INTO administrators VALUES(1,X'0123');
        INSERT INTO admin_sessions VALUES(1,0);
        INSERT INTO quick_tokens VALUES(1,0);
        INSERT INTO weroxy_devices VALUES(1,X'2345',0,0);
        INSERT INTO legacy_devices VALUES(1,0);
        INSERT INTO config_revisions VALUES('credential',1,1);
        INSERT INTO access_rules VALUES('192.0.2.0/24','ban');
        INSERT INTO firewall_sync VALUES(1,0,0,'unsupported','');
        ''')
    (root/'device-seal.key').write_bytes(b'fixture-seal')
    (root/'legacy-mac.key').write_bytes(b'fixture-mac')


class AutomaticRollbackTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=pathlib.Path(self.temp.name);self.data=self.root/'data';self.backup=self.root/'rollback-data'
        fixture(self.data);shutil.copytree(self.data,self.backup)

    def change(self,sql):
        with sqlite3.connect(self.data/'weroxy.db') as db:db.executescript(sql)

    def test_observations_and_applied_revision_do_not_invalidate_evidence(self):
        self.change("INSERT INTO metric_samples VALUES(1,200); UPDATE admin_sessions SET revoked=1; UPDATE config_revisions SET applied_revision=0")
        (self.data/'logs').mkdir();(self.data/'logs/event.log').write_text('new startup')
        (self.data/'deployment-publication.json').write_text('new container')
        self.assertTrue(manage.security_state_unchanged(self.data,self.backup))

    def test_credential_policy_admin_and_future_table_changes_fail_closed(self):
        mutations=[
            "UPDATE weroxy_devices SET key_mac=X'ffff'",
            "UPDATE weroxy_devices SET revoked=1",
            "UPDATE legacy_devices SET paused=1",
            "UPDATE administrators SET password_hash=X'ffff'",
            "UPDATE quick_tokens SET revoked=1",
            "DELETE FROM access_rules",
            "UPDATE config_revisions SET desired_revision=2",
            "CREATE TABLE future_security(access INTEGER)",
            "CREATE TABLE sqliteFutureSecurity(access INTEGER)",
        ]
        for sql in mutations:
            with self.subTest(sql=sql):
                shutil.rmtree(self.data);shutil.copytree(self.backup,self.data)
                self.change(sql)
                self.assertFalse(manage.security_state_unchanged(self.data,self.backup))

    def test_secret_change_corruption_and_managed_firewall_fail_closed(self):
        (self.data/'device-seal.key').write_bytes(b'changed')
        self.assertFalse(manage.security_state_unchanged(self.data,self.backup))
        shutil.rmtree(self.data);shutil.copytree(self.backup,self.data)
        self.change('UPDATE firewall_sync SET managed=1')
        self.assertFalse(manage.security_state_unchanged(self.data,self.backup))
        (self.data/'weroxy.db').write_bytes(b'corrupt')
        self.assertFalse(manage.security_state_unchanged(self.data,self.backup))

    def test_automatic_unchanged_retains_devices_but_revokes_admin_sessions(self):
        self.rollback(automatic=True,expected_revoked=0)

    def test_manual_rollback_still_quarantines_unchanged_credentials(self):
        self.rollback(automatic=False,expected_revoked=1)

    def test_automatic_changed_credentials_are_quarantined(self):
        self.change("UPDATE weroxy_devices SET revoked=1")
        self.rollback(automatic=True,expected_revoked=1)

    def rollback(self,automatic,expected_revoked):
        saved={'image':'new','previous_image':'old','rollback_available':True,'previous_running':True}
        with patch.object(manage,'ROOT',self.root),patch.object(manage,'DATA',self.data),patch.object(manage,'command'),patch.object(manage,'compose'),patch.object(manage,'prepare_publication'),patch.object(manage,'ready'),patch.object(manage,'save'),patch.object(manage,'revoke_managed_firewall'),patch('manage.os.geteuid',return_value=0),patch('manage.os.chown'):
            manage.rollback(saved,automatic=automatic)
        with sqlite3.connect(self.data/'weroxy.db') as db:
            self.assertEqual(db.execute('SELECT revoked,paused FROM weroxy_devices').fetchone(),(expected_revoked,expected_revoked))
            self.assertEqual(db.execute('SELECT paused FROM legacy_devices').fetchone()[0],expected_revoked)
            self.assertEqual(db.execute('SELECT revoked FROM quick_tokens').fetchone()[0],expected_revoked)
            self.assertEqual(db.execute('SELECT revoked FROM admin_sessions').fetchone()[0],1)

if __name__=='__main__':unittest.main()


class FrozenDockerBindingsTest(unittest.TestCase):
    def test_actual_root_controlled_host_bindings_are_used(self):
        result=manage.frozen_publication({'HostConfig':{'PortBindings':{'9415/tcp':[{'HostIp':'127.0.0.1','HostPort':'19415'}],'29999/tcp':[{'HostIp':'127.0.0.1','HostPort':'19999'}]}}})
        self.assertEqual(result,{'host_ip':'127.0.0.1','ports':[[19415,9415],[19999,29999]]})

    def test_mixed_interfaces_and_multiple_bindings_are_rejected(self):
        for bindings in [None,{'9415/tcp':[{'HostIp':'127.0.0.1','HostPort':'9415'},{'HostIp':'0.0.0.0','HostPort':'19415'}]}, {'9415/tcp':[{'HostIp':'127.0.0.1','HostPort':'9415'}],'4900/tcp':[{'HostIp':'0.0.0.0','HostPort':'4900'}]}]:
            with self.subTest(bindings=bindings),self.assertRaises(RuntimeError):manage.frozen_publication({'HostConfig':{'PortBindings':bindings}})


    def test_preserved_publication_does_not_rescan_or_configure_firewall(self):
        frozen={'host_ip':'127.0.0.1','ports':[[19415,9415]]}
        with patch.object(manage.port_plan,'check_firewall') as firewall,patch.object(manage.port_plan,'plan') as rescan,patch.object(manage.port_plan,'preserved_plan',return_value=frozen),patch.object(manage.port_plan,'write_plan'):
            self.assertEqual(manage.prepare_publication('new',frozen),frozen)
        firewall.assert_not_called();rescan.assert_not_called()
