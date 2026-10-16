import pathlib
import socket
import sqlite3
import tempfile
import unittest
from unittest.mock import patch, Mock

import port_plan


class PortPlanTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = pathlib.Path(self.tmp.name) / 'weroxy.db'
        with sqlite3.connect(self.db) as db:
            db.execute('CREATE TABLE port_settings(id INTEGER PRIMARY KEY, forward_first INTEGER, forward_last INTEGER, data_first INTEGER, data_last INTEGER, bind_host TEXT)')
            db.execute("INSERT INTO port_settings VALUES(1,40000,40002,40100,40102,'0.0.0.0')")
        self.overrides = patch.dict('os.environ', {'WERXY_LEGACY_HOST_PORT': '40200', 'WERXY_CONTROL_HOST_PORT': '40201', 'WERXY_WEB_HOST_PORT': '40202'})
        self.overrides.start()
        self.addCleanup(self.overrides.stop)

    def test_pool_collision_is_skipped_and_published_plan_matches(self):
        with socket.socket() as occupied:
            occupied.bind(('127.0.0.1', 40001))
            value = port_plan.plan(self.db, '127.0.0.1')
        self.assertEqual(value['unavailable_forward'], [40001])
        self.assertEqual(value['unavailable_data'], [])
        self.assertNotIn((40001, 40001), value['ports'])
        self.assertIn((40000, 40000), value['ports'])
        publication = pathlib.Path(self.tmp.name) / 'publication.compose.yaml'
        port_plan.write_plan(value, pathlib.Path(self.tmp.name), publication)
        self.assertNotIn('40001:40001', publication.read_text())

    def test_required_entry_collision_rejects_all_publication(self):
        with socket.socket() as occupied:
            occupied.bind(('127.0.0.1', 40201))
            with self.assertRaisesRegex(RuntimeError, 'required host TCP port 40201 is occupied'):
                port_plan.plan(self.db, '127.0.0.1')

    def test_time_wait_allows_restart_but_reusable_live_listener_is_rejected(self):
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            listener.bind(('127.0.0.1',0));port=listener.getsockname()[1];listener.listen()
            self.assertFalse(port_plan.host_port_free('127.0.0.1',port))
            with socket.create_connection(('127.0.0.1',port)) as client:
                accepted,_=listener.accept()
                accepted.close() # Active close puts the server endpoint in TIME_WAIT.
                self.assertEqual(client.recv(1),b'')
        self.assertTrue(port_plan.host_port_free('127.0.0.1',port))



class OptionalFirewallTest(unittest.TestCase):
    def test_missing_manager_skips_all_firewall_work(self):
        with patch('port_plan.shutil.which',return_value=None), patch('port_plan.subprocess.run') as run, patch('port_plan.pathlib.Path.read_text',side_effect=AssertionError('OS inspection must not block skipping')):
            self.assertFalse(port_plan.check_firewall())
            self.assertEqual(port_plan.open_firewall({'ports':[(40000,40000)]}),[])
            port_plan.close_firewall([])
            run.assert_not_called()

    def test_installed_inactive_manager_is_not_silently_skipped(self):
        with patch('port_plan.shutil.which',return_value='/usr/sbin/ufw'), patch('port_plan.pathlib.Path.read_text',return_value='ID=debian'), patch('port_plan.subprocess.run',return_value=Mock(stdout='Status: inactive')):
            with self.assertRaisesRegex(RuntimeError,'must be active'):
                port_plan.open_firewall({'ports':[(40000,40000)]})

    def test_installed_active_manager_still_applies_rules(self):
        with patch('port_plan.shutil.which',return_value='/usr/sbin/ufw'), patch('port_plan.pathlib.Path.read_text',return_value='ID=debian'), patch('port_plan.subprocess.run',side_effect=[Mock(stdout='Status: active'),Mock(stdout='Rule added'),Mock(stdout='Status: active\n40000/tcp')]) as run:
            self.assertEqual(port_plan.open_firewall({'ports':[(40000,40000)]}),['40000'])
            self.assertEqual(run.call_args_list[1].args[0],['ufw','allow','40000/tcp','comment','Weroxy'])

if __name__ == '__main__':
    unittest.main()
