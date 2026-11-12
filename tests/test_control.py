import http.client
import json
import os
import tempfile
import threading
import unittest
from unittest.mock import patch
from control import server


class ControlTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {'DB_PATH': self.tmp.name + '/db.sqlite', 'API_TOKEN': 'a' * 40})
        self.env.start()
        server.initialize()
        self.http = server.http.server.ThreadingHTTPServer(('127.0.0.1', 0), server.Handler)
        self.thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.thread.start()
        self.agent = patch.object(server, 'agent', return_value={'stats': {}, 'flows': []})
        self.agent.start()

    def tearDown(self):
        self.http.shutdown()
        self.http.server_close()
        self.agent.stop()
        self.env.stop()
        self.tmp.cleanup()

    def request(self, path, method='GET', body=None, auth=True):
        conn = http.client.HTTPConnection('127.0.0.1', self.http.server_port, timeout=3)
        headers = {'Authorization': 'Bearer ' + 'a' * 40} if auth else {}
        conn.request(method, path, json.dumps(body) if body is not None else None, headers)
        response = conn.getresponse()
        data = response.read()
        conn.close()
        return response.status, json.loads(data) if response.getheader('Content-Type') == 'application/json' else data

    def test_authentication_and_health(self):
        self.assertEqual(self.request('/api/state', auth=False)[0], 401)
        self.assertEqual(self.request('/healthz', auth=False)[0], 200)

    def test_rule_revision_application_delete_and_audit(self):
        code, data = self.request('/api/rules', 'POST', {'cidr': '192.0.2.9/24', 'ttl_seconds': 60, 'reason': 'test'})
        self.assertEqual(code, 202)
        state = self.request('/api/state')[1]
        self.assertEqual(state['rules'][0]['cidr'], '192.0.2.0/24')
        self.assertEqual(state['status']['applied'], -1)
        server.reconcile_once()
        state = self.request('/api/state')[1]
        self.assertEqual(state['status']['applied'], state['revision'])
        self.assertEqual(len(state['audit']), 1)
        self.assertEqual(self.request('/api/rules/1', 'DELETE')[0], 202)
        self.assertEqual(self.request('/api/state')[1]['rules'], [])

    def test_invalid_input_does_not_modify_revision(self):
        for body in [{'cidr': 'bad'}, {'cidr': '0.0.0.0/0'}, {'cidr': '::/0'}, {'cidr':'::1', 'ttl_seconds':-1}, {'cidr':'::1', 'ttl_seconds':True}]:
            self.assertEqual(self.request('/api/rules', 'POST', body)[0], 400)
        self.assertEqual(self.request('/api/state')[1]['revision'], 0)

    def test_agent_failure_keeps_policy_pending(self):
        self.request('/api/rules', 'POST', {'cidr':'2001:db8::/32'})
        with patch.object(server, 'agent', side_effect=RuntimeError('offline')):
            server.reconcile_once()
        state = self.request('/api/state')[1]
        self.assertEqual(state['status']['applied'], -1)
        self.assertEqual(state['status']['error'], 'offline')

    def test_invalid_config_duplicate_and_csv(self):
        self.assertEqual(self.request('/api/config', 'POST', {'enforce':'false'})[0], 400)
        self.assertEqual(self.request('/api/config', 'POST', {'enforce':False, 'udp_pps_cpu':-1})[0], 400)
        rule = {'cidr':'198.51.100.8', 'reason':'=FORMULA()'}
        self.assertEqual(self.request('/api/rules','POST',rule)[0],202)
        self.assertEqual(self.request('/api/rules','POST',rule)[0],400)
        self.assertEqual(self.request('/api/report.csv')[0],200)

    def test_range_and_overlap_rejection(self):
        code, _ = self.request('/api/rules', 'POST', {'cidr':'192.0.2.5-192.0.2.10'})
        self.assertEqual(code,202)
        rules=self.request('/api/state')[1]['rules']
        self.assertEqual(len(rules),4)
        self.assertEqual(self.request('/api/rules','POST',{'cidr':'192.0.2.0/24'})[0],400)
        self.assertEqual(self.request('/api/rules','POST',[])[0],400)
