"""Run inside the control container to exercise the real Unix-socket agent."""
import json
import os
import time
import urllib.request

TOKEN = os.environ['API_TOKEN']
def request(path, method='GET', body=None, auth=True):
    req=urllib.request.Request('http://127.0.0.1:8080'+path,method=method,data=json.dumps(body).encode() if body is not None else None,headers={'Authorization':'Bearer '+TOKEN} if auth else {})
    with urllib.request.urlopen(req,timeout=25) as response:
        data=response.read()
        return json.loads(data) if response.headers['Content-Type']=='application/json' else data

assert b'Firewall control' in request('/',auth=False)
if not request('/api/state')['rules']:
    request('/api/rules','POST',{'cidr':'192.0.2.0/24','reason':'compose integration','ttl_seconds':600})
for _ in range(20):
    state=request('/api/state')
    if state['status']['applied']==state['revision'] and not state['status']['error']:
        break
    time.sleep(1)
else:
    raise AssertionError(state)
assert not state['telemetry'].get('error'),state
assert state['rules'][0]['cidr']=='192.0.2.0/24'
assert 'local_sockets' in state['telemetry']
if os.environ.get('SMOKE_KEEP_RULE') == '1':
    print('PASS: durable rule ready for restart/recovery test')
    raise SystemExit(0)
request('/api/rules/'+str(state['rules'][0]['id']),'DELETE')
assert not request('/api/state')['rules']
assert b'compose integration' in request('/api/report.csv')
print('PASS: UI assets, authenticated API, durable rules, real agent reconciliation, telemetry and audit export')
