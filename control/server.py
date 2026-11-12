#!/usr/bin/env python3
"""Single-host MVP control plane. Persistent SQLite, no third-party packages."""
import csv
import hmac
import http.client
import http.server
import io
import ipaddress
import json
import os
from pathlib import Path
import socket
import sqlite3
import threading
import time

ROOT = Path(__file__).resolve().parent.parent
LOCK = threading.RLock()


class UnixHTTP(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(os.environ.get('AGENT_SOCKET', '/run/xdp-firewall/agent.sock'))


def agent(method='GET', policy=None):
    conn = UnixHTTP('localhost', timeout=20)
    try:
        conn.request(method, '/', body=json.dumps(policy) if policy is not None else None, headers={'Content-Type': 'application/json'})
        response = conn.getresponse()
        data = json.loads(response.read())
        if response.status != 200:
            raise RuntimeError(data.get('error', 'agent failed'))
        return data
    finally:
        conn.close()


def connect():
    db = sqlite3.connect(os.environ.get('DB_PATH', 'state/firewall.db'), timeout=10)
    db.row_factory = sqlite3.Row
    return db


def initialize():
    path = Path(os.environ.get('DB_PATH', 'state/firewall.db'))
    path.parent.mkdir(parents=True, exist_ok=True)
    with connect() as db:
        db.executescript('''
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS rules(id INTEGER PRIMARY KEY AUTOINCREMENT, cidr TEXT UNIQUE NOT NULL, reason TEXT NOT NULL, expires_at REAL);
        CREATE TABLE IF NOT EXISTS meta(id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL, applied INTEGER NOT NULL, config TEXT NOT NULL, error TEXT);
        INSERT OR IGNORE INTO meta VALUES(1,0,-1,'{"enforce":false,"udp_pps_cpu":0,"syn_pps_cpu":0}',NULL);
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, ts REAL, action TEXT, details TEXT);
        CREATE TABLE IF NOT EXISTS samples(ts REAL PRIMARY KEY, counters TEXT NOT NULL);
        ''')


def policy(db):
    meta = dict(db.execute('SELECT * FROM meta').fetchone())
    return {'revision': meta['revision'], 'rules': [dict(r) for r in db.execute('SELECT * FROM rules ORDER BY id')], 'config': json.loads(meta['config'])}


def reconcile_once():
    with LOCK, connect() as db:
        p = policy(db)
        try:
            agent('POST', p)
            snapshot = agent()
            db.execute('INSERT INTO samples VALUES(?,?)', (time.time(), json.dumps(snapshot.get('stats', {}))))
            db.execute('DELETE FROM samples WHERE ts<?', (time.time()-86400,))
            db.execute('UPDATE meta SET applied=?,error=NULL WHERE id=1', (p['revision'],))
        except Exception as exc:
            db.execute('UPDATE meta SET error=? WHERE id=1', (str(exc),))


def reconcile_loop():
    while True:
        reconcile_once()
        time.sleep(5)


def validate_rule(body):
    source = str(body['cidr']).strip()
    if '-' in source:
        first, last = [ipaddress.ip_address(v.strip()) for v in source.split('-', 1)]
        networks = list(ipaddress.summarize_address_range(first, last))
    else:
        networks = [ipaddress.ip_network(source, strict=False)]
    if len(networks) > 256:
        raise ValueError('range expands beyond 256 CIDRs')
    if any(net.prefixlen == 0 for net in networks):
        raise ValueError('default-route blocks are disabled to protect management access')
    reason = str(body.get('reason', 'manual')).strip()
    if not 1 <= len(reason) <= 240:
        raise ValueError('reason must contain 1–240 characters')
    ttl = body.get('ttl_seconds', 0)
    if type(ttl) is not int or not 0 <= ttl <= 31536000:
        raise ValueError('TTL must be integer seconds between 0 and 31536000')
    return [str(net) for net in networks], reason, time.time() + ttl if ttl else None


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = 'XDPFirewall'

    def log_message(self, fmt, *args):
        # Do not log authorization headers or request bodies.
        pass

    def send(self, status, payload, content_type='application/json'):
        data = json.dumps(payload).encode() if content_type == 'application/json' else payload.encode()
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(data)

    def authorized(self):
        expected = 'Bearer ' + os.environ['API_TOKEN']
        if not hmac.compare_digest(self.headers.get('Authorization', '').encode(), expected.encode()):
            self.send(401, {'error': 'authentication required'})
            return False
        return True

    def do_GET(self):
        if self.path == '/healthz':
            return self.send(200, {'alive': True})
        if self.path in ('/', '/app.js', '/style.css'):
            name = {'/': 'index.html', '/app.js': 'app.js', '/style.css': 'style.css'}[self.path]
            mime = {'/': 'text/html', '/app.js': 'application/javascript', '/style.css': 'text/css'}[self.path]
            return self.send(200, (ROOT / 'ui' / name).read_text(), mime)
        if not self.authorized():
            return
        if self.path == '/api/state':
            with LOCK, connect() as db:
                p = policy(db)
                p['status'] = dict(db.execute('SELECT applied,error FROM meta').fetchone())
                p['history'] = [dict(r) for r in db.execute('SELECT * FROM samples ORDER BY ts DESC LIMIT 120')]
                p['audit'] = [dict(r) for r in db.execute('SELECT * FROM audit ORDER BY id DESC LIMIT 100')]
            try:
                p['telemetry'] = agent()
            except Exception as exc:
                p['telemetry'] = {'error': str(exc), 'flows': [], 'stats': {}}
            return self.send(200, p)
        if self.path == '/api/report.csv':
            with connect() as db:
                rows = db.execute('SELECT ts,action,details FROM audit ORDER BY id DESC LIMIT 10000').fetchall()
            out = io.StringIO()
            writer = csv.writer(out)
            writer.writerow(['timestamp', 'action', 'details'])
            for row in rows:
                writer.writerow([("'" + str(v)) if str(v).startswith(('=', '+', '-', '@')) else v for v in row])
            return self.send(200, out.getvalue(), 'text/csv')
        self.send(404, {'error': 'not found'})

    def do_POST(self):
        self.mutate()

    def do_DELETE(self):
        self.mutate()

    def mutate(self):
        if not self.authorized():
            return
        try:
            length = int(self.headers.get('Content-Length', 0))
            if not 0 <= length <= 16384:
                raise ValueError('invalid request size')
            body = json.loads(self.rfile.read(length)) if length else {}
            if not isinstance(body, dict):
                raise ValueError('request must be a JSON object')
            with LOCK, connect() as db:
                if self.command == 'POST' and self.path == '/api/rules':
                    cidrs, reason, expiry = validate_rule(body)
                    seq = db.execute("SELECT seq FROM sqlite_sequence WHERE name='rules'").fetchone()
                    if (seq[0] if seq else 0) + len(cidrs) >= 4096:
                        raise ValueError('rule ID capacity reached; migration required')
                    existing_networks = [ipaddress.ip_network(r['cidr']) for r in db.execute('SELECT cidr FROM rules WHERE expires_at IS NULL OR expires_at>?', (time.time(),))]
                    for cidr in cidrs:
                        net = ipaddress.ip_network(cidr)
                        if any(net.version == other.version and net.overlaps(other) for other in existing_networks):
                            raise ValueError('overlapping active CIDRs are not supported in this release')
                    for cidr in cidrs:
                        db.execute('INSERT INTO rules(cidr,reason,expires_at) VALUES(?,?,?)', (cidr, reason, expiry))
                elif self.command == 'DELETE' and self.path.startswith('/api/rules/'):
                    ident = int(self.path.rsplit('/', 1)[1])
                    if db.execute('DELETE FROM rules WHERE id=?', (ident,)).rowcount != 1:
                        raise ValueError('rule not found')
                elif self.command == 'POST' and self.path == '/api/config':
                    if type(body.get('enforce')) is not bool:
                        raise ValueError('enforce must be boolean')
                    cfg = {'enforce': body['enforce']}
                    for name in ('udp_pps_cpu', 'syn_pps_cpu'):
                        val = body.get(name, 0)
                        if type(val) is not int or not 0 <= val <= 100000000:
                            raise ValueError('rate limits must be integers between 0 and 100000000')
                        cfg[name] = val
                    db.execute('UPDATE meta SET config=?', (json.dumps(cfg),))
                else:
                    return self.send(404, {'error': 'not found'})
                db.execute('UPDATE meta SET revision=revision+1,error=NULL WHERE id=1')
                db.execute('INSERT INTO audit(ts,action,details) VALUES(?,?,?)', (time.time(), self.command + ' ' + self.path, json.dumps(body)))
            # Async delivery: response never claims the rule is already in the kernel.
            self.send(202, {'status': 'pending'})
        except (ValueError, TypeError, KeyError, sqlite3.IntegrityError) as exc:
            self.send(400, {'error': str(exc)})


def main():
    if len(os.environ.get('API_TOKEN', '')) < 32:
        raise SystemExit('API_TOKEN must have at least 32 characters')
    initialize()
    threading.Thread(target=reconcile_loop, daemon=True).start()
    http.server.ThreadingHTTPServer((os.environ.get('BIND', '127.0.0.1'), int(os.environ.get('PORT', '8080'))), Handler).serve_forever()


if __name__ == '__main__':
    main()
