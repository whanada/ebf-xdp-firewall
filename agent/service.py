#!/usr/bin/env python3
"""Local root-owned Unix socket service; only this process writes BPF maps."""
import argparse
import http.server
import ipaddress
import json
import os
import socketserver
import struct
import subprocess
import time


def raw(value):
    return bytes(int(x, 16) if isinstance(x, str) else x for x in value)


class Maps:
    def __init__(self, root):
        self.root = root

    def run(self, *args):
        result = subprocess.run(['bpftool', '-j', *args], check=True, capture_output=True, text=True, timeout=15)
        return json.loads(result.stdout) if result.stdout.strip() else None

    def dump(self, name):
        return self.run('map', 'dump', 'pinned', f'{self.root}/{name}') or []

    def update(self, name, key, value):
        self.run('map', 'update', 'pinned', f'{self.root}/{name}', 'key', 'hex', *[f'{b:02x}' for b in key], 'value', 'hex', *[f'{b:02x}' for b in value])

    def delete(self, name, key):
        self.run('map', 'delete', 'pinned', f'{self.root}/{name}', 'key', 'hex', *[f'{b:02x}' for b in key])

    def reconcile(self, policy):
        # Validate everything before making any mutation.
        desired = {'block4': {}, 'block6': {}}
        now = time.time()
        for rule in policy['rules']:
            net = ipaddress.ip_network(rule['cidr'], strict=True)
            if not 1 <= rule['id'] < 4096:
                raise ValueError('rule ID out of range')
            expires = rule.get('expires_at')
            if expires is not None and expires <= now:
                continue
            deadline = 0 if expires is None else time.monotonic_ns() + int((expires - now) * 1e9)
            key = struct.pack('<I', net.prefixlen) + net.network_address.packed
            desired[f'block{net.version}'][key] = struct.pack('<QII', deadline, rule['id'], 0)
        cfg = policy['config']
        limits = [cfg.get('udp_pps_cpu', 0), cfg.get('syn_pps_cpu', 0)]
        if any(type(v) is not int or not 0 <= v <= 100000000 for v in limits):
            raise ValueError('invalid rate limit')
        config = struct.pack('<IIII', int(bool(cfg['enforce'])), *limits, 0)
        # Add/update before removing stale entries. No atomic multi-map commit.
        for name, entries in desired.items():
            existing = {raw(row['key']) for row in self.dump(name)}
            for key, value in entries.items():
                self.update(name, key, value)
            for key in existing - entries.keys():
                self.delete(name, key)
        self.update('settings', bytes(4), config)

    def snapshot(self):
        stats = {}
        for row in self.dump('stats'):
            idx = struct.unpack('<I', raw(row['key']))[0]
            counts = [struct.unpack('<QQ', raw(v['value'])) for v in row.get('values', [])]
            stats[idx] = {'packets': sum(c[0] for c in counts), 'bytes': sum(c[1] for c in counts)}
        flows = []
        now = time.monotonic_ns()
        for row in self.dump('flows'):
            key, val = raw(row['key']), raw(row['value'])
            src, dst, sport, dport, outer, inner, vni, family, proto, direction, tagged, tsrc, tdst, ovouter, ovinner, ovtagged, tfamily = struct.unpack('<16s16sHHHHIBBBB16s16sHHBB2x', key)
            first, last, packets, size, flags, _ = struct.unpack('<QQQQII', val)
            if now - last > 120 * 1000000000:
                continue
            n = 4 if family == 4 else 16
            flows.append(dict(src=str(ipaddress.ip_address(src[:n])), dst=str(ipaddress.ip_address(dst[:n])), sport=sport, dport=dport, protocol=proto, direction='egress' if direction else 'ingress', vlan_outer=outer if tagged else None, vlan_inner=inner if tagged > 1 else None, vni=vni if tfamily else None, tunnel_src=str(ipaddress.ip_address(tsrc[:4 if tfamily == 4 else 16])) if tfamily else None, tunnel_dst=str(ipaddress.ip_address(tdst[:4 if tfamily == 4 else 16])) if tfamily else None, overlay_outer=ovouter if ovtagged else None, overlay_inner=ovinner if ovtagged > 1 else None, tcp_flags_seen=flags, packets=packets, bytes=size, age_seconds=(now-first)/1e9, idle_seconds=(now-last)/1e9, state='observed; TCP state not confirmed'))
        return {'stats': stats, 'flows': flows[:2000], 'active_records': len(flows), 'flow_limit': 65536, 'flow_view_limit': 2000, 'vlan_metadata': 'packet bytes only; stripped tags unavailable', 'packet_counts': 'hook observations; egress GSO may differ from wire packets'}


class Server(socketserver.UnixStreamServer):
    allow_reuse_address = True


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.reply(self.server.maps.snapshot)

    def do_POST(self):
        def apply():
            length = int(self.headers.get('Content-Length', 0))
            if not 0 < length <= 1048576:
                raise ValueError('invalid policy size')
            self.server.maps.reconcile(json.loads(self.rfile.read(length)))
            return {'applied': True}
        self.reply(apply)

    def reply(self, fn):
        try:
            payload, code = fn(), 200
        except Exception as exc:
            payload, code = {'error': str(exc)}, 503
        data = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--maps', required=True)
    parser.add_argument('--socket', default='/run/xdp-firewall/agent.sock')
    args = parser.parse_args()
    if os.path.exists(args.socket):
        os.unlink(args.socket)
    os.umask(0o007)
    with Server(args.socket, Handler) as server:
        server.maps = Maps(args.maps)
        server.serve_forever()


if __name__ == '__main__':
    main()
