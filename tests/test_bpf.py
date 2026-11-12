"""Kernel-executed packet fixtures. Set BPF_TEST_ROOT after loading programs."""
import ipaddress
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import time
import unittest
from agent.service import Maps


def ethernet(payload, proto=0x0800, tags=()):
    data = bytes.fromhex('00112233445566778899aabb')
    for i, tag in enumerate(tags):
        data += struct.pack('!HH', 0x88a8 if i == 0 and len(tags) == 2 else 0x8100, tag)
    return data + struct.pack('!H', proto) + payload


def packet(src='192.0.2.1', dst='198.51.100.1', protocol=17, tags=(), payload=None, flags=2):
    ip = ipaddress.ip_address(src)
    if payload is None:
        payload = struct.pack('!HHHH',12345,443,8,0) if protocol == 17 else struct.pack('!HHIIBBHHH',12345,443,0,0,0x50,flags,4096,0,0)
    if ip.version == 4:
        header = struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(payload),0,0,64,protocol,0,ip.packed,ipaddress.ip_address(dst).packed)
    else:
        header = struct.pack('!IHBB16s16s',6<<28,len(payload),protocol,64,ip.packed,ipaddress.ip_address(dst).packed)
    return ethernet(header+payload,0x0800 if ip.version == 4 else 0x86dd,tags)


@unittest.skipUnless(os.environ.get('BPF_TEST_ROOT'), 'requires isolated privileged BPF runner')
class BPFTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(os.environ['BPF_TEST_ROOT'])
        self.maps = Maps(str(self.root/'maps'))
        for name in ('block4','block6','flows'):
            for row in self.maps.dump(name):
                from agent.service import raw
                self.maps.delete(name,raw(row['key']))
        self.configure()

    def configure(self,enforce=True,udp=0,syn=0):
        self.maps.update('settings',bytes(4),struct.pack('<IIII',enforce,udp,syn,0))

    def block(self,cidr,expires=0):
        net=ipaddress.ip_network(cidr)
        self.maps.update(f'block{net.version}',struct.pack('<I',net.prefixlen)+net.network_address.packed,struct.pack('<QII',expires,1,0))

    def run_packet(self,data,program='ingress',repeat=1):
        with tempfile.NamedTemporaryFile() as file:
            file.write(data);file.flush()
            result=subprocess.run(['bpftool','-j','prog','run','pinned',str(self.root/'progs'/program),'data_in',file.name,'repeat',str(repeat)],check=True,capture_output=True,text=True)
            return json.loads(result.stdout)['retval']

    def test_ipv4_ipv6_cidr(self):
        for cidr,src,dst in [('192.0.2.0/24','192.0.2.9','198.51.100.1'),('2001:db8::/32','2001:db8::5','2001:db9::1')]:
            self.block(cidr)
            self.assertEqual(self.run_packet(packet(src,dst)),1)
        self.assertEqual(self.run_packet(packet('203.0.113.1')),2)

    def test_observe_and_expiry(self):
        self.block('192.0.2.0/24')
        self.configure(False)
        self.assertEqual(self.run_packet(packet()),2)
        self.configure()
        self.block('192.0.2.0/24',time.monotonic_ns()-1)
        self.assertEqual(self.run_packet(packet()),2)

    def test_vlan_qinq_and_flow_decode(self):
        for tags in [(),(100,),(200,100)]:
            self.assertEqual(self.run_packet(packet(tags=tags)),2)
        flows=self.maps.snapshot()['flows']
        self.assertEqual(len(flows),3)
        self.assertTrue(any(f['vlan_outer']==200 and f['vlan_inner']==100 for f in flows))

    def test_vxlan_inner_policy_and_identity(self):
        inner=packet('10.0.0.1','10.0.0.2',tags=(77,))
        vx=bytes([8,0,0,0,0,0,42,0])+inner
        udp=struct.pack('!HHHH',50000,4789,len(vx)+8,0)+vx
        outer=packet(payload=udp,tags=(200,100))
        self.assertEqual(self.run_packet(outer),2)
        flow=self.maps.snapshot()['flows'][0]
        self.assertEqual((flow['vni'],flow['src'],flow['overlay_outer']),(42,'10.0.0.1',77))
        self.block('10.0.0.0/24')
        self.assertEqual(self.run_packet(outer),1)

    def test_malformed_and_unsupported(self):
        self.assertEqual(self.run_packet(ethernet(bytes(20))),1)
        self.assertEqual(self.run_packet(ethernet(bytes(28),0x0806)),2)
        bad=bytearray(packet()); bad[14+20+4:14+20+6]=struct.pack('!H',999)
        self.assertEqual(self.run_packet(bad),1)

    def test_udp_and_syn_budgets(self):
        self.configure(udp=1,syn=1)
        self.assertEqual(self.run_packet(packet(),repeat=100),1)
        self.assertEqual(self.run_packet(packet(protocol=6),repeat=100),1)
        self.configure(False,1,1)
        self.assertEqual(self.run_packet(packet(),repeat=100),2)

    def test_tc_egress(self):
        self.assertEqual(self.run_packet(packet(protocol=6,flags=18),'egress'),0)
        flow=self.maps.snapshot()['flows'][0]
        self.assertEqual(flow['direction'],'egress')
        self.assertEqual(flow['tcp_flags_seen'],18)

    def test_fragment_still_obeys_source_block(self):
        fragmented = bytearray(packet())
        fragmented[20:22] = struct.pack('!H',0x2000)
        self.assertEqual(self.run_packet(fragmented),2)
        self.block('192.0.2.0/24')
        self.assertEqual(self.run_packet(fragmented),1)

    def test_ipv6_extension_still_obeys_source_block(self):
        extended = packet('2001:db8::1','2001:db9::1',protocol=0,payload=bytes(8))
        self.assertEqual(self.run_packet(extended),2)
        self.block('2001:db8::/32')
        self.assertEqual(self.run_packet(extended),1)
