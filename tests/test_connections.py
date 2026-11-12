import unittest
from agent.service import connections, local_sockets

class ConnectionTests(unittest.TestCase):
    def test_bidirectional_tenant_isolation(self):
        base=dict(src='10.0.0.1',sport=1000,dst='10.0.0.2',dport=443,protocol=6,vlan_outer=None,vlan_inner=None,vni=10,tunnel_src='192.0.2.1',tunnel_dst='192.0.2.2',tcp_flags_seen=2,packets=3,bytes=100)
        reverse=dict(base,src=base['dst'],dst=base['src'],sport=443,dport=1000,tunnel_src=base['tunnel_dst'],tunnel_dst=base['tunnel_src'],tcp_flags_seen=18)
        tenant=dict(base,vni=20)
        result=connections([base,reverse,tenant])
        self.assertEqual(len(result),2)
        self.assertEqual(result[0]['packets'],6)
        self.assertEqual(result[0]['state'],'bidirectional TCP traffic (inferred)')
    def test_socket_table(self):
        self.assertIsInstance(local_sockets(),list)
