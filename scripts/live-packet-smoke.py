"""Inject a packet into the disposable veth peer and check live XDP counters."""
import socket
import struct
import sys
import time
from agent.service import Maps
from tests.test_bpf import packet
maps=Maps(sys.argv[1])
# Keep observation mode for the first live packet.
maps.update('settings',bytes(4),struct.pack('<IIII',0,0,0,0))
with socket.socket(socket.AF_PACKET,socket.SOCK_RAW) as sock:
    sock.bind(('fwtest1',0))
    sock.send(packet())
    time.sleep(.1)
    assert maps.snapshot()['stats'][0]['packets'] >= 1
    maps.update('block4',struct.pack('<I',24)+bytes([192,0,2,0]),struct.pack('<QII',0,1,0))
    maps.update('settings',bytes(4),struct.pack('<IIII',1,0,0,0))
    sock.send(packet())
    time.sleep(.1)
    assert maps.snapshot()['stats'][8]['packets'] >= 1
print('PASS: live veth packet passes in observation mode and drops under CIDR enforcement')
