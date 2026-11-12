import struct
import time
import unittest
from agent.service import Maps


class FakeMaps(Maps):
    def __init__(self):
        self.data = {'block4':{},'block6':{},'settings':{}}
    def dump(self, name):
        return [{'key':list(k),'value':list(v)} for k,v in self.data[name].items()]
    def update(self, name, key, value):
        self.data[name][key] = value
    def delete(self, name, key):
        del self.data[name][key]


class AgentTests(unittest.TestCase):
    def test_reconcile_expiry_and_removal(self):
        maps = FakeMaps()
        cfg = {'enforce':True}
        maps.reconcile({'config':cfg,'rules':[{'cidr':'192.0.2.0/24','id':1,'expires_at':time.time()+60}]})
        self.assertEqual(len(maps.data['block4']),1)
        deadline, ident, pad = struct.unpack('<QII',next(iter(maps.data['block4'].values())))
        self.assertGreater(deadline,time.monotonic_ns())
        self.assertEqual(ident,1)
        maps.reconcile({'config':cfg,'rules':[{'cidr':'192.0.2.0/24','id':1,'expires_at':time.time()-1}]})
        self.assertEqual(maps.data['block4'],{})

    def test_invalid_policy_has_no_partial_mutation(self):
        maps = FakeMaps()
        with self.assertRaises(ValueError):
            maps.reconcile({'config':{'enforce':True},'rules':[{'cidr':'192.0.2.0/24','id':1},{'cidr':'bad','id':2}]})
        self.assertFalse(maps.data['block4'])
