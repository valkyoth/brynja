"""Cross-image runtime normalization and mapping regressions."""
import struct
import unittest
from unittest.mock import patch

import windows_enclave_route_memory as r


def synthetic(delta):
    result = {n:bytearray(size) for n,(_,size,_) in r.prior.BODIES.items()}
    targets = {0:0,**{n:n+0x2000 for n in r.SELECTORS}}
    for n,a,p,t,s in r.prior.RIP_READS:
        at=a-r.prior.BODIES[n][0];p,s=bytes.fromhex(p),bytes.fromhex(s)
        raw=p+struct.pack('<i',targets[t]-a-delta-len(p)-4-len(s))+s
        result[n][at:at+len(raw)]=raw
    for n,a,t,small in r.prior.DISPATCH:
        at=a-r.prior.BODIES[n][0]
        raw=bytes.fromhex('478b8c82' if small else '478b9c9a')+struct.pack('<I',t+0x1000)
        raw+=bytes.fromhex('4d03ca41ffe1' if small else '4d03da41ffe3')
        result[n][at:at+len(raw)]=raw
    return {n:bytes(b) for n,b in result.items()},targets


class Tests(unittest.TestCase):
    def test_complete_normalization_and_all_body_mutations(self):
        bodies,targets=synthetic(-1000)
        with patch.object(r.prior,'check_bodies'),patch.object(r.prior,'check_instructions'):
            normalized,actual,tables=r.normalize(bodies,-1000)
        self.assertEqual(actual,targets)
        self.assertEqual(tables,{t:t+0x1000 for t in r.prior.TABLES})
        specs={n:(r.prior.BODIES[n][0],len(b),r.digest(b)) for n,b in normalized.items()}
        with patch.dict(r.prior.BODIES,specs),patch.object(r.prior,'check_instructions'):
            r.normalize(bodies,-1000)
            for n,b in bodies.items():
                for i in range(len(b)):
                    bad=bytearray(b);bad[i]^=1
                    try:
                        _,t,v=r.normalize(bodies | {n:bytes(bad)},-1000)
                        self.assertNotEqual((t,v),(targets,tables))
                    except ValueError: pass
            for bad in ({},bodies | {'extra':b''},bodies | {'copy':bodies['copy'][:-1]}):
                with self.assertRaises(ValueError): r.normalize(bad,-1000)
            with self.assertRaises(ValueError): r.normalize(bodies,True)

    def test_tables_reject_every_byte_and_bad_permissions(self):
        delta=-1000;addresses={a:a+0x1000 for a in r.prior.TABLES}
        raw=b''.join(struct.pack('<16I',*(v+delta for v in values)) for values in r.prior.TABLES.values())
        row=dict(rva=min(addresses.values()),virtual_size=512,code=raw,flags=0x40000040)
        self.assertEqual(len(r.mapped_tables([row],addresses,delta)),8)
        for i in range(len(raw)):
            bad=bytearray(raw);bad[i]^=1
            with self.assertRaises(ValueError): r.mapped_tables([row | {'code':bytes(bad)}],addresses,delta)
        for rows in ([],[row,row],[row | {'virtual_size':511}],[row | {'code':raw[:-1]}],
                     [row | {'flags':0xc0000040}],[row | {'flags':0x60000040}]):
            with self.assertRaises(ValueError): r.mapped_tables(rows,addresses,delta)
        with self.assertRaises(ValueError): r.mapped_tables([row],{},delta)

    def test_selector_spans_and_aliases(self):
        targets={0:0,**{n:n+0x2000 for n in r.SELECTORS}}
        row=dict(rva=0x13000,virtual_size=0x1000,flags=0xc0000040)
        self.assertTrue(all(not v['live_value_established'] for v in r.selectors([row],targets)))
        for rows in ([],[row,row],[row | {'flags':0xe0000040}],[row | {'flags':0x40000040}],
                     [row | {'virtual_size':100}]):
            with self.assertRaises(ValueError): r.selectors(rows,targets)
        with self.assertRaises(ValueError): r.selectors([row],targets | {0x11068:targets[0x11060]})

    def test_unknown_artifacts_and_catalog_fail_closed(self):
        for fill in (0,-1,True,1<<32):
            with self.assertRaises(ValueError): r.inspect(b'bad',fill)
        with self.assertRaises(ValueError): r.inspect(b'bad',10000)
        with self.assertRaises(ValueError): r.collect(None,b'[]')


if __name__ == '__main__': unittest.main()
