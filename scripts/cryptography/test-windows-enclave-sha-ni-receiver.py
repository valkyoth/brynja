"""Receiver semantic checks independent of body/IR review pins."""
import unittest
from unittest.mock import patch

import windows_enclave_sha_ni_receiver as r


class Tests(unittest.TestCase):
    def test_length_readback_dispatch_and_export_mutants(self):
        code = bytearray(638);sites = {}
        for at,h in r.SEGMENTS:
            for i,b in enumerate(bytes.fromhex(h),at):
                if i in sites: self.assertEqual(sites[i],b)
                sites[i] = b;code[i] = b
        r.instructions(code)
        for at in sites:
            bad = code.copy();bad[at] ^= 1
            with self.assertRaises(ValueError): r.instructions(bad)
        self.assertGreater(len(sites),560)

    def test_both_table_bases_and_every_entry(self):
        start,address = 4096,8192
        raw = b''.join((start+t-address-(0 if i<6 else 24)).to_bytes(4,'little',signed=True)
                       for i,t in enumerate(r.TARGETS))
        self.assertEqual(r.table_targets(raw,address,start),r.TARGETS)
        for i in range(52):
            bad = bytearray(raw);bad[i] ^= 1
            with self.assertRaises(ValueError): r.table_targets(bad,address,start)
        for bad in (raw[:-1],raw+b'\0'):
            with self.assertRaises(ValueError): r.table_targets(bad,address,start)
        for delta in (1,24,-24):
            with self.assertRaises(ValueError): r.table_targets(raw,address+delta,start)

    def test_ir_length_preconditions_not_assumed_from_source(self):
        text = ''.join('define internal fastcc i8 @'+r.life.PREFIX+s+
                       '(ptr %0, i64 %1, ptr %2, i64 noundef range(i64 0, 1025) %3) {\n'
                       for s in ('6update','6finish'))
        raw = text.encode()
        with patch.object(r,'IR_HASH',r.digest(raw)):
            result = r.preconditions(raw)
            self.assertFalse(result['standalone_length_checks_claimed'])
            with self.assertRaises(ValueError): r.preconditions(raw+b' ')
        for bad in ('',text*2,text.replace('internal ',''),text.replace('1025','2049'),
                    text.replace('6finish','6other')):
            raw = bad.encode()
            with patch.object(r,'IR_HASH',r.digest(raw)):
                with self.assertRaises(ValueError): r.preconditions(raw)


if __name__ == '__main__': unittest.main()
