#!/usr/bin/env python3
"""Focused archive, full-population and real-operand binding regressions."""
import copy
from pathlib import Path
import unittest
from unittest.mock import patch

import windows_enclave_worker_boundaries as review


def member(name, value):
    return (name.encode().ljust(16)+b'0'.ljust(12)+b'0'.ljust(6)*2+b'0'.ljust(8)+
            str(len(value)).encode().ljust(10)+b'`\n'+value+(b'\n' if len(value)%2 else b''))


class Tests(unittest.TestCase):
    def test_archive_long_names_and_metadata(self):
        raw = b'!<arch>\n'+member('/', b'index')+member('/', b'other')
        raw += member('//', b'worker.o\0path/compiler.o\0')+member('/0', b'abc')+member('/9', b'defg')
        self.assertEqual(review.archive.members(raw), {'worker.o':b'abc', 'path/compiler.o':b'defg'})
        gnu = b'!<arch>\n'+member('//', b'worker.o/\n')+member('/0', b'obj')
        self.assertEqual(review.archive.members(gnu), {'worker.o':b'obj'})

    def test_archive_rejects_truncation_ambiguity_and_bad_offsets(self):
        good = b'!<arch>\n'+member('one.o/', b'abc')
        for cut in range(8, len(good)):
            with self.assertRaises(ValueError): review.archive.members(good[:cut])
        bad = [good+member('one.o/', b'x'), good[:-1]+b'x', b'!<thin>\n'+good[8:],
               b'!<arch>\n'+member('/0', b'x'), b'!<arch>\n'+member('#1/4', b'name'),
               b'!<arch>\n'+member('//', b'one.o\0')+member('/1', b'x'),
               b'!<arch>\n'+member('//', b'one.o')+member('/0', b'x'),
               b'!<arch>\n'+member('//', b'x\0')+member('//', b'y\0')+member('/0', b'x')]
        for raw in bad:
            with self.assertRaises(ValueError): review.archive.members(raw)

    def test_complete_body_and_relocation_pins(self):
        code = b'\xe8\0\0\0\0\xc3'; refs = [dict(offset=1, symbol='PublicXInput', trailing=0, addend=0)]
        pin = dict(bytes=len(code), code_sha256=review.digest(code), refs_sha256=review.digest(review.shared.encoded(refs)))
        review.body_check(code, refs, pin)
        for at in range(len(code)):
            bad = bytearray(code); bad[at] ^= 1
            with self.assertRaises(ValueError): review.body_check(bad, refs, pin)
        for field, value in (('offset',2),('symbol','Other'),('trailing',1),('addend',1)):
            bad = copy.deepcopy(refs); bad[0][field] = value
            with self.assertRaises(ValueError): review.body_check(code, bad, pin)

    def test_full_executable_reference_population(self):
        rows = [dict(flags=0x60000020, code=b'\xe8\0\0\0\0\xc3')]*2
        symbols = {0:dict(section=1,kind=0x20,value=0,name='first'),
                   1:dict(section=2,kind=0x20,value=0,name='second'),
                   2:dict(section=0,kind=0,value=0,name='PublicXInput')}
        refs = {1:dict(symbol=2,kind=4)}
        with patch.object(review.obj,'tables',return_value=(rows,symbols)), patch.object(review.obj,'relocations',return_value=refs):
            self.assertEqual(review.call_population(b''), [['first',1,'PublicXInput'],['second',1,'PublicXInput']])
            for kind in (3,5,9):
                refs[1]['kind'] = kind
                with self.assertRaises(ValueError): review.call_population(b'')
            refs[1]['kind'] = 4
            rows[0] = rows[0] | {'code':b'\xe9\0\0\0\0\xc3'}
            with self.assertRaises(ValueError): review.call_population(b'')

    def test_actual_frame_entry_and_callback_edges(self):
        profile = dict(functions={'RetainedWork':dict(stack_bytes=[40])}, calls=[['RetainedWork',1,'PublicXInput']])
        record = dict(rva=4096,image_sha256='image',unwind=[dict(stack_bytes=40,chain=None,saved_registers=[])],
                      references=[dict(offset=1,symbol='PublicXInput',addend=0,trailing=0)],
                      reference_targets={'PublicXInput':8192})
        parent = dict(retained_worker_rva=4096,image_sha256='image'); targets = {'PublicXInput':8192}
        review.reconcile(profile,{'RetainedWork':record},parent,targets)
        for field,value in (('rva',4097),('image_sha256','other'),('references',[]),
                            ('reference_targets',{'PublicXInput':8193})):
            bad = copy.deepcopy(record); bad[field] = value
            with self.assertRaises(ValueError): review.reconcile(profile,{'RetainedWork':bad},parent,targets)
        for field,value in (('stack_bytes',41),('chain',1),('saved_registers',[1])):
            bad = copy.deepcopy(record); bad['unwind'][0][field] = value
            with self.assertRaises(ValueError): review.reconcile(profile,{'RetainedWork':bad},parent,targets)
        with self.assertRaises(ValueError): review.reconcile(profile,{},parent,targets)

    def test_spec_is_complete_and_tamper_rejected(self):
        path = review.SPEC if review.SPEC.exists() else Path(__file__).with_name(review.SPEC.name)
        raw = path.read_bytes(); spec = review.specification(raw)
        self.assertEqual(len({p['route'] for p in spec['profiles']}),17)
        self.assertEqual(sum(len(p['calls']) for p in spec['profiles']),97)
        for p in spec['profiles']:
            self.assertEqual(set(p['functions']), {n for n,_,_ in p['calls']} | {'RetainedWork'})
        with self.assertRaises(ValueError): review.specification(raw+b' ')


if __name__ == '__main__': unittest.main()
