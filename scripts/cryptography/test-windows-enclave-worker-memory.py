#!/usr/bin/env python3
"""Memory-call population must respect actual runtime ranges, not section names."""
import unittest
from unittest.mock import patch

import windows_enclave_worker_memory as review


class Tests(unittest.TestCase):
    def fixture(self):
        rows = [dict(flags=0x60000020,code=b'\xe8'+bytes(4)+b'\xc3\x90\x90\xe9'+bytes(4)+b'\xc3')]
        symbols = {0:dict(name='main',section=1,kind=0x20,value=0),
                   1:dict(name='cleanup',section=1,kind=0x20,value=8),
                   2:dict(name='memcpy',section=0,kind=0,value=0),
                   3:dict(name='memset',section=0,kind=0,value=0)}
        ranges = [dict(section=1,start=0,end=6),dict(section=1,start=8,end=14)]
        refs = {1:dict(symbol=2,kind=4),9:dict(symbol=3,kind=4)}
        return rows,symbols,ranges,refs

    def run_fixture(self,fixture):
        rows,symbols,ranges,refs = fixture
        with patch.object(review.obj,'tables',return_value=(rows,symbols)), \
             patch.object(review.obj,'ranges',return_value=ranges), \
             patch.object(review.obj,'relocations',return_value=refs):
            return review.population(b'')

    def test_main_and_interior_cleanup_calls_are_both_counted(self):
        self.assertEqual(self.run_fixture(self.fixture()),[['cleanup',1,'memset'],['main',1,'memcpy']])

    def test_incomplete_overlapping_or_cross_boundary_ranges_rejected(self):
        for change in ('missing','overlap','cut','alias','gap'):
            rows,symbols,ranges,refs = self.fixture()
            if change == 'missing': ranges.pop()
            if change == 'overlap': ranges.append(dict(section=1,start=8,end=14))
            if change == 'cut': ranges[1]['end'] = 12
            if change == 'alias': symbols[4] = symbols[1].copy()
            if change == 'gap': ranges[1]['start'] = 9
            with self.assertRaises(ValueError): self.run_fixture((rows,symbols,ranges,refs))

    def test_indirect_or_added_offset_is_not_a_direct_call(self):
        for change in ('opcode','addend','trailing'):
            rows,symbols,ranges,refs = self.fixture()
            if change == 'opcode': rows[0]['code'] = b'\xff'+rows[0]['code'][1:]
            if change == 'addend': rows[0]['code'] = b'\xe8\1'+rows[0]['code'][2:]
            if change == 'trailing': refs[1]['kind'] = 5
            with self.assertRaises(ValueError): self.run_fixture((rows,symbols,ranges,refs))

    def test_ambiguous_bytes_require_an_actual_incoming_anchor(self):
        def binder(data,image,name,anchors):
            if name == 'a' and not any(r['reference_targets'].get('a') == 42 for r in anchors):
                raise ValueError('ambiguous a')
            return dict(entry=name,reference_targets={'a':42} if name=='b' else {})
        with patch.object(review.handlers,'bind',side_effect=binder):
            records = review.bind_callers(b'',b'',{'a','b'})
            self.assertEqual(set(records),{'a','b'})
        with patch.object(review.handlers,'bind',side_effect=ValueError('no anchor')):
            with self.assertRaises(ValueError): review.bind_callers(b'',b'',{'a','b'})

    def test_caller_population_and_destinations_cannot_be_omitted(self):
        calls=[['a',1,'memcpy'],['b',4,'memset']]
        records={'a':dict(reference_targets={'memcpy':10}),'b':dict(reference_targets={'memset':20})}
        review.reconcile(calls,records,{'memcpy':10,'memset':20})
        with self.assertRaises(ValueError): review.reconcile(calls,{'a':records['a']},{'memcpy':10,'memset':20})
        with self.assertRaises(ValueError): review.reconcile(calls,records,{'memcpy':11,'memset':20})


if __name__ == '__main__': unittest.main()
