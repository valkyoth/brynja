"""Exact scalar SHA-2 memory/export caller regression checks."""
import copy
import unittest
from unittest.mock import patch

import windows_enclave_sha2_connections as r


class Tests(unittest.TestCase):
    def test_incoming_population_cannot_be_subset_or_relabelled(self):
        calls=[('function',i,'memcpy') for i in range(40)]
        with patch.object(r,'MEMORY_POPULATION',r.digest(r.shared.encoded(calls))):
            r.population(calls,r.CALLBACKS)
            for bad in (calls[:-1],calls+[calls[0]],list(reversed(calls))):
                with self.assertRaises(ValueError): r.population(bad,r.CALLBACKS)
            for bad in (r.CALLBACKS[:-1],r.CALLBACKS+[r.CALLBACKS[0]],list(reversed(r.CALLBACKS))):
                with self.assertRaises(ValueError): r.population(calls,bad)

    def test_actual_reference_offset_target_and_inventory(self):
        calls=[('one',1,'memcpy'),('two',7,'PublicSha2Output')];targets={'memcpy':1,'PublicSha2Output':2}
        bindings={n:dict(reference_targets={c:targets[c]},references=[dict(offset=at,symbol=c,addend=0,trailing=0)]) for n,at,c in calls}
        r.reconcile(calls,bindings,targets)
        for n,_,_ in calls:
            for delta in ({'offset':99},{'symbol':'other'},{'addend':1},{'trailing':1}):
                bad=copy.deepcopy(bindings);bad[n]['references'][0].update(delta)
                with self.assertRaises(ValueError): r.reconcile(calls,bad,targets)
            bad=copy.deepcopy(bindings);bad[n]['references']*=2
            with self.assertRaises(ValueError): r.reconcile(calls,bad,targets)
        for bad in ({},bindings | {'extra':bindings['one']}):
            with self.assertRaises(ValueError): r.reconcile(calls,bad,targets)
        with self.assertRaises(ValueError): r.reconcile(calls,bindings,targets | {'memcpy':3})

    def test_all_executable_sections_and_direct_callbacks(self):
        obj=r.entry.obj;row=dict(flags=0x60000020,code=b'\xe8'+bytes(4))
        sy={0:dict(name='caller',section=1,kind=32,value=0),1:dict(name='PublicSha2Input',section=0,kind=0,value=0)}
        refs={1:dict(symbol=1,kind=4)}
        with patch.object(obj,'tables',return_value=([row],sy)),patch.object(obj,'relocations',return_value=refs):
            self.assertEqual(r.callback_population(b'object'),[('caller',1,'PublicSha2Input')])
            for bad in (row | {'code':b'\xe9'+bytes(4)},row | {'code':b'\xe8\1'+bytes(3)}):
                with patch.object(obj,'tables',return_value=([bad],sy)):
                    with self.assertRaises(ValueError): r.callback_population(b'object')
            with patch.dict(refs,{1:dict(symbol=1,kind=5)}):
                with self.assertRaises(ValueError): r.callback_population(b'object')
            with patch.object(obj,'tables',return_value=([row],sy | {2:sy[0]})):
                with self.assertRaises(ValueError): r.callback_population(b'object')

    def test_fixed_known_depth_without_runtime_self_erasure_claim(self):
        result=r.geometry(r.primitives.bounded.Window(0,65536))
        for low in (4096,0x700000000000):self.assertEqual(result,r.geometry(r.primitives.bounded.Window(low,low+65536)))
        self.assertEqual(result['output_adapter_rsp_from_high'],-2672)
        self.assertEqual(result['sdk_copy_rsp_from_high'],-2720)
        self.assertEqual(result['primitive_depth'],-5416)
        self.assertFalse(result['payload_registers_erased_by_runtime'])
        self.assertFalse(result['maximum_whole_image_depth_qualified'])


if __name__=='__main__':unittest.main()
