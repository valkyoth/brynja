"""Offline relocation/caller/stack regressions; not native runtime execution."""
import struct
import unittest
from unittest.mock import patch

import windows_enclave_bounded_memory as r


def bodies():
    result = {n:bytearray(size) for n,(_,size,_) in r.prior.BODIES.items()}
    sites = []
    for n,address,prefix,target,suffix in r.prior.RIP_READS:
        at = address-r.prior.BODIES[n][0];p,s = bytes.fromhex(prefix),bytes.fromhex(suffix)
        raw = p+struct.pack('<i',r.TARGETS[target]-address-r.DELTA-len(p)-4-len(s))+s
        result[n][at:at+len(raw)] = raw;sites.extend((n,i) for i in range(at,at+len(raw)))
    for n,address,table,small in r.prior.DISPATCH:
        at = address-r.prior.BODIES[n][0]
        raw = bytes.fromhex('478b8c82' if small else '478b9c9a')+struct.pack('<I',table+r.TABLE_DELTA)
        raw += bytes.fromhex('4d03ca41ffe1' if small else '4d03da41ffe3')
        result[n][at:at+len(raw)] = raw;sites.extend((n,i) for i in range(at,at+len(raw)))
    return {n:bytes(b) for n,b in result.items()},sites


class Tests(unittest.TestCase):
    def test_validate_before_normalizing_every_operand_and_instruction(self):
        actual,sites = bodies();normalized = r.normalize(actual)
        self.assertEqual(set(normalized),set(r.prior.BODIES))
        for n,a,p,t,s in r.prior.RIP_READS:
            at = a-r.prior.BODIES[n][0]+len(bytes.fromhex(p));end = a+len(bytes.fromhex(p))+4+len(bytes.fromhex(s))
            self.assertEqual(int.from_bytes(normalized[n][at:at+4],'little',signed=True)+end,t)
        for n,a,t,_ in r.prior.DISPATCH:
            at = a-r.prior.BODIES[n][0]+4
            self.assertEqual(int.from_bytes(normalized[n][at:at+4],'little'),t)
        for n,i in sites:
            changed = bytearray(actual[n]);changed[i] ^= 1
            with self.assertRaises(ValueError): r.normalize(actual | {n:bytes(changed)})
        # Normalization must not discard unrelated bytes or unknown differences.
        changed = bytearray(actual['copy']);changed[0] = 0x42
        self.assertEqual(r.normalize(actual | {'copy':bytes(changed)})['copy'][0],0x42)
        for wrong in ({},actual | {'extra':b''},actual | {'copy':actual['copy'][:-1]}):
            with self.assertRaises(ValueError): r.normalize(wrong)

    def test_exact_normalized_identity_and_raw_pin_both_required(self):
        actual,_ = bodies();normalized = r.normalize(actual)
        specs = {n:(r.prior.BODIES[n][0],len(b),r.digest(b)) for n,b in normalized.items()}
        hashes = {n:r.digest(b) for n,b in actual.items()}
        # Only semantic landmarks are omitted from this synthetic full-body test.
        with patch.dict(r.prior.BODIES,specs),patch.dict(r.HASHES,hashes),patch.object(r.prior,'check_instructions'):
            r.check_bodies(actual)
            for n,body in actual.items():
                for i in range(len(body)):
                    changed = bytearray(body);changed[i] ^= 1
                    with self.assertRaises(ValueError): r.check_bodies(actual | {n:bytes(changed)})
            with patch.dict(r.HASHES,{'copy':'bad'}):
                with self.assertRaises(ValueError): r.check_bodies(actual)

    def test_tables_all_bytes_and_mapping(self):
        raw = b''.join(struct.pack('<16I',*(v+r.DELTA for v in values)) for values in r.prior.TABLES.values())
        row = dict(rva=0x8390,virtual_size=len(raw),code=raw,flags=0x40000040)
        self.assertEqual(len(r.tables([row])),8)
        for i in range(len(raw)):
            changed = bytearray(raw);changed[i] ^= 1
            with self.assertRaises(ValueError): r.tables([row | {'code':bytes(changed)}])
        for rows in ([],[row,row],[row | {'flags':0xc0000040}],[row | {'flags':0x60000040}],
                     [row | {'virtual_size':511}],[row | {'code':raw[:-1]}]):
            with self.assertRaises(ValueError): r.tables(rows)

    def test_exact_frames_and_raw_v2_unwind_without_semantics_claim(self):
        entries = {(r.UNWIND[n],raw) for n,(_,raw,_) in r.prior.UNWIND.items()}
        rows = [dict(rva=a,virtual_size=len(bytes.fromhex(h)),code=bytes.fromhex(h),flags=0x40000040)
                for a,h in sorted(entries)]
        fs = [(a+r.DELTA,a+r.DELTA+size,r.UNWIND[n]) for n,(a,size,_) in r.prior.BODIES.items()]
        self.assertTrue(all(not v['unwind_semantics_qualified'] for v in r.frames(rows,fs).values()))
        for index,row in enumerate(rows):
            for i in range(len(row['code'])):
                changed = bytearray(row['code']);changed[i] ^= 1
                with self.assertRaises(ValueError): r.frames(rows[:index]+[row | {'code':bytes(changed)}]+rows[index+1:],fs)
        for index,(a,b,u) in enumerate(fs):
            for replacement in ([],[(a,b,u),(a,b,u)],[(a+1,b,u)],[(a,b-1,u)],[(a,b,u+1)]):
                with self.assertRaises(ValueError): r.frames(rows,fs[:index]+replacement+fs[index+1:])

    def test_mutable_selector_mapping_without_live_value_claim(self):
        row = dict(rva=0xa000,virtual_size=0x1000,flags=0xc0000040)
        self.assertEqual(len(r.selectors([row])),4)
        self.assertTrue(all(not v['live_value_established'] for v in r.selectors([row])))
        for rows in ([],[row,row],[row | {'flags':0xe0000040}],[row | {'flags':0x40000040}],
                     [row | {'virtual_size':0x88c}],[row,row | {'rva':0xa061,'virtual_size':1}]):
            with self.assertRaises(ValueError): r.selectors(rows)

    def test_all_executable_relocations_not_just_preselected_callers(self):
        row = dict(flags=0x60000020,code=b'\xe8'+bytes(4))
        symbols = {0:dict(name='caller',section=1,kind=0x20,value=0),1:dict(name='memcpy',section=0,kind=0,value=0)}
        refs = {1:dict(symbol=1,kind=4)}
        with patch.object(r.dispatch.obj,'tables',return_value=([row],symbols)),patch.object(r.dispatch.obj,'relocations',return_value=refs):
            self.assertEqual(r.call_population(b'object'),[('caller',1,'memcpy')])
            for wrong in (row | {'code':b'\xe9'+bytes(4)},row | {'code':b'\xe8\x01'+bytes(3)}):
                with patch.object(r.dispatch.obj,'tables',return_value=([wrong],symbols)):
                    with self.assertRaises(ValueError): r.call_population(b'object')
            with patch.dict(refs,{1:dict(symbol=1,kind=5)}):
                with self.assertRaises(ValueError): r.call_population(b'object')
            for sym in (symbols | {2:symbols[0]},symbols | {0:symbols[0] | {'value':1}}):
                with patch.object(r.dispatch.obj,'tables',return_value=([row],sym)):
                    with self.assertRaises(ValueError): r.call_population(b'object')

    def test_window_geometry_and_limits(self):
        value = r.geometry(r.dispatch.Window(0,65536))
        self.assertEqual([v['deepest_memory_rsp_from_high'] for v in value['callers'].values()],[-3000,-3080])
        self.assertFalse(value['payload_registers_erased'])
        self.assertFalse(value['individual_saved_register_slots_erased'])
        self.assertFalse(value['maximum_whole_image_depth_qualified'])
        self.assertTrue(value['outer_window_and_return_cleanup_required'])
        for low in (4096,0x700000000000): self.assertEqual(value,r.geometry(r.dispatch.Window(low,low+65536)))

    def test_caller_population_arguments_and_destinations(self):
        population = sorted((name,at,sym) for name,calls in r.CALLS.items() for at,sym in calls)
        code = {}
        for name,sites in r.ARGUMENTS.items():
            body = bytearray(2000)
            for at,h in sites: body[at:at+len(bytes.fromhex(h))] = bytes.fromhex(h)
            code[name] = bytes(body)
        targets = {'memcpy':24272,'memset':26000}
        with patch.object(r,'call_population',side_effect=lambda obj:population if obj == b'rust' else []), \
             patch.object(r.shared.caller,'function',side_effect=lambda obj,n:(code[n],[])), \
             patch.object(r.shared.caller,'bind',side_effect=lambda *args:dict(rva=1,reference_targets=targets)), \
             patch.object(r.rehash,'body_check'),patch.object(r.borrowed,'body_check'):
            self.assertEqual(len(r.incoming(b'rust',b'c',b'image')),2)
            for symbol in targets:
                with patch.dict(targets,{symbol:targets[symbol]+1}):
                    with self.assertRaises(ValueError): r.incoming(b'rust',b'c',b'image')
            for name,sites in r.ARGUMENTS.items():
                for at,h in sites:
                    for i in range(len(bytes.fromhex(h))):
                        changed = bytearray(code[name]);changed[at+i] ^= 1
                        with patch.dict(code,{name:bytes(changed)}):
                            with self.assertRaises(ValueError): r.incoming(b'rust',b'c',b'image')
            for bad in (population[:-1],population+[('unexpected',1,'memset')]):
                with patch.object(r,'call_population',return_value=bad):
                    with self.assertRaises(ValueError): r.incoming(b'rust',b'c',b'image')
            with patch.object(r,'call_population',return_value=population):
                with self.assertRaises(ValueError): r.incoming(b'rust',b'c',b'image')

    def test_invalid_artifact_identity_fails_before_review(self):
        with patch.object(r.shared.caller,'pe',side_effect=AssertionError('parsed')):
            with self.assertRaises(ValueError): r.inspect(b'bad',b'bad',b'bad',b'bad',b'bad')


if __name__ == '__main__': unittest.main()
