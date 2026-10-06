"""Regression tests for saved SHA-2 batch binding and admission checks."""
import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import windows_enclave_sha2_batch_chains as c

SAVED=None
ROOT=Path(__file__).resolve().parents[2]
s=c.shapes.s


class Tests(unittest.TestCase):
    def test_four_complete_frozen_populations(self):
        spec=c.specification(c.SPEC.read_bytes())
        for lane,pin in spec.items():
            self.assertEqual(len(pin['functions']),c.COUNTS[lane])
            for key in ('source_count','image_sha256','build_sha256','extra_manifests'):
                bad=copy.deepcopy(spec);bad[lane][key]=None
                with self.assertRaises(ValueError): c.specification(json.dumps(bad).encode())
            for name in pin['functions']:
                bad=copy.deepcopy(spec);del bad[lane]['functions'][name]
                with self.assertRaises(ValueError): c.specification(json.dumps(bad).encode())

    def test_source_closure_rejects_overlap_drift_and_paths(self):
        good={'source_sha256':{'source.rs':c.digest(b'source')}}
        with patch.object(Path,'read_bytes',return_value=b'source'):
            self.assertEqual(c.source_closure(ROOT,[good,good],1),good['source_sha256'])
            for manifests,count in (([good],2),([{'source_sha256':{}}],1),
                    ([good,{'source_sha256':{'source.rs':'0'*64}}],1)):
                with self.assertRaises(ValueError): c.source_closure(ROOT,manifests,count)
            for name in ('/outside','../outside','a/../outside','C:/outside'):
                with self.assertRaises(ValueError):
                    c.source_closure(ROOT,[{'source_sha256':{name:c.digest(b'source')}}],1)
        with patch.object(Path,'read_bytes',return_value=b'changed'):
            with self.assertRaises(ValueError): c.source_closure(ROOT,[good],1)

    def test_callback_vtable_requires_exact_layout_kind_and_destinations(self):
        raw=bytes(16)+(1).to_bytes(8,'little')+bytes(16)
        image=bytearray(256);image[0x3c:0x40]=(64).to_bytes(4,'little')
        image[112:120]=(0x180000000).to_bytes(8,'little')
        refs={24:dict(symbol=0,kind=1),32:dict(symbol=1,kind=1)}
        symbols={0:{'name':'thunk'},1:{'name':'closure'}}
        records={'thunk':{'rva':1000},'closure':{'rva':2000}}
        linked=raw[:24]+b''.join((0x180000000+n).to_bytes(8,'little') for n in (1000,2000))
        with patch.object(c.c.previous,'readonly',return_value=linked):
            result=c.vtable_check(raw,refs,symbols,image,4000,records)
            self.assertTrue(result['callsite_provenance_review_pending'])
            for at in range(40):
                bad=bytearray(raw);bad[at]^=1
                with self.assertRaises(ValueError): c.vtable_check(bad,refs,symbols,image,4000,records)
            for bad in ({24:refs[24]},refs|{0:refs[24]},refs|{24:dict(symbol=0,kind=4)}):
                with self.assertRaises(ValueError): c.vtable_check(raw,bad,symbols,image,4000,records)
            with self.assertRaises(ValueError): c.vtable_check(raw,refs,symbols,image,4000,{'thunk':records['thunk']})
        for at in range(40):
            bad=bytearray(linked);bad[at]^=1
            with patch.object(c.c.previous,'readonly',return_value=bad):
                with self.assertRaises(ValueError): c.vtable_check(raw,refs,symbols,image,4000,records)

    def test_diagnostic_location_binds_string_and_source_coordinates(self):
        image=bytearray(256);image[0x3c:0x40]=(64).to_bytes(4,'little')
        image[112:120]=(0x180000000).to_bytes(8,'little')
        raw=bytes(8)+(3).to_bytes(8,'little')+(219).to_bytes(4,'little')+(18).to_bytes(4,'little')
        refs={0:dict(symbol=0,kind=1)};symbols={0:dict(section=1,value=0)}
        rows=[dict(nrelocs=0,flags=0x40000000,code=b'abc\0')]
        linked=(0x180001000).to_bytes(8,'little')+raw[8:]
        with patch.object(c.c.previous,'readonly',side_effect=[linked,b'abc\0']):
            self.assertEqual(c.location_check(raw,refs,symbols,rows,image,5000)['line'],219)
        for bad in (raw[:-1],raw[:8]+(4).to_bytes(8,'little')+raw[16:]):
            with self.assertRaises(ValueError): c.location_check(bad,refs,symbols,rows,image,5000)
        with patch.object(c.c.previous,'readonly',side_effect=[linked,b'bad\0']):
            with self.assertRaises(ValueError): c.location_check(raw,refs,symbols,rows,image,5000)
        with patch.object(c.c.previous,'readonly',return_value=linked[:-1]+b'\xff'):
            with self.assertRaises(ValueError): c.location_check(raw,refs,symbols,rows,image,5000)


class SavedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if SAVED is None: raise unittest.SkipTest('saved Windows artifacts not supplied')
        cls.routes=[]
        for lane,pin in c.specification(c.SPEC.read_bytes()).items():
            row,data,image,asm,ir,sources=c.load(SAVED,ROOT,pin)
            functions=c.c.previous.inventory(data);bodies=c.c.previous.s.bodies(asm,functions)
            cls.routes.append((lane,pin,data,image,ir,functions,bodies))

    def test_semantic_sequences_are_load_bearing(self):
        counts={};actual=s.sequences
        for lane,_,_,_,ir,_,bodies in self.routes:
            captures=[]
            def capture(body,items):
                names=[n for n,b in bodies.items() if b==body];self.assertEqual(len(names),1)
                captures.extend((names[0],item) for item in items);actual(body,items)
            with patch.object(s,'sequences',capture): c.shapes.inspect(bodies,ir,lane)
            for name,item in captures:
                text='\n'.join(s.lines(bodies[name]));bad=text.replace(item.replace('|','\n'),'int3')
                self.assertNotEqual(bad,text)
                with self.assertRaises(ValueError): c.shapes.inspect(bodies|{name:bad},ir,lane)
            counts[lane]=len(captures)
        print('Batch semantic mutations rejected: '+json.dumps(counts,sort_keys=True))

    def test_actual_cleanup_events_reject_bypass(self):
        count=0;actual=s.normal_returns
        for lane,_,_,_,ir,_,bodies in self.routes:
            events=[]
            def capture(body,start,event,alternatives=()):
                events.append((body,start,event,alternatives));return actual(body,start,event,alternatives)
            with patch.object(s,'normal_returns',capture): c.shapes.inspect(bodies,ir,lane)
            self.assertTrue(events)
            for body,start,event,alternatives in events:
                text='\n'.join(s.lines(body));bad=text.replace('\n'.join(event),'int3')
                self.assertNotEqual(bad,text)
                with self.assertRaises(ValueError): actual(bad,start,event,alternatives)
                count+=1
        print('Batch cleanup-event mutations rejected: '+str(count))

    def test_actual_private_abi_constraints_cannot_be_removed(self):
        count=0
        for lane,_,_,_,ir,_,bodies in self.routes:
            for name,tokens in c.shapes.abi(bodies,ir,lane).items():
                header=next(l for l in ir.splitlines() if l.startswith('define ') and '@'+name+'(' in l)
                for token in tokens:
                    bad=ir.replace(header,header.replace(token,'BROKEN'))
                    with self.assertRaises(ValueError): c.shapes.abi(bodies,bad,lane)
                    count+=1
        print('Batch private ABI mutations rejected: '+str(count))

    def test_complete_replay_keeps_unfinished_claims_explicit(self):
        for lane,pin,_,_,_,_,_ in self.routes:
            r=c.inspect_route(SAVED,ROOT,lane,pin,False)
            self.assertFalse(r['transitive_depth_qualified'])
            self.assertEqual(len(r['functions']),c.COUNTS[lane])
            if lane.startswith('simd'):
                self.assertTrue(r['callback_callsite_review_pending'])
                self.assertEqual(len(r['callback_tables']),1)
            else: self.assertFalse(r['callback_callsite_review_pending'])


if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser();p.add_argument('--saved-directory',type=Path)
    args,rest=p.parse_known_args();SAVED=args.saved_directory
    unittest.main(argv=[__file__]+rest)
