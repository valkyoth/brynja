"""TupleHash saved-image binding, ABI, framing and cleanup regressions."""
import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import windows_enclave_tuple_chains as c

SAVED=None
ROOT=Path(__file__).resolve().parents[2]
s=c.shapes.s


class Tests(unittest.TestCase):
    def test_frozen_complete_route_population(self):
        spec=c.specification(c.SPEC.read_bytes())
        self.assertEqual([len(spec[k]['functions']) for k in ('scalar','avx2')],[52,61])
        for lane in spec:
            for key in ('image_sha256','object_sha256','assembly_sha256','ir_sha256','build_sha256','source_count'):
                changed=copy.deepcopy(spec);changed[lane][key]=0
                with self.assertRaises(ValueError): c.specification(json.dumps(changed).encode())
            for name in spec[lane]['functions']:
                changed=copy.deepcopy(spec);del changed[lane]['functions'][name]
                with self.assertRaises(ValueError): c.specification(json.dumps(changed).encode())

    def test_scalar_label_mapping_is_bijective_and_explicit(self):
        body='\n'.join(f'.Ltmp{n}:\njne .Ltmp{n}' for n in range(8,14))
        expected='\n'.join(f'.Ltmp{n}:\njne .Ltmp{n}' for n in range(4,10))
        self.assertEqual(c.scalar_labels(body),expected)
        for bad in (body.replace('.Ltmp8:', '.Ltmp9:'),body.replace('.Ltmp8:', ''),
                    body.replace('jne .Ltmp8','jne .Ltmp99'),body+'\n.Ltmp8:',
                    body.replace('.Ltmp8:', '.Ltmp7:')):
            with self.assertRaises(ValueError): c.scalar_labels(bad)
        # This helper only renumbers labels. Instruction/edge integrity must
        # still be rejected by the complete kernel and body checks.
        self.assertNotEqual(c.scalar_labels(body.replace('jne .Ltmp8','jne .Ltmp9')),expected)
        self.assertIn('int3',c.scalar_labels(body.replace('jne .Ltmp8','int3')))

    def test_complete_body_reference_and_extent_binding(self):
        values=(b'\xe8\0\0\0\0',[dict(offset=1,symbol='callee',trailing=0,addend=0)],True)
        code,refs,kind=values
        pin=dict(bytes=len(code),sha256=c.digest(code),runtime=kind,
                 references_sha256=c.digest(json.dumps(refs,sort_keys=True).encode()))
        c.c.body_check(values,pin)
        for at in range(len(code)):
            changed=bytearray(code);changed[at]^=1
            with self.assertRaises(ValueError): c.c.body_check((changed,refs,kind),pin)
        for key,value in [('offset',2),('symbol','other'),('trailing',1),('addend',4)]:
            with self.assertRaises(ValueError): c.c.body_check((code,[refs[0]|{key:value}],kind),pin)
        with self.assertRaises(ValueError): c.c.body_check((code,refs,False),pin)

    def test_cleanup_cannot_be_vacuous_or_bypassed(self):
        for lane in ('scalar','avx2'):
            event=c.shapes.clear_event(lane)
            body='entry:\n'+'\n'.join(event)+'\nretq'
            self.assertEqual(s.normal_returns(body,'entry',event),1)
            for line in event:
                with self.assertRaises(ValueError): s.normal_returns(body.replace(line,'nop'),'entry',event)
            for bad in (body.replace('entry:', 'entry:\nje early')+'\nearly:\nretq',
                        'entry:\njmp entry',body.replace('retq','jmpq *%rax')):
                with self.assertRaises(ValueError): s.normal_returns(bad,'entry',event)

    def test_abi_allowlist_rejects_extra_and_partial_changes(self):
        names={s.CORE+'17secret_memory_xor8xor_bits':('range(i32 0, 9) %3','range(i32 0, 8) %3'),
            s.CORE+'13secret_memory20xor_secret_byte_bits':('range(i8 0, 9) %4','range(i8 0, 8) %4'),
            '_RNvMNtCs58M5yX2Qwr5_16brynja_hash_sha310bit_stringNtB2_16Fips202BitString3new':
                ('range(i64 0, 1025) %2','range(i64 0, 65536) %2')}
        changed={n:dict(prior_abi='prefix '+a+' suffix',current_abi='prefix '+b+' suffix')
                 for n,(a,b) in names.items()}
        c.reuse.abi_changes(changed,'scalar')
        for name in names:
            bad=copy.deepcopy(changed);bad[name]['current_abi']+=' nounwind'
            with self.assertRaises(ValueError): c.reuse.abi_changes(bad,'scalar')
            bad=copy.deepcopy(changed);del bad[name]
            with self.assertRaises(ValueError): c.reuse.abi_changes(bad,'scalar')
        with self.assertRaises(ValueError): c.reuse.abi_changes(changed|{'unknown':{}},'scalar')
        with self.assertRaises(ValueError): c.reuse.abi_changes(changed,'avx2')


class SavedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if SAVED is None: raise unittest.SkipTest('optional saved Windows artifacts not supplied')
        cls.routes=[]
        for lane,pin in c.specification(c.SPEC.read_bytes()).items():
            _,data,image,asm,ir,_=c.c.load(SAVED,ROOT,lane,pin,'tuple-worker-build.json')
            functions=c.c.previous.inventory(data)
            cls.routes.append((lane,data,image,asm,ir,functions,c.c.previous.s.bodies(asm,functions)))

    def test_actual_semantic_landmarks_reject_mutations(self):
        counts={}
        for lane,_,_,_,ir,_,bodies in self.routes:
            landmarks=[];actual=s.sequences
            def capture(body,items):
                names=[n for n,v in bodies.items() if v==body]
                self.assertEqual(len(names),1)
                landmarks.extend((names[0],item) for item in items)
                actual(body,items)
            def check(values):
                c.shapes.inspect(values,lane);c.lifecycle.inspect(values,lane)
                c.reuse.bounded_bits(values,ir)
            with patch.object(s,'sequences',capture): check(bodies)
            for name,item in landmarks:
                text='\n'.join(s.lines(bodies[name]));bad=text.replace(item.replace('|','\n'),'int3')
                self.assertNotEqual(text,bad)
                with self.subTest(lane=lane,name=name,sequence=item):
                    with self.assertRaises(ValueError): check(bodies|{name:bad})
            counts[lane]=len(landmarks)
        print('Actual TupleHash semantic landmark mutations rejected: '+json.dumps(counts,sort_keys=True))

    def test_widened_bits_requires_its_exact_abi_bound(self):
        for _,_,_,_,ir,_,bodies in self.routes:
            c.reuse.bounded_bits(bodies,ir)
            for value in ('65537','1025','-9223372036854775808'):
                with self.assertRaises(ValueError):
                    c.reuse.bounded_bits(bodies,ir.replace('range(i64 0, 65536) %2',f'range(i64 0, {value}) %2'))

    def test_each_actual_cleanup_event_is_load_bearing(self):
        count=0;actual=s.normal_returns
        for lane,_,_,_,_,_,bodies in self.routes:
            calls=[]
            def capture(body,start,event,alternatives=()):
                calls.append((body,start,event,alternatives))
                return actual(body,start,event,alternatives)
            with patch.object(s,'normal_returns',capture):
                c.shapes.inspect(bodies,lane);c.lifecycle.inspect(bodies,lane)
            self.assertTrue(calls)
            for body,start,event,alternatives in calls:
                text='\n'.join(s.lines(body));bad=text
                for item in [event,*alternatives]: bad=bad.replace('\n'.join(item),'int3')
                self.assertNotEqual(text,bad)
                with self.assertRaises(ValueError): actual(bad,start,event,alternatives)
                count+=1
        print('Actual TupleHash cleanup-event mutations rejected: '+str(count))

    def test_reuse_cannot_hide_a_changed_parameter_contract(self):
        for lane,_,_,_,ir,functions,bodies in self.routes:
            prior=dict(route='test-context',image_sha256='test-context')
            report=c.reuse.inspect(SAVED,ROOT,lane,functions,ir,bodies,prior)
            self.assertEqual(len(report['renamed_helpers']),1 if lane=='scalar' else 4)
            for name in report['renamed_helpers']:
                code,refs,kind=functions[name]
                for bad in ((bytes([code[0]^1])+code[1:],refs,kind),
                            (code,refs+[{'unexpected':True}],kind),(code,refs,not kind)):
                    with self.assertRaises(ValueError):
                        c.reuse.inspect(SAVED,ROOT,lane,functions|{name:bad},ir,bodies,prior)
                header=next(l for l in ir.splitlines() if l.startswith('define ') and '@'+name+'(' in l)
                with self.assertRaises(ValueError):
                    c.reuse.inspect(SAVED,ROOT,lane,functions,ir.replace(header,header.replace('define ','define cold ',1)),bodies,prior)


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--saved-directory',type=Path)
    args,rest=parser.parse_known_args();SAVED=args.saved_directory
    unittest.main(argv=[__file__]+rest)
