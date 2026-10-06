"""KMAC review binding, completion, comparison and cleanup-CFG regressions."""
import copy
import json
import unittest
from pathlib import Path
from unittest.mock import patch

import windows_enclave_kmac_chains as c

s=c.shapes
SAVED=None
ROOT=Path(__file__).resolve().parents[2]


class Tests(unittest.TestCase):
    def test_reuse_resolves_attributes_and_keeps_all_abi_constraints(self):
        ir='define internal fastcc void @helper(ptr align 32 %0, i8 range(i8 0, 8) %1) #4 {\nattributes #4 = { nounwind "target-features"="+avx2" }'
        renumbered=ir.replace('#4','#12')
        values=(b'\xc3',[],False)
        old={'helper':values}
        reused,changed=c.reuse.exact_reuse(old,old,renumbered,ir)
        self.assertEqual(set(reused),{'helper'});self.assertFalse(changed)
        for before,after in (('align 32','align 8'),('0, 8','0, 9'),('nounwind',''),('+avx2','+sse2')):
            reused,changed=c.reuse.exact_reuse(old,old,ir.replace(before,after),ir)
            self.assertFalse(reused);self.assertEqual(set(changed),{'helper'})
        for bad in (ir+'\n'+ir,ir.split('\n')[0],ir.replace('@helper','@other')):
            with self.assertRaises(ValueError): c.reuse.abi(bad,'helper')

    def test_reuse_does_not_accept_renames_or_reference_changes(self):
        ir='define internal fastcc void @helper(ptr %0) {\n'
        value=(b'\xc3',[],False);old={'helper':value}
        for changed in ({'renamed':value},{'helper':(b'\x90',[],False)},
                        {'helper':(b'\xc3',[{'symbol':'other'}],False)},
                        {'helper':(b'\xc3',[],True)}):
            self.assertEqual(c.reuse.exact_reuse(changed,old,ir,ir),({},{}))

    def test_frozen_both_route_populations(self):
        spec=c.specification(c.SPEC.read_bytes())
        self.assertEqual([len(spec[k]['functions']) for k in ('scalar','avx2')],[84,77])
        for lane in spec:
            for key in ('image_sha256','object_sha256','assembly_sha256','ir_sha256','build_sha256','source_count'):
                bad=copy.deepcopy(spec);bad[lane][key]=0
                with self.assertRaises(ValueError): c.specification(json.dumps(bad).encode())
            for name in spec[lane]['functions']:
                bad=copy.deepcopy(spec);del bad[lane]['functions'][name]
                with self.assertRaises(ValueError): c.specification(json.dumps(bad).encode())

    def test_references_offsets_addends_and_extent_kind(self):
        code=b'\xe8\0\0\0\0';refs=[dict(offset=1,symbol='target',trailing=0,addend=0)]
        pin=dict(bytes=len(code),sha256=c.digest(code),runtime=True,
                 references_sha256=c.digest(json.dumps(refs,sort_keys=True).encode()))
        c.body_check((code,refs,True),pin)
        for key,value in [('offset',2),('symbol','other'),('trailing',1),('addend',4)]:
            with self.assertRaises(ValueError): c.body_check((code,[refs[0]|{key:value}],True),pin)
        with self.assertRaises(ValueError): c.body_check((code,[],True),pin)
        with self.assertRaises(ValueError): c.body_check((code,refs,False),pin)
        for at in range(len(code)):
            bad=bytearray(code);bad[at]^=1
            with self.assertRaises(ValueError): c.body_check((bad,refs,True),pin)

    def test_cleanup_dominates_every_return_and_handles_loops(self):
        body='entry:\nje loop\njmp cleanup\nloop:\njne loop\ncleanup:\ncallq erase\nretq'
        self.assertEqual(s.normal_returns(body,'entry',['callq erase']),1)
        for bad in (body.replace('callq erase','nop'),body.replace('je loop','je exit')+'\nexit:\nretq',
                    body.replace('jmp cleanup','jmpq *%rax'),body.replace('jmp cleanup','jmp outside'),
                    body+'\nentry:\nretq',body.replace('callq erase','callq *%rax')):
            with self.assertRaises(ValueError): s.normal_returns(bad,'entry',['callq erase'])

    def test_no_vacuous_cleanup_or_partial_sequence(self):
        for body in ('entry:\njmp entry','entry:\nnop','wrong:\ncallq erase\nretq'):
            with self.assertRaises(ValueError): s.normal_returns(body,'entry',['callq erase'])
        body='entry:\nmovl $1, %edx\ncallq erase\nretq'
        event=['movl $1, %edx','callq erase']
        self.assertEqual(s.normal_returns(body,'entry',event),1)
        for line in event:
            with self.assertRaises(ValueError): s.normal_returns(body.replace(line,'nop'),'entry',event)

    def test_semantic_roles_must_be_unique(self):
        self.assertEqual(s.one({'Owner6verify':'retq'},r'Owner6verify$'),'Owner6verify')
        for values in ({},{'aOwner6verify':'retq','bOwner6verify':'retq'}):
            with self.assertRaises(ValueError): s.one(values,r'Owner6verify$')

    def test_semantic_sequences_keep_width_branch_and_order(self):
        sequence='cmpq $128, %rax|jb .B4|movq %rax, %r9|callq suffix'
        s.sequences(sequence.replace('|','\n'),[sequence])
        for line in sequence.split('|'):
            with self.assertRaises(ValueError): s.sequences(sequence.replace('|','\n').replace(line,'nop'),[sequence])
        with self.assertRaises(ValueError): s.sequences(sequence.replace('|','\n').replace('128','64'),[sequence])

    def test_constant_probe_and_alignment_contribute_to_bound(self):
        records={'RetainedWork':dict(reference_targets={'helper':100}),
                 'helper':dict(reference_targets={})}
        asm={'RetainedWork':'.seh_pushreg %rbx\n.seh_stackalloc 40',
             'helper':'movl $4360, %eax\ncallq __chkstk\nsubq %rax, %rsp\n.seh_stackalloc 4360\nandq $-32, %rsp'}
        frames,_,_,_,geometry=c.frames(records,asm)
        self.assertEqual(frames,{'RetainedWork':48,'helper':4391})
        # The nested call adds its return-address slot as well as both frames.
        self.assertEqual(geometry['local_rsp_bound_from_window_high'],-4551)
        self.assertTrue(geometry['shared_runtime_frames_excluded'])
        for instruction in ('subq %rbx, %rsp','andq %rax, %rsp','andq $-64, %rsp',
                            'movq unknown, %rax\ncallq __chkstk\nsubq %rax, %rsp'):
            with self.assertRaises(ValueError): c.frames(records,asm|{'helper':instruction})

    def test_cycles_and_window_overflow_are_rejected(self):
        with self.assertRaises(ValueError): c.scalar.contributions({'RetainedWork':['RetainedWork']},{'RetainedWork':8})
        with self.assertRaises(ValueError): c.scalar.contributions({'RetainedWork':[]},{'RetainedWork':65536})

    def test_every_dispatch_byte_is_binding_including_subtable_base(self):
        pin=dict(object_hex=b''.join(n.to_bytes(4,'little') for n in (24,36,48)).hex(),subtable_bytes=[8,4])
        raw=b''.join((1000+d-2000-base).to_bytes(4,'little',signed=True) for d,base in zip((20,28,44),(0,0,8)))
        check=c.previous.s.scalar.ops.table_destinations
        self.assertEqual(check(raw,2000,1000,pin),[20,28,44])
        for at in range(len(raw)):
            bad=bytearray(raw);bad[at]^=1
            with self.assertRaises(ValueError): check(bad,2000,1000,pin)


class SavedTests(unittest.TestCase):
    def routes(self):
        if SAVED is None: self.skipTest('optional saved Windows artifacts not supplied')
        for lane,pin in c.specification(c.SPEC.read_bytes()).items():
            _,data,_,asm,ir,_=c.load(SAVED,ROOT,lane,pin)
            route='sha3/mod.rs::open'+('_avx2' if lane=='avx2' else '')
            row=next(r for r in c.shared.catalog(c.shared.CATALOG.read_bytes()) if r['route']==route)
            profile=next(p for p in c.w.specification(c.w.SPEC.read_bytes())['profiles'] if p['route']==route)
            directory=(SAVED/row['object']).parent
            prior=c.previous.inventory(c.w.archive.members((directory/'normal_rust.lib').read_bytes())[profile['member']])
            current=c.previous.inventory(data)
            yield (lane,current,prior,ir,(directory/'normal_rust.ll').read_text(),
                   c.previous.s.bodies(asm,current),
                   c.previous.s.bodies((directory/'normal_rust.s').read_text(),prior))

    def test_explicit_renames_require_full_body_references_kind_and_abi(self):
        count=0
        for lane,current,prior,ir,old_ir,_,_ in self.routes():
            renamed=c.reuse.renamed_reuse(current,prior,ir,old_ir,lane)
            for name in renamed:
                code,refs,kind=current[name]
                variants=[(bytes([code[0]^1])+code[1:],refs,kind),(code,refs+[{'unexpected':True}],kind),
                          (code,refs,not kind)]
                for bad in variants:
                    with self.assertRaises(ValueError):
                        c.reuse.renamed_reuse(current|{name:bad},prior,ir,old_ir,lane)
                    count+=1
                # A correct symbol and body cannot excuse a changed contract.
                header=next(l for l in ir.splitlines() if l.startswith('define ') and '@'+name+'(' in l)
                bad_ir=ir.replace(header,header.replace('define ','define cold ',1))
                with self.assertRaises(ValueError): c.reuse.renamed_reuse(current,prior,bad_ir,old_ir,lane)
                count+=1
        self.assertEqual(count,24)

    def test_prefix_specializations_reject_unlisted_instruction_and_abi_changes(self):
        count=0
        for lane,_,_,ir,old_ir,bodies,old in self.routes():
            accepted=c.reuse.prefix_specializations(bodies,old,ir,old_ir,lane)
            for name in accepted:
                code='\n'.join(s.lines(bodies[name]))
                selected=[l for l in code.splitlines() if l.startswith(('callq ','xorl ','cmp'))]
                self.assertTrue(selected)
                for instruction in selected:
                    changed=code.replace(instruction,'int3',1)
                    with self.subTest(lane=lane,function=name,instruction=instruction):
                        with self.assertRaises(ValueError):
                            c.reuse.prefix_specializations(bodies|{name:changed},old,ir,old_ir,lane)
                    count+=1
                header=next(l for l in ir.splitlines() if l.startswith('define ') and '@'+name+'(' in l)
                with self.assertRaises(ValueError):
                    c.reuse.prefix_specializations(bodies,old,ir.replace(header,header.replace('define ','define cold ',1)),old_ir,lane)
                count+=1
        print('Explicit prefix specialization mutations rejected: '+str(count))

    def test_actual_semantic_landmarks_and_private_abi(self):
        if SAVED is None: self.skipTest('optional saved Windows artifacts not supplied')
        totals={}
        for lane,pin in c.specification(c.SPEC.read_bytes()).items():
            _,data,_,asm,ir,_=c.load(SAVED,ROOT,lane,pin)
            bodies=c.previous.s.bodies(asm,c.previous.inventory(data));landmarks=[]
            actual=s.sequences
            def capture(body,items):
                names=[n for n,b in bodies.items() if b==body]
                self.assertEqual(len(names),1)
                landmarks.extend((names[0],item) for item in items)
                actual(body,items)
            def inspect_all(values):
                s.inspect(values,lane);c.reuse.encoder(values,lane)
                if lane=='avx2': c.reuse.widened_xor(values)
                else: c.reuse.scalar_construction(values,ir)
            with patch.object(s,'sequences',capture): inspect_all(bodies)
            for name,item in landmarks:
                text='\n'.join(s.lines(bodies[name]))
                changed=text.replace(item.replace('|','\n'),'int3')
                self.assertNotEqual(changed,text)
                with self.subTest(lane=lane,function=name,landmark=item):
                    with self.assertRaises(ValueError): inspect_all(bodies|{name:changed})
            abi=s.preconditions(ir,bodies,lane)
            if lane=='scalar':
                for token in ('range(i64 136, 169)','dereferenceable(1041)'):
                    with self.assertRaises(ValueError):
                        c.reuse.scalar_construction(bodies,ir.replace(token,'removed'))
            for name,tokens in abi['checked_functions'].items():
                for token in tokens:
                    with self.subTest(lane=lane,function=name,abi=token):
                        with self.assertRaises(ValueError): s.preconditions(ir.replace(token,'removed'),bodies,lane)
            totals[lane]=dict(semantic_landmarks=len(landmarks),
                             abi_tokens=sum(map(len,abi['checked_functions'].values())))
        print('Actual saved KMAC semantic mutations rejected: '+json.dumps(totals,sort_keys=True))


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--saved-directory',type=Path)
    args,rest=parser.parse_known_args();SAVED=args.saved_directory
    unittest.main(argv=[__file__]+rest)
