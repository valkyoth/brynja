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
    def test_public_kat_expected_digest_is_sha256_abc(self):
        import hashlib
        value=int(c.shapes.placement.kat.EXPECTED[6:],16).to_bytes(32,'little')
        big=b''.join(value[i:i+4][::-1] for i in range(0,32,4))
        self.assertEqual(big,hashlib.sha256(b'abc').digest())

    def test_general_t_decimal_reciprocals_and_padding_bound(self):
        for parameter in range(1,512):
            if parameter==384: continue
            label=c.shapes.iv.decimal_label(parameter)
            self.assertEqual(label,b'SHA-512/'+str(parameter).encode())
            self.assertIn(len(label),(9,10,11))
            self.assertLess(len(label)+1,112)
        for parameter in (0,384,512,-1,True):
            with self.assertRaises(ValueError): c.shapes.iv.decimal_label(parameter)

    def test_every_plan_slot_rejects_invalid_identity_and_empty_plan(self):
        for lane in ('scalar','sha_ni'):
            check=c.shapes.placement.admitted_plan
            self.assertFalse(check([0]*8,lane))
            for slot in range(8):
                for identity in (*range(65536),(1<<32)-1,(1<<63),(1<<64)-1):
                    plan=[0]*8;plan[slot]=identity
                    allowed=(1<=identity<=6 or 4097<=identity<=4607 and identity!=4480
                             if lane=='scalar' else 1<=identity<=2)
                    self.assertEqual(check(plan,lane),allowed)
                    # A separate valid slot must not hide the invalid one.
                    plan[(slot+1)%8]=1
                    self.assertEqual(check(plan,lane),identity==0 or allowed)
            for bad in ([0]*7,[0]*9,[True]+[0]*7,[-1]+[0]*7,[1<<64]+[0]*7):
                with self.assertRaises(ValueError): check(bad,lane)

    def test_unrolled_slot_selection_for_every_bitmap_pair(self):
        for active in range(256):
            for completed in range(256):
                remaining=active & ~completed
                expected=(remaining & -remaining).bit_length()-1 if remaining else None
                self.assertEqual(c.shapes.batch_state.selected_slot(active,completed),expected)

    def test_decoded_identity_and_rounded_width_domains(self):
        for identity in (*range(65536),(1<<32)-1,(1<<63),(1<<64)-1):
            if 1<=identity<=6: expected=(identity-1,0,(28,32,48,64,28,32)[identity-1])
            elif 4097<=identity<=4607 and identity!=4480:
                parameter=identity-4096;expected=(6,parameter,(parameter+7)//8)
            else: expected=None
            self.assertEqual(c.shapes.batch_state.decoded_width(identity),expected)
            if expected:
                for slot in range(8): self.assertLessEqual(64*slot+expected[2],512)
        for identity in (-1,1<<64,True):
            with self.assertRaises(ValueError): c.shapes.batch_state.decoded_width(identity)

    def test_reuse_requires_resolved_target_abi_and_explicit_names(self):
        body=(b'code',[{'symbol':'callee'}],True)
        old='define internal void @old(ptr align 8 %0) #1 {\nattributes #1 = { nounwind "target-features"="+sha" }'
        now=old.replace('@old(','@new(').replace('#1','#9')
        args=({'new':body,'unreviewed':body},{'old':body},now,old,{'new':'old'})
        self.assertEqual(set(c.reuse.exact(*args)),{'new'})
        for bad in (now.replace('+sha','-sha'),now.replace('align 8','align 1'),
                    now.replace('nounwind',''),now.splitlines()[0],now+'\n'+now.splitlines()[0]):
            with self.assertRaises(ValueError): c.reuse.exact(args[0],args[1],bad,old,args[4])
        for bad in ({}, {'new':(b'bad',body[1],True)},
                    {'new':(body[0],[{'symbol':'different'}],True)}, {'new':(body[0],body[1],False)}):
            with self.assertRaises(ValueError): c.reuse.exact(bad,args[1],now,old,args[4])

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

    def test_actual_required_return_events_reject_bypass(self):
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
        print('Batch required-return-event mutations rejected: '+str(count))

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
                authority=r['semantics']['simd_authority']
                self.assertFalse(authority['complete_callback_provenance_qualified'])
                self.assertTrue(authority['authority_session']['kernel_and_transpose_semantics_pending'])
                self.assertFalse(authority['callback_unwind']['cleanup_state_order_review_pending'])
                self.assertTrue(authority['callback_unwind']['enclosing_storage_lifetimes_pending'])
                self.assertFalse(authority['callback_unwind']['arbitrary_os_unwind_qualified'])
                self.assertTrue(authority['padding_helper']['caller_early_failure_cleanup_pending'])
                self.assertTrue(authority['padding_helper']['callback_object_provenance_pending'])
                self.assertEqual(len(authority['callback_unwind']['invoked_funclets']),16)
                self.assertTrue(authority['cleanup_tables']['compiler_cleanup_order_checked'])
                self.assertFalse(authority['cleanup_tables']['os_dispatcher_qualified'])
            else:
                self.assertFalse(r['callback_callsite_review_pending'])
                reused=r['reproduced_primitive_contracts']
                self.assertTrue(reused['prior_semantic_review_replayed'])
                self.assertTrue(reused['batch_specific_caller_preconditions_pending'])
                self.assertFalse(reused['unlisted_equal_bodies_implicitly_qualified'])
                self.assertEqual(len(reused['exact_helper_contracts']),15 if lane=='scalar' else 14)
                admission=r['semantics']['placement_and_plan']
                self.assertEqual(admission['plan']['slots'],8)
                self.assertTrue(admission['plan']['nonempty_required'])
                self.assertTrue(admission['initial_placement']['duplicate_live_rejected'])
                if lane=='scalar':
                    loops=reused['explicitly_substituted_public_iv_loops']
                    self.assertEqual({n:v['instructions'] for n,v in loops.items()},{'schedule':23,'rounds':46})
                    self.assertEqual(r['semantics']['public_iv']['named']['variants'],6)
                else:
                    kat=admission['initial_placement']['public_static_kat']
                    self.assertEqual(kat['comparison_dominates_normal_returns'],1)
                    self.assertFalse(kat['kat_is_platform_support_or_independent_review'])
                    self.assertFalse(admission['initial_placement']['constructor_stack_cleanup_claimed'])
                lifecycle=r['semantics']['lifecycle']
                self.assertTrue(lifecycle['primitive_and_finalizer_composition_pending'])
                self.assertEqual(lifecycle['sealing']['slots'],8)
                self.assertEqual(lifecycle['export']['identity_bytes_compared'],64)
                self.assertEqual(lifecycle['retirement']['page_erasure_bytes'],4096)
                self.assertFalse(lifecycle['operation_guard']['arbitrary_os_unwind_qualified'])
                if lane=='sha_ni':
                    self.assertEqual(r['semantics']['finalizer']['exact_variant_widths'],[28,32])
                    self.assertFalse(r['semantics']['finalizer_caller']['cleanup_funclet_review_pending'])
                    funclet=r['semantics']['state_transitions']['finish_funclet']
                    self.assertEqual(funclet['all_invoked_returns_call_guard'],1)
                    self.assertFalse(funclet['arbitrary_os_unwind_qualified'])
                self.assertTrue(r['semantics']['state_transitions']['complete_constructor_composition_pending'])

    def test_simd_population_rejects_indirect_call_changes(self):
        module=c.shapes.simd_authority;count=0
        for lane,_,_,_,_,_,bodies in self.routes:
            if not lane.startswith('simd'): continue
            expected=module.population(bodies,lane)
            self.assertEqual(sum(map(len,expected.values())),13 if lane=='simd256' else 16)
            for name,calls in expected.items():
                lines=s.lines(bodies[name])
                for at,line in enumerate(lines):
                    if not line.startswith('callq *'): continue
                    for replacement in ('nop','callq *%r11',line+'\n'+line):
                        bad=list(lines);bad[at]=replacement
                        with self.assertRaises(ValueError):
                            module.population(bodies|{name:'\n'.join(bad)},lane)
                        count+=1
            with self.assertRaises(ValueError):
                module.population(bodies|{'unexpected':'callq *%rax'},lane)
        self.assertEqual(count,87)

    def test_simd_funclets_and_session_failure_reject_early_returns(self):
        actual=s.normal_returns;count=0
        for lane,_,_,_,_,_,bodies in self.routes:
            if not lane.startswith('simd'): continue
            checks=[]
            def capture(body,start,event,alternatives=()):
                checks.append((body,start,event,alternatives));return actual(body,start,event,alternatives)
            with patch.object(s,'normal_returns',capture): c.shapes.simd_authority.inspect(bodies,lane)
            for body,start,event,alternatives in checks:
                lines=s.lines(body);lines.insert(lines.index(start+':')+1,'retq')
                with self.assertRaises(ValueError): actual('\n'.join(lines),start,event,alternatives)
                count+=1
        self.assertEqual(count,40)

    def test_simd_cleanup_tables_reject_each_field_change(self):
        import re
        count=0
        for lane,pin,_,_,_,_,bodies in self.routes:
            if not lane.startswith('simd'): continue
            _,_,_,asm,_,_=c.load(SAVED,ROOT,pin)
            module=c.shapes.simd_authority;result=module.cleanup_tables(asm,bodies,lane)
            for label,values in result['expected_tables'].items():
                match=re.search(r'^'+re.escape(label)+r':\n((?:\s*\.long[^\n]*\n)+)',asm,re.M)
                for at in range(len(values)):
                    lines=match[1].splitlines(keepends=True)
                    lines[at]='\t.long\tBROKEN\n'
                    bad=asm[:match.start(1)]+''.join(lines)+asm[match.end(1):]
                    with self.assertRaises(ValueError): module.cleanup_tables(bad,bodies,lane)
                    count+=1
                for bad in (asm[:match.start()]+asm[match.end():],asm+match[0]):
                    with self.assertRaises(ValueError): module.cleanup_tables(bad,bodies,lane)
        self.assertGreater(count,200)
        print('SIMD cleanup-state/order field mutations rejected: '+str(count))

    def test_scalar_dispatch_order_mutations(self):
        pin=c.specification(c.SPEC.read_bytes())['scalar']
        _,data,_,asm,_,_=c.load(SAVED,ROOT,pin)
        bodies=c.c.previous.s.bodies(asm,c.c.previous.inventory(data))
        checked=c.shapes.batch_state.scalar_tables(bodies,asm)
        self.assertEqual(sum(map(len,checked.values())),21)
        import re
        mutants=set()
        for role in checked:
            body=bodies[c.shapes.owner(bodies,role)]
            table=re.search(r'\.LJTI\d+_0',body)[0]
            start=asm.index(table+':\n');end=asm.index('\n\n',start)
            fragment=asm[start:end]
            entries=fragment.splitlines(keepends=True)
            for index,line in enumerate(entries):
                if not line.strip().startswith(('.long ','.long\t')): continue
                changed=list(entries);changed[index]=line.replace('.LBB','.BROKEN')
                bad=asm[:start]+''.join(changed)+asm[end:]
                self.assertNotEqual(bad,asm)
                with self.assertRaises(ValueError): c.shapes.batch_state.scalar_tables(bodies,bad)
                mutants.add(c.digest(bad.encode()))
        self.assertEqual(len(mutants),21)

    def test_public_loop_comparison_rejects_instruction_changes(self):
        lane,pin,data,_,ir,functions,bodies=next(r for r in self.routes if r[0]=='scalar')
        result=c.reuse.inspect(SAVED,lane,data,functions,ir,bodies)
        self.assertEqual(set(result['explicitly_substituted_public_iv_loops']),{'schedule','rounds'})
        row,old,_,_=c.reuse.prior(SAVED,lane)
        assembly=((SAVED/row['object']).parent/'normal_rust.s').read_text()
        previous=c.c.previous.s.bodies(assembly,c.c.previous.inventory(old))[c.reuse.scalar.state.NEW]
        name=s.one(bodies,r'Owner5start$');current=bodies[name];iv=c.shapes.iv
        count=0
        for before,after in (('.B14','.B30'),('.B16','.B32')):
            for body,label,is_current in ((previous,before,False),(current,after,True)):
                lines=s.lines(body);fragment=iv.loop(body,label)
                start=lines.index(label+':')
                for i in range(1,len(fragment)):
                    bad=list(lines);bad[start+i]='int3';mutant='\n'.join(bad)
                    with self.assertRaises((ValueError,IndexError)):
                        iv.loops(previous,mutant) if is_current else iv.loops(mutant,current)
                    count+=1
        self.assertEqual(count,138)
        # Pinning an old assembly file is required even after the old object review.
        original=Path.read_bytes
        def tampered(path):
            raw=original(path)
            return raw+b'changed' if path.name=='normal_rust.s' else raw
        with patch.object(Path,'read_bytes',tampered):
            with self.assertRaisesRegex(ValueError,'prior scalar emitted assembly identity'):
                c.reuse.scalar_loops(SAVED,row,old,bodies)

    def test_linked_public_constructor_constants_reject_drift(self):
        count=0
        for lane,pin,_,_,_,_,_ in self.routes:
            if lane not in ('scalar','sha_ni'): continue
            report=c.inspect_route(SAVED,ROOT,lane,pin,False)
            expected=report['semantics']['public_constructor_constants']
            constants={n:dict(bytes=size,sha256=sha) for n,(size,sha) in expected.items()}
            c.public_constructor_constants(constants,lane)
            for name in constants:
                for change in (None,dict(bytes=0,sha256=constants[name]['sha256']),
                               dict(bytes=constants[name]['bytes'],sha256='0'*64)):
                    bad=copy.deepcopy(constants)
                    if change is None: del bad[name]
                    else: bad[name]=change
                    with self.assertRaises(ValueError): c.public_constructor_constants(bad,lane)
                    count+=1
        self.assertEqual(count,12)

    def test_state_cleanup_and_funclet_reject_premature_returns(self):
        actual=s.normal_returns;count=0
        for lane,_,_,_,_,_,bodies in self.routes:
            if lane not in ('scalar','sha_ni'): continue
            checks=[]
            def capture(body,start,event,alternatives=()):
                checks.append((body,start,event,alternatives));return actual(body,start,event,alternatives)
            with patch.object(s,'normal_returns',capture): c.shapes.batch_state.inspect(bodies,lane)
            for body,start,event,alternatives in checks:
                lines=s.lines(body);lines.insert(lines.index(start+':')+1,'retq')
                with self.assertRaises(ValueError): actual('\n'.join(lines),start,event,alternatives)
                count+=1
        self.assertEqual(count,7)

    def test_plan_rejection_cleanup_rejects_premature_returns(self):
        actual=s.normal_returns;count=0
        for lane,_,_,_,_,_,bodies in self.routes:
            if lane not in ('scalar','sha_ni'): continue
            checks=[]
            def capture(body,start,event,alternatives=()):
                checks.append((body,start,event,alternatives));return actual(body,start,event,alternatives)
            with patch.object(s,'normal_returns',capture): c.shapes.placement.inspect(bodies,lane)
            for body,start,event,alternatives in checks:
                lines=s.lines(body);lines.insert(lines.index(start+':')+1,'retq')
                with self.assertRaises(ValueError): actual('\n'.join(lines),start,event,alternatives)
                count+=1
        self.assertEqual(count,3)

    def test_saved_reuse_rejects_each_body_reference_extent_and_abi_change(self):
        count=0
        for lane,_,data,_,ir,functions,_ in self.routes:
            if lane not in ('scalar','sha_ni'): continue
            reviewed=c.reuse.inspect(SAVED,lane,data,functions,ir)
            _,old,old_ir,_=c.reuse.prior(SAVED,lane)
            previous=c.c.previous.inventory(old)
            names={n:v['prior_name'] for n,v in reviewed['exact_helper_contracts'].items()}
            for name in names:
                code,refs,extent=functions[name]
                header=next(l for l in ir.splitlines() if l.startswith('define ') and '@'+name+'(' in l)
                bad_ir=ir.replace(header,header.replace('define ','define BROKEN ',1))
                with self.assertRaises(ValueError): c.reuse.exact(functions,previous,bad_ir,old_ir,names)
                for changed in ((bytes([code[0]^1])+code[1:],refs,extent),
                                (code,refs+[{'symbol':'unreviewed'}],extent),(code,refs,not extent)):
                    with self.assertRaises(ValueError):
                        c.reuse.exact(functions|{name:changed},previous,ir,old_ir,names)
                count+=4
        self.assertEqual(count,116)
        print('Reused helper body/reference/extent/ABI mutations rejected: '+str(count))

    def test_prior_review_and_scalar_tables_cannot_be_skipped(self):
        lane,_,data,_,ir,functions,_=self.routes[0]
        self.assertEqual(lane,'scalar')
        with patch.object(c.reuse.scalar,'inspect',side_effect=ValueError('prior semantic failure')) as prior:
            with self.assertRaisesRegex(ValueError,'prior semantic failure'):
                c.reuse.inspect(SAVED,lane,data,functions,ir)
            prior.assert_called_once()
        actual=c.reuse.local_tables
        def changed(raw,name):
            tables=actual(raw,name)
            if raw==data: tables[0]['raw']='00'+tables[0]['raw'][2:]
            return tables
        with patch.object(c.reuse,'local_tables',side_effect=changed):
            with self.assertRaisesRegex(ValueError,'dispatch tables'):
                c.reuse.inspect(SAVED,lane,data,functions,ir)
        for lane,_,data,_,ir,functions,_ in self.routes:
            if lane!='sha_ni': continue
            with patch.object(c.reuse.accelerated,'inspect',side_effect=ValueError('prior semantic failure')) as prior:
                with self.assertRaisesRegex(ValueError,'prior semantic failure'):
                    c.reuse.inspect(SAVED,lane,data,functions,ir)
                prior.assert_called_once()

    def test_changed_finalizer_rejects_early_return_before_wipes(self):
        bodies=next(row[-1] for row in self.routes if row[0]=='sha_ni')
        name=s.one(bodies,r'state.*State6finish$');lines=s.lines(bodies[name])
        for label in (name,'.B7','.B11','.B2','.B12','.B14','.B15','.B20','.B4','.B9','.B5'):
            bad=list(lines);bad.insert(bad.index(label+':')+1,'retq')
            with self.assertRaises(ValueError): c.shapes.sha_ni_finalizer(bodies|{name:'\n'.join(bad)})

    def test_sequential_cleanup_rejects_early_return_insertion(self):
        count=0;actual=s.normal_returns
        for lane,_,_,_,_,_,bodies in self.routes:
            if lane not in ('scalar','sha_ni'): continue
            checks=[]
            def capture(body,start,event,alternatives=()):
                checks.append((body,start,event,alternatives));return actual(body,start,event,alternatives)
            with patch.object(s,'normal_returns',capture): c.shapes.lifecycle.inspect(bodies,lane)
            for body,start,event,alternatives in checks:
                lines=s.lines(body);at=lines.index(start+':')+1
                lines.insert(at,'retq')
                with self.assertRaises(ValueError): actual('\n'.join(lines),start,event,alternatives)
                count+=1
        self.assertEqual(count,12)
        print('Sequential premature-return mutations rejected: '+str(count))


if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser();p.add_argument('--saved-directory',type=Path)
    args,rest=p.parse_known_args();SAVED=args.saved_directory
    unittest.main(argv=[__file__]+rest)
