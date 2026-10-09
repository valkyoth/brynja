"""Control/publication footprints reject mixed roots, truncation and collisions."""
import copy
import re
from unittest.mock import patch
import windows_enclave_sha3_simd_control_effects as t


class SimdControlEffectsModelTests:
    def test_simd_control_effects_typed_loads_joins_and_slot_reuse(self):
        code=['movq %rdx, %rdi','movq (%rdi), %rax','movq %rax, 952(%rbp)',
            'callq revalidate','movq 952(%rbp), %rax','retq']
        edges={i:[i+1] for i in range(5)}|{5:[]}
        states=t.analyse(code,edges,{2:(952,960)})
        self.assertEqual(states[5]['rax'],{'authority'})
        for at,line in ((0,'movl %edx, %edi'),(1,'movq 8(%rdi), %rax'),
            (2,'movb %al, 952(%rbp)'),(4,'movq 960(%rbp), %rax')):
            bad=code.copy();bad[at]=line;spans={2:(952,953) if at==2 else (952,960)}
            self.assertIn('unknown',t.analyse(bad,edges,spans)[5]['rax'])
        bad=code.copy();bad[3]='movq %rcx, 952(%rbp)'
        self.assertEqual(t.analyse(bad,edges,{2:(952,960),3:(952,960)})[5]['rax'],{'result'})
        code=['nop','movq %rdx, %rcx','movq %rcx, %rsi','retq']
        states=t.analyse(code,{0:[1,2],1:[2],2:[3],3:[]},{})
        self.assertEqual(states[3]['rsi'],{'result','executor'})
        code=['movq %rax, %rsi','movq %rsi, %rax','retq']
        self.assertEqual(t.analyse(code,{0:[1],1:[0,2],2:[]},{})[2]['rax'],{'unknown'})

    def test_simd_control_effects_allocation_crossing_and_unknown_objects(self):
        geometry=t.origins.reconcile.terminal.shape.reject.digest.geometry()
        effects=[dict(site=1,root=root,write=[a,b]) for root,a,b in
            (('control',16,32),('result',0,136),('executor',16,17),('authority',16,17))]
        self.assertEqual(len(t.placement(effects,geometry,-1200)),3)
        for root,a,b in (('result',0,137),('control',24,33),('executor',16,19),
            ('authority',0,8),('unknown',0,1),('result',-1,1),('result',1,1)):
            with self.assertRaises(ValueError):t.placement([dict(site=1,root=root,write=[a,b])],geometry,-1200)
        for other in ('workspace','staging','scratch','inputs','control'):
            bad=copy.deepcopy(geometry);bad['executor_entry_objects'][other]=[8608,8744]
            with self.assertRaises(ValueError):t.placement(effects,bad,-1200)
        bad=copy.deepcopy(geometry);bad['executor_entry_objects']['result']=[-1000,-864]
        with self.assertRaises(ValueError):t.placement(effects,bad,-1200)
        with self.assertRaises(ValueError):t.placement(effects,geometry,-1192)


class SimdControlEffectsSavedTests:
    def simd_control_effects_fixture(self):
        import windows_enclave_sha3_batch_chains as c
        r=c.inspect_route(self.saved,self.root,'simd',self.spec['simd'])
        _,_,asm,_,_,b=self.routes['simd']
        return (b,asm,*[r[k] for k in ('simd_digest','simd_frame_alias_effects','simd_terminal',
            'simd_vector_caller','simd_scalar_fallback')])

    def test_simd_control_effects_all_saved_store_destinations(self):
        b,asm,*rest=self.simd_control_effects_fixture();name=rest[1]['function'];code=t.life.code(b[name]);count=0
        for at,(root,offset,width) in t.STORES.items():
            op,args=t.origins.instruction(code[at])
            replacements=[re.sub(r'\(%\w+\)$','(%rbp)',code[at]),
                op+' '+args[0]+', '+str(offset+1)+re.search(r'\(%\w+\)$',code[at])[0],
                'movw %ax, '+args[-1] if width!=2 else 'movb %al, '+args[-1]]
            for line in replacements:
                bad=code.copy();bad[at]=line
                with self.assertRaises(ValueError):t.inspect(b|{name:name+':\n'+'\n'.join(bad)},asm,*rest)
                count+=1
        self.assertEqual(count,72)
        print('Keccak control/quarantine/result footprint mutants rejected: 72')

    def test_simd_control_effects_saved_pointer_root_corruption(self):
        b,asm,*rest=self.simd_control_effects_fixture();name=rest[1]['function'];code=t.life.code(b[name]);count=0
        for at,line in ((11,'movq %rcx, %rdi'),(12,'movq %rdx, %rsi'),
            (34,'movq 8(%rdi), %rax'),(1282,'movq 8(%rdi), %rax'),
            (538,'movq 8(%rdi), %rax'),(1288,'movl %eax, 952(%rbp)'),
            (1292,'movq 960(%rbp), %rax'),(1645,'movq 1120(%rbp), %rcx'),
            (1402,'movl %edi, %r14d'),(1594,'movq %r12, %rdi')):
            bad=code.copy();bad[at]=line
            with self.assertRaises(ValueError):t.inspect(b|{name:name+':\n'+'\n'.join(bad)},asm,*rest)
            count+=1
        for at,line in enumerate(code):
            if line=='movq 1120(%rbp), %r12':
                bad=code.copy();bad[at]='movq 1112(%rbp), %r12'
                with self.assertRaises(ValueError):t.inspect(b|{name:name+':\n'+'\n'.join(bad)},asm,*rest)
                count+=1
        self.assertEqual(count,13)
        print('Keccak original root/spill/restore mutants rejected: 13')

    def test_simd_control_effects_prerequisites_scope_and_integration(self):
        args=self.simd_control_effects_fixture();b,asm,caller,frame,terminal,vector,scalar=args;r=t.inspect(*args)
        self.assertEqual(len(r['write_effects']),24);self.assertEqual(len(r['caller_relative_effects']),21)
        self.assertEqual(len(r['pending_non_frame_store_sites']),33)
        self.assertEqual(len(r['pending_callee_effect_sites']),53)
        self.assertTrue(r['authority_allocation_lifetime_nonnull_and_physical_separation_required'])
        self.assertTrue(r['other_callee_and_indirect_memory_effects_still_required'])
        self.assertFalse(r['private_frame_and_exception_cleanup_qualified'])
        for obj,key in ((terminal,'ordinary_rejection_retains_reuse_and_integrity_failure_quarantines'),
            (terminal,'vector_call_counter_preserved_across_mixed_width_serialization'),
            (vector,'control_charge_committed_before_state_copy'),
            (scalar,'whole_scalar_owner_wiped_before_checked_report_increment')):
            with patch.dict(obj,{key:False}):
                with self.assertRaises(ValueError):t.inspect(*args)
        with patch.dict(caller['geometry'],{'frame_allocation_bytes':1}):
            with self.assertRaises(ValueError):t.inspect(*args)
        import windows_enclave_sha3_batch_chains as c
        with patch.object(t,'inspect',side_effect=ValueError('control effects failed')) as check:
            with self.assertRaisesRegex(ValueError,'control effects failed'):
                c.inspect_route(self.saved,self.root,'simd',self.spec['simd'])
            check.assert_called_once()
