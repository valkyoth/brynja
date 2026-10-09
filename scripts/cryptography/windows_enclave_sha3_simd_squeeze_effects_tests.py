"""Squeeze footprints reject overflow, stale lanes, aliases and mask bypass."""
import copy
from unittest.mock import patch
import windows_enclave_sha3_simd_squeeze_effects as t


class SimdSqueezeEffectsModelTests:
    def test_simd_squeeze_effects_all_admitted_staging_windows(self):
        count=0
        for rate in sorted(set(t.squeeze.model.RATES)):
            for take in range(1,rate+1):
                for start in range(1025-take):
                    r=t.admitted_window(take*8,0,start,rate)
                    self.assertEqual(r,dict(copy=True,offset=start,take=take,end=start+take,mask_index=None))
                    count+=1
        self.assertEqual(count,597560)
        for bits,written,start,rate in ((True,0,0,72),(-1,0,0,72),(t.MASK+1,0,0,72),
            (8,-1,0,72),(8,0,t.MASK+1,72),(8,0,0,0),(8,0,0,200)):
            with self.assertRaises(ValueError):t.admitted_window(bits,written,start,rate)
        self.assertEqual(t.admitted_window(0,0,t.MASK,72),dict(copy=False))
        self.assertIsNone(t.admitted_window(0,1,0,72))
        self.assertIsNone(t.admitted_window(16,1,t.MASK,72))
        self.assertIsNone(t.admitted_window(16,0,t.MASK,72))
        self.assertEqual(t.admitted_window(1,0,1023,72)['mask_index'],1023)
        self.assertIsNone(t.admitted_window(9,0,1023,72))
        print('Keccak every admitted rate-clamped staging window: '+str(count))

    def test_simd_squeeze_effects_physical_source_staging_separation(self):
        geometry=t.o.reconcile.terminal.shape.reject.digest.geometry()
        self.assertEqual(len(t.separation(geometry)),4)
        for key,span in (('workspace',[-64,5195]),('staging',[5200,6225]),
            ('staging',[1920,2944]),('staging',[-1200,-176]),('result',[5300,5400])):
            bad=copy.deepcopy(geometry);bad['executor_entry_objects'][key]=span
            with self.assertRaises(ValueError):t.separation(bad)


class SimdSqueezeEffectsSavedTests:
    def simd_squeeze_effects_fixture(self):
        import windows_enclave_sha3_batch_chains as c
        r=c.inspect_route(self.saved,self.root,'simd',self.spec['simd']);_,_,asm,_,_,b=self.routes['simd']
        return (b,asm,*[r[k] for k in ('simd_digest','simd_public_framing','simd_lane_squeeze','simd_scalar_call_effects')])

    def simd_squeeze_effects_state(self,b,asm):
        n=t.squeeze.names(b);code=t.life.code(b[n['executor']]);edges,_=t.o.reconcile.graph(code,asm)
        spans,_,_=t.o.frame_writes(code,edges);states=t.w.definitions(code,edges,spans,(*t.m.SLOTS,960))
        return n,code,edges,spans,states

    def test_simd_squeeze_effects_full_width_metadata_saved_instruction_replay(self):
        b,asm,*_=self.simd_squeeze_effects_fixture();n,code,_,_,_=self.simd_squeeze_effects_state(b,asm);count=0
        actual=code[920:992]+code[624:648]
        for tag,rate in enumerate(t.squeeze.model.RATES):
            for bits in ((1<<32)+3,(1<<63)+1,t.MASK):
                total=(bits+7)//8
                for written in (0,total-1,total,total+1):
                    for start in (0,1023,t.MASK):
                        result=t.squeeze.model.check(actual,n,tag,bits,written,start,tag%4)
                        window=t.admitted_window(bits,written,start,rate)
                        self.assertEqual(result['failed'],window is None)
                        events=result['events']
                        self.assertEqual(bool(events),window is not None and window['copy'])
                        if events:
                            self.assertEqual(events[0][1:3],(t.squeeze.model.STAGING+window['offset'],window['take']))
                            self.assertEqual(len(events)==2,window['mask_index'] is not None)
                        count+=1
        self.assertEqual(count,288)
        print('Keccak full-width metadata saved-instruction comparisons: 288')

    def test_simd_squeeze_effects_every_instruction_and_guard_bypass(self):
        b,asm,*_=self.simd_squeeze_effects_fixture();n,code,edges,_,_=self.simd_squeeze_effects_state(b,asm)
        for at in range(920,992):
            bad=code.copy();bad[at]='nop'
            with self.assertRaises(ValueError):t.flow(bad,edges,n)
        for at in (920,932,938,942,949,953,961,964,974,977,985):
            bad=copy.deepcopy(edges);bad[0].append(at)
            with self.assertRaises(ValueError):t.flow(code,bad,n)
        for at in (931,937,941,948,963,973,976):
            bad=copy.deepcopy(edges);bad[at]=[at+1]
            with self.assertRaises(ValueError):t.flow(code,bad,n)
        print('Keccak squeeze instruction mutations: 72; entry/guard bypasses: 18 rejected')

    def test_simd_squeeze_effects_root_lane_and_partial_restore_mutations(self):
        b,asm,*rest=self.simd_squeeze_effects_fixture();n,code,_,_,_=self.simd_squeeze_effects_state(b,asm)
        changes=((589,'leaq 1921(%rbx), %rax'),(590,'movl %eax, 960(%rbp)'),
            (622,'movl $1, %r9d'),(638,'addq $2, %r9'),(640,'cmpq $560, %r8'),
            (789,'movq 880(%rbp), %r9'),(838,'movq 880(%rbp), %r9'),
            (967,'movl 864(%rbp), %r9d'),(984,'movq %r8, %r14'),(987,'movq %r8, %r9'))
        for at,line in changes:
            bad=code.copy();bad[at]=line
            with self.assertRaises(ValueError):t.inspect(b|{n['executor']:n['executor']+':\n'+'\n'.join(bad)},asm,*rest)
        print('Keccak squeeze root/lane/restore mutations rejected: 10')

    def test_simd_squeeze_effects_observer_preserves_loop_model_and_scope(self):
        args=self.simd_squeeze_effects_fixture();b,asm,*_=args;n,code,edges,spans,_=self.simd_squeeze_effects_state(b,asm)
        for lane in range(4):
            seen=set();plain=t.m.check_lane(code,edges,spans,lane)
            observed=t.m.check_lane(code,edges,spans,lane,lambda at,before:seen.add(at))
            self.assertEqual(plain,observed);self.assertEqual(seen,t.m.NODES)
        with self.assertRaisesRegex(ValueError,'observer failure'):
            t.m.check_lane(code,edges,spans,0,lambda *_:(_ for _ in ()).throw(ValueError('observer failure')))
        r=t.inspect(*args)
        self.assertEqual(r['call_sites'],[961,985]);self.assertEqual(len(r['pending_callee_effect_sites']),22)
        self.assertEqual([v['reachable_positions'] for v in r['lane_provenance']],[371]*4)
        self.assertTrue(r['requires_receiver_validated_identity_and_live_descriptor_metadata'])
        self.assertFalse(r['allocation_lifetimes_and_private_frame_exception_cleanup_qualified'])

    def test_simd_squeeze_effects_prerequisites_and_integration(self):
        args=self.simd_squeeze_effects_fixture();b,asm,caller,framing,squeezing,previous=args
        for obj,key in ((caller['helpers'],'copy_wrapper_checks_equal_lengths'),
            (framing,'public_framing_fields_and_output_offsets_checked'),
            (squeezing,'copy_lengths_equal_and_at_most_rate'),(squeezing,'final_partial_byte_uses_low_bit_mask'),
            (squeezing,'restored_lane_index_input_control_and_frame_pointers_checked'),
            (previous,'original_pointers_lengths_and_saved_index_restores_checked')):
            with patch.dict(obj,{key:False}):
                with self.assertRaises(ValueError):t.inspect(*args)
        for obj,key,value in ((squeezing,'linked_rates',[200]*8),(squeezing['mask']['functions'],'mask','wrong'),
            (previous,'pending_callee_effect_sites',[]),(previous,'pending_non_frame_store_sites',[619])):
            with patch.dict(obj,{key:value}):
                with self.assertRaises(ValueError):t.inspect(*args)
        import windows_enclave_sha3_batch_chains as c
        with patch.object(t,'inspect',side_effect=ValueError('squeeze effects failed')) as check:
            with self.assertRaisesRegex(ValueError,'squeeze effects failed'):
                c.inspect_route(self.saved,self.root,'simd',self.spec['simd'])
            check.assert_called_once()
