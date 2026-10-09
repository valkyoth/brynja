"""Internal XOR effects reject cursor drift, stale roots and guard bypasses."""
import copy
from unittest.mock import patch
import windows_enclave_sha3_simd_absorb_effects as t


class SimdAbsorbEffectsModelTests:
    def test_simd_absorb_effects_transfer_kills_partial_and_overlapping_cells(self):
        state={k:t.m.UNKNOWN for k in (*t.o.REGS,*t.SLOTS)}
        state.update(r11=t.m.one('byte_cursor',0),r12=t.m.one('workspace',3584))
        saved=t.transfer('movq %r11, 848(%rbp)',state,(848,856))
        self.assertEqual(t.transfer('movq 848(%rbp), %rcx',saved)['rcx'],state['r11'])
        for line,span in (('movl %r11d, 848(%rbp)',(848,852)),('movb $0, 855(%rbp)',(855,856)),
            ('movq %r12, 844(%rbp)',(844,852))):
            self.assertEqual(t.transfer(line,saved,span)[848],t.m.UNKNOWN)
        called=t.transfer('callq helper',saved)
        self.assertTrue(all(called[r]==t.m.UNKNOWN for r in t.o.VOLATILE))
        self.assertEqual(called[848],state['r11']);self.assertEqual(called['r12'],state['r12'])
        self.assertEqual(t.transfer('incl %r11d',saved)['r11'],t.m.UNKNOWN)
        self.assertEqual(t.transfer('incq %r11',saved)['r11'],t.m.one('byte_cursor',1))
        self.assertEqual(t.transfer('leaq 176(%rbp), %rdx',saved)['rdx'],t.m.one('child_frame',176))

    def test_simd_absorb_effects_internal_sources_and_rate_bytes_physically_disjoint(self):
        geometry=t.o.reconcile.terminal.shape.reject.digest.geometry();rows=t.physical(geometry)
        self.assertEqual(len(rows),8);self.assertEqual({r['access_bytes'] for r in rows},{1})
        count=0
        for lane in range(4):
            for rate in sorted(set(t.absorb.model.framing.RATES)):
                for byte in range(rate):
                    offset=1920+lane*200+byte
                    self.assertTrue(1920+lane*200<=offset<1920+(lane+1)*200)
                    count+=1
        self.assertEqual(count,2496)
        for key,span in (('workspace',[-64,5195]),('workspace',[-1300,3960]),
            ('staging',[1920,2944]),('result',[-1024,-1023])):
            bad=copy.deepcopy(geometry);bad['executor_entry_objects'][key]=span
            with self.assertRaises(ValueError):t.physical(bad)


class SimdAbsorbEffectsSavedTests:
    def simd_absorb_effects_fixture(self):
        import windows_enclave_sha3_batch_chains as c
        r=c.inspect_route(self.saved,self.root,'simd',self.spec['simd']);_,_,asm,_,_,b=self.routes['simd']
        return (b,asm,*[r[k] for k in ('simd_digest','simd_lane_absorption','simd_frame_alias_effects','simd_squeeze_call_effects')])

    def simd_absorb_effects_state(self,b,asm,code=None):
        n=t.absorb.shape.names(b);code=t.life.code(b[n['executor']]) if code is None else code
        edges,_=t.o.reconcile.graph(code,asm);spans,_,_=t.o.frame_writes(code,edges)
        states=t.w.definitions(code,edges,spans,t.SLOTS)
        return n,code,edges,spans,states

    def test_simd_absorb_effects_complete_slice_and_cfg_bypasses(self):
        b,asm,*_=self.simd_absorb_effects_fixture();n,code,edges,_,_=self.simd_absorb_effects_state(b,asm)
        for at in range(648,920):
            bad=code.copy();bad[at]='nop'
            with self.assertRaises(ValueError):t.flow(bad,edges,n)
        entries=(648,654,655,656,660,662,668,683,782,827,851,899,911,913)
        for at in entries:
            bad=copy.deepcopy(edges);bad[0].append(at)
            with self.assertRaises(ValueError):t.flow(code,bad,n)
        branches=(653,687,692,696,741,748,769,791,817,829,835,840,859,873,908,913)
        for at in branches:
            bad=copy.deepcopy(edges);bad[at]=[at+1]
            with self.assertRaises(ValueError):t.flow(code,bad,n)
        print('Keccak absorption-effect instruction mutations rejected: 272; entry/guard bypasses: 30')

    def test_simd_absorb_effects_original_lane_root_and_preheader_mutations(self):
        b,asm,*_=self.simd_absorb_effects_fixture();n,code,edges,spans,states=self.simd_absorb_effects_state(b,asm)
        changes=((589,'leaq 1921(%rbx), %rax'),(590,'movl %eax, 960(%rbp)'),
            (621,'movl $1, %r8d'),(622,'movl $1, %r9d'),(638,'addq $2, %r9'),
            (654,'addq %rdx, %r12'),(655,'imulq $201, %r9, %r11'),(656,'addq 824(%rbp), %r11'),
            (661,'addq %r12, %rax'),(667,'leaq 154(%r12), %rax'),(681,'leaq 103(%r12), %rax'))
        for at,line in changes:
            bad=code.copy();bad[at]=line;_,_,e,p,d=self.simd_absorb_effects_state(b,asm,bad)
            with self.assertRaises(ValueError):t.entry(bad,e,p,d,2,168)
        print('Keccak absorption root/lane/preheader mutations rejected: '+str(len(changes)))

    def test_simd_absorb_effects_cursor_restores_and_internal_source_mutations(self):
        b,asm,*_=self.simd_absorb_effects_fixture();n,code,edges,spans,states=self.simd_absorb_effects_state(b,asm)
        initial=t.entry(code,edges,spans,states,2,168)
        changes=((734,'movq %r9, %r10'),(744,'movq %r9, %r11'),(776,'movq 512(%rbp), %rdx'),
            (780,'movl %r11d, 848(%rbp)'),(784,'movq 840(%rbp), %r11'),(799,'movq %rsi, 568(%rbp)'),
            (823,'movq %rcx, 848(%rbp)'),(839,'movq 840(%rbp), %rcx'),(853,'movq 840(%rbp), %r11'),
            (863,'movq 840(%rbp), %r11'),(893,'leaq 175(%rbp), %rdx'),(897,'movq %r9, %r12'),
            (902,'movq %r9, %r11'),(911,'addq $2, %r11'),(911,'incl %r11d'))
        for at,line in changes:
            bad=code.copy();bad[at]=line;_,_,e,p,_=self.simd_absorb_effects_state(b,asm,bad)
            with self.assertRaises(ValueError):t.byte_induction(bad,e,p,initial,n,2)
        print('Keccak absorption cursor/internal-source mutations rejected: '+str(len(changes)))

    def test_simd_absorb_effects_all_lane_rates_and_explicit_scope(self):
        args=self.simd_absorb_effects_fixture();r=t.inspect(*args)
        self.assertEqual(r['call_sites'],[782,899]);self.assertEqual(r['destination_sites'],[782,827,851,899])
        self.assertEqual(len(r['byte_loop_inductions']),20)
        self.assertEqual({v['reachable_positions'] for v in r['byte_loop_inductions']},{231})
        self.assertEqual({(v['lane'],v['rate']) for v in r['byte_loop_inductions']},
            {(l,r) for l in range(4) for r in set(t.absorb.model.framing.RATES)})
        self.assertEqual(r['external_source_sites_pending'],[827,851]);self.assertEqual(len(r['pending_callee_effect_sites']),20)
        self.assertFalse(r['allocation_lifetimes_and_private_frame_exception_cleanup_qualified'])
        self.assertTrue(r['requires_receiver_validated_identity_and_live_descriptor_metadata'])

    def test_simd_absorb_effects_prerequisites_and_integration(self):
        args=self.simd_absorb_effects_fixture();b,asm,caller,absorbing,frame,prior=args
        for obj,key,value in ((absorbing['helpers'],'invalid_parameters_rejected_before_secret_read',False),
            (absorbing['helpers'],'valid_count',[0,8]),(absorbing,'linked_rates',[0]*8),
            (absorbing,'readonly_bit_sources_and_two_byte_splits_checked',False),
            (absorbing,'cursor_block_count_and_absorbing_to_ready_transition_checked',False),
            (frame,'child_frame_origin_in_parent',-1192),(frame,'bounded_frame_effects_exclude_live_pointer_cells_and_caller_objects',False),
            (prior,'original_state_staging_roots_and_lane_induction_checked',False),(prior,'pending_callee_effect_sites',[])):
            with patch.dict(obj,{key:value}):
                with self.assertRaises(ValueError):t.inspect(*args)
        import windows_enclave_sha3_batch_chains as c
        with patch.object(t,'inspect',side_effect=ValueError('absorption effects failed')) as check:
            with self.assertRaisesRegex(ValueError,'absorption effects failed'):
                c.inspect_route(self.saved,self.root,'simd',self.spec['simd'])
            check.assert_called_once()
