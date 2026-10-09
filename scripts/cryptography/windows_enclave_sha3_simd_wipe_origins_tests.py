"""Direct-origin checks must reject a single corrupt predecessor or partial write."""
from unittest.mock import patch
import windows_enclave_sha3_simd_wipe_origins as t


class SimdWipeOriginsModelTests:
    def test_simd_wipe_origins_joins_cycles_and_volatile_effects(self):
        code=['movq 1104(%rbp), %rbx','nop','movq %rbx, %rcx','retq']
        edges={0:[1],1:[1,2],2:[3],3:[]}
        result=t.analyse(code,edges,{})
        self.assertEqual(result[3]['rcx'],{'workspace'})
        # The corrupt branch is not discarded even though a good path exists.
        code=['movq 1104(%rbp), %rbx','nop','movq 1112(%rbp), %rbx','movq %rbx, %rcx','retq']
        result=t.analyse(code,{0:[1],1:[2,3],2:[3],3:[4],4:[]},{})
        self.assertEqual(result[4]['rcx'],{'workspace','staging'})
        code=['nop','movq %rbx, %rcx','movq %rcx, %rbx','retq']
        result=t.analyse(code,{0:[1],1:[2,3],2:[1],3:[]},{})
        self.assertEqual(result[3]['rcx'],{'unknown'})
        for middle in ('movb $0, %bl','movl %ebx, %ebx','leaq 1(%rbx), %rbx','popq %rbx',
            'cmoveq %rax, %rbx'):
            code=['movq 1104(%rbp), %rbx',middle,'movq %rbx, %rcx','retq']
            r=t.analyse(code,{0:[1],1:[2],2:[3],3:[]},{})
            self.assertIn('unknown',r[3]['rcx'])
        for op in ('callq helper','divq %rsi','divl %esi'):
            code=['movq 1104(%rbp), %rax','movq %rax, %rdx','movq %rax, %rbx',op,'retq']
            r=t.analyse(code,{0:[1],1:[2],2:[3],3:[4],4:[]},{})[4]
            self.assertEqual(r['rax'],{'unknown'});self.assertEqual(r['rdx'],{'unknown'})
            self.assertEqual(r['rbx'],{'workspace'})
        with self.assertRaises(ValueError):t.instruction('unassigned %rbx')

    def test_simd_wipe_origins_partial_and_crossing_slot_writes(self):
        for lo,hi in ((1104,1105),(1103,1105),(1108,1116),(1104,1136),(1111,1112)):
            code=['movb $0, 1104(%rbp)','movq 1104(%rbp), %rcx','retq']
            r=t.analyse(code,{0:[1],1:[2],2:[]},{0:(lo,hi)})
            self.assertEqual(r[2]['rcx'],{'unknown'})
        code=['movq 1104(%rbp), %rbx','movq %rbx, 448(%rbp)','movq 448(%rbp), %rcx','retq']
        r=t.analyse(code,{0:[1],1:[2],2:[3],3:[]},{1:(448,456)})
        self.assertEqual(r[3]['rcx'],{'workspace'})


class SimdWipeOriginsSavedTests:
    def simd_wipe_origins_fixture(self):
        import windows_enclave_sha3_batch_chains as c
        r=c.inspect_route(self.saved,self.root,'simd',self.spec['simd'])
        _,_,asm,_,_,b=self.routes['simd']
        return b,asm,r['simd_executor_reconciliation'],r['simd_vector_caller']

    def test_simd_wipe_origins_saved_receivers_and_roots(self):
        b,asm,aggregate,vector=self.simd_wipe_origins_fixture();r=t.inspect(b,asm,aggregate,vector)
        name=r['function'];code=t.life.code(b[name]);count=0
        # Substitute the wrong incoming root at every original argument reload.
        for at,line in enumerate(code):
            if line.startswith(('movq 1104(%rbp),','movq 1112(%rbp),')):
                other='1112' if '1104' in line else '1104'
                bad=code.copy();bad[at]=line.replace('1104' if other=='1112' else '1112',other)
                # Some reloads only feed inner work, not a cleanup receiver.
                # This sweep tests the standalone dataflow demand at its load,
                # independently of downstream normal cleanup liveness.
                edges,_=t.reconcile.graph(bad,asm);spans,_,_=t.frame_writes(bad,edges)
                states=t.analyse(bad,edges,spans)
                reg=line.rsplit('%',1)[1];root=t.ROOTS[int(line[5:9])]
                self.assertNotEqual(states[at+1][reg],{root});count+=1
        self.assertEqual(count,28)
        # Corrupt the exact receiver at each of the seven wipe call sites.
        for at in (73,530,533,1588,1591,1598,1601):
            bad=code.copy();bad[at-1]='movq $0, %rcx'
            with self.assertRaises(ValueError):t.inspect(b|{name:name+':\n'+'\n'.join(bad)},asm,aggregate,vector)
        for at in (13,14,1401,1408):
            bad=code.copy();bad[at]='movl $0, '+('%r15d' if at in (13,1408) else '%ebx' if at==14 else '%r12d')
            with self.assertRaises(ValueError):t.inspect(b|{name:name+':\n'+'\n'.join(bad)},asm,aggregate,vector)
        for slot in (1104,1112):
            for width,source in (('b','$0'),('l','$0'),('q','$0')):
                bad=code.copy();bad[10]=f'mov{width} {source}, {slot}(%rbp)'
                with self.assertRaises(ValueError):t.inspect(b|{name:name+':\n'+'\n'.join(bad)},asm,aggregate,vector)
        print('Keccak direct root reload checks:',count,'; wipe receiver/partial/root-slot mutants: 17')

    def test_simd_wipe_origins_guarded_index_and_frame_mutations(self):
        b,asm,aggregate,vector=self.simd_wipe_origins_fixture();name=aggregate['function'];code=t.life.code(b[name])
        for at,line in ((1042,'cmpq $5, %rcx'),(1043,'ja .B214'),(1045,'movq %r8, 176(%rbp,%rcx,4)'),
            (1045,'movq %r8, 1104(%rbp,%rcx,8)'),(9,'leaq 120(%rsp), %rbp'),
            (76,'movq %rax, %rbp'),(76,'movq %rax, %rsp'),(1044,'movq %r8, %rcx')):
            bad=code.copy();bad[at]=line
            with self.assertRaises(ValueError):t.inspect(b|{name:name+':\n'+'\n'.join(bad)},asm,aggregate,vector)
        # A branch directly into the indexed store invalidates its guard proof.
        for destination in (1043,1044,1045):
            edges,_=t.reconcile.graph(code,asm);edges[1010]=[destination]
            with self.assertRaises(ValueError):t.frame_writes(code,edges)
        r=t.inspect(b,asm,aggregate,vector)
        self.assertEqual(r['indexed_compaction_store_span'],[176,208])
        self.assertTrue(r['call_sites_pending_memory_effects']);self.assertTrue(r['non_frame_store_sites_pending'])

    def test_simd_wipe_origins_prerequisites_and_integration(self):
        args=self.simd_wipe_origins_fixture();b,asm,aggregate,vector=args;r=t.inspect(*args)
        for key in ('all_executor_positions_have_replayed_region_review','normal_cfg_workspace_then_staging_wipe_order_checked'):
            with patch.dict(aggregate,{key:False}):
                with self.assertRaises(ValueError):t.inspect(*args)
        with patch.dict(vector,{'selected_indices':'unknown'}):
            with self.assertRaises(ValueError):t.inspect(*args)
        self.assertTrue(r['indirect_effects_and_physical_aliases_still_required'])
        self.assertFalse(r['original_allocation_lifetimes_qualified'])
        self.assertFalse(r['private_frame_and_exception_cleanup_qualified'])
        import windows_enclave_sha3_batch_chains as c
        with patch.object(t,'inspect',side_effect=ValueError('wipe origins failed')) as check:
            with self.assertRaisesRegex(ValueError,'wipe origins failed'):
                c.inspect_route(self.saved,self.root,'simd',self.spec['simd'])
            check.assert_called_once()
