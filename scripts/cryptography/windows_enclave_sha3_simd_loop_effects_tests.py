"""Last store footprints reject lane, cursor, spill, extent and CFG corruption."""
import copy
import re
from unittest.mock import patch
import windows_enclave_sha3_simd_loop_effects as t
m=t.model


class SimdLoopEffectsModelTests:
    def test_simd_loop_effects_abstract_values_clobbers_and_partial_stores(self):
        state={k:m.UNKNOWN for k in (*t.o.REGS,*m.SLOTS)}
        state.update(rax=m.one('workspace',3584),r9=m.one('number',3))
        self.assertEqual(m.address('8(%rax,%r9,8)',state),m.one('workspace',3616))
        self.assertEqual(m.transfer('imulq $156, %r9, %r12',state)['r12'],m.one('number',468))
        for line in ('movl %eax, %ecx','movb %al, %cl','callq helper','divq %r9'):
            after=m.transfer(line,state)
            self.assertEqual(after['rax'] if line.startswith(('call','div')) else after['rcx'],m.UNKNOWN)
        state[880]=m.one('workspace',3584)
        self.assertEqual(m.transfer('movq %rax, 880(%rbp)',state,(880,888))[880],state['rax'])
        for line,span in (('movb %al, 880(%rbp)',(880,881)),('movq %rax, 876(%rbp)',(876,884))):
            self.assertEqual(m.transfer(line,state,span)[880],m.UNKNOWN)
        self.assertEqual(m.add(state['rax'],state['rax']),m.UNKNOWN)
        self.assertEqual(m.add(m.one('number',65536),m.one('number',1)),m.UNKNOWN)
        self.assertEqual(m.merge(state['rax'],m.UNKNOWN),m.UNKNOWN)
        self.assertEqual(m.merge(frozenset(('number',v) for v in range(8)),m.one('number',8)),m.UNKNOWN)
        self.assertEqual(m.operand('%ah',state),m.UNKNOWN)
        for lane in (-1,4,True):
            with self.assertRaises(ValueError):m.check_lane([],{}, {},lane)

    def test_simd_loop_effects_workspace_and_frame_separation(self):
        geometry=t.o.reconcile.terminal.shape.reject.digest.geometry()
        t.separation([[3584,3592],[5259,5260]],geometry)
        for span in ((-1,1),(5260,5261),(1,1),(2,1)):
            with self.assertRaises(ValueError):t.separation([span],geometry)
        for key,span in (('workspace',[-64,5195]),('workspace',[-1200,4060]),('staging',[3500,5300])):
            bad=copy.deepcopy(geometry);bad['executor_entry_objects'][key]=span
            with self.assertRaises(ValueError):t.separation([[3584,3592],[5259,5260]],bad)


class SimdLoopEffectsSavedTests:
    def simd_loop_effects_fixture(self):
        import windows_enclave_sha3_batch_chains as c
        r=c.inspect_route(self.saved,self.root,'simd',self.spec['simd']);_,_,asm,_,_,b=self.routes['simd']
        return (b,asm,*[r[k] for k in ('simd_digest','simd_lane_squeeze','simd_lane_absorption',
            'simd_vector_caller','simd_workspace_write_effects')])

    def test_simd_loop_effects_all_remaining_store_mutations(self):
        b,asm,*rest=self.simd_loop_effects_fixture();name=rest[-1]['function'];code=t.life.code(b[name]);count=0
        for at in sorted(t.SITES):
            op,args=t.o.instruction(code[at]);dest=args[-1]
            replacements=[re.sub(r'\(%\w+','(%rbp',code[at]),
                code[at].rsplit(dest,1)[0]+re.sub(r'^\d*\(',lambda v:str(int(v[0][:-1] or 0)+1)+'(',dest),
                'movw %ax, '+dest]
            for line in replacements:
                bad=code.copy();bad[at]=line
                with self.assertRaises(ValueError):t.inspect(b|{name:name+':\n'+'\n'.join(bad)},asm,*rest)
                count+=1
        self.assertEqual(count,42)
        print('Keccak final reset/cursor/ready/written store mutants rejected: 42')

    def test_simd_loop_effects_root_restore_guard_and_stride_mutations(self):
        b,asm,*rest=self.simd_loop_effects_fixture();name=rest[-1]['function'];code=t.life.code(b[name])
        changes=((588,'leaq 5249(%rbx), %r11'),(609,'leaq 3625(%rbx), %rsi'),
            (615,'movl %r11d, 888(%rbp)'),(616,'movq %rax, 504(%rbp)'),
            (620,'movq %rdi, %rdx'),(621,'movl $112, %r8d'),(622,'movl $1, %r9d'),
            (637,'addq $111, %r8'),(638,'addq $2, %r9'),(639,'addq $155, %rdx'),
            (640,'cmpq $560, %r8'),(641,'jne .B131'),(648,'imulq $157, %r9, %r12'),
            (649,'movq 888(%rbp), %rcx'),(654,'addq %rdx, %r12'),
            (788,'movq 888(%rbp), %r12'),(832,'movq 888(%rbp), %rdx'),
            (833,'movq 880(%rbp), %r9'),(838,'movq 888(%rbp), %r12'),
            (862,'movl 880(%rbp), %r12d'),(872,'movq 864(%rbp), %r8'),
            (878,'movq %r10, 864(%rbp)'),(879,'movl %r12d, 880(%rbp)'),
            (880,'movq %rcx, 896(%rbp)'),(905,'movq 888(%rbp), %r12'),
            (966,'movq 1112(%rbp), %rax'),(967,'movq 832(%rbp), %r9'),
            (971,'movq 888(%rbp), %rdx'),(972,'movq 864(%rbp), %r8'),
            (1225,'cmpq $5, %rax'),(1233,'cmpq $4, %rax'),(1239,'cmpq $4, %rax'),
            (1246,'cmpq $4, %rax'),(1340,'movq 504(%rbp), %r11'),(1341,'movq 888(%rbp), %rsi'))
        for at,line in changes:
            bad=code.copy();bad[at]=line
            with self.assertRaises(ValueError):t.inspect(b|{name:name+':\n'+'\n'.join(bad)},asm,*rest)
        print('Keccak final store root/restore/stride/guard mutants rejected: '+str(len(changes)))

    def test_simd_loop_effects_entry_guard_bypasses(self):
        b,asm,*rest=self.simd_loop_effects_fixture();name=rest[-1]['function'];code=t.life.code(b[name])
        edges,_=t.o.reconcile.graph(code,asm);spans,_,_=t.o.frame_writes(code,edges)
        states=t.w.definitions(code,edges,spans,m.SLOTS);count=0
        for dest in (621,622,623,633,642,702,866,1352):
            bad=copy.deepcopy(edges);bad[0].append(dest)
            with self.assertRaises(ValueError):t.loop_entry(code,bad,states)
            count+=1
        for site,(load,cmp,branch) in t.CLEARS.items():
            for dest in (cmp,branch,site):
                bad=copy.deepcopy(edges);bad[0].append(dest)
                with self.assertRaises(ValueError):t.selected_clears(code,bad,states)
                count+=1
        self.assertEqual(count,20)
        print('Keccak lane-entry and selected-clear CFG bypass mutants rejected: 20')

    def test_simd_loop_effects_complete_lanes_scope_and_integration(self):
        args=self.simd_loop_effects_fixture();b,asm,caller,squeeze,absorb,vector,previous=args;r=t.inspect(*args)
        self.assertEqual(len(r['store_sites']),14);self.assertEqual(r['pending_non_frame_store_sites'],[])
        self.assertEqual(len(r['pending_callee_effect_sites']),53)
        self.assertEqual([v['reachable_positions'] for v in r['per_lane_effects']],[371]*4)
        self.assertEqual([v['backedges'] for v in r['per_lane_effects']],[[641],[641],[641],[]])
        self.assertTrue(r['callee_memory_effects_and_win64_nonvolatile_abi_required'])
        self.assertFalse(r['allocation_lifetimes_indirect_aliases_and_private_frame_exception_cleanup_qualified'])
        for obj,key in ((squeeze,'restored_lane_index_input_control_and_frame_pointers_checked'),
            (absorb,'cursor_block_count_and_absorbing_to_ready_transition_checked'),
            (vector,'completed_group_readiness_cleared_before_rescan'),(previous,'original_workspace_and_guarded_lane_checked')):
            with patch.dict(obj,{key:False}):
                with self.assertRaises(ValueError):t.inspect(*args)
        with patch.dict(previous,{'pending_non_frame_store_sites':[]}):
            with self.assertRaises(ValueError):t.inspect(*args)
        import windows_enclave_sha3_batch_chains as c
        with patch.object(t,'inspect',side_effect=ValueError('loop effects failed')) as check:
            with self.assertRaisesRegex(ValueError,'loop effects failed'):
                c.inspect_route(self.saved,self.root,'simd',self.spec['simd'])
            check.assert_called_once()
