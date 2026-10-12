"""Actual callback, session and final-health provenance mutation checks."""
import copy
from unittest.mock import patch
import windows_enclave_sha3_simd_service_effects as t


class SimdServiceEffectsSavedTests:
    def simd_service_effects_fixture(self):
        import windows_enclave_sha3_batch_chains as c
        r=c.inspect_route(self.saved,self.root,'simd',self.spec['simd']);_,_,asm,_,_,b=self.routes['simd']
        return b,asm,*[r[k] for k in ('simd_digest','simd_resident_construction','simd_session_cleanup','simd_terminal','simd_transfer_call_effects')]

    def simd_service_effects_state(self,b,asm,code=None):
        n=t.o.reconcile.terminal.shape.names(b)
        n['session']=t.s.one(b,r'^[^?].*keccak_hardened_batch.*Session13permute_bytes$')
        code=t.life.code(b[n['executor']]) if code is None else code
        edges,_=t.o.reconcile.graph(code,asm);spans,_,_=t.o.frame_writes(code,edges)
        states=t.w.definitions(code,edges,spans,t.SLOTS)
        return n,code,edges,states,t.control.analyse(code,edges,spans)

    def test_simd_service_effects_callback_context_target_and_spill_mutations(self):
        b,asm,caller,construction,*_=self.simd_service_effects_fixture()
        n,code,_,_,_=self.simd_service_effects_state(b,asm)
        changes=((496,'movq 1112(%rbp), %r12'),(497,'movq 8(%r12), %rcx'),(498,'movq (%r12), %rax'),
            (499,'movq 24(%rax), %rax'),(500,'movl %ecx, 928(%rbp)'),(501,'movq %rcx, 912(%rbp)'),
            (502,'callq *%rcx'),(1057,'movq 912(%rbp), %rcx'),(1059,'callq *928(%rbp)'),
            (1264,'movq 912(%rbp), %rcx'),(1266,'callq *928(%rbp)'),
            (1391,'movq 912(%rbp), %rcx'),(1393,'callq *928(%rbp)'),
            (40,'movzbl 16(%rax), %ecx'),(43,'callq *16(%rax)'),(1282,'movq 8(%rdi), %rax'),
            (1287,'movzbl 16(%rax), %ecx'),(1289,'callq *16(%rax)'))
        for at,line in changes:
            bad=code.copy();bad[at]=line;_,_,_,states,origins=self.simd_service_effects_state(b,asm,bad)
            with self.assertRaises(ValueError):t.callbacks(bad,states,origins,n,caller,construction)
        print('Keccak service callback provenance mutations rejected: 18')

    def test_simd_service_effects_session_roots_bounds_and_guard_mutations(self):
        b,asm,_,_,session,*_=self.simd_service_effects_fixture()
        n,code,edges,states,origins=self.simd_service_effects_state(b,asm)
        for at,line in ((1125,'movq 8(%rdi), %rcx'),(1127,'movq 960(%rbp), %rdx'),
            (1128,'movq 1112(%rbp), %r8'),(1129,'callq '+n['check']),
            (1055,'cmpq $0, 8(%rdi)'),(1056,'jne .B227')):
            bad=code.copy();bad[at]=line;_,_,e,d,r=self.simd_service_effects_state(b,asm,bad)
            with self.assertRaises(ValueError):t.session_call(bad,e,d,r,n,session)
        bad=copy.deepcopy(edges);bad[0].append(1125)
        with self.assertRaises(ValueError):t.session_call(code,bad,states,origins,n,session)

    def test_simd_service_effects_health_and_nonreturning_terminal(self):
        b,asm,_,_,_,terminal,_=self.simd_service_effects_fixture()
        n,code,_,_,origins=self.simd_service_effects_state(b,asm)
        bad=code.copy();bad[1398]='movq %r12, %rcx';_,_,_,_,r=self.simd_service_effects_state(b,asm,bad)
        with self.assertRaises(ValueError):t.health_call(bad,r,n,terminal)
        for at,line in ((1465,'nop'),(1466,'callq '+n['check']),(1467,'retq')):
            bad=code.copy();bad[at]=line
            with self.assertRaises(ValueError):t.panic_terminal(bad,b,n)
        bad=b|{n['panic']:n['panic']+':\nretq'}
        with self.assertRaises(ValueError):t.panic_terminal(code,bad,n)
        self.assertFalse(t.panic_terminal(code,b,n)['abort_runtime_and_fatal_exit_cleanup_qualified'])

    def test_simd_service_effects_complete_inventory_not_lifetime_promotion(self):
        args=self.simd_service_effects_fixture();b,asm,caller,construction,session,terminal,prior=args
        result=t.inspect(*args)
        self.assertEqual(result['pending_callee_effect_sites'],[])
        self.assertEqual(result['pending_non_frame_store_sites'],[])
        self.assertEqual(len(result['service_effects']),8)
        self.assertFalse(result['allocation_lifetimes_and_private_frame_exception_cleanup_qualified'])
        for obj,key,value in ((caller['callbacks'],'host_callback_accepted',True),
            (construction,'callback_is_pure_compiled_tag_check',False),(construction,'public_callback_not_host_supplied',False),
            (session,'full_scratch_wipe_ranges',[]),(prior,'pending_callee_effect_sites',[1129])):
            with patch.dict(obj,{key:value}):
                with self.assertRaises(ValueError):t.inspect(*args)
        import windows_enclave_sha3_batch_chains as c
        with patch.object(t,'inspect',side_effect=ValueError('service failed')):
            with self.assertRaisesRegex(ValueError,'service failed'):c.inspect_route(self.saved,self.root,'simd',self.spec['simd'])
