"""Output extent/provenance regressions over actual saved machine instructions."""
import copy
import itertools
from unittest.mock import patch
import windows_enclave_sha3_simd_transfer_effects as t


class SimdTransferEffectsModelTests:
    def test_simd_transfer_effects_all_presence_and_boundary_shapes(self):
        n={'copy':'copy','zero':t.life.ZERO,'workspace_wipe':'wipe'}
        code=['nop']*1482+t.output.prepare_shape()+t.output.copy_shape(n)
        count=0
        for present in itertools.product((False,True),repeat=4):
            for lengths in itertools.product((0,1,31,255,256),repeat=4):
                events=t.model.copies(code,n,present,lengths)
                self.assertEqual(len(events),sum(present));count+=1
            for failed in range(4):t.model.copies(code,n,present,(1,31,255,256),failed)
        self.assertEqual(count,10000)
        print('Keccak output copy boundary/presence cases: 10000; first-failure cases: 64')

    def test_simd_transfer_effects_every_lane_length_and_invalid_input(self):
        n={'copy':'copy','zero':t.life.ZERO,'workspace_wipe':'wipe'}
        code=['nop']*1482+t.output.prepare_shape()+t.output.copy_shape(n)
        for lane in range(4):
            for length in range(257):
                lengths=[256]*4;lengths[lane]=length
                t.model.copies(code,n,[True]*4,lengths)
        for lengths in ((257,0,0,0),(-1,0,0,0),(True,0,0,0),((1<<64)-1,0,0,0)):
            with self.assertRaises(ValueError):t.model.copies(code,n,[True]*4,lengths)
        print('Keccak output full individual length domain cases: 1028')


class SimdTransferEffectsSavedTests:
    def simd_transfer_effects_fixture(self):
        import windows_enclave_sha3_batch_chains as c
        r=c.inspect_route(self.saved,self.root,'simd',self.spec['simd']);_,_,asm,_,_,b=self.routes['simd']
        return b,asm,*[r[k] for k in ('simd_digest','simd_output','simd_frame_alias_effects','simd_source_call_effects')]

    def simd_transfer_effects_state(self,b,asm,code=None):
        n=t.o.reconcile.terminal.shape.names(b)|{'zero':t.life.ZERO}
        code=t.life.code(b[n['executor']]) if code is None else code
        edges,_=t.o.reconcile.graph(code,asm);spans,_,_=t.o.frame_writes(code,edges)
        return n,code,edges,spans,t.w.definitions(code,edges,spans,t.previous.SLOTS)

    def test_simd_transfer_effects_capture_and_direct_alias_mutations(self):
        b,asm,*_=self.simd_transfer_effects_fixture();_,code,edges,spans,_=self.simd_transfer_effects_state(b,asm)
        for at,line in ((15,'movq %r8, %r9'),(17,'vmovups 8(%r9), %ymm0'),
            (18,'vmovups 16(%r9), %ymm1'),(19,'vmovups %ymm1, 592(%rbp)'),(20,'vmovups %ymm0, 624(%rbp)')):
            bad=code.copy();bad[at]=line
            with self.assertRaises(ValueError):t.capture(bad,edges,spans)
        for offset in (591,592,623,624,655):
            with self.assertRaises(ValueError):t.capture(code,edges,spans|{500:(offset,offset+2)})
        for at in (17,19,20):
            bad=copy.deepcopy(edges);bad[27].append(at)
            with self.assertRaises(ValueError):t.capture(code,bad,spans)

    def test_simd_transfer_effects_validator_roots_and_guard_entries(self):
        b,asm,*_=self.simd_transfer_effects_fixture();n,code,edges,_,_=self.simd_transfer_effects_state(b,asm)
        for at,line in ((50,'leaq 600(%rbp), %rdx'),(52,'movq %r9, %rcx'),
            (1428,'leaq 624(%rbp), %rdx'),(1429,'movq 976(%rbp), %rcx')):
            bad=code.copy();bad[at]=line;_,_,_,_,states=self.simd_transfer_effects_state(b,asm,bad)
            with self.assertRaises(ValueError):t.validate_calls(bad,states,n)
        for at in (550,557,560,563,570,573,1485,1506,1519,1534,1546,1555,1567,1579):
            bad=copy.deepcopy(edges);bad[0].append(at)
            with self.assertRaises(ValueError):t.region_entries(code,bad)

    def test_simd_transfer_effects_copy_model_rejects_wrong_lane_length_source_or_failure(self):
        b,asm,*_=self.simd_transfer_effects_fixture();n,code,_,_,_=self.simd_transfer_effects_state(b,asm)
        changes=((1546,'movq 616(%rbp), %rdx'),(1555,'movq 600(%rbp), %rdx'),
            (1556,'movq %rbx, %rcx'),(1557,'movq 960(%rbp), %r8'),(1558,'movq %r12, %r9'),
            (1568,'movq 928(%rbp), %rcx'),(1569,'movq 944(%rbp), %r8'),(1570,'movq 912(%rbp), %r9'),
            (1580,'movq 824(%rbp), %rcx'),(1581,'movq %r12, %r8'),(1582,'movq 936(%rbp), %r9'))
        for at,line in changes:
            bad=code.copy();bad[at]=line
            with self.assertRaises((ValueError,KeyError)):t.model.copies(bad,n,[True]*4,(1,31,255,256))
        for at,lane in ((1549,0),(1561,1),(1573,2),(1585,3)):
            bad=code.copy();bad[at]='jmp .B270'
            with self.assertRaises(ValueError):t.model.copies(bad,n,[True]*4,(1,31,255,256),lane)

    def test_simd_transfer_effects_clear_all_lanes_empty_and_failure_metadata(self):
        b,asm,*_=self.simd_transfer_effects_fixture();n,code,_,_,_=self.simd_transfer_effects_state(b,asm)
        for present in itertools.product((False,True),repeat=4):
            for lengths in itertools.product((0,1,256),repeat=4):t.model.clears(code,n,present,lengths)
        for at,line in ((553,'addq $32, %rsi'),(554,'cmpq $48, %rsi'),(557,'movq 600(%rbp,%rsi), %rcx'),
            (560,'movq 608(%rbp,%rsi), %rdx'),(564,'addq $32, %rsi'),(565,'cmpq $48, %rsi'),
            (568,'movl $3, %edx'),(569,'movq %rdi, %rcx'),(571,'movl $31, %edx'),(572,'movq %rbx, %rcx')):
            bad=code.copy();bad[at]=line
            present=[False,True,True,True] if at==553 else [False,False,False,True] if at==554 else [True]*4
            with self.subTest(instruction=at):
                with self.assertRaises((ValueError,KeyError)):t.model.clears(bad,n,present,(1,31,255,256))
        print('Keccak exact rejection clear shapes: 1296')

    def test_simd_transfer_effects_prerequisites_placement_and_integration(self):
        args=self.simd_transfer_effects_fixture();b,asm,caller,output,frame,prior=args
        result=t.inspect(*args);self.assertEqual(len(result['pending_callee_effect_sites']),9)
        self.assertFalse(result['allocation_lifetimes_and_private_frame_exception_cleanup_qualified'])
        for obj,key,value in ((output,'output_borrow_pointer_ir_uses_closed',False),
            (frame,'bounded_frame_effects_exclude_live_pointer_cells_and_caller_objects',False),
            (prior,'pending_callee_effect_sites',[])):
            with patch.dict(obj,{key:value}):
                with self.assertRaises(ValueError):t.inspect(*args)
        bad=copy.deepcopy(caller);bad['geometry']['destination_slots'][1][0]=7120
        with self.assertRaises(ValueError):t.placement(bad,frame)
        import windows_enclave_sha3_batch_chains as c
        with patch.object(t,'inspect',side_effect=ValueError('transfer failed')):
            with self.assertRaisesRegex(ValueError,'transfer failed'):c.inspect_route(self.saved,self.root,'simd',self.spec['simd'])
