"""Actual resident descriptor moves and caller allocation separation regressions."""
import copy
from unittest.mock import patch
import windows_enclave_sha3_simd_allocation_lifetimes as t


class SimdAllocationLifetimesSavedTests:
    def simd_allocation_lifetimes_fixture(self):
        import windows_enclave_sha3_batch_chains as c
        r=c.inspect_route(self.saved,self.root,'simd',self.spec['simd']);_,_,asm,_,_,b=self.routes['simd']
        keys=('simd_digest','simd_receiver','simd_resident_construction','simd_service_call_effects','simd_exception_call_effects')
        return b,asm,*[r[k] for k in keys]

    def test_simd_allocation_lifetimes_all_four_descriptor_move_mutations(self):
        b,_,caller,*_=self.simd_allocation_lifetimes_fixture();code=t.life.code(b[caller['functions']['digest']])
        start=code.index('.B4:')+1;stop=code.index('addq $112, %rax',start);count=0
        for lane in range(4):
            t.moves.transfer(code,lane)
            for at in range(start,stop):
                bad=code.copy();bad[at]='ud2'
                with self.assertRaises(ValueError):t.moves.transfer(bad,lane)
                count+=1
        for old,new in (('movq -56(%rdi,%rax), %r8','movq -24(%rdi,%rax), %r8'),
            ('vmovups 32(%r13), %xmm0','vmovups (%r13), %xmm0'),
            ('movq %r14, 8096(%rbp,%rax)','movq %r8, 8096(%rbp,%rax)'),
            ('movq %r12, 8128(%rbp,%rax)','movq %r15, 8128(%rbp,%rax)')):
            self.assertIn(old,code);bad=[new if line==old else line for line in code]
            with self.assertRaises(ValueError):t.moves.transfer(bad,2)
        print('Keccak resident descriptor move instruction mutations rejected:',count)

    def test_simd_allocation_lifetimes_fixed_frames_and_interior_base_clobbers(self):
        b,_,caller,*_=self.simd_allocation_lifetimes_fixture()
        for name,allocation,probe in ((caller['functions']['digest'],9112,True),(caller['functions']['executor'],1128,False)):
            code=t.life.code(b[name]);t.fixed_frame(code,allocation,probe)
            for old,new in ((f'addq ${allocation}, %rsp',f'addq ${allocation-8}, %rsp'),
                ('leaq 128(%rsp), %rbp','leaq 120(%rsp), %rbp'),('pushq %r15','pushq %r14')):
                self.assertIn(old,code);bad=[new if line==old else line for line in code]
                with self.assertRaises(ValueError):t.fixed_frame(bad,allocation,probe)
            at=code.index('nop')
            for line in ('movq %rax, %rbp','movl %eax, %esp','pushq %rax','popq %rax'):
                bad=code.copy();bad[at]=line
                with self.assertRaises(ValueError):t.fixed_frame(bad,allocation,probe)

    def test_simd_allocation_lifetimes_page_admission_and_publication_mutations(self):
        b,asm,caller,*_=self.simd_allocation_lifetimes_fixture();n=t.moves.digest.helpers.names(b)
        body=b['RetainedWork'];lines=t.s.lines(body)
        for line in ('testq %rdx, %rdx','cmpq $65536, %rax',f'cmpq %rdx, {n["identity"]}(%rip)'):
            at=lines.index(line)+1;self.assertTrue(lines[at].startswith(('set','j')))
        # Redirect a real admission-success edge straight to the receive call.
        graph=t.stack.edges(lines,asm);consume=lines.index('callq '+n['receive'])
        with patch.object(t.stack,'edges',return_value=graph|{0:[consume]}):
            with self.assertRaises(ValueError):t.lifetime_edges(b,asm,n)
        original=t.s.lines(body)
        at=original.index(f'movq %rax, {n["live"]}+16(%rip)')
        changed=original.copy();changed[at]=f'movq %rcx, {n["live"]}+16(%rip)'
        with self.assertRaises(ValueError):t.allocations.publication(b|{'RetainedWork':'\n'.join(changed)},'simd256')
        extra='other:\nleaq '+n['live']+'(%rip), %rax\nretq'
        with self.assertRaises(ValueError):t.allocations.publication(b|{'other':extra},'simd256')

    def test_simd_allocation_lifetimes_physical_overlap_and_bridge_substitution(self):
        b,asm,caller,receiver,*_=self.simd_allocation_lifetimes_fixture();n=t.moves.digest.helpers.names(b)
        t.geometry(b,asm,n,caller);t.bridge(b,n,caller,receiver)
        for key in ('inputs','workspace','control','result'):
            bad=copy.deepcopy(caller);bad['geometry']['executor_entry_objects'][key]=bad['geometry']['executor_entry_objects']['staging']
            with self.assertRaises(ValueError):t.geometry(b,asm,n,bad)
        lines=t.s.lines(b[n['receive']]);old='leaq 1064(%rsp), %r9';self.assertIn(old,lines)
        bad=b|{n['receive']:'\n'.join('leaq 784(%rsp), %r9' if line==old else line for line in lines)}
        with self.assertRaises(ValueError):t.bridge(bad,n,caller,receiver)
        bad=copy.deepcopy(receiver);bad['descriptor_geometry']['slots'][2]['payload']=[0,1024]
        with self.assertRaises(ValueError):t.bridge(b,n,caller,bad)

    def test_simd_allocation_lifetimes_conditional_scope_and_integration(self):
        args=self.simd_allocation_lifetimes_fixture();r=t.inspect(*args)
        self.assertTrue(r['original_payload_and_authority_allocations_joined'])
        self.assertTrue(r['nested_callee_private_frame_effects_and_pointer_cell_preservation_still_required'])
        self.assertFalse(r['complete_private_frame_erasure_qualified'])
        self.assertEqual(len(r['physical_allocations']['worker_payload_slots']),12)
        self.assertEqual(r['lifetime_edges']['admission_edges'],15)
        _,_,_,_,construction,services,exceptions=args
        for obj,key,value in ((construction,'publication_after_authority_and_owner_initialization',False),
            (services,'all_executor_call_site_footprints_assigned',False),
            (exceptions,'original_guard_fields_live_at_all_synchronous_throw_sites',False)):
            with patch.dict(obj,{key:value}):
                with self.assertRaises(ValueError):t.inspect(*args)
        import windows_enclave_sha3_batch_chains as c
        with patch.object(t,'inspect',side_effect=ValueError('allocation failed')):
            with self.assertRaisesRegex(ValueError,'allocation failed'):c.inspect_route(self.saved,self.root,'simd',self.spec['simd'])
