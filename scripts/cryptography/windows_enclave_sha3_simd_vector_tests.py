"""Grouping, charging, lane transfer and counter/error regressions."""
import itertools
from unittest.mock import patch
import windows_enclave_sha3_simd_vector as t
model=t.model


def fixture():
    n=dict(copy='copy',session='session');return t.shape.shape(n),n


class SimdVectorModelTests:
    def test_simd_vector_stable_compaction_campaign(self):
        code,n=fixture();count=0
        for poison in (0x39,0xa5):
            for args in model.selections():model.check_selection(code,n,*args,poison=poison);count+=1
        for flags,kernel in itertools.product(itertools.product((0,1,2,255),repeat=4),(0,1)):
            model.check_selection(code,n,flags,(1,1,1,1),kernel=kernel)
            model.check_selection(code,n,(1,1,1,1),flags,kernel=kernel);count+=2
        self.assertEqual(count,3072)
        print('Keccak stable ready/eligible compaction cases:',count)

    def test_simd_vector_charge_state_counter_campaign(self):
        code,n=fixture();count=0
        for ready,eligible,authority,kernel in model.selections():
            # Both authority states occur in selections; keep each full case once.
            if not authority:continue
            model.check(code,n,ready=ready,eligible=eligible,kernel=kernel);count+=1
        for poison,budget,charged,counter,calls,blocks,cancel in itertools.product(
            (0x39,0xa5),(0,3,4,5),(0,model.MASK-4,model.MASK-3,model.MASK),
            (0,model.MASK),(0,model.MASK),(0,model.MASK-4,model.MASK-3),(False,True)):
            model.check(code,n,budget=budget,charged=charged,counter=counter,vector_calls=calls,
                        blocks=blocks,cancel=cancel,poison=poison);count+=1
        self.assertEqual(count,1280)
        print('Keccak vector charge/transfer/retirement oracle comparisons:',count)

    def test_simd_vector_copy_session_and_counter_failures(self):
        code,n=fixture();mem,writable=model.prepare();machine=model.machine
        for at in range(1,9):
            r=machine.run(code,n,mem,writable,copy_failure=at)
            self.assertEqual(r['exit'],'.B227')
            self.assertEqual(sum(e[0]=='copy' for e in r['events']),at)
            self.assertEqual(r['registers']['r13'],0)
            self.assertEqual([r['memory'][machine.WORK+5248+i] for i in range(4)],[1]*4)
        for error in range(4):
            r=machine.run(code,n,mem,writable,session_error=error)
            self.assertEqual(r['exit'],'.B226')
            self.assertEqual(sum(e[0]=='copy' for e in r['events']),4)
            self.assertEqual(r['memory'][machine.AUTH+16],0)
        for delta in (0,2):
            r=machine.run(code,n,mem,writable,counter_delta=delta)
            self.assertEqual(r['exit'],'.B227')
            self.assertEqual(sum(e[0]=='copy' for e in r['events']),4)
        bad=dict(mem);bad.update(enumerate(bytes(8),machine.EXEC))
        self.assertEqual(machine.run(code,n,bad,writable)['exit'],'.B227')

    def test_simd_vector_unassigned_effects_and_context(self):
        code,n=fixture();mem,writable=model.prepare();m=model.machine
        for line in ('callq unreviewed','movq $0, (%rdi)','movq 6000(%rbx), %rax','ud2','jmp .B999'):
            with self.assertRaises(ValueError):m.run([line]+code,n,mem,writable)
        for offset in (912,928,776,960,888):
            bad=dict(mem);bad.update(enumerate((123).to_bytes(8,'little'),m.STACK+offset))
            with self.assertRaises(ValueError):m.run(code,n,bad,writable)
        with self.assertRaises(ValueError):m.run(code,n,mem,writable,max_steps=1)

    def test_simd_vector_load_bearing_mutants(self):
        code,n=fixture()
        samples=[{},dict(budget=3),dict(charged=model.MASK),dict(counter=model.MASK),
            dict(vector_calls=model.MASK),dict(blocks=model.MASK),dict(cancel=True),
            dict(ready=(1,0,1,1)),dict(eligible=(0,1,1,1)),dict(accelerated=0x80),dict(kernel=1)]
        changes=[('cmpb $1, (%r8)','cmpb $0, (%r8)'),
            ('movq %r8, 176(%rbp,%rcx,8)','movq $0, 176(%rbp,%rcx,8)'),
            ('subq %rbx, %rax','subq $0, %rax'),('addq %rbx, %rcx','addq $0, %rcx'),
            ('jne .B224','je .B224'),('movl $800, %edx','movl $799, %edx'),
            ('imulq $200, %rax, %r8','imulq $199, %rax, %r8'),
            ('movq 728(%rbp), %rcx','movq 736(%rbp), %rcx'),
            ('movq 1104(%rbp), %r8','movq 776(%rbp), %r8'),
            ('incq %rbx','addq $2, %rbx'),('jne .B226','je .B226'),
            ('imulq $200, %rbx, %rcx','imulq $199, %rbx, %rcx'),
            ('movq 728(%rbp), %r8','movq 736(%rbp), %r8'),
            ('orb %al, %r14b','movb %al, %r14b'),
            ('incq %r13','addq $2, %r13'),('addq %rax, 744(%rbp)','addq $0, 744(%rbp)'),
            ('movb %cl, 991(%rbp)','movb $2, 991(%rbp)'),
            ('movb $0, (%rcx,%rax)','movb $1, (%rcx,%rax)'),
            ('movq 968(%rbp), %r14','movq $0, %r14'),
            ('movq 1120(%rbp), %r12','movq $0, %r12')]
        for old,new in changes:
            with self.subTest(old=old):
                self.assertIn(old,code);bad=[new if l==old else l for l in code];caught=False
                for case in samples:
                    try:model.check(bad,n,**case)
                    except ValueError:caught=True;break
                self.assertTrue(caught,'vector semantic mutant survived: '+old)
        print('Keccak vector reached selection/charge/transfer/counter mutants rejected:',len(changes))


class SimdVectorSavedTests:
    def simd_vector_fixture(self):
        import windows_enclave_sha3_batch_chains as c
        args=self.simd_digest_fixture();b,asm,ir,_,session,*_=args
        caller=c.simd_digest.inspect(*args)
        reject_args=self.simd_reject_fixture();rejection=c.simd_reject.inspect(*reject_args)
        absorption=c.simd_absorb.inspect(*self.simd_absorb_fixture())
        return b,caller,session,rejection,absorption

    def test_simd_vector_saved_instruction_mutations(self):
        args=self.simd_vector_fixture();r=t.inspect(*args);b,*rest=args;name=r['function'];code=t.life.code(b[name]);count=0
        for at in range(*r['region']):
            for replacement in ([],['ud2'],['retq',code[at]]):
                bad=code[:at]+replacement+code[at+1:]
                with self.assertRaises(ValueError):t.inspect(b|{name:name+':\n'+'\n'.join(bad)},*rest)
                count+=1
        self.assertEqual(count,783)
        print('Keccak vector grouping/charge/transfer instruction mutations rejected:',count)

    def test_simd_vector_composition_and_scope(self):
        args=self.simd_vector_fixture();b,caller,session,rejection,absorption=args;r=t.inspect(*args)
        for obj,key in ((caller['helpers'],'copy_wrapper_checks_equal_lengths'),
            (caller['callbacks'],'context_is_zero_sized'),
            (session,'caller_output_after_revalidation_and_checked_counter'),
            (session,'success_error_and_callback_unwind_scratch_clearing_composed'),
            (rejection,'first_cancel_callback_uses_original_control_context'),
            (absorption,'cursor_block_count_and_absorbing_to_ready_transition_checked')):
            with patch.dict(obj,{key:False}):
                with self.assertRaises(ValueError):t.inspect(*args)
        for key in ('scalar_fallback_and_final_report_serialization_qualified',
            'all_incoming_pointer_lifetimes_and_storage_nonoverlap_qualified','rejection_edge_and_exception_private_frame_cleanup_composed'):
            self.assertFalse(r[key])
        import windows_enclave_sha3_batch_chains as c
        with patch.object(t,'inspect',side_effect=ValueError('vector caller failed')) as call:
            with self.assertRaisesRegex(ValueError,'vector caller failed'):c.inspect_route(self.saved,self.root,'simd',self.spec['simd'])
            call.assert_called_once()

    def test_simd_vector_actual_saved_selection_and_effects(self):
        args=self.simd_vector_fixture();r=t.inspect(*args);n=t.shape.names(args[0]);code=t.life.code(args[0][r['function']])[992:1253]
        for case in list(model.selections())[::17]:model.check_selection(code,n,*case)
        for case in ({},dict(kernel=1),dict(cancel=True),dict(counter=model.MASK),dict(charged=model.MASK),dict(blocks=model.MASK)):
            model.check(code,n,**case)
