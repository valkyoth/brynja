"""Admission, cancellation and reuse/retirement regressions for saved code."""
import itertools
from unittest.mock import patch
import windows_enclave_sha3_simd_reject as t
model=t.model


def campaign():
    for kernel,mode,total,cancel,flags,poison in itertools.product(
        (None,0,1),range(3),(0,1024,1025,(1<<64)-1),(False,True),
        itertools.product((0,1),repeat=4),(0x39,0xa5)):
        yield dict(kernel=kernel,mode=mode,total=total,cancel=cancel,eligible=flags,poison=poison)
    for error,kernel,present,lengths,poison in itertools.product(model.VALID_ERRORS,
        (None,0,1),itertools.product((False,True),repeat=4),
        ((0,1,255,256),(256,255,1,0)),(0x39,0xa5)):
        yield dict(error=error,kernel=kernel,poison=poison,
            outputs=tuple(n if p else None for p,n in zip(present,lengths)))


class SimdRejectModelTests:
    def test_simd_reject_independent_admission_and_retirement_campaign(self):
        n={'workspace_wipe':'reviewed_wipe'};code=t.shape.eligibility()+t.shape.cleanup(n)
        count=0
        for case in campaign():model.check(code,n,**case);count+=1
        self.assertEqual(count,4992)
        # Corrupt eligibility bytes must not count as the canonical value one.
        for flags in itertools.product((0,1,2,255),repeat=4):
            model.check(code,n,eligible=flags);count+=1
        self.assertEqual(count,5248)
        print('Keccak emitted eligibility/rejection oracle comparisons:',count)

    def test_simd_reject_load_bearing_decisions_and_retirement(self):
        n={'workspace_wipe':'reviewed_wipe'};code=t.shape.eligibility()+t.shape.cleanup(n)
        samples=[{},dict(total=1025),dict(eligible=(1,1,0,0)),dict(mode=1,kernel=None),
            dict(cancel=True),dict(outputs=(None,0,1,256),error=14)]
        samples += [dict(error=e,outputs=(1,2,3,4)) for e in model.VALID_ERRORS]
        samples += [dict(eligible=tuple(int(i!=j) for i in range(4))) for j in range(4)]
        changes=[('cmpq $1024, %r8','cmpq $1025, %r8'),
            ('jbe .B66','jb .B66'),('xorl $1, %eax','xorl $0, %eax'),
            ('cmpb $2, 17(%rdi)','cmpb $1, 17(%rdi)'),
            ('movq 32(%rax), %rax','movq 24(%rax), %rax'),
            ('movq (%r12), %rcx','movq 16(%r12), %rcx'),
            ('je .B86','jne .B86'),('movb $-3, %dl','movb $-1, %dl'),
            ('shlb $3, %cl','shlb $2, %cl'),('movb $1, %r14b','movb $0, %r14b'),
            ('callq reviewed_wipe','nop'),('movl $1024, %edx','movl $1023, %edx'),
            ('movb $1, 16(%rdi)','movb $0, 16(%rdi)'),
            ('movb $0, 16(%rax)','movb $1, 16(%rax)'),
            ('movb $-1, 129(%rsi)','movb $0, 129(%rsi)'),
            ('movq 600(%rbp,%rsi), %rdx','movq 608(%rbp,%rsi), %rdx'),
            ('movl $4, %edx','movl $3, %edx'),('movl $32, %edx','movl $31, %edx')]
        changes += [(f'cmpb $1, {5252+i}(%rbx)',f'cmpb $1, {5252+(i+1)%4}(%rbx)') for i in range(4)]
        for old,new in changes:
            with self.subTest(old=old):
                self.assertIn(old,code);bad=list(code);bad[bad.index(old)]=new;caught=False
                for case in samples:
                    try:model.check(bad,n,**case)
                    except ValueError:caught=True;break
                self.assertTrue(caught,'semantic rejection mutant survived: '+old)
        print('Keccak reached admission/classification/retirement mutants rejected:',len(changes))

    def test_simd_reject_model_disallows_unassigned_effects(self):
        n={'workspace_wipe':'reviewed_wipe'};code=t.shape.eligibility()+t.shape.cleanup(n)
        for line in ('callq unreviewed','movq $0, (%rdi)',
                     'movq 4096(%rdi), %rax','ud2','jmp .B85'):
            with self.assertRaises(ValueError):model.check([line]+code,n)
        with self.assertRaises(ValueError):model.run(code,n,max_steps=1)


class SimdRejectSavedTests:
    def simd_reject_fixture(self):
        import windows_enclave_sha3_simd_output as output
        import windows_enclave_sha3_simd_frame as frame
        args=self.simd_digest_fixture();caller=t.shape.digest.inspect(*args)
        return args[0],args[2],caller,output.inspect(args[0],args[2],caller),frame.inspect(args[0],args[1],caller)

    def test_simd_reject_saved_instruction_mutations(self):
        args=self.simd_reject_fixture();r=t.inspect(*args);b,ir,caller,out,frame=args
        name=r['function'];code=t.life.code(b[name]);count=0
        for begin,end in (r['entry_region'],r['eligibility_region'],r['normal_rejection_region']):
            for at in range(begin,end):
                for replacement in ([],['ud2'],['retq',code[at]]):
                    bad=code[:at]+replacement+code[at+1:]
                    with self.assertRaises(ValueError):t.inspect(b|{name:name+':\n'+'\n'.join(bad)},ir,caller,out,frame)
                    count+=1
        self.assertEqual(count,609)
        print('Keccak entry/admission/rejection instruction mutations rejected:',count)

    def test_simd_reject_callback_transfer_and_prerequisites(self):
        args=self.simd_reject_fixture();r=t.inspect(*args);b,ir,caller,out,frame=args
        changes=[('%.val.i.i = load ptr, ptr %6, align 8','%.val.i.i = load ptr, ptr %5, align 8'),
            ('%90 = getelementptr inbounds nuw i8, ptr %6, i64 8','%90 = getelementptr inbounds nuw i8, ptr %6, i64 16'),
            ('%91 = getelementptr inbounds nuw i8, ptr %.val1.i.i, i64 32','%91 = getelementptr inbounds nuw i8, ptr %.val1.i.i, i64 24'),
            ('i1 %92(ptr noundef nonnull %.val.i.i)','i1 %92(ptr noundef nonnull %6)'),
            ('to label %.noexc.i unwind label %798','to label %.noexc.i unwind label %41'),
            ('br i1 %93, label %.loopexit538.thread, label %94','br i1 %93, label %94, label %.loopexit538.thread')]
        for old,new in changes:
            self.assertIn(old,ir)
            with self.assertRaises(ValueError):t.inspect(b,ir.replace(old,new,1),caller,out,frame)
        for container,key in ((caller['callbacks'],'context_is_zero_sized'),
            (out,'output_borrow_pointer_ir_uses_closed'),(frame,'public_framing_fields_and_output_offsets_checked')):
            with patch.dict(container,{key:False}):
                with self.assertRaises(ValueError):t.inspect(*args)
        self.assertFalse(r['all_error_predecessor_pointer_lifetimes_qualified'])
        self.assertFalse(r['exception_and_private_frame_erasure_qualified'])
        import windows_enclave_sha3_batch_chains as c
        with patch.object(t,'inspect',side_effect=ValueError('rejection review failed')) as call:
            with self.assertRaisesRegex(ValueError,'rejection review failed'):
                c.inspect_route(self.saved,self.root,'simd',self.spec['simd'])
            call.assert_called_once()

    def test_simd_reject_actual_saved_region_with_sparse_outputs(self):
        args=self.simd_reject_fixture();r=t.inspect(*args)
        code=t.life.code(args[0][r['function']])[454:588]
        n=t.shape.digest.helpers.names(args[0])
        for case in list(campaign())[::71]:model.check(code,n,**case)
