"""Scalar fallback caller, actual kernel/ABI and failure-order regressions."""
import itertools
from unittest.mock import patch
import windows_enclave_sha3_simd_scalar as t
model=t.model


def fixture():
    n=dict(copy='copy',scalar='scalar',scalar_wipe='scalar_wipe')
    return t.shape.shape(n),n


class SimdScalarModelTests:
    def test_simd_scalar_flags_and_effect_campaign(self):
        code,n=fixture();count=0
        for ready,authority,poison in itertools.product(itertools.product((0,1,2,255),repeat=4),(False,True),(0x39,0xa5)):
            model.check(code,n,ready=ready,authority=authority,poison=poison);count+=1
        self.assertEqual(count,1024)
        print('Keccak scalar flag/effect oracle comparisons:',count)

    def test_simd_scalar_health_charge_and_counter_campaign(self):
        code,n=fixture();count=0
        for budget,charged,blocks,authority,healthy,quarantined in itertools.product(
            (0,1,3,4),(0,model.MASK-1,model.MASK),(0,model.MASK-1,model.MASK),
            (False,True),(False,True),(False,True)):
            model.check(code,n,budget=budget,charged=charged,blocks=blocks,authority=authority,
                healthy=healthy,quarantined=quarantined);count+=1
        self.assertEqual(count,288)
        for slot in range(1,5):
            model.check(code,n,cancel_at=slot);model.check(code,n,revoke_at=slot)
        for copy in range(1,9):model.check(code,n,copy_failure=copy)
        print('Keccak scalar accounting/health cases:',count,'; poll/revocation/copy failures: 16')

    def test_simd_scalar_unassigned_effects_and_corrupt_homes(self):
        code,n=fixture();mem,writable=model.prepare();m=model.m
        for line in ('callq unreviewed','movq $0, (%rdi)','movq 6000(%rbx), %rax','ud2','jmp .B999'):
            with self.assertRaises(ValueError):m.run([line]+code,n,mem,writable)
        for offset in (888,928,912,960,704,488,712,720,496):
            bad=dict(mem);bad.update(enumerate((123).to_bytes(8,'little'),m.STACK+offset))
            with self.assertRaises(ValueError):m.run(code,n,bad,writable)
        bad=dict(mem);bad.update(enumerate((123).to_bytes(8,'little'),m.AUTH+8))
        with self.assertRaises(ValueError):m.run(code,n,bad,writable)
        with self.assertRaises(ValueError):m.run(code,n,mem,writable,max_steps=1)

    def test_simd_scalar_load_bearing_mutations(self):
        code,n=fixture()
        samples=[{},dict(authority=False),dict(ready=(0,1,0,1)),dict(budget=0),
            dict(charged=model.MASK),dict(blocks=model.MASK),dict(cancel_at=1),
            dict(revoke_at=1),dict(healthy=False),dict(quarantined=True),dict(copy_failure=2)]
        changes=[('cmpq $4, %rsi','cmpq $3, %rsi'),('cmpb $1, (%rax,%rsi)','cmpb $0, (%rax,%rsi)'),
            ('jne .B216','je .B216'),('je .B217','jne .B217'),('incq %rcx','addq $2, %rcx'),
            ('decq %rax','incq %rax'),('movq %rcx, 24(%r12)','movq %rax, 24(%r12)'),
            ('jne .B218','je .B218'),('je .B215','jne .B215'),
            ('movzbl 17(%rax), %ecx','movzbl 16(%rax), %ecx'),
            ('imulq $200, %rsi, %rbx','imulq $199, %rsi, %rbx'),
            ('movq 712(%rbp), %r8','movq 720(%rbp), %r8'),
            ('movl $40, %edx','movl $39, %edx'),('movl $200, %r9d','movl $199, %r9d'),
            ('callq scalar_wipe','nop'),('incq %rax','addq $2, %rax'),
            ('je .B244','jne .B244'),('movq 504(%rbp), %rsi','movq 496(%rbp), %rsi'),
            ('movq 888(%rbp), %r11','movq 960(%rbp), %r11')]
        for old,new in changes:
            self.assertIn(old,code);bad=[new if line==old else line for line in code];caught=False
            for case in samples:
                try:model.check(bad,n,**case)
                except ValueError:caught=True;break
            self.assertTrue(caught,'scalar semantic mutant survived: '+old)
        print('Keccak scalar reached ordering/pointer/cleanup/counter mutants rejected:',len(changes))


class SimdScalarSavedTests:
    def simd_scalar_fixture(self):
        import windows_enclave_sha3_batch_chains as c
        data,image,_,ir,functions,b=self.routes['simd']
        runtime={'memcpy','memset','memcmp','__chkstk','__umodti3','PublicProbeAbort'}|{
            'PublicKeccakSimd'+part for part in ('Input','Output','Source','Observe')}
        constants=c.binding.data_bindings(data,image,c.binding.bind_all(data,image,functions),functions,runtime,'simd')[0]
        vector_args=self.simd_vector_fixture();caller=vector_args[1]
        return b,ir,constants,caller,c.simd_vector.inspect(*vector_args)

    def test_simd_scalar_saved_region_instruction_mutations(self):
        args=self.simd_scalar_fixture();r=t.inspect(*args);b,*rest=args;name=r['function'];code=t.life.code(b[name]);count=0
        for at in range(*r['region']):
            for replacement in ([],['ud2'],['retq',code[at]]):
                bad=code[:at]+replacement+code[at+1:]
                with self.assertRaises(ValueError):t.inspect(b|{name:name+':\n'+'\n'.join(bad)},*rest)
                count+=1
        self.assertEqual(count,270)
        print('Keccak scalar caller instruction mutations rejected:',count)

    def test_simd_scalar_kernel_envelope_schedule_abi_constants(self):
        b,ir,constants,*_=self.simd_scalar_fixture();n=t.shape.names(b);name=n['scalar'];body=b[name]
        t.shape.inspect_kernel(b,ir,constants,n);count=0
        # Mutate the actual opaque block, including labels and erase markers.
        lines=body.splitlines()
        for at,line in enumerate(lines):
            if not line.strip():continue
            with self.assertRaises(ValueError):
                t.shape.inspect_kernel(b|{name:'\n'.join(lines[:at]+['ud2']+lines[at+1:])},ir,constants,n)
            count+=1
        for old,new in (('noalias ','alias '),('dereferenceable(40)','dereferenceable(39)'),('nounwind','noreturn')):
            with self.assertRaises(ValueError):t.shape.inspect_kernel(b,ir.replace(old,new),constants,n)
        table=t.shape.kernel.TABLE
        with self.assertRaises(ValueError):t.shape.inspect_kernel(b,ir,constants|{table:dict(bytes=192,sha256='0'*64)},n)
        print('Keccak scalar kernel complete assembly-position mutations rejected:',count)

    def test_simd_scalar_composition_and_scope(self):
        args=self.simd_scalar_fixture();r=t.inspect(*args);_,_,_,caller,vector=args
        for obj,key in ((caller['helpers'],'copy_wrapper_checks_equal_lengths'),
            (caller['callbacks'],'context_is_zero_sized'),
            (vector,'completed_group_readiness_cleared_before_rescan'),
            (vector,'scatter_returns_each_group_lane_to_original_slot')):
            with patch.dict(obj,{key:False}):
                with self.assertRaises(ValueError):t.inspect(*args)
        for key in ('common_exit_rejection_and_final_report_composed',
            'all_incoming_pointer_lifetimes_and_storage_nonoverlap_qualified','private_frame_and_exception_cleanup_qualified'):
            self.assertFalse(r[key])
        import windows_enclave_sha3_batch_chains as c
        with patch.object(t,'inspect',side_effect=ValueError('scalar fallback failed')) as call:
            with self.assertRaisesRegex(ValueError,'scalar fallback failed'):c.inspect_route(self.saved,self.root,'simd',self.spec['simd'])
            call.assert_called_once()

    def test_simd_scalar_actual_saved_effects(self):
        args=self.simd_scalar_fixture();r=t.inspect(*args);n=t.shape.names(args[0]);code=t.life.code(args[0][r['function']])[1253:1343]
        for case in ({},dict(authority=False),dict(cancel_at=3),dict(revoke_at=4),dict(copy_failure=8),
            dict(ready=(0,1,2,255)),dict(blocks=model.MASK),dict(charged=model.MASK)):
            model.check(code,n,**case)
