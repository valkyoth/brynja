"""Terminal public-field, mixed-width, failure bridge and health regressions."""
import itertools
from unittest.mock import patch
import windows_enclave_sha3_simd_terminal as t
model=t.model


def fixture():
    n=dict(workspace_wipe='workspace_wipe',check='check',validate='validate',panic='panic')
    return n


def errors(n):return t.shape.bridges(n)+t.shape.rejection_entry(n)+t.shape.reject.cleanup(n)


class SimdTerminalModelTests:
    def test_simd_terminal_report_fields_and_byte_carries(self):
        n=fixture();code=t.shape.report(n);count=0
        for tags,poison in itertools.product(itertools.product((0,7,255),repeat=4),(0x39,0xa5)):
            model.report(code,n,tags=tags,poison=poison);count+=1
        for calls,kernel,mask in itertools.product((0,1,255,256,65535,1<<32,1<<48,1<<56,model.MASK),
            (0,1,2,255),(0,1,15,0xa5)):
            model.report(code,n,calls=calls,kernel=kernel,accelerated=mask);count+=1
        self.assertEqual(count,306)
        print('Keccak terminal byte-exact report cases:',count)

    def test_simd_terminal_aggregate_bit_lengths(self):
        n=fixture();code=t.shape.preflight(n);count=0
        for tags,bits in itertools.product(itertools.product((0,255),repeat=4),
            itertools.product((0,1,7,8,2048,2049),repeat=2)):
            model.preflight(code,n,tags=tags,bits=bits*2);count+=1
        for bits in ((8192,0,0,0),(8193,0,0,0),(model.MASK,)*4,(model.MASK,1,1,1)):
            model.preflight(code,n,bits=bits);count+=1
        self.assertEqual(count,580)
        print('Keccak final aggregate bit-length admission cases:',count)

    def test_simd_terminal_error_bridges_and_final_health(self):
        n=fixture();code=errors(n);count=0
        for entry,authority,poison in itertools.product(('.B207','.B208','.B210','.B211','.B212','.B213',
            '.B214','.B216','.B217','.B218','.B224','.B225'),(False,True),(0x39,0xa5)):
            model.bridge(code,n,entry,authority=authority,poison=poison);count+=1
        for entry,error in itertools.product(('.B223','.B226','.B227','.B228'),(0,1,2,3,4,6,7,8,9,10,11,12,13,14)):
            model.bridge(code,n,entry,err=error);count+=1
        model.bridge(code,n,'.B215');model.bridge(code,n,'.B209',err=2);count+=2
        self.assertEqual(count,106)
        for authority,healthy,quarantined,cancel,revalidate,poison in itertools.product(*([(False,True)]*5),(0x39,0xa5)):
            model.final_health(code,n,authority=authority,healthy=healthy,quarantined=quarantined,
                cancel=cancel,revalidate=revalidate,poison=poison)
        print('Keccak terminal error bridge cases:',count,'; final-health cases: 64')

    def test_simd_terminal_reached_semantic_mutations(self):
        n=fixture();cases=[{},dict(calls=model.MASK),dict(tags=(255,0,255,7)),dict(kernel=255)]
        changes=[('movl $1024, %edx','movl $1023, %edx'),('incb %al','nop'),
            ('movq %rax, 664(%rbp)','movq %rax, 656(%rbp)'),('vmovups %ymm1, 32(%rcx)','vmovups %ymm0, 32(%rcx)'),
            ('movl %esi, 105(%rcx)','movl %esi, 104(%rcx)'),('shrq $48, %rax','shrq $40, %rax'),
            ('shrq $32, %rsi','shrq $24, %rsi'),('movq 808(%rbp), %rax','movq 744(%rbp), %rax'),
            ('movb %r13b, 104(%rcx)','movb %r13b, 105(%rcx)'),('je .B280','jne .B280')]
        for old,new in changes:
            code=t.shape.report(n);self.assertIn(old,code);bad=[new if line==old else line for line in code];caught=False
            for case in cases:
                try:model.report(bad,n,**case)
                except ValueError:caught=True;break
            self.assertTrue(caught,old)
        for old,new in (('shrq $3, %r8','shrq $2, %r8'),('sbbq $-1, %r8','addq $0, %r8'),
            ('cmpq $1024, %rax','cmpq $1025, %rax'),('shrq $8, %rsi','shrq $7, %rsi')):
            code=t.shape.preflight(n);bad=[new if l==old else l for l in code];caught=False
            for case in ({},dict(bits=(8193,0,0,0))):
                try:model.preflight(bad,n,**case)
                except ValueError:caught=True;break
            self.assertTrue(caught,old)
        for old,new in (('movb $12, %sil','movb $14, %sil'),('movb $2, %r13b','movb $13, %r13b'),
            ('movb $0, 16(%rax)','movb $1, 16(%rax)'),('movq %r12, %r15','movq %r14, %r15')):
            code=errors(n);bad=[new if l==old else l for l in code];caught=False
            for entry in ('.B225','.B215','.B223'):
                try:model.bridge(bad,n,entry)
                except ValueError:caught=True;break
            self.assertTrue(caught,old)
        print('Keccak terminal reached serialization/size/bridge mutants rejected: 18')

    def test_simd_terminal_unknown_effects_and_corrupt_sources(self):
        n=fixture();code=t.shape.report(n);m=model.m;mem,writable,regs=model.prepare()
        regs.update(r12=m.STAGING,rsi=regs['r13']>>8)
        for line in ('ud2','callq unreviewed','jmp .B999','movq $0, (%rdi)','movq 6000(%rbx), %rax'):
            with self.assertRaises(ValueError):m.run(['.bad:',line]+code,n,mem,writable,regs,'.bad',{'.B85','.B79'})
        for offset in (968,976,1104):
            bad=dict(mem);bad.update(enumerate((123).to_bytes(8,'little'),m.STACK+offset))
            with self.assertRaises(ValueError):m.run(code,n,bad,writable,regs,'.B270',{'.B85','.B79'})
        with self.assertRaises(ValueError):m.run(code,n,mem,writable,regs,'.B270',{'.B85'},max_steps=1)
        pre=t.shape.preflight(n);regs.update(r12=m.STAGING,r14=m.EXEC)
        for slot in range(4):
            bad=dict(mem);bad.update(enumerate((999).to_bytes(8,'little'),m.STACK+600+16*slot))
            result=m.run(pre,n,bad,writable,regs,'.B230',{'.B223'})
            self.assertEqual(result['exit'],'.B223');self.assertEqual(result['events'],[('validate',)])
            self.assertEqual(result['memory'],bad)
        result=m.run(pre,n,mem,writable,regs,'.B233',{'panic'})
        self.assertEqual(result['exit'],'panic');self.assertEqual(result['events'],[('panic',)])


class SimdTerminalSavedTests:
    def simd_terminal_fixture(self):
        import windows_enclave_sha3_batch_chains as c
        b,ir,caller,output,frame=self.simd_reject_fixture()
        rejection=c.simd_reject.inspect(b,ir,caller,output,frame)
        scalar=c.simd_scalar.inspect(*self.simd_scalar_fixture())
        return b,ir,caller,output,rejection,scalar

    def test_simd_terminal_saved_instruction_and_helper_mutations(self):
        args=self.simd_terminal_fixture();r=t.inspect(*args);b,*rest=args;name=r['function'];code=t.life.code(b[name]);count=0
        for region in (r['bridge_region'],r['size_admission_region'],r['report_region']):
            for at in range(*region):
                for replacement in ([],['ud2' if code[at]!='ud2' else 'nop'],['retq',code[at]]):
                    bad=code[:at]+replacement+code[at+1:]
                    with self.assertRaises(ValueError):t.inspect(b|{name:name+':\n'+'\n'.join(bad)},*rest)
                    count+=1
        self.assertEqual(count,657)
        name=r['executor_check'];code=t.life.code(b[name])
        for at in range(len(code)):
            with self.assertRaises(ValueError):t.inspect(b|{name:name+':\n'+'\n'.join(code[:at]+['ud2']+code[at+1:])},*rest)
        print('Keccak terminal region mutations rejected:',count,'; complete health helper:',len(code))

    def test_simd_terminal_prerequisites_and_actual_saved_execution(self):
        args=self.simd_terminal_fixture();r=t.inspect(*args);b,ir,caller,output,rejection,scalar=args
        for obj,key in ((caller['callbacks'],'context_is_zero_sized'),(output,'output_borrow_pointer_ir_uses_closed'),
            (rejection,'normal_rejection_clears_workspace_staging_then_destinations'),
            (scalar,'whole_scalar_owner_wiped_before_checked_report_increment')):
            with patch.dict(obj,{key:False}):
                with self.assertRaises(ValueError):t.inspect(*args)
        for old,new in (('readonly align 8 captures(none) %0','readonly align 4 captures(none) %0'),
            ('noundef range(i8 -1, 5) i8','noundef range(i8 -1, 6) i8')):
            with self.assertRaises(ValueError):t.inspect(b,ir.replace(old,new),*args[2:])
        for key in ('complete_machine_pointer_lifetimes_and_nonoverlap_qualified','private_frame_and_exception_cleanup_qualified'):
            self.assertFalse(r[key])
        self.assertTrue(r['report_padding_not_claimed_initialized_or_erased'])
        import windows_enclave_sha3_batch_chains as c
        with patch.object(t,'inspect',side_effect=ValueError('terminal failed')) as check:
            with self.assertRaisesRegex(ValueError,'terminal failed'):c.inspect_route(self.saved,self.root,'simd',self.spec['simd'])
            check.assert_called_once()
