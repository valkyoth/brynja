"""Public index interpreter semantics and saved compaction regressions."""
from unittest.mock import patch
import windows_enclave_sha2_index_machine as m
import windows_enclave_sha2_simd_indices as c


def run(lines,registers=None,memory=None,writable=None,steps=64):
    program=m.compile_region(['entry:']+lines+['done:'],'entry','done')
    return m.run(program,registers or {},memory or {},set() if writable is None else writable,
                 ('wipe',100,[(0,8)]),steps)


class IndexTests:
    def test_index_register_widths_unsigned_flags_and_little_endian_memory(self):
        result=run(['movq $-1, %rax','movl $1, %eax','movb $254, %al','movq %rax, (%rbx)',
                    'movzbl (%rbx), %ecx'],{'rbx':0},writable=set(range(8)))
        self.assertEqual(result['registers']['rax'],254)
        self.assertEqual(result['registers']['rcx'],254)
        self.assertEqual([result['memory'][i] for i in range(8)],[254]+[0]*7)
        result=run(['movq $-1, %rax','addq $1, %rax','incq %rax','ja bad',
                    'jbe done','bad:','callq unexpected'])
        self.assertEqual(result['registers']['rax'],1)  # INC preserves carry from ADD.
        result=run(['cmpw $-1, (%rbx)','jne bad','jmp done','bad:','callq unexpected'],
                    {'rbx':0},{0:255,1:255})
        self.assertEqual(result['memory'],{0:255,1:255})

    def test_index_address_arithmetic_and_unknown_state_reject(self):
        result=run(['leaq 3(%rbx,%rax,8), %rdx','shlq $5, %rdx'],{'rbx':100,'rax':2})
        self.assertEqual(result['registers']['rdx'],119*32)
        for lines,regs in ((['movq %rax, %rcx'],{}),(['movq (%rbx), %rax'],{'rbx':0}),
                           (['movq $1, (%rbx)'],{'rbx':0}),(['movb $1, %al'],{}),
                           (['je done'],{}),(['leaq 8(%rbx), %rax'],{'rbx':(1<<64)-1}),
                           (['movl %rax, %ecx'],{'rax':0}),(['shlq $64, %rax'],{'rax':1})):
            with self.assertRaises(ValueError):run(lines,regs)
        with self.assertRaises(ValueError):run(['jmp entry'],steps=8)
        for line in ('retq','nop','subq $1, %rax','callq *%rax','jmp outside','movq $1'):
            with self.assertRaises(ValueError):run([line])
        with self.assertRaises(ValueError):m.compile_region(['entry:','entry:','done:'],'entry','done')

    def test_index_wipe_model_clears_only_assigned_spans_and_havocs_volatile_registers(self):
        regs={'rcx':100,'rax':7,'rdi':9,'rbx':11}
        result=run(['callq wipe'],regs,{i:0xa5 for i in range(99,110)},set(range(100,108)))
        self.assertEqual([result['memory'][i] for i in range(100,108)],[0]*8)
        self.assertEqual(result['memory'][99],0xa5)
        self.assertEqual(result['memory'][108],0xa5)
        self.assertEqual(result['registers'],{'rdi':9,'rbx':11})
        with self.assertRaises(ValueError):run(['callq wipe','movq %rax, %rdx'],regs,{},set(range(100,108)))
        with self.assertRaises(ValueError):run(['callq wipe'],{'rcx':101},writable=set(range(100,108)))
        with self.assertRaises(ValueError):run(['callq wipe'],regs,writable=set(range(100,107)))


class IndexSavedTests:
    def test_compaction_rejects_wrong_addresses_counts_identities_and_public_iv(self):
        count=0
        for lane,_,_,_,_,_,bodies in self.routes:
            if not lane.startswith('simd'):continue
            narrow=lane=='simd256';name,_,_=c.program(bodies,lane)
            body='\n'.join(c.s.lines(bodies[name]))
            mutations=(('movq $0, 80(%rbx)','movq $1, 80(%rbx)'),
                ('incq %rax','addq $2, %rax'),('leaq 1(%rdx), %r9','leaq 2(%rdx), %r9'),
                ('addq $544, %rdx','addq $545, %rdx'),('leaq 7200(%rbx), %rdx','leaq 7201(%rbx), %rdx'),
                ('movb %r8b, 10784(%rbx,%rcx)','movb $0, 10784(%rbx,%rcx)'),
                ('movb %r8b, 10784(%rbx,%rcx)','movb %r8b, 10785(%rbx,%rcx)'),
                ('leaq 344(%rbx), %r9','leaq 345(%rbx), %r9'),
                ('movq %rdi, %r9','movq %rbx, %r9')) if narrow else (
                ('leaq 4576(%rdi), %rcx','leaq 4577(%rdi), %rcx'),
                ('movb $0, (%rcx)','movb $1, (%rcx)'),('movb $1, (%rcx,%rdx)','movb $0, (%rcx,%rdx)'),
                ('movb $2, (%rcx,%rdx)','movb $1, (%rcx,%rdx)'),('movb $3, (%rcx,%rdx)','movb $2, (%rcx,%rdx)'),
                ('movl $1, %edx','movl $2, %edx'),('incq %rdx','addq $2, %rdx'))
            tags=(1,)*8 if narrow else (0,1,2,3)
            for old,new in mutations:
                self.assertIn(old,body)
                with self.assertRaises(ValueError):c.evaluate(bodies|{name:body.replace(old,new)},lane,tags)
                count+=1
            if narrow:
                lines=c.s.lines(body)
                for start,end,tag in (('.B70:','.B74:',1),('.B74:','.B75:',0)):
                    for line in lines[lines.index(start):lines.index(end)]:
                        if not line.startswith('movl $'):continue
                        value=int(line.split('$')[1].split(',')[0]);bad=body.replace('$'+str(value)+',','$'+str(value+1)+',')
                        with self.assertRaises(ValueError):c.evaluate(bodies|{name:bad},lane,(tag,)*8)
                        count+=1
        self.assertEqual(count,32)
        print('SIMD compact-index/count/address/IV mutations rejected: '+str(count))

    def test_compaction_requires_reviewed_wipe_and_parent_integration(self):
        import windows_enclave_sha2_batch_chains as chains
        for lane,pin,_,_,_,_,bodies in self.routes:
            if not lane.startswith('simd'):continue
            with patch.object(c.storage,'wiping',side_effect=ValueError('wipe review failed')) as check:
                with self.assertRaisesRegex(ValueError,'wipe review failed'):c.inspect(bodies,lane)
                check.assert_called_once()
            with patch.object(c,'inspect',side_effect=ValueError('index review failed')) as check:
                with self.assertRaisesRegex(ValueError,'index review failed'):
                    chains.inspect_route(self.saved,self.root,lane,pin,False)
                check.assert_called_once()
