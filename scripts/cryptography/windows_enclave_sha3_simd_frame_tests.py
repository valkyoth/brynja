"""Saved public framing: independent arithmetic, memory bounds and mutations."""
import copy
from unittest.mock import patch
import windows_enclave_sha3_simd_frame as t
model=t.model


class SimdFrameModelTests:
    def test_simd_frame_independent_arithmetic_campaign(self):
        n={'workspace_wipe':'reviewed_wipe'};code=t.shape.shape(n);count=0
        for lanes,threshold in model.cases():
            for poison in (0x39,0xa5):
                model.check(code,n,lanes,threshold,poison);count+=1
        self.assertEqual(count,4934)
        print('Keccak emitted public frame/oracle comparisons:',count)

    def test_simd_frame_semantic_changes_are_load_bearing(self):
        n={'workspace_wipe':'reviewed_wipe'};code=t.shape.shape(n)
        samples=[[(0,1149,0,0,224),(4,1339,0,0,0),(6,8192,255,256,2048),
                  (7,1,8192,1,1089)], [None,(7,1,0,0,1),None,None]]
        changes=[('movl $144, %ecx','movl $136, %ecx'),
            ('movl $104, %ecx','movl $136, %ecx'),
            ('movl $72, %ecx','movl $136, %ecx'),
            ('movl $31, %edx','movl $6, %edx'),
            ('movl $6, %r8d','movl $31, %r8d'),
            ('movb $4, 155(%r14)','movb $6, 155(%r14)'),
            ('movq $3, 88(%r14)','movq $5, 88(%r14)'),
            ('movq $16, (%rax)','movq $8, (%rax)'),
            ('leaq 121(%r14), %rcx','leaq 122(%r14), %rcx'),
            ('movq %r13, 64(%r14)','movq %r13, 48(%r14)'),
            ('movq %rcx, 72(%r14)','movq $0, 72(%r14)'),
            ('movq %rax, 96(%r14)','movq $0, 96(%r14)'),
            ('cmpq $1, %rax','cmpq $0, %rax'),
            ('setae 5251(%rbx,%r12)','setne 5251(%rbx,%r12)'),
            ('movq %r11, 3512(%rbx,%r12,8)','movq %r11, 3520(%rbx,%r12,8)'),
            ('imulq $156, %rax, %rdi','imulq $155, %rax, %rdi'),
            ('addq $112, %rsi','addq $111, %rsi')]
        # Include each fixed identity so mutations in either fixed-rate branch
        # must fail a reached path rather than being rejected by a shape pin.
        samples += [[(tag,8192,0,0,model.FIXED[tag])]*4 for tag in range(4)]
        for old,new in changes:
            with self.subTest(old=old):
                self.assertIn(old,code);bad=list(code);bad[bad.index(old)]=new
                caught=False
                for lanes in samples:
                    try:model.check(bad,n,lanes,2)
                    except ValueError:caught=True;break
                self.assertTrue(caught,'semantic mutant survived: '+old)
        print('Keccak reached arithmetic/offset/encoding mutants rejected:',len(changes))

    def test_simd_frame_model_rejects_unassigned_effects(self):
        n={'workspace_wipe':'reviewed_wipe'};code=t.shape.shape(n)
        lanes=[(7,8192,255,256,2048)]*4
        for line in ('callq unreviewed','movq $0, (%rdi)',
                     'movq 4096(%r14), %rax','ud2','jmp .B11'):
            with self.assertRaises(ValueError):model.check(code[:1]+[line]+code[1:],n,lanes)
        with self.assertRaises(ValueError):model.machine.run(code,n,lanes,max_steps=1)


class SimdFrameSavedTests:
    def simd_frame_fixture(self):
        args=self.simd_digest_fixture()
        return args[0],args[1],t.shape.digest.inspect(*args)

    def test_simd_frame_saved_instruction_and_table_mutations(self):
        b,asm,caller=self.simd_frame_fixture();r=t.inspect(b,asm,caller)
        name=r['function'];lines=t.life.code(b[name]);count=0
        for at in range(*r['region']):
            for replacement in ([],['ud2'],['retq',lines[at]]):
                bad=lines[:at]+replacement+lines[at+1:]
                with self.assertRaises(ValueError):t.inspect(b|{name:name+':\n'+'\n'.join(bad)},asm,caller)
                count+=1
        self.assertEqual(count,1155)
        start=asm.index('.LJTI30_0:\n');end=asm.index('.LJTI30_1:',start)
        rows=asm[start:end].splitlines(keepends=True)
        for i in range(1,9):
            bad=list(rows);bad[i]='\t.long\t.LBB30_63-.LJTI30_0\n'
            with self.assertRaises(ValueError):t.inspect(b,asm[:start]+''.join(bad)+asm[end:],caller)
        print('Keccak public framing instruction/table mutations rejected:',count+8)

    def test_simd_frame_saved_region_and_prerequisites(self):
        b,asm,caller=self.simd_frame_fixture();r=t.inspect(b,asm,caller)
        code=t.life.code(b[r['function']])[69:454];n=t.shape.digest.helpers.names(b)
        # Sparse lanes and independently varying threshold on the actual saved
        # slice complement the full generated-shape campaign.
        for lanes,threshold in list(model.cases())[::79]:model.check(code,n,lanes,threshold)
        bad=copy.deepcopy(caller);bad['helpers']['geometry']['workspace_bytes']=5259
        with self.assertRaises(ValueError):t.inspect(b,asm,bad)
        self.assertFalse(r['inner_absorption_permutation_and_report_qualified'])
        self.assertFalse(r['full_machine_pointer_lifetimes_qualified'])
        self.assertFalse(r['private_frame_erasure_qualified'])
        import windows_enclave_sha3_batch_chains as c
        with patch.object(t,'inspect',side_effect=ValueError('framing review failed')) as call:
            with self.assertRaisesRegex(ValueError,'framing review failed'):
                c.inspect_route(self.saved,self.root,'simd',self.spec['simd'])
            call.assert_called_once()
