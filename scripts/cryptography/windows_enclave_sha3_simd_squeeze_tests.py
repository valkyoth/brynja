"""Bounded copy/mask/continuation regressions for the saved SIMD squeeze lane."""
import hashlib
from unittest.mock import patch
import windows_enclave_sha3_simd_squeeze as t
model=t.model


def cases():
    for tag,rate in enumerate(model.RATES):
        for bits in (0,1,7,8,rate*8-1,rate*8,rate*8+1,2047,2048):
            total=(bits+7)//8
            for written in sorted({0,1,rate-1,rate,total,total+1,model.MASK}):
                for start in sorted({0,768,1024-total,1025-total,model.MASK}):
                    yield dict(tag=tag,bits=bits,written=written,start=start,lane=tag%4)
    for lane in range(4):
        for tail in range(1,8):
            for poison in (0x39,0xa5):
                yield dict(tag=7,bits=1024+tail,written=128,start=768,lane=lane,poison=poison)


class SimdSqueezeModelTests:
    def test_simd_squeeze_independent_storage_and_mask_campaign(self):
        n=dict(executor='executor',copy='copy',mask='mask');code=t.shape.squeeze(n)+t.shape.ready()
        count=0
        for case in cases():model.check(code,n,**case);count+=1
        self.assertGreater(count,2000)
        for tag in range(8):
            for lane in range(4):
                for bits in (0,1,2047):
                    model.check(code,n,tag,bits,0,768,lane,copy_failure=True);count+=1
        print('Keccak squeeze independent storage/mask/failure comparisons:',count)

    def test_simd_squeeze_load_bearing_copy_mask_counter_and_restoration(self):
        n=dict(executor='executor',copy='copy',mask='mask');code=t.shape.squeeze(n)+t.shape.ready()
        samples=[dict(tag=7,bits=1025,written=128,start=768,lane=3),
            dict(tag=0,bits=2048,written=0,start=0,lane=1),
            dict(tag=1,bits=1,written=2,start=0,lane=2),
            dict(tag=2,bits=2048,written=1,start=model.MASK,lane=0),
            dict(tag=3,bits=2048,written=0,start=953,lane=0),
            dict(tag=4,bits=2048,written=0,start=0,lane=2,copy_failure=True)]
        changes=[('subq %r11, %r12','addq %r11, %r12'),
            ('cmovbq %rax, %r12','movq %rax, %r12'),
            ('addq %r11, %r14','addq $0, %r14'),
            ('cmpq $1025, %rax','cmpq $1026, %rax'),
            ('imulq $200, %r9, %r8','imulq $199, %r9, %r8'),
            ('movq %r12, %r9','movq $1, %r9'),
            ('cmpb $-1, %al','cmpb $0, %al'),
            ('addq %r12, %r11','addq $1, %r11'),
            ('decq %rax','addq $0, %rax'),
            ('movabsq $35816724670907137, %rdx','movabsq $35816724670907136, %rdx'),
            ('callq mask','vzeroupper'),('movq %r14, %r9','movq $0, %r9'),
            ('movq 832(%rbp), %r8','movq $0, %r8'),
            ('movq 896(%rbp), %rdx','movq $0, %rdx'),
            ('movq 968(%rbp), %r14','movq $0, %r14'),
            ('movq 1120(%rbp), %r12','movq $0, %r12'),
            ('setb %al','setae %al')]
        for old,new in changes:
            with self.subTest(old=old):
                self.assertIn(old,code);bad=[new if line==old else line for line in code];caught=False
                for case in samples:
                    try:model.check(bad,n,**case)
                    except ValueError:caught=True;break
                self.assertTrue(caught,'squeeze semantic mutant survived: '+old)
        print('Keccak squeeze copy/mask/counter/restoration mutants rejected:',len(changes))

    def test_simd_squeeze_model_rejects_unassigned_effects(self):
        n=dict(executor='executor',copy='copy',mask='mask');code=t.shape.squeeze(n)+t.shape.ready()
        for line in ('callq unreviewed','movq $0, (%rbx)','movq 6000(%rbx), %rax',
                     'ud2','jmp .B999'):
            with self.assertRaises(ValueError):model.check([code[0],line]+code[1:],n,0,1,0,0,0)
        with self.assertRaises(ValueError):model.run(code,n,0,1,0,0,0,max_steps=1)


class SimdSqueezeSavedTests:
    def simd_squeeze_fixture(self):
        import windows_enclave_sha3_simd_reject as reject
        b,ir,caller,out,frame=self.simd_reject_fixture();n=t.names(b)
        # The integrated route check binds this record to actual object/image data.
        raw=b''.join(x.to_bytes(8,'little') for x in model.RATES)
        constants={'switch.table.'+n['executor']:dict(bytes=64,sha256=hashlib.sha256(raw).hexdigest())}
        return b,self.routes['simd'][2],ir,constants,caller,frame,reject.inspect(b,ir,caller,out,frame)

    def test_simd_squeeze_saved_instruction_mutations(self):
        args=self.simd_squeeze_fixture();r=t.inspect(*args);b,*rest=args
        name=r['function'];code=t.life.code(b[name]);count=0
        for begin,end in (r['setup_region'],r['ready_dispatch_region'],r['squeeze_region']):
            for at in range(begin,end):
                for replacement in ([],['ud2'],['retq',code[at]]):
                    bad=code[:at]+replacement+code[at+1:]
                    with self.assertRaises(ValueError):t.inspect(b|{name:name+':\n'+'\n'.join(bad)},*rest)
                    count+=1
        self.assertEqual(count,399)
        print('Keccak setup/squeeze/ready instruction mutations rejected:',count)

    def test_simd_squeeze_mask_body_markers_and_abi(self):
        args=self.simd_squeeze_fixture();b,asm,ir,constants,caller,frame,reject=args;n=t.names(b)
        for role in ('mask','mask_leaf'):
            name=n[role];code=t.life.code(b[name]);raw=b[name].splitlines()
            indices=[i for i,line in enumerate(raw) if t.s.lines(line) and
                not t.s.lines(line)[0].startswith('.') and t.s.lines(line)[0]!=name+':']
            self.assertEqual([t.s.lines(raw[i])[0] for i in indices],code)
            for at in range(len(code)):
                for replacement in ([],['ud2'],['retq',code[at]]):
                    # Preserve the original opaque comments while changing an instruction.
                    i=indices[at];body='\n'.join(raw[:i]+replacement+raw[i+1:])
                    with self.assertRaises(ValueError):t.inspect(b|{name:body},*args[1:])
        leaf=n['mask_leaf']
        for marker in ('BRYNJA_MASK_BEGIN','BRYNJA_MASK_ERASE','BRYNJA_MASK_END','#APP','#NO_APP'):
            with self.assertRaises(ValueError):t.inspect(b|{leaf:b[leaf].replace(marker,'REMOVED')},*args[1:])
        for old,new in (('range(i8 1, -128)','range(i8 0, -128)'),('fastcc void @'+n['mask'],'ccc void @'+n['mask'])):
            self.assertIn(old,ir)
            with self.assertRaises(ValueError):t.inspect(b,asm,ir.replace(old,new),constants,caller,frame,reject)

    def test_simd_squeeze_linked_table_and_prerequisites(self):
        args=self.simd_squeeze_fixture();b,asm,ir,constants,caller,frame,reject=args
        label=next(iter(constants));record=constants[label]
        for bad in ({},{label:record|dict(bytes=63)},{label:record|dict(sha256='0'*64)}):
            with self.assertRaises(ValueError):t.inspect(b,asm,ir,bad,caller,frame,reject)
        at=asm.index(label+':');tail=asm[at:];self.assertIn('.quad\t144',tail)
        with self.assertRaises(ValueError):t.inspect(b,asm[:at]+tail.replace('.quad\t144','.quad\t145',1),*args[2:])
        for container,key in ((caller['helpers'],'copy_wrapper_checks_equal_lengths'),
            (frame,'public_framing_fields_and_output_offsets_checked'),
            (reject,'normal_rejection_clears_workspace_staging_then_destinations')):
            with patch.dict(container,{key:False}):
                with self.assertRaises(ValueError):t.inspect(*args)
        r=t.inspect(*args)
        for key in ('all_incoming_pointer_lifetimes_and_storage_nonoverlap_qualified',
            'absorption_permutation_work_accounting_and_report_qualified','exception_and_private_frame_erasure_qualified'):
            self.assertFalse(r[key])
        import windows_enclave_sha3_batch_chains as c
        with patch.object(t,'inspect',side_effect=ValueError('squeeze review failed')) as call:
            with self.assertRaisesRegex(ValueError,'squeeze review failed'):
                c.inspect_route(self.saved,self.root,'simd',self.spec['simd'])
            call.assert_called_once()

    def test_simd_squeeze_actual_saved_region(self):
        args=self.simd_squeeze_fixture();r=t.inspect(*args);n=t.names(args[0])
        code=t.life.code(args[0][r['function']]);actual=code[920:992]+code[624:648]
        for case in list(cases())[::37]:model.check(actual,n,**case)
