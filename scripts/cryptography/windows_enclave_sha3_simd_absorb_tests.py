"""Independent bitstream, source bounds, fault injection and saved mutations."""
import hashlib
from unittest.mock import patch
import windows_enclave_sha3_simd_absorb as t
model=t.model


def fixture():
    n=dict(executor='executor',xor='xor')
    return t.shape.shape(n)+t.shape.squeeze.shape.ready()[7:13],n


class SimdAbsorbModelTests:
    def test_simd_absorb_complete_bitstream_campaign(self):
        code,n=fixture();count=0;sites=set()
        for poison in (0x39,0xa5):
            for case in model.cases():
                r=model.check(code,n,**case,poison=poison);sites.update(r['call_sites']);count+=1
        for lane in range(4):
            for tail in range(1,8):
                r=model.check(code,n,6,17,tail,9,lane);sites.update(r['call_sites']);count+=1
        self.assertEqual(sites,{134,179,203,251})
        self.assertEqual(count,412)
        print('Keccak complete-rate bitstream/source/cursor comparisons:',count)

    def test_simd_absorb_xor_byte_contract(self):
        count=0
        for right in range(256):
            for bits in range(9):
                for left in range(16):
                    result=t.helpers.effect(0xa5,right,bits,left)
                    valid=bits>0 and right+bits<=8 and left+bits<=8
                    self.assertEqual(result is not None,valid);count+=1
        for bits in range(1,9):
            for right in range(9-bits):
                for left in range(9-bits):
                    for source in range(256):
                        want=sum(((source>>(right+i))&1)<<(left+i) for i in range(bits))
                        self.assertEqual(t.helpers.effect(source,right,bits,left),want);count+=1
        self.assertEqual(count,89088)
        print('Keccak checked XOR metadata/byte comparisons:',count)

    def test_simd_absorb_helper_failure_at_every_distinct_call_site(self):
        code,n=fixture();args=(6,17,7,9,3);sites=set()
        for block in (0,1):
            mem,writable,*_=model.prepare(*args,block=block)
            baseline=model.machine.run(code,n,mem,writable,args[0],args[4])
            for i,site in enumerate(baseline['call_sites']):
                if site in sites:continue
                sites.add(site);r=model.machine.run(code,n,mem,writable,args[0],args[4],fail_call=i+1)
                self.assertIn(r['failure'],('.B207','.B208'))
                self.assertEqual(len(r['calls']),i+1)
                # Failure stops before block retirement/readiness; shared cleanup is separate.
                base=model.WORK+3584+156*args[4]
                for at in (*range(base+16,base+24),model.WORK+5248+args[4],model.WORK+5256+args[4]):
                    self.assertEqual(r['memory'][at],mem[at])
        self.assertEqual(sites,{134,179,203,251})

    def test_simd_absorb_corrupt_metadata_and_short_sources_reject(self):
        code,n=fixture();args=(6,17,7,9,3);mem,writable,*_=model.prepare(*args)
        base=model.WORK+3584+156*args[4]
        changes=[({base+16:0},'.B213'),({base:9},'.B211'),
            ({base+8:(1<<64)-1},'.B211'),({base:8,base+8:int.from_bytes(bytes(mem[base+96+i] for i in range(8)),'little')},'.B210'),
            ({model.INPUT+112*3+40:0},'.B207'),({model.INPUT+112*3+72:1},'.B207')]
        for fields,error in changes:
            bad=dict(mem)
            for at,value in fields.items():bad.update(enumerate(value.to_bytes(8,'little'),at))
            r=model.machine.run(code,n,bad,writable,args[0],args[4])
            self.assertEqual(r['failure'],error)
        for line in ('callq unreviewed','movq $0, (%r14)','movq 20000(%rbx), %rax','ud2','jmp .B999'):
            with self.assertRaises(ValueError):model.machine.run([line]+code,n,mem,writable,6,3)
        with self.assertRaises(ValueError):model.machine.run(code,n,mem,writable,6,3,max_steps=1)

    def test_simd_absorb_load_bearing_source_cursor_padding_mutants(self):
        code,n=fixture()
        samples=[dict(tag=6,message=17,name=7,custom=9,lane=3),
            dict(tag=0,message=1149,name=0,custom=0,lane=1),
            dict(tag=7,message=2048,name=255,custom=256,lane=2),
            dict(tag=6,message=17,name=7,custom=9,lane=3,block=1),
            dict(tag=6,message=17,name=3,custom=19,lane=2)]
        changes=[('imulq $200, %r9, %r11','imulq $199, %r9, %r11'),
            ('imulq $156, %r9, %r12','imulq $155, %r9, %r12'),
            ('decq %r10','incq %r10'),('movq 8(%r14,%r8), %rax','movq 40(%r14,%r8), %rax'),
            ('movq 64(%r14,%r8), %rax','movq 32(%r14,%r8), %rax'),
            ('movq 32(%r14,%r8), %rax','movq (%r14,%r8), %rax'),
            ('leaq 155(%r12), %rax','leaq 154(%r12), %rax'),
            ('orq %rax, %rsi','addq $0, %rsi'),
            ('andl $7, %r8d','andl $3, %r8d'),('shrq $3, %r14','shrq $2, %r14'),
            ('subl %r8d, %r9d','addl %r8d, %r9d'),('addl %r8d, %eax','addl $0, %eax'),
            ('movq %rcx, 8(%r12)','movq $0, 8(%r12)'),
            ('cmovnel %r14d, %eax','movl %r14d, %eax'),
            ('movq %r10, 16(%r12)','movq $0, 16(%r12)'),
            ('movb $1, %al','movb $0, %al'),('movq 832(%rbp), %r8','movq $0, %r8')]
        for old,new in changes:
            with self.subTest(old=old):
                self.assertIn(old,code);bad=[new if l==old else l for l in code];caught=False
                for case in samples:
                    try:model.check(bad,n,**case)
                    except ValueError:caught=True;break
                self.assertTrue(caught,'absorption semantic mutant survived: '+old)
        print('Keccak reached absorption source/cursor/padding mutants rejected:',len(changes))


class SimdAbsorbSavedTests:
    def simd_absorb_fixture(self):
        b,asm,ir,constants,caller,frame,reject=self.simd_squeeze_fixture()
        squeeze=t.shape.squeeze.inspect(b,asm,ir,constants,caller,frame,reject)
        raw=b''.join(v.to_bytes(8,'little') for v in model.framing.RATES)
        label='switch.table.'+squeeze['function']+'.104'
        return b,asm,ir,{label:dict(bytes=64,sha256=hashlib.sha256(raw).hexdigest())},frame,squeeze

    def test_simd_absorb_saved_instruction_mutations(self):
        args=self.simd_absorb_fixture();b,*rest=args;r=t.inspect(*args);name=r['function']
        code=t.life.code(b[name]);count=0
        for at in range(*r['region']):
            for replacement in ([],['ud2'],['retq',code[at]]):
                bad=code[:at]+replacement+code[at+1:]
                with self.assertRaises(ValueError):t.inspect(b|{name:name+':\n'+'\n'.join(bad)},*rest)
                count+=1
        self.assertEqual(count,816)
        print('Keccak complete absorption instruction mutations rejected:',count)

    def test_simd_absorb_xor_helpers_and_abi(self):
        b,asm,ir,constants,frame,squeeze=self.simd_absorb_fixture();n=t.shape.names(b);count=0
        t.helpers.inspect(b,ir,n)
        for role in ('xor','xor_leaf'):
            name=n[role];raw=b[name].splitlines();code=t.life.code(b[name])
            indices=[i for i,l in enumerate(raw) if t.s.lines(l) and
                (not t.s.lines(l)[0].startswith('.') or t.s.lines(l)[0].startswith('.B')) and t.s.lines(l)[0]!=name+':']
            self.assertEqual([t.s.lines(raw[i])[0] for i in indices],code)
            for at,i in enumerate(indices):
                for replacement in ([],['ud2'],['retq',code[at]]):
                    bad='\n'.join(raw[:i]+replacement+raw[i+1:])
                    with self.assertRaises(ValueError):t.helpers.inspect(b|{name:bad},ir,n)
                    count+=1
        self.assertEqual(count,129)
        leaf=n['xor_leaf']
        for marker in ('BRYNJA_XOR_BEGIN','BRYNJA_XOR_ERASE','BRYNJA_XOR_END','#APP','#NO_APP'):
            with self.assertRaises(ValueError):t.helpers.inspect(b|{leaf:b[leaf].replace(marker,'REMOVED')},ir,n)
        for old,new in (('range(i8 0, 9)','range(i8 0, 10)'),('range(i8 0, 16)','range(i8 0, 17)'),
            ('range(i32 0, 256)','range(i32 0, 257)'),('readonly captures(address, read_provenance)','captures(address, read_provenance)')):
            self.assertIn(old,ir)
            with self.assertRaises(ValueError):t.helpers.inspect(b,ir.replace(old,new),n)
        print('Keccak XOR helper instruction mutations rejected:',count)

    def test_simd_absorb_tables_and_composition(self):
        args=self.simd_absorb_fixture();b,asm,ir,constants,frame,squeeze=args;r=t.inspect(*args)
        label=next(iter(constants));record=constants[label]
        for bad in ({},{label:record|dict(bytes=63)},{label:record|dict(sha256='0'*64)}):
            with self.assertRaises(ValueError):t.inspect(b,asm,ir,bad,frame,squeeze)
        start=asm.index('.LJTI30_1:');end=asm.index('.seh_handlerdata',start)
        for j in range(9):
            rows=asm[start:end].splitlines();rows[j+1]='\t.long\t.LBB30_120-.LJTI30_1'
            with self.assertRaises(ValueError):t.inspect(b,asm[:start]+'\n'.join(rows)+'\n'+asm[end:],*args[2:])
        start=asm.index(label+':');tail=asm[start:];self.assertIn('.quad\t144',tail)
        with self.assertRaises(ValueError):t.inspect(b,asm[:start]+tail.replace('.quad\t144','.quad\t145',1),*args[2:])
        for obj,key in ((frame,'public_framing_fields_and_output_offsets_checked'),
            (squeeze,'restored_lane_index_input_control_and_frame_pointers_checked')):
            with patch.dict(obj,{key:False}):
                with self.assertRaises(ValueError):t.inspect(*args)
        for key in ('all_incoming_pointer_lifetimes_and_storage_nonoverlap_qualified',
                    'permutation_work_accounting_and_report_qualified','exception_and_private_frame_erasure_qualified'):
            self.assertFalse(r[key])
        import windows_enclave_sha3_batch_chains as c
        with patch.object(t,'inspect',side_effect=ValueError('absorption review failed')) as call:
            with self.assertRaisesRegex(ValueError,'absorption review failed'):
                c.inspect_route(self.saved,self.root,'simd',self.spec['simd'])
            call.assert_called_once()

    def test_simd_absorb_actual_saved_region(self):
        args=self.simd_absorb_fixture();r=t.inspect(*args);n=t.shape.names(args[0]);code=t.life.code(args[0][r['function']])
        for case in list(model.cases())[::7]:model.check(code[648:920]+code[631:637],n,**case)
