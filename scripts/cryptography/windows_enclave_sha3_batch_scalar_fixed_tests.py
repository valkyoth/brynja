"""Fixed finalization: all instructions, padding oracle, copied owners and CFG."""
import copy
from unittest.mock import patch
import windows_enclave_sha3_batch_chains as c

t=c.finish.scalar_fixed


class ScalarFixedModelTests:
    def test_scalar_fixed_inlined_padding_against_independent_bit_string(self):
        count=0
        for rate in (72,104,144):
            for buffered in range(rate):
                whole=bytes((i*37+buffered)%256 for i in range(buffered))
                for valid in range(8):
                    for partial in (0,255,165,(buffered*17+valid)%256):
                        bits=[(byte>>b)&1 for byte in whole for b in range(8)]
                        bits.extend((partial>>b)&1 for b in range(valid))
                        bits.extend((0,1,1))  # SHA-3 domain 01, then first pad bit.
                        bits.extend([0]*((-len(bits)-1)%(rate*8)));bits.append(1)
                        packed=bytes(sum(bits[i+j]<<j for j in range(8)) for i in range(0,len(bits),8))
                        expected=[packed[i:i+rate] for i in range(0,len(packed),rate)]
                        self.assertEqual(t.padding(rate,whole,partial,valid),expected);count+=1
        self.assertEqual(count,10240)
        for args in ((136,b'',0,0),(72,bytes(72),0,0),(72,b'',-1,0),(72,b'',256,0),
            (72,b'',0,-1),(72,b'',0,8),(True,b'',0,0),(72,b'',False,0),(72,b'',0,False)):
            with self.assertRaises(ValueError):t.padding(*args)

    def test_scalar_fixed_move_layout_and_checked_input_partition(self):
        result=t.move_origins()
        self.assertEqual(result['copied_owner_span'],[96,1136]);self.assertEqual(result['snapshot_span'],[2160,3296])
        self.assertFalse(result['snapshot_and_original_payload_cleared_individually'])
        count=0
        for length in range(1025):
            for last in ((0,) if length==0 else range(1,9)):
                bits=0 if length==0 else (length-1)*8+last
                prefix,tail=t.xof.input_partition(length,last)
                self.assertEqual(prefix,bits//8);self.assertEqual(tail,length-1 if bits%8 else None)
                for counter in (0,(1<<64)-1,(1<<128)-1,(1<<128)-1-prefix):
                    self.assertEqual(t.xof.admit(counter,bits),counter+bits//8<1<<128);count+=1
        self.assertEqual(count,32772)


class ScalarFixedTests:
    def test_scalar_fixed_all_emitted_instructions_are_load_bearing(self):
        _,_,asm,_,_,bodies=self.routes['scalar'];n,lines=t.check_shape(bodies,asm);count=0
        for at in range(len(lines)):
            for bad in (lines[:at]+lines[at+1:],lines[:at]+['ud2']+lines[at+1:]):
                with self.assertRaises(ValueError):
                    t.check_shape(bodies|{n['fixed']:n['fixed']+':\n'+'\n'.join(bad)},asm)
                count+=1
        self.assertEqual(count,2390)

    def test_scalar_fixed_dispatch_table_is_complete_and_identity_bound(self):
        _,_,asm,_,_,bodies=self.routes['scalar']
        for old,new in [(f'.long\t.LBB50_{b}-.LJTI50_0',f'.long\t.LBB50_{other}-.LJTI50_0')
            for b,other in zip(t.TARGETS,(18,8,13,3))]:
            self.assertIn(old,asm)
            with self.assertRaises(ValueError):t.check_shape(bodies,asm.replace(old,new))
        table='.LJTI50_0:\n'+''.join(f'\t.long\t.LBB50_{b}-.LJTI50_0\n' for b in t.TARGETS)
        for bad in (asm.replace('.LJTI50_0:','.LJTI50_missing:'),asm+'\n'+table,
            asm.replace('.LJTI50_0:', '.LJTI50_0:\n\t.long\t.LBB50_3-.LJTI50_0')):
            with self.assertRaises(ValueError):t.check_shape(bodies,bad)

    def test_scalar_fixed_pointer_padding_counter_result_and_cleanup_mutants(self):
        _,_,asm,_,_,bodies=self.routes['scalar'];n,lines=t.check_shape(bodies,asm);body='\n'.join(lines)
        changes=[('cmpq $1024, %rsi','cmpq $1025, %rsi'),('movl $1136, %r8d','movl $1135, %r8d'),
            ('movb $0, (%r15)','movb $0, 1(%r15)'),('incq %r15','addq $2, %r15'),
            ('movl $1040, %r8d','movl $1041, %r8d'),('leaq 96(%rsp), %rcx','leaq 97(%rsp), %rcx'),
            ('movq %r15, %rdx','movq %r14, %rdx'),('cmpq $28, %rsi','cmpq $32, %rsi'),
            ('cmpq $48, %rsi','cmpq $64, %rsi'),('adcq $0, %rax','addq $0, %rax'),
            ('adcq $-1, %rax','addq $-1, %rax'),('cmovneq %rcx, %r14','cmoveq %rcx, %r14'),
            ('jne .B140','je .B140'),('callq '+n['update68'],'callq '+n['update48']),
            ('movb $3, 32(%rsp)','movb $2, 32(%rsp)'),('movb $6, %r9b','movb $4, %r9b'),
            ('movzbl 1134(%rsp), %r12d','movzbl 1135(%rsp), %r12d'),
            ('leaq 344(%rsp), %r8','leaq 345(%rsp), %r8'),('leaq 512(%rsp), %r13','leaq 511(%rsp), %r13'),
            ('shrb %cl, %dl','shlb %cl, %dl'),('cmpl $832, %r15d','cmpl $831, %r15d'),
            ('cmpq $575, %r15','cmpq $576, %r15'),('cmpq $1151, %r15','cmpq $1152, %r15'),
            ('leaq -368(%r15), %rcx','leaq -367(%r15), %rcx'),('movl $104, %ebp','movl $103, %ebp'),
            ('movb $8, %r9b','movb $7, %r9b'),('movb $0, 32(%rsp)','movb $1, 32(%rsp)'),
            ('movl $168, %edx','movl $144, %edx'),('movl $200, %edx','movl $199, %edx'),
            ('leaq 615(%rsp), %rcx','leaq 616(%rsp), %rcx'),('movb $-128, %r8b','movb $64, %r8b'),
            ('movq $48, 88(%rsp)','movq $47, 88(%rsp)'),('movq 40(%rsp), %r12','movq 48(%rsp), %r12'),
            ('cmpq $2, %r12','cmpq $1, %r12'),('cmovneq %r14, %r9','cmoveq %r14, %r9'),
            ('movq %rdi, %rcx','movq %r15, %rcx'),('sete %bl','setne %bl'),
            ('callq '+n['wipe'],'nop'),('callq '+c.lifecycle.ZERO,'nop')]
        for old,new in changes:
            self.assertIn(old,body)
            with self.assertRaises(ValueError):t.check_shape(bodies|{n['fixed']:n['fixed']+':\n'+body.replace(old,new)},asm)
        self.assertEqual(len(changes),39)

    def test_scalar_fixed_cfg_requires_owner_and_staging_clears(self):
        _,_,asm,_,_,bodies=self.routes['scalar'];n,lines=t.check_shape(bodies,asm)
        self.assertTrue(t.cleanup_cfg(lines,n)['normal_returns_clear_copied_owner_and_staging'])
        final=lines.index('.B145:')
        for offset,new in ((1,'leaq 1137(%rsp), %rcx'),(2,'movl $1023, %edx'),(3,'nop'),(3,'callq memset')):
            bad=lines.copy();bad[final+offset]=new
            with self.assertRaises(ValueError):t.cleanup_cfg(bad,n)
        sites=[i for i,l in enumerate(lines) if l=='callq '+n['wipe']]
        self.assertEqual(len(sites),3)
        for at in sites:
            bad=lines.copy();bad[at]='nop'
            with self.assertRaises(ValueError):t.cleanup_cfg(bad,n)
        bad=lines.copy();bad[lines.index('.B149:')+1]='retq'
        with self.assertRaises(ValueError):t.cleanup_cfg(bad,n)

    def test_scalar_fixed_replay_abis_placement_and_integrated_scope(self):
        args=self.update_fixture('scalar');caller=c.finish.inspect(*args)
        bodies,asm,ir,_,prior,storage=args[:6];result=t.inspect(bodies,asm,ir,prior,caller,storage)
        self.assertEqual(len(result['helpers']),13)
        for name in result['helpers']:
            bad=copy.deepcopy(prior);del bad['exact_body_reference_extent_and_abi'][name]
            with self.assertRaises(ValueError):t.inspect(bodies,asm,ir,bad,caller,storage)
            bad=copy.deepcopy(prior);bad['exact_body_reference_extent_and_abi'][name]['abi_sha256']='0'*64
            with self.assertRaises(ValueError):t.inspect(bodies,asm,ir,bad,caller,storage)
            row=next(l for l in ir.splitlines() if l.startswith('define ') and '@'+name+'(' in l)
            self.assertIn('nonnull',row)
            with self.assertRaises(ValueError):t.inspect(bodies,asm,ir.replace(row,row.replace('nonnull','')),prior,caller,storage)
        for key,value in (('input_pointer_preserved_to_descriptor',False),('partial_tail_only_after_nonempty_shape_check',False),
            ('maximum_input_bytes',1025),('maximum_input_bits',8193),('descriptor_bytes',31),
            ('prefix_width_sum_and_end_both_checked',False),('output_base',1343),('output_capacity',1025),
            ('state_span',[16,1151]),('outer_rejection_clears_entire_output_and_quarantines',False)):
            with self.assertRaises(ValueError):t.inspect(bodies,asm,ir,prior,caller|{key:value},storage)
        for container,path in ((prior,('prior_semantics_replayed',)),
            (prior,('state_destructor_rebinding','exact_code_references_extent_and_renamed_abi')),
            (storage,('state_pointer_inside_owner',)),(storage,('state_destructor','typed_payload_cleanup_composed'))):
            bad=copy.deepcopy(container);node=bad
            for key in path[:-1]:node=node[key]
            node[path[-1]]=False
            with self.assertRaises(ValueError):
                t.inspect(bodies,asm,ir,bad if container is prior else prior,caller,bad if container is storage else storage)
        bad=copy.deepcopy(caller);bad['functions']['finish_fixed']='wrong'
        with self.assertRaises(ValueError):t.inspect(bodies,asm,ir,prior,bad,storage)
        with patch.object(t,'inspect',side_effect=ValueError('scalar fixed failed')):
            with self.assertRaisesRegex(ValueError,'scalar fixed failed'):c.finish.inspect(*args)
        self.assertEqual(caller['lower_finalizer_review_pending'],[])
        self.assertTrue(caller['all_lower_finalizers_normal_paths_composed'])
        self.assertFalse(caller['all_lower_finalizers_composed'])
        for key in ('state_construction_qualified','private_frame_erasure_qualified','all_unwind_paths_qualified','whole_image_qualified'):
            self.assertFalse(result[key])
