"""Scalar squeezing: geometry reference, instruction, cleanup and join mutants."""
import copy
from unittest.mock import patch
import windows_enclave_sha3_batch_chains as c

t=c.finish.scalar_squeeze


class ScalarSqueezeModelTests:
    def test_scalar_squeeze_rate_cursor_chunks_and_partial_bytes(self):
        count=0
        for rate in (136,168):
            for cursor in range(rate+1):
                for length in (0,1,2,rate-1,rate,rate+1,2*rate-1,2*rate,2*rate+1,1023,1024):
                    for last in ((0,) if length==0 else range(1,9)):
                        self.check_squeeze_geometry(rate,cursor,length,last);count+=1
            for cursor in (0,1,rate-1,rate):
                for length in range(1025):
                    for last in ((0,) if length==0 else (1,7,8)):
                        self.check_squeeze_geometry(rate,cursor,length,last);count+=1
        self.assertEqual(count,49370)

    def check_squeeze_geometry(self,rate,cursor,length,last):
        result=t.geometry(rate,cursor,length,last)
        # Independent unbounded stream positions, not the model's nested loops.
        expected=[(cursor+i)%rate for i in range(length)]
        got=[];written=0
        for offset,source,size in result['copies']:
            self.assertEqual(offset,written);self.assertGreater(size,0)
            self.assertLessEqual(source+size,rate);got.extend(range(source,source+size));written+=size
        self.assertEqual(got,expected);self.assertEqual(written,length)
        if length:
            self.assertEqual(result['cursor'],(cursor+length-1)%rate+1)
            self.assertEqual(result['permutations'],(cursor+length-1)//rate)
        else:
            self.assertEqual(result['cursor'],cursor);self.assertEqual(result['permutations'],0)
        bits=0 if length==0 else (length-1)*8+last
        self.assertEqual(result['prefix_bytes'],bits//8)
        self.assertEqual(result['mask'],(1<<last)-1 if bits%8 else None)
        previous=0
        for start,end in result['chunks']:
            self.assertEqual(start,previous);self.assertTrue(0<end-start<=rate);previous=end
        self.assertEqual(previous,bits//8)

    def test_scalar_squeeze_invalid_geometry_never_becomes_copy(self):
        for args in ((135,0,1,8),(169,0,1,8),(136,-1,1,8),(168,169,1,8),
            (136,0,-1,8),(136,0,1025,8),(136,0,0,1),(136,0,1,0),(136,0,1,9),
            (True,0,1,8),(136,False,1,8),(136,0,True,8)):
            with self.assertRaises(ValueError):t.geometry(*args)


class ScalarSqueezeTests:
    def test_scalar_squeeze_every_instruction_and_label_is_bound(self):
        bodies=self.routes['scalar'][-1];n,lines=t.check_shape(bodies);count=0
        for at in range(len(lines)):
            for bad in (lines[:at]+lines[at+1:],lines[:at]+['ud2']+lines[at+1:]):
                with self.assertRaises(ValueError):t.check_shape(bodies|{n['squeeze']:n['squeeze']+':\n'+'\n'.join(bad)})
                count+=1
        self.assertEqual(count,1266)

    def test_scalar_squeeze_bounds_lifetimes_mask_and_erasure_mutants(self):
        bodies=self.routes['scalar'][-1];n,lines=t.check_shape(bodies);body='\n'.join(lines)
        changes=[('cmpq $1024, %rsi','cmpq $1025, %rsi'),('cmpb $8, %cl','cmpb $9, %cl'),
            ('cmpb $1, 1(%rdi)','cmpb $0, 1(%rdi)'),('movb $2, 1(%rdi)','movb $1, 1(%rdi)'),
            ('adcq $-1, %rdx','addq $-1, %rdx'),('adcq 26(%rdi), %rcx','addq 26(%rdi), %rcx'),
            ('adcq $0, %rax','addq $0, %rax'),('movq %rcx, 80(%rsp)','movq %rcx, 88(%rsp)'),
            ('movq %r14, 104(%rsp)','movq %rdi, 104(%rsp)'),('cmpb $-88, %r14b','cmpb $-87, %r14b'),
            ('cmpb $-120, %r14b','cmpb $-119, %r14b'),('jne .B30','je .B30'),('jne .B55','je .B55'),
            ('leaq 754(%rdi), %r14','leaq 753(%rdi), %r14'),('leaq 834(%rdi), %r9','leaq 835(%rdi), %r9'),
            ('leaq 586(%rdi), %rax','leaq 587(%rdi), %rax'),('leaq 50(%rdi), %rax','leaq 49(%rdi), %rax'),
            ('leaq (%rax,%r13), %rcx','leaq (%rax,%r12), %rcx'),('cmovaeq %r15, %r12','cmovbq %r15, %r12'),
            ('cmpq %rsi, %r12','cmpq %rsi, %r15'),('setb %al','seta %al'),('orb %al, %cl','andb %al, %cl'),
            ('movl $168, %edx','movl $136, %edx'),('movl $200, %edx','movl $199, %edx'),
            ('movq %r15, %r8','movq %r12, %r8'),('shrb %cl, %dl','shlb %cl, %dl'),
            ('subb 96(%rsp), %cl','subb 95(%rsp), %cl'),('subb %bpl, %cl','subb %bl, %cl'),
            ('movq 104(%rsp), %rcx','movq 112(%rsp), %rcx'),('movq %rsi, %r9','movq %r12, %r9'),
            ('cmpb $-1, %al','cmpb $0, %al'),('callq '+n['wipe'],'nop'),
            ('callq '+n['drop'],'nop'),('callq '+c.lifecycle.ZERO,'nop')]
        for old,new in changes:
            self.assertIn(old,body)
            with self.assertRaises(ValueError):t.check_shape(bodies|{n['squeeze']:n['squeeze']+':\n'+body.replace(old,new)})
        self.assertEqual(len(changes),34)

    def test_scalar_squeeze_normal_cfg_cannot_omit_or_replace_final_clear(self):
        bodies=self.routes['scalar'][-1];n,lines=t.check_shape(bodies)
        self.assertTrue(t.staging_returns(lines,n)['normal_returns_clear_staging'])
        at=lines.index('.B75:')
        for offset,new in ((1,'leaq 121(%rsp), %rcx'),(2,'movl $1023, %edx'),
            (3,'nop'),(3,'callq memset')):
            bad=lines.copy();bad[at+offset]=new
            with self.assertRaises(ValueError):t.staging_returns(bad,n)
        bad=lines.copy();bad[bad.index('.B73:')+1]='retq'
        with self.assertRaises(ValueError):t.staging_returns(bad,n)

    def test_scalar_squeeze_replay_abi_placement_and_composition(self):
        args=self.update_fixture('scalar');caller=c.finish.inspect(*args)
        bodies,_,ir,_,prior,storage=args[:6];result=t.inspect(bodies,ir,prior,caller,storage)
        for name in result['helpers']:
            bad=copy.deepcopy(prior);del bad['exact_body_reference_extent_and_abi'][name]
            with self.assertRaises(ValueError):t.inspect(bodies,ir,bad,caller,storage)
            bad=copy.deepcopy(prior);bad['exact_body_reference_extent_and_abi'][name]['abi_sha256']='0'*64
            with self.assertRaises(ValueError):t.inspect(bodies,ir,bad,caller,storage)
            row=next(l for l in ir.splitlines() if l.startswith('define ') and '@'+name+'(' in l)
            self.assertIn('nonnull',row)
            with self.assertRaises(ValueError):t.inspect(bodies,ir.replace(row,row.replace('nonnull','')),prior,caller,storage)
        for key,value in (('prefix_width_sum_and_end_both_checked',False),('output_capacity',1025),
            ('output_base',1343),('state_span',[16,1151]),('outer_rejection_clears_entire_output_and_quarantines',False),
            ('success_destroys_state_and_returns_to_collecting',False)):
            with self.assertRaises(ValueError):t.inspect(bodies,ir,prior,caller|{key:value},storage)
        for container,path in ((prior,('prior_semantics_replayed',)),
            (prior,('state_destructor_rebinding','exact_code_references_extent_and_renamed_abi')),
            (storage,('state_pointer_inside_owner',)),(storage,('state_destructor','typed_payload_cleanup_composed'))):
            bad=copy.deepcopy(container);node=bad
            for key in path[:-1]:node=node[key]
            node[path[-1]]=False
            with self.assertRaises(ValueError):
                t.inspect(bodies,ir,bad if container is prior else prior,caller,bad if container is storage else storage)
        bad=copy.deepcopy(caller);bad['functions']['squeeze']='wrong'
        with self.assertRaises(ValueError):t.inspect(bodies,ir,prior,bad,storage)
        with patch.object(t,'inspect',side_effect=ValueError('scalar squeeze failed')):
            with self.assertRaisesRegex(ValueError,'scalar squeeze failed'):c.finish.inspect(*args)
        self.assertEqual(caller['lower_finalizer_review_pending'],[])
        self.assertEqual(result['instructions_and_labels_checked'],633)
        for key in ('state_construction_qualified','private_frame_erasure_qualified','all_unwind_paths_qualified','whole_image_qualified'):
            self.assertFalse(result[key])
