"""Changed AVX2 terminal instruction, CFG, bounds and composition regressions."""
import copy
from unittest.mock import patch
import windows_enclave_sha3_batch_chains as c

t=c.finish.terminal


class TerminalModelTests:
    def test_terminal_output_shape_matches_independent_domain(self):
        count=0
        for length in range(1026):
            for last in range(256):
                want=(length==0 and last==0) or (1<=length<=1024 and 1<=last<=8)
                self.assertEqual(t.output_shape(length,last),want);count+=1
        self.assertEqual(count,262656)
        for length in (1025,1<<32,(1<<63)-1):
            for last in range(256):self.assertFalse(t.output_shape(length,last))
        for args in ((-1,0),(1<<63,0),(0,-1),(0,256),(True,0),(0,False)):
            with self.assertRaises(ValueError):t.output_shape(*args)


class TerminalTests:
    def test_terminal_every_changed_instruction_is_bound(self):
        bodies=self.routes['avx2'][-1];_,expected=t.check_shapes(bodies);count=0
        for name,lines in expected.items():
            for at in range(len(lines)):
                for bad in (lines[:at]+lines[at+1:],lines[:at]+['ud2']+lines[at+1:]):
                    with self.assertRaises(ValueError):
                        t.check_shapes(bodies|{name:name+':\n'+'\n'.join(bad)})
                    count+=1
        self.assertEqual(count,616)

    def test_terminal_normal_cfg_rejects_dirty_exit_and_fake_clear(self):
        n,expected=t.check_shapes(self.routes['avx2'][-1]);count=0
        for name,lines in expected.items():
            result=t.staging_returns(lines,n)
            self.assertTrue(result['read_failure_treated_as_partial_write'])
            for at,line in enumerate(lines):
                if line=='callq '+c.lifecycle.ZERO and lines[at-2:at]==t.shapes.wipe(n)[:2]:
                    for index,replacement in ((at,'nop'),(at-1,'movl $1023, %edx'),(at-2,'leaq 41(%rsp), %rcx')):
                        bad=lines.copy();bad[index]=replacement
                        with self.assertRaises(ValueError):t.staging_returns(bad,n)
                        count+=1
            at=lines.index('callq '+n['read'])
            bad=lines[:at+1]+['retq']+lines[at+1:]
            with self.assertRaises(ValueError):t.staging_returns(bad,n)
            # Normal read failure may have written output; bypassing only its cleanup must fail too.
            bad=lines[:at+1]+['jmp '+('.B20' if name==n['fixed'] else '.B27')]+lines[at+1:]
            with self.assertRaises(ValueError):t.staging_returns(bad,n)
            for old,new in (('callq memset','nop'),('callq '+n['read'],'nop')):
                bad=[new if line==old else line for line in lines]
                with self.assertRaises(ValueError):t.staging_returns(bad,n)
        self.assertEqual(count,15)

    def test_terminal_staging_bounds_masks_and_state_cleanup(self):
        bodies=self.routes['avx2'][-1];n,expected=t.check_shapes(bodies);count=0
        for name,lines in expected.items():
            text='\n'.join(lines)
            changes=[('leaq 40(%rsp)','leaq 41(%rsp)'),('movl $1024, %edx','movl $1023, %edx'),
                ('callq '+n['copy'],'nop'),('callq '+n['clear'],'nop'),('callq '+n['drop'],'nop'),
                ('movq $2, 944(%rsi)','movq $0, 944(%rsi)'),('cmpq 584(%rsi)','cmpq 592(%rsi)'),
                ('movl $44,','movl $40,'),('movb $1, 859(%rsi)','movb $0, 859(%rsi)')]
            changes+=([('cmpq $1024, %r14','cmpq $1025, %r14'),('cmpq %r9, 952(%rsi)','cmpq %r8, 952(%rsi)'),
                ('movq %r8, %rbx','movq %rdx, %rbx'),('movl %r10d, %r9d','movl $0, %r9d')]
                if name==n['fixed'] else [('cmpq $1025, %r14','cmpq $1026, %r14'),
                ('cmpb $8, %r15b','cmpb $9, %r15b'),('addq $39, %rax','addq $40, %rax'),
                ('shrb %cl, %dl','shlb %cl, %dl'),('movq %rdx, %rbx','movq %rcx, %rbx'),
                ('callq '+n['mask'],'nop'),('testb %r9b, %r9b','testb %al, %al')])
            for old,new in changes:
                self.assertIn(old,text)
                with self.assertRaises(ValueError):t.check_shapes(bodies|{name:name+':\n'+text.replace(old,new)})
                count+=1
        self.assertEqual(count,29)

    def test_terminal_requires_actual_caller_replayed_helpers_and_copy(self):
        args=self.update_fixture('avx2');caller=c.finish.inspect(*args)
        bodies,_,ir,_,prior=args[:5];result=t.inspect(bodies,ir,prior,caller)
        for key in ('input_pointer_preserved_to_descriptor','prefix_width_sum_and_end_both_checked',
                    'outer_rejection_clears_entire_output_and_quarantines'):
            with self.assertRaises(ValueError):t.inspect(bodies,ir,prior,caller|{key:False})
        for key,value in (('state_span',[1215,2208]),('output_base',1),('output_capacity',1025)):
            with self.assertRaises(ValueError):t.inspect(bodies,ir,prior,caller|{key:value})
        for key in ('finish_fixed','squeeze'):
            bad=copy.deepcopy(caller);bad['functions'][key]='wrong'
            with self.assertRaises(ValueError):t.inspect(bodies,ir,prior,bad)
        for name in result['lower_helpers_replayed_and_exact']:
            bad=copy.deepcopy(prior);del bad['exact_body_reference_extent_and_abi'][name]
            with self.assertRaises(ValueError):t.inspect(bodies,ir,bad,caller)
        with self.assertRaises(ValueError):t.inspect(bodies,ir,prior|{'prior_semantics_replayed':False},caller)
        with patch.object(t.copies,'inspect',side_effect=ValueError('copy failed')):
            with self.assertRaisesRegex(ValueError,'copy failed'):t.inspect(bodies,ir,prior,caller)
        with patch.object(t,'inspect',side_effect=ValueError('terminal failed')):
            with self.assertRaisesRegex(ValueError,'terminal failed'):c.finish.inspect(*args)
        for key in ('all_unwind_paths_qualified','private_frame_erasure_qualified','whole_image_qualified'):
            self.assertFalse(result[key])
        self.assertTrue(result['runtime_memset_qualification_pending'])

    def test_terminal_helper_abi_rebinding_is_load_bearing(self):
        args=self.update_fixture('avx2');caller=c.finish.inspect(*args)
        bodies,_,ir,_,prior=args[:5];result=t.inspect(bodies,ir,prior,caller)
        helpers=result['lower_helpers_replayed_and_exact']
        for name in helpers:
            row=next(l for l in ir.splitlines() if l.startswith('define ') and '@'+name+'(' in l)
            self.assertIn('nonnull',row)
            with self.assertRaises(ValueError):
                t.inspect(bodies,ir.replace(row,row.replace('nonnull','')),prior,caller)
            bad=copy.deepcopy(prior);bad['exact_body_reference_extent_and_abi'][name]['abi_sha256']='0'*64
            with self.assertRaises(ValueError):t.inspect(bodies,ir,bad,caller)
        self.assertEqual(len(helpers),7)
