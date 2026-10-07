"""Regression probes for the last three wide-parent call interfaces."""
import copy
from unittest.mock import patch
import windows_enclave_sha2_parent_remaining as p


class ParentRemainingSavedTests:
    def parent_remaining_fixture(self):return self.normal_effect_fixture('simd512')

    def test_actual_parent_remaining_interfaces_and_shared_limits(self):
        import windows_enclave_sha2_batch_chains as main
        row,asm,prior=self.parent_remaining_fixture();proof=p.inspect(row[-1],asm,prior)
        self.assertEqual([v['line'] for v in proof['assigned']],[21,121,444])
        self.assertEqual(proof['assigned_parent_call_count'],27)
        self.assertEqual(proof['remaining_parent_calls'],[])
        self.assertTrue(proof['all_parent_call_interfaces_assigned'])
        self.assertFalse(proof['all_parent_memory_and_stack_effects_qualified'])
        self.assertFalse(proof['whole_frame_qualified'])
        self.assertEqual(len(proof['shared_runtime_calls']),7)
        self.assertTrue(proof['child_private_frame_assignment_and_erasure_pending'])
        probe,mask,child=proof['assigned']
        self.assertFalse(probe['stack_effects_qualified']);self.assertNotIn('footprints',probe)
        self.assertEqual(mask['actual_read_bytes'],1);self.assertEqual(mask['normal_stack_span'],[-8,0])
        self.assertEqual(mask['header_offsets'],[20,44,68,92])
        self.assertEqual(child['child_returning_calls'],36)
        with patch.object(p,'inspect',side_effect=ValueError('remaining parent failed')) as check:
            with self.assertRaisesRegex(ValueError,'remaining parent failed'):
                main.inspect_route(self.saved,self.root,'simd512',row[1],False)
            check.assert_called_once()

    def test_actual_parent_remaining_predicate_full_body_mutations(self):
        row,asm,_=self.parent_remaining_fixture();bodies=row[-1]
        name=p.s.one(bodies,r'mask_is_zero$');lines=p.p.storage.instructions(bodies[name]);count=0
        for at in range(len(lines)):
            with self.assertRaises(ValueError):p.predicate(bodies|{name:'\n'.join(lines[:at]+lines[at+1:])},asm)
            count+=1
        for text in ('movb $0, (%rcx)','movq %rcx, (%rdx)','pushq %r10','callq unreviewed'):
            with self.assertRaises(ValueError):p.predicate(bodies|{name:'\n'.join(lines[:-1]+[text,lines[-1]])},asm)
            count+=1
        self.assertEqual(count,11)

    def test_actual_parent_remaining_predicate_cursor_bounds_and_bypass_mutations(self):
        row,asm,_=self.parent_remaining_fixture();bodies=row[-1]
        proof=p.predicate(bodies,asm);name=p.s.one(bodies,r'Resident6digest$');lines=p.s.lines(bodies[name])
        count=0
        changes={'movq %r9, %rdi':'movq %r8, %rdi','addq $20, %rdi':'addq $21, %rdi',
            'addq $24, %rdi':'addq $25, %rdi','movq -12(%rdi), %r13':'movq -11(%rdi), %r13',
            'cmpq $1024, %r13':'cmpq $1025, %r13','ja .B24':'jb .B24',
            'movq -20(%rdi), %r12':'movq -19(%rdi), %r12','movzbl (%rdi), %r14d':'movzbl 1(%rdi), %r14d',
            'testq %r13, %r13':'testq %r12, %r12','je .B11':'jne .B11',
            'cmpb $7, %al':'cmpb $8, %al','ja .B13':'jb .B13','cmpb $7, %r14b':'cmpb $8, %r14b',
            'ja .B3':'jb .B3','leaq -1(%r13), %rax':'leaq (%r13), %rax',
            'movb $-1, %dl':'movb $0, %dl','movl %r14d, %ecx':'movl %r13d, %ecx',
            'shrb %cl, %dl':'shlb %cl, %dl','addq %r12, %rax':'addq %r13, %rax',
            'movq %rax, %rcx':'movq %r12, %rcx'}
        for old,new in changes.items():
            at=lines.index(old);bad=lines[:];bad[at]=new
            with self.subTest(old=old):
                with self.assertRaises(ValueError):p.predicate(bodies|{name:'\n'.join(bad)},asm)
            count+=1
        for at in (proof['header_seed'],proof['header_step'],proof['line']-6,proof['line']):
            bad=lines[:1]+['jne predicate_bypass']+lines[1:at]+['predicate_bypass:']+lines[at:]
            with self.assertRaises(ValueError):p.predicate(bodies|{name:'\n'.join(bad)},asm)
            count+=1
        self.assertEqual(count,24)

    def test_actual_parent_remaining_child_arguments_and_overwrites(self):
        row,asm,prior=self.parent_remaining_fixture();bodies=row[-1]
        proof=p.child_interface(bodies,asm,prior);name=p.s.one(bodies,r'Resident6digest$')
        lines=p.s.lines(bodies[name]);at=proof['line'];count=0
        for site in range(at-8,at):
            bad=lines[:];bad[site]='nop'
            with self.assertRaises(ValueError):p.child_interface(bodies|{name:'\n'.join(bad)},asm,prior)
            count+=1
        seed=p.o.unique(lines,'leaq 7200(%rbx), %rdi')
        for text in ('leaq 7201(%rbx), %rdi','movq %rsi, %rdi','movb $0, %dil'):
            bad=lines[:];bad[seed]=text
            with self.assertRaises(ValueError):p.child_interface(bodies|{name:'\n'.join(bad)},asm,prior)
            count+=1
        for text in ('movb $0, 39(%rsp)','movq %rax, 39(%rsp)','movb $0, %r9b'):
            bad=lines[:at]+[text]+lines[at:]
            with self.assertRaises(ValueError):p.child_interface(bodies|{name:'\n'.join(bad)},asm,prior)
            count+=1
        for site in (at-6,at-2,at):
            bad=lines[:1]+['jne child_bypass']+lines[1:site]+['child_bypass:']+lines[site:]
            with self.assertRaises(ValueError):p.child_interface(bodies|{name:'\n'.join(bad)},asm,prior)
            count+=1
        self.assertEqual(count,17)

    def test_actual_parent_remaining_joined_effects_and_child_inventory(self):
        row,asm,prior=self.parent_remaining_fixture();count=0
        for key in ('simd_descriptor_normal_effects','simd_wide_output_effects'):
            for kind in ('missing','duplicate','wrong_target','bad_effect'):
                bad=copy.deepcopy(prior);node=bad[key]
                if kind=='missing':node['assigned'].pop()
                elif kind=='duplicate':node['assigned'].append(copy.deepcopy(node['assigned'][0]))
                elif kind=='wrong_target':node['assigned'][0]['target']='unreviewed'
                else:node['mapped_effects'].append(['writes','resident-frame',64,65])
                with self.assertRaises(ValueError):p.child_interface(row[-1],asm,bad)
                count+=1
        bad=copy.deepcopy(prior);bad['simd_wide_output_effects']['terminal_calls']=[]
        with self.assertRaises(ValueError):p.child_interface(row[-1],asm,bad)
        count+=1
        bad=copy.deepcopy(prior);bad['simd_wide_descriptor_handoff']['child']['stores'][0]['span']=[0,105]
        with self.assertRaises(ValueError):p.child_interface(row[-1],asm,bad)
        self.assertEqual(count+1,10)

    def test_actual_parent_remaining_prerequisites_probe_and_parent_inventory(self):
        row,asm,prior=self.parent_remaining_fixture();count=0
        for key,field in p.PREREQUISITES:
            bad=copy.deepcopy(prior);bad[key][field]=False
            with self.assertRaises(ValueError):p.inspect(row[-1],asm,bad)
            count+=1
        for kind in ('missing','duplicate','wrong'):
            bad=copy.deepcopy(prior);calls=bad['simd_parent_setup_effects']['remaining_parent_calls']
            if kind=='missing':calls.pop()
            elif kind=='duplicate':calls.append(copy.deepcopy(calls[0]))
            else:calls[0]['target']='wrong'
            with self.assertRaises(ValueError):p.inspect(row[-1],asm,bad)
            count+=1
        name=p.s.one(row[-1],r'Resident6digest$');lines=p.s.lines(row[-1][name])
        for old,new in [('movl $12984, %eax','movl $12985, %eax'),('callq __chkstk','callq wrong_probe'),
                        ('subq %rax, %rsp','subq $4096, %rsp')]:
            bad=lines[:];bad[p.o.unique(lines,old)]=new
            with self.assertRaises(ValueError):p.inspect(row[-1]|{name:'\n'.join(bad)},asm,prior)
            count+=1
        self.assertEqual(count,14)
