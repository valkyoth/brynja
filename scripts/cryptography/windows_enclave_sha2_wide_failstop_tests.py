"""Saved wide overflow proof: actual guard, induction and origin mutations."""
import copy
from unittest.mock import patch
import windows_enclave_sha2_wide_failstop as p


class WideFailstopSavedTests:
    def wide_failstop_fixture(self):
        import windows_enclave_sha2_batch_chains as parent
        if not hasattr(self.__class__,'_wide_failstop_fixture'):
            row=next(v for v in self.routes if v[0]=='simd512');bodies=row[-1]
            asm=parent.load(self.saved,self.root,row[1])[3]
            prior=dict(simd_control_call_effects={'failstop_paths':[]},
                simd_metadata_preservation=parent.field_integrity.inspect(bodies,row[4],'simd512'),
                simd_physical_allocation_lifetimes=parent.allocation_lifetimes.inspect(bodies,asm,'simd512'))
            self.__class__._wide_failstop_fixture=(row,asm,prior)
        return self.__class__._wide_failstop_fixture

    def wide_failstop_mutants(self,selector,replacements=(),insertions=()):
        row,asm,prior=self.wide_failstop_fixture();bodies=row[-1]
        name=p.s.one(bodies,selector);lines=p.s.lines(bodies[name]);changes=[]
        for at,text in replacements:
            bad=lines[:];bad[at]=text;changes.append(bad)
        for at,text in insertions:changes.append(lines[:at]+[text]+lines[at:])
        for bad in changes:
            with self.subTest(change=next((i,b) for i,(a,b) in enumerate(zip(lines,bad)) if a!=b)):
                with self.assertRaises(ValueError):p.inspect(bodies|{name:'\n'.join(bad)},asm,prior)
        return len(changes)

    def test_actual_wide_failstop_proof_and_parent_integration(self):
        import windows_enclave_sha2_batch_chains as parent
        row,asm,prior=self.wide_failstop_fixture();result=p.inspect(row[-1],asm,prior)
        self.assertFalse(result['admitted_input_unreachability_join_pending'])
        self.assertTrue(result['selected_overflow_unreachable_for_admitted_preserved_inputs'])
        self.assertEqual(result['whole_function_overflow_paths'],1)
        self.assertEqual(result['guard'],1286)
        self.assertEqual(result['admitted_tail']['descriptor_offsets'],[192,232,272,312])
        self.assertEqual(result['scalar_index']['scalar_lane_offsets'],[0,40,80,120])
        self.assertEqual(result['partial_tail']['possible_compare_values'],list(range(1,8)))
        self.assertFalse(result['whole_frame_qualified'])
        self.assertFalse(result['caller_frame_erasure_or_OS_window_qualification'])
        with patch.object(p,'inspect',side_effect=ValueError('wide overflow composition failed')) as check:
            with self.assertRaisesRegex(ValueError,'wide overflow composition failed'):
                parent.inspect_route(self.saved,self.root,row[0],row[1],False)
            check.assert_called_once()

    def test_actual_wide_failstop_parent_admission_and_publication_mutants(self):
        changes=[(76,'movl $74, %r15d'),(96,'movb %al, 182(%rbx,%r15)'),
            (99,'addq $80, %r15'),(101,'cmpq $154, %r15'),(102,'jne .B14'),
            (107,'movzbl 1(%rdi), %r14d'),(110,'leal -2(%r14), %eax'),
            (111,'cmpb $8, %al'),(112,'jg .B13'),(132,'movl $9, %r14d'),
            (441,'leaq 232(%rbx), %r8')]
        inserts=[(76,'jne .B3'),(107,'jne .B14'),(96,'movb $9, %r14b'),
            (111,'xorl %eax, %eax'),(112,'testb %al, %al'),(110,'jne .B3'),
            (96,'incq %r15'),(99,'jne .B4'),(444,'xorl %r8d, %r8d')]
        count=self.wide_failstop_mutants(r'Resident6digest$',changes,inserts)
        self.assertEqual(count,20);print('Wide tail publication mutations rejected: '+str(count))

    def test_actual_wide_failstop_scalar_index_seed_restore_and_bypass_mutants(self):
        changes=[(1134,'movl $40, %edx'),(1139,'addq $80, %rdx'),
            (1141,'cmpq $200, %rdx'),(1142,'jne .B233'),(1149,'movq %rax, 1000(%rbp)'),
            (1400,'movq 1008(%rbp), %r14'),(1415,'movq %rax, %rdx'),
            (1417,'jmp .B184')]
        inserts=[(1133,'jne .B184'),(1149,'incq %rdx'),(1150,'movb $0, 1007(%rbp)'),
            (1201,'movq %rax, 999(%rbp)'),(1415,'incq %r14'),(1133,'jne .B201'),
            (1150,'jne .B184'),(1400,'jne .B183')]
        count=self.wide_failstop_mutants(r'Executor13digest_secret$',changes,inserts)
        self.assertEqual(count,16);print('Wide scalar index mutations rejected: '+str(count))

    def test_actual_wide_failstop_partial_byte_origin_guard_and_copy_mutants(self):
        changes=[(26,'movq %r9, 1040(%rbp)'),(1200,'movq 1048(%rbp), %rax'),
            (1201,'movq 1008(%rbp), %rcx'),(1202,'movzbl 25(%rax,%rcx), %ebx'),
            (1203,'testb $-1, %bl'),(1204,'je .B201'),(1285,'cmpb $8, %bl'),
            (1286,'jg .B302')]
        inserts=[(1200,'movb $0, 1047(%rbp)'),(1203,'incq %rbx'),
            (1285,'movb $9, %bl'),(1286,'testb %bl, %bl'),(1200,'jne .B201'),
            (1203,'jne .B201'),(1285,'movq %rax, %rbx')]
        count=self.wide_failstop_mutants(r'Executor13digest_secret$',changes,inserts)
        self.assertEqual(count,15);print('Wide partial-byte lifetime mutations rejected: '+str(count))

    def test_actual_wide_failstop_preserves_scope_of_conditional_proof(self):
        row,asm,prior=self.wide_failstop_fixture();bodies=row[-1]
        name=p.s.one(bodies,r'Executor13digest_secret$');lines=p.s.lines(bodies[name])
        # Other kernel semantics are not established by this tail-byte proof.
        # Whole-body pins and independent checks still reject these changes.
        bad=lines[:];bad[1140]='addq $2, %r14'
        # The exact loop skeleton deliberately rejects the altered instruction.
        with self.assertRaises(ValueError):p.inspect(bodies|{name:'\n'.join(bad)},asm,prior)
        bad=lines[:1282]+['movl $2, %edx']+lines[1282:]
        result=p.inspect(bodies|{name:'\n'.join(bad)},asm,prior)
        self.assertTrue(result['selected_overflow_unreachable_for_admitted_preserved_inputs'])
        self.assertFalse(result['whole_frame_qualified'])

    def test_actual_wide_failstop_requires_current_preservation_and_physical_reviews(self):
        row,asm,prior=self.wide_failstop_fixture()
        mutations=[('simd_metadata_preservation','function','wrong'),
            ('simd_metadata_preservation','conditional_input_and_authority_field_preservation_checked',False),
            ('simd_physical_allocation_lifetimes','conditional_physical_separation',False),
            ('simd_physical_allocation_lifetimes','constructor_result_and_worker_use_joined',False),
            ('simd_control_call_effects','failstop_paths',['unassigned'])]
        for key,field,value in mutations:
            bad=copy.deepcopy(prior);bad[key][field]=value
            with self.assertRaises(ValueError):p.inspect(row[-1],asm,bad)
