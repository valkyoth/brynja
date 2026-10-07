"""Overflow-path regressions: no guard, dataflow or parent-proof bypasses."""
import copy
from unittest.mock import patch
import windows_enclave_sha2_failstop as p


class FailstopTests:
    def test_failstop_byte_domains_exhaust_every_unsigned_byte(self):
        result=p.byte_domains()
        self.assertEqual(result['byte_values'],256)
        self.assertEqual(result['nonempty'],list(range(1,9)))
        self.assertEqual(result['empty'],[0]);self.assertEqual(result['partial'],list(range(1,8)))
        for v in range(256):
            self.assertEqual(v in result['nonempty'],1<=v<=8)
            self.assertEqual(v in result['partial'],1<=v<=7)

    def test_failstop_single_entry_includes_unreachable_and_backwards_bypasses(self):
        graph={0:[1],1:[2],2:[3,4],3:[2],4:[],5:[0]}
        p.single_entry(graph,1,3)
        for bad in (graph|{0:[1,3]},graph|{5:[2]},graph|{4:[3]}):
            with self.assertRaises(ValueError):p.single_entry(bad,1,3)

    def test_failstop_guard_cannot_be_satisfied_vacuously_or_on_one_path(self):
        graph={0:[1],1:[2,4],2:[3],3:[],4:[]}
        p.guarded_path(graph,0,3,(1,2))
        for bad in (graph|{0:[1,3]},graph|{4:[3]},graph|{2:[]}):
            with self.assertRaises(ValueError):p.guarded_path(bad,0,3,(1,2))
        with self.assertRaises(ValueError):p.guarded_path(graph,0,3,(1,3))

    def test_failstop_value_definition_exclusion_removes_incoming_edges(self):
        graph={0:[1,4],1:[2,4],2:[3],3:[],4:[3]}
        with self.assertRaises(ValueError):p.guarded_path(graph,0,3,(1,2))
        p.guarded_path(graph,0,3,(1,2),exclude=(4,))
        self.assertNotIn(4,p.filtered(graph,nodes=(4,)))
        self.assertFalse(any(4 in v for v in p.filtered(graph,nodes=(4,)).values()))

    def test_failstop_terminal_does_not_receive_empty_returning_effects(self):
        lines=['entry:','je .B190','ja .B190','retq','.B190:',
               'callq _panic_const_add_overflow','ud2']
        result=p.terminal(lines,p.g.graph(lines,{}),[1,2])
        self.assertFalse(result['returning_effects_assigned'])
        for old,new in [('ud2','retq'),('callq _panic_const_add_overflow','callq returning'),
                        ('retq','jmp .B190')]:
            bad=[v.replace(old,new) for v in lines]
            with self.assertRaises(ValueError):p.terminal(bad,p.g.graph(bad,{}),[1,2])


class FailstopSavedTests:
    def failstop_fixture(self):
        import windows_enclave_sha2_batch_chains as parent
        if not hasattr(self.__class__,'_failstop_fixture'):
            row=next(v for v in self.routes if v[0]=='simd256');bodies=row[-1]
            asm=parent.load(self.saved,self.root,row[1])[3]
            prior=dict(simd_narrow_pointer_lifetimes=parent.narrow_lifetimes.inspect(bodies,asm,row[4]),
                simd_metadata_preservation=parent.field_integrity.inspect(bodies,row[4],'simd256'),
                simd_compact_indices=parent.simd_indices.inspect(bodies,'simd256'),
                simd_physical_allocation_lifetimes=parent.allocation_lifetimes.inspect(bodies,asm,'simd256'))
            self.__class__._failstop_fixture=(row,asm,prior)
        return self.__class__._failstop_fixture

    def failstop_mutants(self,replacements=(),insertions=()):
        row,asm,prior=self.failstop_fixture();bodies=row[-1]
        name=p.s.one(bodies,r'Resident6digest$');lines=p.s.lines(bodies[name]);changes=[]
        for at,text in replacements:
            changed=lines[:];changed[at]=text;changes.append(changed)
        for at,text in insertions:changes.append(lines[:at]+[text]+lines[at:])
        for changed in changes:
            with self.subTest(change=next((i,b) for i,(a,b) in enumerate(zip(lines,changed)) if a!=b)):
                with self.assertRaises(ValueError):
                    p.inspect(bodies|{name:'\n'.join(changed)},asm,'simd256',prior)
        return len(changes)

    def test_actual_failstop_proof_and_parent_integration(self):
        import windows_enclave_sha2_batch_chains as parent
        row,asm,prior=self.failstop_fixture();result=p.inspect(row[-1],asm,'simd256',prior)
        self.assertEqual(result['terminal']['incoming_guards'],[534,1103])
        self.assertTrue(result['selected_overflow_unreachable_for_admitted_preserved_inputs'])
        self.assertFalse(result['whole_frame_qualified'])
        self.assertFalse(result['caller_frame_erasure_or_OS_window_qualification'])
        self.assertEqual(result['iterator']['overflow_compare_values'],list(range(8)))
        self.assertEqual(result['partial_tail']['possible_compare_values'],list(range(1,8)))
        with patch.object(p,'inspect',side_effect=ValueError('failstop composition failed')) as check:
            with self.assertRaisesRegex(ValueError,'failstop composition failed'):
                parent.inspect_route(self.saved,self.root,row[0],row[1],False)
            check.assert_called_once()

    def test_actual_failstop_iterator_seed_update_guard_and_bypass_mutants(self):
        replacements=[(527,'movq $-1, %rax'),(528,'movl $1, %edx'),(531,'cmpq $8, %rdx'),
            (532,'jg .B69'),(533,'cmpq $0, %rax'),(534,'jne .B190'),
            (535,'leaq 2(%rdx), %r9'),(544,'addq $2, %rax'),(546,'movq %r8, %rdx')]
        insertions=[(at,'incq %rax') for at in (535,544,547,599)]
        insertions += [(at,'movb $0, %dl') for at in (535,547,599)]
        insertions += [(at,'movq %rcx, %r9') for at in (535,544)]
        insertions += [(527,'jne .B66'),(548,'jne .B66'),(599,'jne .B65'),
                       (527,'jne .B75')]
        count=self.failstop_mutants(replacements,insertions)
        self.assertEqual(count,22);print('Overflow iterator mutations rejected: '+str(count))

    def test_actual_failstop_scope_does_not_claim_compaction_geometry_or_termination(self):
        row,asm,prior=self.failstop_fixture();bodies=row[-1]
        name=p.s.one(bodies,r'Resident6digest$');lines=p.s.lines(bodies[name])
        # These changes are not safe full programs. They leave the proved pair
        # of counters intact but can break pointer geometry or termination.
        # The independent compaction/image checks, not this bounded guard proof,
        # own those properties. Keep that distinction executable.
        for at,text in ((544,'movb $0, %dl'),(547,'movq %rcx, %r9'),
                        (599,'movq %rcx, %r9'),(599,'jne .B70')):
            changed=lines[:at]+[text]+lines[at:]
            result=p.inspect(bodies|{name:'\n'.join(changed)},asm,'simd256',prior)
            self.assertTrue(result['selected_overflow_unreachable_for_admitted_preserved_inputs'])
            self.assertFalse(result['whole_frame_qualified'])

    def test_actual_failstop_tail_admission_register_and_edge_mutants(self):
        replacements=[(121,'movzbl -2(%rdi,%r15), %r14d'),(124,'leal -2(%r14), %eax'),
            (125,'cmpb $8, %al'),(126,'jg .B13'),(146,'movl $8, %r14d'),
            (110,'movb %al, -8(%r12)'),(1026,'movq 72(%rbx), %rax'),
            (1027,'movzbl 567(%rbx,%rax), %edi'),(1028,'testb $-1, %dil'),
            (1029,'je .B163'),(1102,'cmpb $8, %dil'),(1103,'jg .B190')]
        insertions=[(124,'jne .B3'),(125,'xorl %eax, %eax'),(126,'testb %al, %al'),
                    (110,'movb $9, %r14b'),(1028,'movb $8, %dil'),
                    (1029,'testb %dil, %dil'),(1102,'incq %rdi'),(1103,'testb %dil, %dil'),
                    (1030,'jne .B163'),(1027,'jne .B163')]
        count=self.failstop_mutants(replacements,insertions)
        self.assertEqual(count,22);print('Overflow tail admission/lifetime mutations rejected: '+str(count))

    def test_actual_failstop_unassigned_terminal_entries_reject(self):
        count=self.failstop_mutants([(1220,'retq')],[(at,'jne .B190') for at in (45,530,1030,1109)])
        self.assertEqual(count,5)

    def test_actual_failstop_requires_all_fresh_composition_results(self):
        row,_,prior=self.failstop_fixture();name=p.s.one(row[-1],r'Resident6digest$')
        count=0
        for key,field in [('simd_metadata_preservation','conditional_input_and_authority_field_preservation_checked'),
            ('simd_physical_allocation_lifetimes','conditional_physical_separation'),
            ('simd_physical_allocation_lifetimes','constructor_result_and_worker_use_joined'),
            ('simd_narrow_pointer_lifetimes','normal_cfg_pointer_definition_lifetimes_checked'),
            ('simd_compact_indices','active_count_exact')]:
            bad=copy.deepcopy(prior);bad[key][field]=False
            with self.assertRaises(ValueError):p.compose(bad,name)
            count+=1
        for key in ('simd_metadata_preservation','simd_narrow_pointer_lifetimes','simd_compact_indices'):
            bad=copy.deepcopy(prior);bad[key]['function']='another_function'
            with self.assertRaises(ValueError):p.compose(bad,name)
            count+=1
        self.assertEqual(count,8)
