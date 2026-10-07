"""Final-output argument, callback and clearing composition regressions."""
import copy
from unittest.mock import patch
import windows_enclave_sha2_wide_outputs as p


class WideOutputTests:
    def test_wide_output_nonnull_cut_is_only_the_four_exact_destination_edges(self):
        lines=['entry:'];expected=[]
        for i,label in enumerate((243,247,251,255)):
            lines += [f'cmpq $0, {816+16*i}(%rbp)',f'je .B{label}',f'.B{label}:']
            expected.append(len(lines)-2)
        lines+=['retq'];edges=p.n.g.graph(lines,{})
        actual,removed=p.nonnull_preflight(lines,edges)
        self.assertEqual([v['branch'] for v in removed],expected)
        self.assertEqual([i for i,(a,b) in enumerate(zip(lines,actual)) if a!=b],expected)
        self.assertTrue(all(actual[i]=='nop' for i in expected))
        for at in expected:
            bad=lines[:];bad[at-1]='cmpq $0, 880(%rbp)'
            with self.assertRaises(ValueError):p.nonnull_preflight(bad,p.n.g.graph(bad,{}))
        bad=lines[:1]+['jne .B243']+lines[1:]
        # An additional branch doesn't qualify as one of the excluded edges.
        result,removed=p.nonnull_preflight(bad,p.n.g.graph(bad,{}))
        self.assertEqual(result[1],'jne .B243');self.assertEqual(len(removed),4)

    def test_wide_output_descriptor_trace_rejects_partial_and_wrong_field_loads(self):
        lines=['entry:','movq 824(%rbp), %r12','movq %r12, %r9','callq copy','retq']
        states=p.o.definitions(lines,'entry',{})
        self.assertEqual(p.descriptor_load(lines,states,3,'r9',824),[1])
        for load in ('movl 824(%rbp), %r12d','movq 840(%rbp), %r12','movq %rcx, %r12'):
            bad=lines[:];bad[1]=load;states=p.o.definitions(bad,'entry',{})
            with self.assertRaises(ValueError):p.descriptor_load(bad,states,3,'r9',824)


class WideOutputSavedTests:
    def wide_output_fixture(self):
        # The existing fixture supplies fresh integrated prerequisite reports,
        # cached only within this test process, not a stale report from disk.
        return self.normal_effect_fixture('simd512')

    def test_actual_wide_output_complete_child_call_assignment_and_integration(self):
        import windows_enclave_sha2_batch_chains as parent
        row,asm,prior=self.wide_output_fixture();proof=p.inspect(row[-1],asm,prior)
        self.assertEqual(len(proof['assigned']),8);self.assertEqual(proof['child_returning_call_count'],36)
        self.assertEqual(len(proof['terminal_calls']),1);self.assertFalse(proof['remaining_child_calls'])
        self.assertTrue(proof['all_child_normal_calls_assigned']);self.assertFalse(proof['whole_frame_qualified'])
        self.assertEqual(len(proof['final_copies']['excluded_null_edges']),4)
        with patch.object(p,'inspect',side_effect=ValueError('wide output failed')) as check:
            with self.assertRaisesRegex(ValueError,'wide output failed'):
                parent.inspect_route(self.saved,self.root,'simd512',row[1],False)
            check.assert_called_once()

    def test_actual_wide_output_sources_and_lengths_cannot_be_clobbered_or_bypassed(self):
        row,asm,prior=self.wide_output_fixture();bodies=row[-1]
        proof=p.exports(bodies,asm);name=proof['function'];lines=p.s.lines(bodies[name]);changes=[]
        # Corrupt saved state just before the preflight, outside its literal
        # instruction sequences, so the new reaching-definition proof must act.
        at=p.o.unique(lines,'cmpb $-1, %r15b')
        for instruction in ('movb $0, 983(%rbp)','movq %rcx, 976(%rbp)',
                            'movq %rax, 1168(%rbp)'):
            changes.append(lines[:at]+[instruction]+lines[at:])
        for call in proof['calls']:
            first=p.o.unique(lines,f'.B{256+3*call["lane"]}:');at=call['line']
            # Keep the reviewed block intact but add an external predecessor.
            changes.append(lines[:1]+['jne injected']+lines[1:at]+['injected:']+lines[at:])
            guard=call['width_guard'];bad=lines[:];bad[guard]='jb .B14';changes.append(bad)
            bad=lines[:];bad[call['length_load']]=bad[call['length_load']].replace(
                str(824+16*call['lane']),str(824+16*((call['lane']+1)%4)))
            changes.append(bad)
            for text in ('movb $0, %r12b','movb $0, 1023(%rbp)','movb $0, 967(%rbp)'):
                if call['lane'] not in (1,2,3):continue
                # One relevant corruption per later lane, before its copy block.
                if text!=('movb $0, %r12b','movb $0, 1023(%rbp)','movb $0, 967(%rbp)')[call['lane']-1]:continue
                changes.append(lines[:first]+[text]+lines[first:])
        for bad in changes:
            with self.assertRaises(ValueError):p.exports(bodies|{name:'\n'.join(bad)},asm)
        self.assertEqual(len(changes),18)

    def test_actual_wide_output_copy_capacity_and_lane_mutants_reject(self):
        row,asm,_=self.wide_output_fixture();bodies=row[-1];proof=p.exports(bodies,asm)
        name=proof['function'];lines=p.s.lines(bodies[name]);count=0
        for call in proof['calls']:
            at=call['line'];lane=call['lane']
            for target,replace in [(call['destination_loads'][0],'movq 880(%rbp), %rcx'),
                (call['capacity_loads'][0],'movl $65, %edx'),(at-1,'movq %rax, %r9')]:
                bad=lines[:];bad[target]=replace
                with self.assertRaises(ValueError):p.exports(bodies|{name:'\n'.join(bad)},asm)
                count+=1
        self.assertEqual(count,12)

    def test_actual_wide_output_clear_pointer_width_and_loop_mutants_reject(self):
        row,asm,prior=self.wide_output_fixture();bodies=row[-1]
        name=p.s.one(bodies,r'Executor13digest_secret$');lines=p.s.lines(bodies[name])
        desc=prior['simd_dynamic_clearing_descriptors'];proof=p.clears(bodies,asm,desc)
        at=proof['calls'][1]['line'];origin=proof['calls'][1]['pointer_origins'][0]
        changes=[]
        for site,text in [(at-2,'movl $9, %edx'),(at-1,'movq %rsi, %rcx'),
            (origin,'leaq 879(%rbp), %rdi'),(proof['calls'][0]['line']-3,'movq 840(%rbp,%rsi), %rdx')]:
            bad=lines[:];bad[site]=text;changes.append(bad)
        changes.append(lines[:at-2]+['movb $0, %dil']+lines[at-2:])
        changes.append(lines[:1]+['jne injected']+lines[1:at]+['injected:']+lines[at:])
        for bad in changes:
            with self.assertRaises(ValueError):p.clears(bodies|{name:'\n'.join(bad)},asm,desc)
        self.assertEqual(len(changes),6)

    def test_actual_wide_output_callback_original_roots_and_leaf_contracts(self):
        row,asm,prior=self.wide_output_fixture();bodies=row[-1]
        leaves=prior['simd_control_call_effects']['leaf_targets'];calls=p.callbacks(bodies,asm,leaves)
        name=p.s.one(bodies,r'Executor13digest_secret$');lines=p.s.lines(bodies[name]);a,b=[v['line'] for v in calls]
        changes=[]
        for at,text in [(a-10,'movq 8(%r15), %rax'),(a-4,'movzbl 16(%rax), %ecx'),
            (b-7,'movq 1168(%rbp), %rax'),(b-5,'movq 16(%rax), %rax'),(b-4,'movq 24(%rax), %rax')]:
            bad=lines[:];bad[at]=text;changes.append(bad)
        origin=lines.index('movq %rdx, %r15');self.assertLess(origin,a-10)
        bad=lines[:];bad[origin]='movq %rcx, %r15';changes.append(bad)
        changes.append(lines[:b-7]+['movq %rax, 1176(%rbp)']+lines[b-7:])
        for bad in changes:
            with self.assertRaises(ValueError):p.callbacks(bodies|{name:'\n'.join(bad)},asm,leaves)
        for leaf in leaves.values():
            bad=bodies[leaf].replace('retq','movb $0, (%rcx)\nretq')
            with self.assertRaises(ValueError):p.callbacks(bodies|{leaf:bad},asm,leaves)
        self.assertEqual(len(changes)+len(leaves),9)

    def test_actual_wide_output_missing_prerequisites_or_call_assignment_reject(self):
        row,asm,prior=self.wide_output_fixture();count=0
        for key,field in [('simd_dynamic_clearing_descriptors','normal_direct_descriptor_write_lifetimes_checked'),
            ('simd_dynamic_clearing_descriptors','exact_pointer_length_pair_and_all_loop_indices_checked'),
            ('simd_physical_allocation_lifetimes','conditional_physical_separation'),
            ('simd_physical_allocation_lifetimes','constructor_result_and_worker_use_joined'),
            ('simd_wide_descriptor_handoff','conditional_direct_descriptor_handoff_checked'),
            ('simd_descriptor_normal_effects','selected_normal_helpers_conditionally_preserve_descriptors'),
            ('simd_metadata_preservation','conditional_input_and_authority_field_preservation_checked'),
            ('simd_helper_slot_origins','direct_cfg_origins_and_preservation_checked'),
            ('simd_primitive_contracts','prior_semantic_review_replayed'),
            ('simd_admitted_overflow_paths','selected_overflow_unreachable_for_admitted_preserved_inputs')]:
            bad=copy.deepcopy(prior);bad[key][field]=False
            with self.assertRaises(ValueError):p.inspect(row[-1],asm,bad)
            count+=1
        for field in ('exact_lane_pointers_and_widths','ordered_disjoint_in_bounds','maximum_slot_bytes','scratch_bytes'):
            bad=copy.deepcopy(prior);bad['simd_dynamic_clearing_descriptors']['geometry'][field]=False
            with self.assertRaises(ValueError):p.inspect(row[-1],asm,bad)
            count+=1
        bad=copy.deepcopy(prior);bad['simd_descriptor_normal_effects']['unassigned_calls'].pop(0)
        with self.assertRaises(ValueError):p.inspect(row[-1],asm,bad)
        self.assertEqual(count+1,15)
