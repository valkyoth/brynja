"""Actual wide-parent output/callee argument and noninterference regressions."""
import copy
from unittest.mock import patch
import windows_enclave_sha2_parent_outputs as p


class ParentOutputSavedTests:
    def parent_output_fixture(self):return self.normal_effect_fixture('simd512')

    def test_actual_parent_output_partial_assignment_and_integration(self):
        import windows_enclave_sha2_batch_chains as main
        row,asm,prior=self.parent_output_fixture();proof=p.inspect(row[-1],asm,prior)
        self.assertEqual(len(proof['assigned']),10);self.assertEqual(proof['assigned_parent_call_count'],12)
        self.assertEqual(len(proof['remaining_parent_calls']),15)
        self.assertTrue(proof['parent_output_transfer_and_cleanup_arguments_checked'])
        self.assertFalse(proof['whole_frame_qualified'])
        self.assertEqual(len(proof['transfers']['indexed_write_extents']),16)
        with patch.object(p,'inspect',side_effect=ValueError('parent output failed')) as check:
            with self.assertRaisesRegex(ValueError,'parent output failed'):
                main.inspect_route(self.saved,self.root,'simd512',row[1],False)
            check.assert_called_once()

    def test_actual_parent_output_copy_lane_width_and_owner_mutants(self):
        row,asm,_=self.parent_output_fixture();bodies=row[-1];proof=p.transfers(bodies,asm)
        name=proof['function'];lines=p.s.lines(bodies[name]);changes=[]
        for call in proof['calls']:
            at=call['line']
            for site,text in [(at-2,'leaq 23(%rax), %rcx'),(at-1,'movl $65, %r9d'),
                (call['source_load'],'movq 416(%rbx), %r8'),
                (call['length_load'],'movq 416(%rbx), %rdx'),
                (call['width_guard']-1,'cmpq $65, %rdx'),(at-3,'movq 72(%rbx), %rax')]:
                bad=lines[:];bad[site]=text;changes.append(bad)
            changes.append(lines[:1]+['jne injected']+lines[1:at]+['injected:']+lines[at:])
        for bad in changes:
            with self.assertRaises(ValueError):p.transfers(bodies|{name:'\n'.join(bad)},asm)
        self.assertEqual(len(changes),28)

    def test_actual_parent_output_owner_slot_partial_and_indexed_corruption(self):
        row,asm,_=self.parent_output_fixture();bodies=row[-1]
        proof=p.transfers(bodies,asm);name=proof['function'];lines=p.s.lines(bodies[name])
        first=proof['calls'][0]['line']-3;changes=[]
        for instruction in ('movb $0, 71(%rbx)','movq %rcx, 64(%rbx)',
                            'movq %rax, 64(%rbx,%r15)'):
            changes.append(lines[:first]+[instruction]+lines[first:])
        for at,text in [(p.o.unique(lines,'movl $34, %r15d'),'movl $33, %r15d'),
            (p.o.unique(lines,'addq $40, %r15'),'addq $41, %r15'),
            (p.o.unique(lines,'movl $224, %eax'),'movl $225, %eax'),
            (p.o.unique(lines,'addq $256, %rax'),'addq $255, %rax'),
            (p.o.unique(lines,'cmpq $2784, %rax'),'cmpq $2785, %rax'),
            (p.o.unique(lines,'movq 7200(%rbx), %rax'),'movq 7208(%rbx), %rax'),
            (p.o.unique(lines,'movq %rax, 64(%rbx)'),'movl %eax, 64(%rbx)')]:
            bad=lines[:];bad[at]=text;changes.append(bad)
        at=p.o.unique(lines,'movl %edx, 190(%rbx,%r15)')
        changes.append(lines[:1]+['jne injected']+lines[1:at]+['injected:']+lines[at:])
        changes.append(lines[:1]+['jne .B2']+lines[1:])
        for bad in changes:
            with self.assertRaises(ValueError):p.transfers(bodies|{name:'\n'.join(bad)},asm)
        self.assertEqual(len(changes),12)

    def test_actual_parent_output_cleanup_arguments_bypass_and_callee_bodies(self):
        row,asm,prior=self.parent_output_fixture();bodies=row[-1]
        handoff=prior['simd_wide_descriptor_handoff']['parent'];calls=p.cleanup(bodies,asm,handoff)
        name=handoff['function'];lines=p.s.lines(bodies[name]);count=0
        for call in calls:
            at=call['line'];start=at-2 if lines[at-1]=='vzeroupper' else at-1
            bad=lines[:];bad[start]='movq %rax, %rcx'
            with self.assertRaises(ValueError):p.cleanup(bodies|{name:'\n'.join(bad)},asm,handoff)
            bad=lines[:1]+['jne injected']+lines[1:at]+['injected:']+lines[at:]
            with self.assertRaises(ValueError):p.cleanup(bodies|{name:'\n'.join(bad)},asm,handoff)
            count+=2
        for reg in ('r12','r13'):
            at=next(v['line'] for v in calls if v['role']==('scalar_wipe' if reg=='r12' else 'cpu_wipe'))
            bad=lines[:at-1]+[f'movb $0, %{reg}b']+lines[at-1:]
            with self.assertRaises(ValueError):p.cleanup(bodies|{name:'\n'.join(bad)},asm,handoff)
            count+=1
        for key in ('scalar','cpu','output'):
            target=p.p.storage.symbols(bodies)[key];original='\n'.join(p.s.lines(bodies[target]))
            bad=original.replace('movl $','movl $1',1)
            self.assertNotEqual(bad,original)
            with self.assertRaises(ValueError):p.cleanup(bodies|{target:bad},asm,handoff)
            count+=1
        self.assertEqual(count,17)

    def test_actual_parent_output_prerequisites_inventory_and_effect_overlap(self):
        row,asm,prior=self.parent_output_fixture();count=0
        for key,field in [('simd_wide_descriptor_handoff','conditional_direct_descriptor_handoff_checked'),
            ('simd_physical_allocation_lifetimes','conditional_physical_separation'),
            ('simd_physical_allocation_lifetimes','constructor_result_and_worker_use_joined'),
            ('simd_dynamic_clearing_descriptors','normal_direct_descriptor_write_lifetimes_checked'),
            ('simd_dynamic_clearing_descriptors','exact_pointer_length_pair_and_all_loop_indices_checked'),
            ('simd_wide_output_effects','all_child_normal_calls_assigned'),
            ('simd_primitive_contracts','prior_semantic_review_replayed'),
            ('simd_descriptor_normal_effects','selected_normal_helpers_conditionally_preserve_descriptors')]:
            bad=copy.deepcopy(prior);bad[key][field]=False
            with self.assertRaises(ValueError):p.inspect(row[-1],asm,bad)
            count+=1
        bad=copy.deepcopy(prior);bad['simd_descriptor_normal_effects']['parent']['pending']=[]
        with self.assertRaises(ValueError):p.inspect(row[-1],asm,bad)
        proof=p.transfers(row[-1],asm)
        for lo in (64,352,4640):
            bad=copy.deepcopy(proof);bad['calls'][0]['footprints'].append(['writes','parent',lo,lo+1])
            with patch.object(p,'transfers',return_value=bad):
                with self.assertRaises(ValueError):p.inspect(row[-1],asm,prior)
            count+=1
        self.assertEqual(count+1,12)
