"""SDK initialization arguments and temporal frame reuse regressions."""
import copy
from unittest.mock import patch
import windows_enclave_sha2_parent_setup as p


class ParentSetupSavedTests:
    def parent_setup_fixture(self):return self.normal_effect_fixture('simd512')

    def test_actual_parent_setup_assignment_keeps_shared_runtime_open(self):
        import windows_enclave_sha2_batch_chains as main
        row,asm,prior=self.parent_setup_fixture();proof=p.inspect(row[-1],asm,prior)
        self.assertEqual(len(proof['assigned']),6);self.assertEqual(proof['assigned_parent_call_count'],24)
        self.assertEqual([v['line'] for v in proof['remaining_parent_calls']],[21,121,444])
        self.assertTrue(proof['SDK_memory_semantics_and_stack_contracts_still_required'])
        self.assertFalse(proof['memset_is_volatile_erasure']);self.assertFalse(proof['whole_frame_qualified'])
        with patch.object(p,'inspect',side_effect=ValueError('parent setup failed')) as check:
            with self.assertRaisesRegex(ValueError,'parent setup failed'):
                main.inspect_route(self.saved,self.root,'simd512',row[1],False)
            check.assert_called_once()

    def test_actual_parent_setup_pointer_size_and_bypass_mutations(self):
        row,asm,prior=self.parent_setup_fixture();bodies=row[-1];proof=p.inspect(bodies,asm,prior)
        name=proof['function'];lines=p.s.lines(bodies[name]);count=0
        _,_,_,states,_=p.output.prepare(bodies,asm)
        for call in proof['assigned']:
            at=call['line'];size=next(iter(states[at]['r8']))
            changes=[]
            for roots in call['pointer_origins'].values():
                self.assertEqual(len(roots),1);site=roots[0]
                bad=lines[:];bad[site]=bad[site].replace('leaq ','leaq 1',1);changes.append(bad)
            bad=lines[:];bad[size]=f'movl ${call["bytes"]+1}, %r8d';changes.append(bad)
            changes.append(lines[:1]+['jne injected']+lines[1:at]+['injected:']+lines[at:])
            if call['target']=='memset':
                site=next(iter(states[at]['rdx']));bad=lines[:];bad[site]='movl $1, %edx';changes.append(bad)
            for bad in changes:
                with self.assertRaises(ValueError):p.inspect(bodies|{name:'\n'.join(bad)},asm,prior)
                count+=1
        self.assertEqual(count,24)

    def test_actual_parent_setup_late_reentry_cannot_destroy_live_descriptors(self):
        row,asm,prior=self.parent_setup_fixture();bodies=row[-1];proof=p.inspect(bodies,asm,prior)
        name=proof['function'];lines=p.s.lines(bodies[name]);count=0
        for call in proof['assigned']:
            # Update only the changed instruction coordinates, so the real CFG
            # non-reentry proof (not a stale-coordinate check) rejects this.
            entry=call['line']-5 if call['line']==258 else call['line']
            bad=lines[:];bad.insert(entry,'setup_replay:')
            end=p.o.unique(bad,'movq %r8, 408(%rbx)');bad.insert(end+1,'jne setup_replay')
            changed=bodies|{name:'\n'.join(bad)};edges=p.output.child.d.graph(bad,asm)
            first,last,_=p.output.child.d.constructor(changed,name,'simd512',edges)
            altered=copy.deepcopy(prior);altered['simd_dynamic_clearing_descriptors']['construction']=[first,last]
            with self.assertRaisesRegex(ValueError,'no normal path from output descriptor construction'):
                p.inspect(changed,asm,altered)
            count+=1
        self.assertEqual(count,6)

    def test_actual_parent_setup_prerequisites_and_missing_assignment(self):
        row,asm,prior=self.parent_setup_fixture();count=0
        for key,field in [('simd_physical_allocation_lifetimes','conditional_physical_separation'),
            ('simd_physical_allocation_lifetimes','constructor_result_and_worker_use_joined'),
            ('simd_parent_authority_effects','operation_original_owner_result_and_authority_callers_joined'),
            ('simd_parent_output_effects','parent_output_transfer_and_cleanup_arguments_checked'),
            ('simd_dynamic_clearing_descriptors','normal_direct_descriptor_write_lifetimes_checked')]:
            bad=copy.deepcopy(prior);bad[key][field]=False
            with self.assertRaises(ValueError):p.inspect(row[-1],asm,bad)
            count+=1
        bad=copy.deepcopy(prior);bad['simd_parent_authority_effects']['remaining_parent_calls']=[]
        with self.assertRaises(ValueError):p.inspect(row[-1],asm,bad)
        self.assertEqual(count+1,6)
