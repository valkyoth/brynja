"""Wide parent admission, result identity, callback and clearing regressions."""
import copy
from unittest.mock import patch
import windows_enclave_sha2_parent_authority as p


class ParentAuthoritySavedTests:
    def parent_authority_fixture(self):return self.normal_effect_fixture('simd512')

    def test_actual_parent_authority_assignment_and_integration(self):
        import windows_enclave_sha2_batch_chains as main
        row,asm,prior=self.parent_authority_fixture();proof=p.inspect(row[-1],asm,prior)
        self.assertEqual(len(proof['assigned']),6);self.assertEqual(proof['assigned_parent_call_count'],18)
        self.assertEqual(len(proof['remaining_parent_calls']),9)
        self.assertTrue(proof['operation_original_owner_result_and_authority_callers_joined'])
        self.assertTrue(proof['helpers']['success_returns_original_owner_pointer'])
        self.assertFalse(proof['whole_frame_qualified'])
        with patch.object(p,'inspect',side_effect=ValueError('parent authority failed')) as check:
            with self.assertRaisesRegex(ValueError,'parent authority failed'):
                main.inspect_route(self.saved,self.root,'simd512',row[1],False)
            check.assert_called_once()

    def test_actual_parent_authority_every_helper_instruction_is_load_bearing(self):
        row,_,prior=self.parent_authority_fixture();bodies=row[-1]
        compiled=prior['simd_control_call_effects']['leaf_targets']['compiled']
        helpers=p.contracts(bodies,compiled);count=0
        for name in (helpers['operation'],helpers['check'],compiled):
            lines=p.s.lines(bodies[name])
            for at,line in enumerate(lines):
                if line.startswith('.') or line.endswith(':'):continue
                bad=lines[:at]+lines[at+1:]
                with self.subTest(name=name,instruction=line):
                    with self.assertRaises(ValueError):p.contracts(bodies|{name:'\n'.join(bad)},compiled)
                count+=1
        self.assertGreater(count,100)
        print('Parent authority complete helper instruction deletions rejected:',count)

    def test_actual_parent_authority_operation_arguments_and_success_identity(self):
        row,asm,prior=self.parent_authority_fixture();bodies=row[-1]
        helpers=p.contracts(bodies,prior['simd_control_call_effects']['leaf_targets']['compiled'])
        joined=p.callsites(bodies,asm,helpers);name=joined['function'];lines=p.s.lines(bodies[name])
        at=joined['calls'][0]['line'];changes=[]
        for site,text in [(at-2,'leaq 7192(%rbx), %rcx'),(at-1,'movl $1, %r9d')]:
            bad=lines[:];bad[site]=text;changes.append(bad)
        for text in ('movq %rax, %rdx','movb $0, %dl','movq %rax, %r8','movb $0, %r8b'):
            changes.append(lines[:at-2]+[text]+lines[at-2:])
        changes.append(lines[:1]+['jne .B2']+lines[1:])
        for bad in changes:
            with self.assertRaises(ValueError):p.callsites(bodies|{name:'\n'.join(bad)},asm,helpers)
        operation=helpers['operation'];original='\n'.join(p.s.lines(bodies[operation]))
        for old,new in [('movq %rbx, (%rsi)','movq %rdi, (%rsi)'),
                        ('movb $0, 8(%rsi)','movb $2, 8(%rsi)'),
                        ('cmpb %r9b, 288(%rdx)','cmpb %r9b, 280(%rdx)'),
                        ('movq %rdi, 280(%rbx)','movq %rdi, 16(%rbx)')]:
            self.assertEqual(original.count(old),1)
            with self.assertRaises(ValueError):p.contracts(bodies|{operation:original.replace(old,new)},helpers['compiled'])
        self.assertEqual(len(changes)+4,11)

    def test_actual_parent_authority_callback_check_and_clear_pointer_corruptions(self):
        row,asm,prior=self.parent_authority_fixture();bodies=row[-1]
        helpers=p.contracts(bodies,prior['simd_control_call_effects']['leaf_targets']['compiled'])
        joined=p.callsites(bodies,asm,helpers);name=joined['function'];lines=p.s.lines(bodies[name]);changes=[]
        for call in joined['calls'][1:]:
            at=call['line']
            # An alternate predecessor at the actual call must not skip its argument checks.
            changes.append(lines[:1]+['jne injected']+lines[1:at]+['injected:']+lines[at:])
            if call['role']=='compiled':
                site=call['backend_load'];bad=lines[:];bad[site]='movzbl 16(%r8), %ecx';changes.append(bad)
                if at==155:
                    reload=at-6;self.assertEqual(lines[reload],'movq 88(%rbx), %r8')
                    changes.append(lines[:reload]+['movb $0, 95(%rbx)']+lines[reload:])
            elif call['role']=='check':
                site=at-4 if at==576 else at-5
                self.assertEqual(lines[site],'movq 64(%rbx), %rax')
                bad=lines[:];bad[site]='movq 72(%rbx), %rax';changes.append(bad)
                changes.append(lines[:site]+['movb $0, 71(%rbx)']+lines[site:])
            else:
                bad=lines[:];bad[at-1]='movl $257, %edx';changes.append(bad)
                bad=lines[:];bad[at-2]='leaq 16(%rsi), %rcx';changes.append(bad)
        at=p.o.unique(lines,'movq 16(%rax), %r8');bad=lines[:];bad[at]='movq 8(%rax), %r8';changes.append(bad)
        for bad in changes:
            with self.assertRaises(ValueError):p.callsites(bodies|{name:'\n'.join(bad)},asm,helpers)
        self.assertEqual(len(changes),15)

    def test_actual_parent_authority_prerequisites_and_effect_exclusions(self):
        row,asm,prior=self.parent_authority_fixture();count=0
        for key,field in [('simd_physical_allocation_lifetimes','conditional_physical_separation'),
            ('simd_physical_allocation_lifetimes','constructor_result_and_worker_use_joined'),
            ('simd_parent_output_effects','parent_output_transfer_and_cleanup_arguments_checked'),
            ('simd_descriptor_normal_effects','selected_normal_helpers_conditionally_preserve_descriptors'),
            ('simd_wide_descriptor_handoff','conditional_direct_descriptor_handoff_checked'),
            ('simd_metadata_preservation','conditional_input_and_authority_field_preservation_checked')]:
            bad=copy.deepcopy(prior);bad[key][field]=False
            with self.assertRaises(ValueError):p.inspect(row[-1],asm,bad)
            count+=1
        for mutation in ('missing','duplicate'):
            bad=copy.deepcopy(prior)
            if mutation=='missing':bad['simd_parent_output_effects']['remaining_parent_calls']=[]
            else:bad['simd_parent_output_effects']['assigned'].append(
                p.inspect(row[-1],asm,prior)['assigned'][0])
            with self.assertRaises(ValueError):p.inspect(row[-1],asm,bad)
            count+=1
        helpers=p.contracts(row[-1],prior['simd_control_call_effects']['leaf_targets']['compiled'])
        joined=p.callsites(row[-1],asm,helpers)
        for lo in (64,352,4640):
            bad=copy.deepcopy(joined);bad['calls'][0]['footprints'].append(['writes','parent',lo,lo+1])
            with patch.object(p,'callsites',return_value=bad):
                with self.assertRaises(ValueError):p.inspect(row[-1],asm,prior)
            count+=1
        with patch.object(p.p.stack,'depth',return_value=1024):
            with self.assertRaises(ValueError):p.inspect(row[-1],asm,prior)
        self.assertEqual(count+1,12)
