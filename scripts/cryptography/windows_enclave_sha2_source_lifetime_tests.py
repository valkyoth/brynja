"""Must-origin regressions for all normal first-source CFG paths."""
from unittest.mock import patch
import windows_enclave_sha2_source_lifetime as p
from windows_enclave_sha2_slot_origins_tests import SlotOriginTests, SlotOriginSavedTests
from windows_enclave_sha2_narrow_lifetimes_tests import NarrowLifetimeTests, NarrowLifetimeSavedTests
from windows_enclave_sha2_field_integrity_tests import FieldIntegrityTests, FieldIntegritySavedTests
from windows_enclave_sha2_allocation_tests import AllocationTests, AllocationSavedTests
from windows_enclave_sha2_failstop_tests import FailstopTests, FailstopSavedTests
from windows_enclave_sha2_dynamic_cleanup_tests import DynamicCleanupTests, DynamicCleanupSavedTests
from windows_enclave_sha2_wide_result_tests import WideResultTests, WideResultSavedTests


class SourceLifetimeTests(SlotOriginTests, NarrowLifetimeTests, FieldIntegrityTests, AllocationTests, FailstopTests, DynamicCleanupTests, WideResultTests):
    def source_states(self,lines,tables=None):
        return p.analyse(lines,'entry',tables or {},(64,72),{'rbp':(0,0),'rsp':(-128,-128)},
                         lines.index('movq %rax, 64(%rbp)'),lines.index('movq $0, 64(%rbp)'))

    def test_source_origin_merges_unknown_bypass_partial_and_indexed_writes(self):
        good=['entry:','leaq 1024(%rdi), %rax','movq %rax, 64(%rbp)','jne absent',
              'jmp read','absent:','movq $0, 64(%rbp)','read:','movq 64(%rbp), %r8','retq']
        self.assertEqual(self.source_states(good)[8][2],{'prepared','absent'})
        bypass=good[:1]+['jne read']+good[1:]
        self.assertIn('unknown',self.source_states(bypass)[9][2])
        for write in ('movq %rcx, 64(%rbp)','movb $0, 71(%rbp)','movq %rax, 63(%rbp)',
                      'movq %rax, 192(%rsp)','movq %rax, (%rbp,%rsi,8)'):
            changed=good[:3]+[write]+good[3:]
            self.assertIn('unknown',self.source_states(changed)[9][2])
        changed=good[:3]+['movq %rcx, 72(%rbp)']+good[3:]
        self.assertEqual(self.source_states(changed)[9][2],{'prepared','absent'})

    def test_source_register_definitions_include_partial_conditional_and_abi_clobbers(self):
        lines=['entry:','movq 1168(%rbp), %rdi','leaq 1024(%rdi), %rax','jne merge',
               'xorl %eax, %eax','merge:','cmovaeq %rcx, %rax','callq target',
               'movq %rax, 64(%rbp)','movq $0, 64(%rbp)','retq']
        states=self.source_states(lines)
        self.assertEqual(states[6][0],{2,4})
        self.assertEqual(states[7][0],{2,4,6})
        self.assertEqual(states[8][0],{7});self.assertEqual(states[8][1],{1})
        lines[7]='movb $0, %dil'
        self.assertEqual(self.source_states(lines)[8][1],{7})
        lines[7]='cmovbq %rcx, %rdi'
        self.assertEqual(self.source_states(lines)[8][1],{1,7})

    def test_source_cfg_follows_backedges_all_table_targets_and_rejects_unknown_instructions(self):
        lines=['entry:','leaq 1024(%rdi), %rax','movq %rax, 64(%rbp)',
               'read:','movq 64(%rbp), %r8','jmpq *%rax',
               'again:','movb $1, 64(%rbp)','jmp read',
               'absent:','movq $0, 64(%rbp)','retq']
        states=self.source_states(lines,{5:['again','absent']})
        self.assertEqual(states[4][2],{'prepared','unknown'})
        for tables in ({},{5:['outside']}):
            with self.assertRaises(ValueError):self.source_states(lines,tables)
        for bad in ('xchgq %rax, %rdi','movsq','stosq','leaveq'):
            with self.assertRaises(ValueError):p.instruction(bad)


class SourceLifetimeSavedTests(SlotOriginSavedTests, NarrowLifetimeSavedTests, FieldIntegritySavedTests, AllocationSavedTests, FailstopSavedTests, DynamicCleanupSavedTests, WideResultSavedTests):
    def source_fixture(self,row):
        import windows_enclave_sha2_batch_chains as parent
        lane,pin,_,_,_,_,bodies=row
        return parent.load(self.saved,self.root,pin)[3],parent.frame_cell.inspect(bodies,lane)

    def test_actual_first_source_reaching_definitions_and_parent_integration(self):
        import windows_enclave_sha2_batch_chains as parent
        for row in self.routes:
            lane,pin,_,_,_,_,bodies=row
            if not lane.startswith('simd'):continue
            asm,frame=self.source_fixture(row);result=p.inspect(bodies,asm,lane,frame)
            self.assertEqual(result['reachable_instructions'],1655 if lane=='simd256' else 1736)
            self.assertEqual(len(result['workspace_argument_reload_sites']),0 if lane=='simd256' else 3)
            self.assertTrue(result['indirect_effects_and_original_argument_lifetimes_required'])
            self.assertFalse(result['whole_frame_qualified'])
            with patch.object(p,'inspect',side_effect=ValueError('source CFG failed')) as check:
                with self.assertRaisesRegex(ValueError,'source CFG failed'):
                    parent.inspect_route(self.saved,self.root,lane,pin,False)
                check.assert_called_once()

    def test_actual_source_origins_bypass_and_overlap_mutations_reject(self):
        count=0
        for row in self.routes:
            lane,_,_,_,_,_,bodies=row
            if not lane.startswith('simd'):continue
            asm,frame=self.source_fixture(row);result=p.inspect(bodies,asm,lane,frame)
            name=frame['function'];lines=p.s.lines(bodies[name]);narrow=lane=='simd256'
            offset=frame['cell'][0];base='rbx' if narrow else 'rbp'
            init=result['initializer'];origin=result['address_calculation']
            changes=[]
            for text in (f'movq %rcx, {offset}(%{base})',f'movb $0, {offset+7}(%{base})',
                         f'movq %rax, {offset-1}(%{base})',f'movq %rax, (%{base},%rsi,8)'):
                changes.append(lines[:init+1]+[text]+lines[init+1:])
            # Add a real entry path directly to the first source's consuming block.
            changes.append(lines[:1]+['jne '+frame['end']]+lines[1:])
            bad=lines[:];bad[origin]=bad[origin].replace('7712','7713').replace('1024','1025');changes.append(bad)
            bad=lines[:];bad[result['absent_initializer']]='movq %rcx, '+f'{offset}(%{base})';changes.append(bad)
            for at in result['workspace_argument_reload_sites']:
                bad=lines[:];bad[at]=bad[at].replace('1168','1176');changes.append(bad)
                changes.append(lines[:at+1]+['xorl %edi, %edi']+lines[at+1:])
            if not narrow:
                changes.append(lines[:init+1]+['movq %rax, 1168(%rbp)']+lines[init+1:])
            for changed in changes:
                with self.assertRaises(ValueError):p.inspect(bodies|{name:'\n'.join(changed)},asm,lane,frame)
                count+=1
        self.assertEqual(count,21)
        print('First-source CFG origin/bypass/overlap mutations rejected: '+str(count))
