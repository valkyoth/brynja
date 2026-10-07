"""Normal-return cleanup coverage regressions, independent of body hash pins."""
from unittest.mock import patch
import windows_enclave_sha2_cleanup_paths as p


class CleanupPathTests:
    def test_cleanup_must_follow_the_last_sensitive_call_on_every_return(self):
        good=['entry:','callq write','testb %al, %al','je error','callq wipe','retq',
              'error:','callq wipe','retq']
        self.assertEqual(len(p.check(good,'entry',{'write'},{'wipe'}, {})['normal_return_sites']),2)
        for code in (good[:7]+good[8:],['entry:','callq wipe','callq write','retq'],
                     good[:4]+['jmp escape']+good[4:]+['escape:','retq']):
            with self.assertRaises(ValueError):p.check(code,'entry',{'write'},{'wipe'}, {})
        with self.assertRaises(ValueError):p.check(good,'entry',set(),{'wipe'}, {})
        with self.assertRaises(ValueError):p.check(good,'entry',{'write'},{'write'}, {})

    def test_loop_and_indirect_targets_are_all_explored_and_abort_is_not_a_return(self):
        code=['entry:','callq write','jmpq *%rax','again:','callq wipe','jne entry','retq',
              'failed:','ud2']
        result=p.check(code,'entry',{'write'},{'wipe'},{2:['again','failed']})
        self.assertEqual(result['normal_return_sites'],[6]);self.assertEqual(result['terminal_sites'],[8])
        with self.assertRaises(ValueError):p.check(code,'entry',{'write'},{'wipe'}, {})
        with self.assertRaises(ValueError):p.check(code,'entry',{'write'},{'wipe'}, {2:['outside']})
        with self.assertRaises(ValueError):p.check(code+['unwiped:','retq'],'entry',{'write'},{'wipe'},
                                                {2:['again','unwiped']})
        with self.assertRaises(ValueError):p.check(['entry:','callq write','callq wipe','ud2'],
                                                 'entry',{'write'},{'wipe'}, {})


class CleanupPathSavedTests:
    def test_all_sensitive_helper_sites_reject_injected_unclean_returns(self):
        import windows_enclave_sha2_batch_chains as parent
        total=0
        for lane,pin,_,_,_,_,bodies in self.routes:
            if not lane.startswith('simd'):continue
            assembly=parent.load(self.saved,self.root,pin)[3]
            result=p.inspect(bodies,assembly,lane)
            self.assertEqual(len(result['normal_return_sites']),1)
            self.assertEqual(len(result['terminal_sites']),1)
            self.assertEqual(len(result['sensitive_helper_sites']),22 if lane=='simd256' else 18)
            self.assertTrue(result['helper_argument_and_original_storage_lifetimes_required'])
            self.assertFalse(result['arbitrary_exception_cleanup_qualified'])
            name=result['function'];lines=p.s.lines(bodies[name])
            for at in result['sensitive_helper_sites']:
                changed=lines[:at+1]+['retq']+lines[at+1:]
                with self.assertRaises(ValueError):p.inspect(bodies|{name:'\n'.join(changed)},assembly,lane)
                total+=1
            changed=[v if v not in ['callq '+n for n in result['complete_wipe_targets']] else 'nop' for v in lines]
            with self.assertRaises(ValueError):p.inspect(bodies|{name:'\n'.join(changed)},assembly,lane)
            with patch.object(p,'inspect',side_effect=ValueError('cleanup CFG failed')) as check:
                with self.assertRaisesRegex(ValueError,'cleanup CFG failed'):
                    parent.inspect_route(self.saved,self.root,lane,pin,False)
                check.assert_called_once()
        self.assertEqual(total,40)
        print('Whole-function SIMD premature-return mutations rejected: '+str(total))

    def test_actual_cleanup_jump_tables_reject_wrong_base_and_target(self):
        import windows_enclave_sha2_batch_chains as parent
        row=next(row for row in self.routes if row[0]=='simd512');lane,pin,_,_,_,_,bodies=row
        assembly=parent.load(self.saved,self.root,pin)[3]
        name=p.s.one(bodies,r'Executor13digest_secret$');lines=p.s.lines(bodies[name])
        tables=p.jump_tables(assembly,lines);self.assertEqual(len(tables),11)
        for at in tables:
            changed=lines[:];changed[at]='jmpq *%r11'
            with self.assertRaises(ValueError):p.jump_tables(assembly,changed)
        result=p.inspect(bodies,assembly,lane)
        for at in tables:
            bad=tables|{at:['missing_label']}
            with self.assertRaises(ValueError):p.check(lines,name,set(result['sensitive_targets']),
                                                     set(result['complete_wipe_targets']),bad)
