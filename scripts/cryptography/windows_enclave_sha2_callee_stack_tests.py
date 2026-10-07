"""Normal callee stack bounds, ABI restoration and composition regressions."""
from unittest.mock import patch
import windows_enclave_sha2_callee_stack as c
from windows_enclave_sha2_source_lifetime_tests import SourceLifetimeTests, SourceLifetimeSavedTests
from windows_enclave_sha2_vector_stack_tests import VectorStackTests, VectorStackSavedTests


class CalleeStackTests(SourceLifetimeTests, VectorStackTests):
    def test_stack_bounds_exclude_return_address_saves_and_incoming_home(self):
        prefix=['f:','pushq %rbp','subq $48, %rsp','leaq 48(%rsp), %rbp']
        suffix=['addq $48, %rsp','popq %rbp','retq']
        good=prefix+['movq %rdx, -16(%rbp)','movq -16(%rbp), %rdx']+suffix
        result=c.inspect_body('\n'.join(good),'f',{'f'}, {})
        self.assertEqual(result['local_low'],-56)
        self.assertEqual([v[2:] for v in result['direct_stack_accesses']],[[-24,-16],[-24,-16]])
        for line in ('movq %rdx, (%rbp)','movq %rdx, 8(%rbp)','movq %rdx, 16(%rbp)',
                     'movq %rdx, -49(%rbp)','movq %rsp, %rax','leaq 8(%rsp), %rax',
                     'movl %eax, %esp','movq %rax, (%rsp,%rcx,8)'):
            with self.assertRaises(ValueError):c.inspect_body('\n'.join(prefix+[line]+suffix),'f',{'f'}, {})

    def test_all_returns_tails_and_joins_require_balanced_owned_stack(self):
        good='f:\npushq %rsi\nsubq $32, %rsp\ncallq g\naddq $32, %rsp\npopq %rsi\njmp g'
        result=c.inspect_body(good,'f',{'f','g'}, {})
        self.assertEqual(result['calls'],[[3,'g',-48]])
        self.assertEqual(result['tail_calls'],[[6,'g',0]])
        for bad in (good.replace('popq %rsi','popq %rdi'),good.replace('addq $32','addq $24'),
                    good.replace('subq $32, %rsp','subq $24, %rsp'),
                    'f:\nsubq $32, %rsp\nretq',
                    'f:\njne done\npushq %rsi\ndone:\nretq',
                    'f:\npushq %rsi\njmp f',
                    'f:\nsubq $40, %rsp\ncallq unknown\naddq $40, %rsp\nretq'):
            with self.assertRaises(ValueError):c.inspect_body(bad,'f',{'f','g'}, {})
        for instruction in ('pushw %ax','popw %ax','leaveq','enterq $16, $0','iretq','lretq'):
            with self.assertRaises(ValueError):c.inspect_body('f:\n'+instruction+'\nretq','f',{'f'}, {})

    def test_transitive_stack_includes_call_return_slots_and_rejects_recursion(self):
        f=c.inspect_body('f:\nsubq $40, %rsp\ncallq g\naddq $40, %rsp\nretq','f',{'f','g'}, {})
        g=c.inspect_body('g:\npushq %rsi\npopq %rsi\nretq','g',{'f','g'}, {})
        self.assertEqual(c.depth('f',{'f':f,'g':g}),-56)
        with self.assertRaises(ValueError):c.depth('f',{'f':f,'g':g|{'calls':[[0,'f',-8]]}})
        code='f:\nsubq $40, %rsp\ncallq *8(%rax)\naddq $40, %rsp\nretq'
        with self.assertRaises(ValueError):c.inspect_body(code,'f',{'f','g'}, {})
        self.assertEqual(c.inspect_body(code,'f',{'f','g'},{('f','*8(%rax)'):'g'})['calls'],[[2,'g',-48]])


class CalleeStackSavedTests(SourceLifetimeSavedTests, VectorStackSavedTests):
    def stack_fixture(self,row):
        import windows_enclave_sha2_batch_chains as parent
        lane,_,_,_,_,_,bodies=row;frame,transfer,tables=self.control_fixture(row)
        primitive=parent.call_effects.inspect(bodies,lane,frame)
        control=parent.control_effects.inspect(bodies,lane,frame,transfer,tables)
        return frame,primitive,transfer,control

    def test_complete_tracked_callee_stack_closures_and_parent_integration(self):
        import windows_enclave_sha2_batch_chains as parent
        for row in self.routes:
            lane,pin,_,_,_,_,bodies=row
            if not lane.startswith('simd'):continue
            result=c.inspect(bodies,lane,*self.stack_fixture(row))
            self.assertEqual(result['normal_callee_count'],10 if lane=='simd256' else 11)
            self.assertEqual(result['caller_frame_relative_stack_span'],[-136,0] if lane=='simd256' else [-264,-128])
            self.assertEqual(result['tracked_returning_call_sites'],17 if lane=='simd256' else 18)
            self.assertTrue(result['normal_private_stack_effects_exclude_saved_pointer'])
            self.assertTrue(result['original_pointer_slot_lifetimes_pending'])
            self.assertFalse(result['arbitrary_unwind_qualified']);self.assertFalse(result['whole_frame_qualified'])
            with patch.object(c,'inspect',side_effect=ValueError('callee stack failed')) as check:
                with self.assertRaisesRegex(ValueError,'callee stack failed'):
                    parent.inspect_route(self.saved,self.root,lane,pin,False)
                check.assert_called_once()

    def test_actual_callees_reject_stack_alias_escape_overwrite_and_unbalanced_returns(self):
        count=0
        for row in self.routes:
            lane,_,_,_,_,_,bodies=row
            if not lane.startswith('simd'):continue
            args=self.stack_fixture(row);result=c.inspect(bodies,lane,*args)
            for name,review in result['functions'].items():
                lines=c.s.lines(bodies[name]);entry=lines.index(name+':')+1
                for instruction in ('movq %rax, (%rsp)','movq %rsp, %r11','pushq %rsi'):
                    changed=lines[:entry]+[instruction]+lines[entry:]
                    with self.assertRaises(ValueError):c.inspect(bodies|{name:'\n'.join(changed)},lane,*args)
                    count+=1
                for at,target,offset in review['calls']:
                    changed=lines[:];changed[at]='callq unassigned'
                    with self.assertRaises(ValueError):c.inspect(bodies|{name:'\n'.join(changed)},lane,*args)
                    count+=1
            name=c.s.one(bodies,r'Executor5check$') if lane=='simd512' else c.s.one(bodies,r'engine7padding$')
            with self.assertRaises(ValueError):c.inspect({n:b for n,b in bodies.items() if n!=name},lane,*args)
            count+=1
        self.assertEqual(count,92)
        print('Tracked SIMD callee stack/alias/call mutations rejected: '+str(count))
