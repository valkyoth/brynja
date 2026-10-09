"""Direct AVX2 constructor ABI, byte provenance and failure-join regressions."""
import copy
from unittest.mock import patch
import windows_enclave_sha3_batch_chains as c

t=c.avx2_start


class Avx2StartModelTests:
    def test_avx2_start_physical_transfers_and_deletions(self):
        count=0
        for identity in range(6):
            result=t.replay(identity);steps=t.schedule()
            self.assertEqual(result['authority_retained_span'],[1792,1800])
            self.assertTrue(result['output_plan_and_outer_authority_preserved'])
            self.assertFalse(result['padding_and_inactive_initialization_qualified'])
            self.assertFalse(result['temporary_copy_erasure_qualified'])
            for at in range(len(steps)):
                with self.assertRaises(ValueError):t.replay(identity,steps[:at]+steps[at+1:])
                count+=1
        self.assertEqual(count,102)
        print('Direct AVX2 transfer deletions rejected:',count)
        for identity in (-1,6,7,8,True):
            with self.assertRaises(ValueError):t.replay(identity)

    def test_avx2_start_origins_bounds_and_order(self):
        steps=t.schedule();count=0
        for identity in range(6):
            for at,step in enumerate(steps):
                if step[0]!='copy':continue
                for index in (2,4,5):
                    bad=list(step);bad[index]+=(-1 if index==5 else 1)
                    with self.assertRaises(ValueError):t.replay(identity,steps[:at]+[tuple(bad)]+steps[at+1:])
                    count+=1
            for extra in (('publish',),('destroy',),('accept',),
                ('copy','frame',1696,'frame',1697,992),
                ('copy','frame',1696,'frame',31,1),
                ('copy','frame',4888,'saved',0,1),
                ('copy','frame',1696,'saved',16,1),
                ('copy','frame',1696,'owner',1215,1),
                ('copy','frame',1696,'owner',2208,1),
                ('copy','frame',1696,'frame',2272,8)):
                with self.assertRaises(ValueError):t.replay(identity,steps[:10]+[extra]+steps[10:])
                count+=1
            with self.assertRaises(ValueError):t.replay(identity,steps+[('destroy',)])
            count+=1
        self.assertEqual(count,300)
        print('Direct AVX2 origin/bounds/order mutants rejected:',count)


class Avx2StartTests:
    def test_avx2_start_all_new_instruction_positions(self):
        _,_,asm,_,_,bodies=self.routes['avx2'];name,positions,total=t.check_shapes(bodies,asm)
        self.assertEqual(len(positions),31);self.assertEqual(len(total),228)
        lines=c.lifecycle.code(bodies[name]);count=0
        for at in positions:
            for bad in (lines[:at]+lines[at+1:],lines[:at]+['ud2']+lines[at+1:]):
                with self.assertRaises(ValueError):t.check_shapes(bodies|{name:name+':\n'+'\n'.join(bad)},asm)
                count+=1
        self.assertEqual(count,62)
        print('Direct AVX2 instruction mutants rejected:',count)

    def test_avx2_start_external_entries_and_wrong_authority(self):
        _,_,asm,_,_,bodies=self.routes['avx2'];name,_,_=t.check_shapes(bodies,asm)
        body='\n'.join(c.lifecycle.code(bodies[name]));count=0
        for old,new in (
            ('movq 2224(%rsi), %rdx','leaq 2224(%rsi), %rdx'),
            ('movl %eax, %r8d','movl $6, %r8d'),
            ('cmpq $2, %r14','cmpq $1, %r14'),
            ('leaq 1696(%rsp), %rcx','leaq 1697(%rsp), %rcx'),
            ('leaq 1697(%rsp), %rdx','leaq 1698(%rsp), %rdx'),
            ('movq 2680(%rsp), %rax','movq 2688(%rsp), %rax'),
            ('jmp .B58','jmp .B56'),
            ('jmp .B23','jmp .B58'),
        ):
            self.assertIn(old,body)
            with self.assertRaises(ValueError):t.check_shapes(bodies|{name:name+':\n'+body.replace(old,new)},asm)
            count+=1
        self.assertEqual(count,8)

    def test_avx2_start_helper_authority_offsets_and_abi(self):
        _,_,_,ir,_,bodies=self.routes['avx2'];helper=c.initial.NAME
        result=t.helper_contract(bodies,ir);self.assertEqual(result['authority_result_span'],[576,584])
        body='\n'.join(c.lifecycle.code(bodies[helper]));count=0
        for old,new in (
            ('movq %rdx, 896(%rsp)','movq %rcx, 896(%rsp)'),
            ('movq 896(%rsp), %r12','movq 904(%rsp), %r12'),
            ('movq %r12, 1504(%rsp)','movq %r12, 1512(%rsp)'),
            ('leaq 929(%rsp), %rsi','leaq 928(%rsp), %rsi'),
            ('movl $607, %r8d','movl $606, %r8d'),
            ('movq $2, 944(%rcx)','movq $1, 944(%rcx)'),
        ):
            self.assertIn(old,body)
            with self.assertRaises(ValueError):t.helper_contract(bodies|{helper:helper+':\n'+body.replace(old,new)},ir)
            count+=1
        declaration=next(l for l in ir.splitlines() if l.startswith('define ') and '@'+helper+'(' in l)
        for token,new in (('noalias ',''),('align 32','align 16'),('captures(none)','captures(address)'),
            ('dereferenceable(992)','dereferenceable(991)'),('align 8','align 1'),
            ('range(i8 0, 8)','range(i8 0, 9)')):
            self.assertIn(token,declaration)
            with self.assertRaises(ValueError):t.helper_contract(bodies,ir.replace(declaration,declaration.replace(token,new)))
            count+=1
        self.assertEqual(count,12)

    def test_avx2_start_prerequisites_and_integrated_failure(self):
        bodies,asm,ir,lane,prior,placement,transitions,receiver=self.update_fixture('avx2')
        construction=c.start.inspect(bodies,asm,ir,lane,placement,transitions,receiver)
        args=(bodies,asm,ir,prior,construction,placement);result=t.inspect(*args)
        self.assertTrue(result['direct_constructor_caller_transfers_qualified'])
        self.assertFalse(result['cshake_constructor_lifetimes_qualified'])
        self.assertFalse(result['private_frame_erasure_qualified'])
        paths=[(3,('prior_semantics_replayed',))]+[(3,('initial_constructor_rebinding',key)) for key in
            ('function','exact_code_extent_and_abi','constructor_semantics_reused')]
        paths += [(4,(key,)) for key in ('function','successful_placement_destroys_previous_typed_state_first',
            'successful_slot_and_phase_commit_after_state_copy','non_cshake_requires_zero_name_and_customization_lengths')]
        paths += [(5,('state_destructor',key)) for key in ('function','typed_payload_cleanup_composed')]
        for index,path in paths:
            bad=list(args);bad[index]=copy.deepcopy(bad[index]);node=bad[index]
            for key in path[:-1]:node=node[key]
            node[path[-1]]=False
            with self.assertRaises(ValueError):t.inspect(*bad)
        self.assertEqual(len(paths),10)
        with patch.object(c.avx2_start,'inspect',side_effect=ValueError('direct constructor failed')) as check:
            with self.assertRaisesRegex(ValueError,'direct constructor failed'):
                c.inspect_route(self.saved,self.root,'avx2',self.spec['avx2'])
            check.assert_called_once()
