"""Handler-prefix and invoke-time pointer mutations for descriptor cleanup."""
import copy
from unittest.mock import patch
import windows_enclave_sha2_cleanup_order as p


class CleanupOrderTests:
    def test_cleanup_order_disjointness_checks_every_descriptor_and_flag(self):
        effects=[('resident-frame',700,800),('resident-page',16,17)]
        regions=[[64,128],[256,320],[33,34]]
        p.disjoint(effects,regions)
        for low,high in [(64,65),(127,129),(255,257),(319,321),(33,34)]:
            with self.assertRaises(ValueError):p.disjoint(effects+[('resident-frame',low,high)],regions)
        for bad in ([],[('unassigned',0,1)],[('resident-frame',800,700)]):
            with self.assertRaises(ValueError):p.disjoint(bad,regions)


class CleanupOrderSavedTests:
    def cleanup_order_fixture(self,lane):
        import windows_enclave_sha2_batch_chains as parent
        if not hasattr(self.__class__,'_cleanup_order_fixtures'):self.__class__._cleanup_order_fixtures={}
        fixtures=self.__class__._cleanup_order_fixtures
        if lane not in fixtures:
            row=next(v for v in self.routes if v[0]==lane);bodies=row[-1]
            asm=parent.load(self.saved,self.root,row[1])[3]
            prior=dict(simd_dynamic_clearing_descriptors=parent.dynamic_cleanup.inspect(bodies,asm,lane),
                simd_metadata_preservation=parent.field_integrity.inspect(bodies,row[4],lane),
                simd_physical_allocation_lifetimes=parent.allocation_lifetimes.inspect(bodies,asm,lane))
            if lane=='simd256':prior['simd_narrow_pointer_lifetimes']=parent.narrow_lifetimes.inspect(bodies,asm,row[4])
            else:prior['simd_wide_descriptor_handoff']=parent.wide_result.inspect(bodies,asm,prior['simd_dynamic_clearing_descriptors'])
            fixtures[lane]=(row,asm,prior)
        return fixtures[lane]

    def test_actual_cleanup_order_join_and_parent_integration(self):
        import windows_enclave_sha2_batch_chains as parent
        for lane in ('simd256','simd512'):
            row,asm,prior=self.cleanup_order_fixture(lane);result=p.inspect(row[-1],asm,lane,prior)
            self.assertEqual(result['protected_boundaries'],9 if lane=='simd256' else 12)
            self.assertTrue(result['prior_handler_and_pre_drop_effects_conditionally_disjoint'])
            self.assertTrue(result['normal_helper_effect_composition_pending'])
            self.assertFalse(result['whole_frame_qualified'])
            self.assertEqual(len(result['handler_prefixes']),4 if lane=='simd256' else 3)
            with patch.object(p,'inspect',side_effect=ValueError('cleanup order failed')) as check:
                with self.assertRaisesRegex(ValueError,'cleanup order failed'):
                    parent.inspect_route(self.saved,self.root,lane,row[1],False)
                check.assert_called_once()

    def test_actual_cleanup_order_rejects_extra_prefix_writes_calls_and_frame_changes(self):
        count=0
        for lane in ('simd256','simd512'):
            row,asm,prior=self.cleanup_order_fixture(lane);bodies=row[-1]
            result=p.inspect(bodies,asm,lane,prior)
            for name,record in result['handler_prefixes'].items():
                lines=p.s.lines(bodies[name]);at=record['first']
                base='rbp' if 'Executor13digest_secret' in name else 'rbx'
                offset=816 if base=='rbp' else 864 if lane=='simd256' else 352
                for text in (f'movb $0, {offset}(%{base})','callq unassigned','movq %rcx, %rdx'):
                    bad=lines[:at]+[text]+lines[at:]
                    with self.subTest(handler=name,mutant=text):
                        with self.assertRaises(ValueError):p.inspect(bodies|{name:'\n'.join(bad)},asm,lane,prior)
                    count+=1
                bad=lines[:];bad[22]='leaq 136(%rdx), %rbp'
                with self.assertRaises(ValueError):p.inspect(bodies|{name:'\n'.join(bad)},asm,lane,prior)
                count+=1
        self.assertEqual(count,28);print('Cleanup handler prefix mutations rejected: '+str(count))

    def test_actual_cleanup_order_wide_invoke_saved_pointer_mutants(self):
        row,asm,prior=self.cleanup_order_fixture('simd512');bodies=row[-1]
        name=p.s.one(bodies,r'Executor13digest_secret$');lines=p.s.lines(bodies[name]);changes=[]
        for at,text in [(27,'movq %rcx, %r15'),(52,'movq 8(%r15), %rax'),
            (60,'movq %r15, 1024(%rbp)'),(56,'movq %rcx, 1048(%rbp)'),
            (477,'movq %rax, 1048(%rbp)')]:
            bad=lines[:];bad[at]=text;changes.append(bad)
        for at,text in [(62,'movb $0, 1031(%rbp)'),(62,'movq %rax, 1168(%rbp)'),
            (1452,'movq %rax, 1047(%rbp)'),(62,'movq %rax, 1048(%rbp)')]:
            changes.append(lines[:at]+[text]+lines[at:])
        for bad in changes:
            with self.subTest(change=next((i,b) for i,(a,b) in enumerate(zip(lines,bad)) if a!=b)):
                with self.assertRaises(ValueError):p.inspect(bodies|{name:'\n'.join(bad)},asm,'simd512',prior)
        self.assertEqual(len(changes),9)

    def test_actual_cleanup_order_missing_or_weakened_prerequisites_reject(self):
        count=0
        for lane in ('simd256','simd512'):
            row,asm,prior=self.cleanup_order_fixture(lane)
            for key,field in [('simd_dynamic_clearing_descriptors','normal_direct_descriptor_write_lifetimes_checked'),
                ('simd_dynamic_clearing_descriptors','exact_pointer_length_pair_and_all_loop_indices_checked'),
                ('simd_physical_allocation_lifetimes','conditional_physical_separation'),
                ('simd_physical_allocation_lifetimes','constructor_result_and_worker_use_joined'),
                ('simd_metadata_preservation','conditional_input_and_authority_field_preservation_checked')]:
                bad=copy.deepcopy(prior);bad[key][field]=False
                with self.assertRaises(ValueError):p.inspect(row[-1],asm,lane,bad)
                count+=1
            bad=copy.deepcopy(prior);bad['simd_dynamic_clearing_descriptors']['unwind_requirements']['handlers']={}
            with self.assertRaises(ValueError):p.inspect(row[-1],asm,lane,bad)
            count+=1
        self.assertEqual(count,12)
