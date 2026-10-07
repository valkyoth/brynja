"""Normal helper/descriptor joins: call identity, temporal reuse and footprints."""
import copy
from unittest.mock import patch
import windows_enclave_sha2_normal_effects as p


class NormalEffectsTests:
    def test_normal_effect_call_offsets_and_single_assignment(self):
        lines=['entry:','callq a','callq b','retq']
        calls=[dict(line=0,target='a')]
        self.assertEqual(p.bind_calls(lines,calls,1),[dict(line=1,target='a')])
        for wrong in (0,2,-2):
            with self.assertRaises(ValueError):p.bind_calls(lines,calls,wrong)
        for bad in (calls+calls,[dict(line=True,target='a')],[dict(line=1,target='changed')]):
            with self.assertRaises(ValueError):p.bind_calls(lines,bad)
        assigned=p.bind_calls(lines,calls,1)
        self.assertEqual(p.inventory(lines,assigned),[dict(line=2,target='b')])
        for bad in (assigned+assigned,[dict(line=1,target='b')],[dict(line=3,target='a')]):
            with self.assertRaises(ValueError):p.inventory(lines,bad)

    def test_normal_effect_all_protected_regions_and_stacks(self):
        layout={'frame':dict(root='resident-frame',offset=0,bounds=[0,1024])}
        protected=[dict(root='resident-frame',span=v) for v in ([64,128],[256,320])]
        p.exclude([('reads',dict(object='frame',span=[64,320])),
                   ('writes',dict(object='frame',span=[128,256]))],protected,layout)
        for span in ([63,65],[127,129],[255,257],[319,321]):
            with self.assertRaises(ValueError):p.exclude([('writes',dict(object='frame',span=span))],protected,layout)
            with self.assertRaises(ValueError):p.stack_exclude(span,protected)
        for span in ([0,0],[1,0],[False,32]):
            with self.assertRaises(ValueError):p.stack_exclude(span,protected)
        for direction in ('write','unassigned'):
            with self.assertRaises(ValueError):p.exclude([(direction,dict(object='frame',span=[0,8]))],protected,layout)
        with self.assertRaises(ValueError):p.exclude([],[],layout)
        for call in ({'reads':[]},{'footprints':[],'writes':[]}):
            with self.assertRaises(ValueError):p.footprints(call)


class NormalEffectsSavedTests:
    def normal_effect_fixture(self,lane):
        import windows_enclave_sha2_batch_chains as parent
        if not hasattr(self.__class__,'_normal_effect_fixtures'):self.__class__._normal_effect_fixtures={}
        cache=self.__class__._normal_effect_fixtures
        if lane not in cache:
            row=next(v for v in self.routes if v[0]==lane)
            asm=parent.load(self.saved,self.root,row[1])[3]
            prior=parent.inspect_route(self.saved,self.root,lane,row[1],False)['semantics']
            cache[lane]=(row,asm,prior)
        return cache[lane]

    def test_actual_normal_helper_join_reports_remaining_calls_and_integration(self):
        import windows_enclave_sha2_batch_chains as parent
        for lane in ('simd256','simd512'):
            row,asm,prior=self.normal_effect_fixture(lane);proof=p.inspect(row[-1],asm,lane,prior)
            self.assertEqual(proof['assigned_returning_calls'],23 if lane=='simd256' else 28)
            self.assertEqual(len(proof['unassigned_calls']),39 if lane=='simd256' else 9)
            self.assertEqual(len(proof['workspace_calls']),6 if lane=='simd256' else 4)
            self.assertTrue(proof['workspace_wipe_original_arguments_and_normal_stacks_checked'])
            self.assertFalse(proof['all_normal_calls_composed']);self.assertFalse(proof['whole_frame_qualified'])
            if lane=='simd512':
                self.assertEqual(len(proof['parent']['assigned']),2)
                self.assertEqual(len(proof['parent']['pending']),25)
            with patch.object(p,'inspect',side_effect=ValueError('normal effects failed')) as check:
                with self.assertRaisesRegex(ValueError,'normal effects failed'):
                    parent.inspect_route(self.saved,self.root,lane,row[1],False)
                check.assert_called_once()

    def test_actual_normal_effects_reject_misdirected_or_overlapping_contracts(self):
        count=0
        for lane in ('simd256','simd512'):
            row,asm,prior=self.normal_effect_fixture(lane)
            for key in ('scalar','transfer','control'):
                for mutation in ('offset','target','duplicate','missing','overlap'):
                    bad=copy.deepcopy(prior);calls=bad['simd_'+key+'_call_effects']['calls']
                    if mutation=='offset':calls[0]['line']+=1
                    elif mutation=='target':calls[0]['target']='unreviewed'
                    elif mutation=='duplicate':calls.append(copy.deepcopy(calls[0]))
                    elif mutation=='missing':calls.pop()
                    else:
                        lo=864 if lane=='simd256' else 816
                        if 'footprints' in calls[0]:calls[0]['footprints'].append(['writes','frame',lo,lo+1])
                        else:calls[0]['writes'].append(dict(object='frame',span=[lo,lo+1]))
                    with self.subTest(lane=lane,key=key,mutation=mutation):
                        with self.assertRaises(ValueError):p.inspect(row[-1],asm,lane,bad)
                    count+=1
        self.assertEqual(count,30)

    def test_actual_normal_wipe_arguments_bypasses_and_pointer_overwrites_reject(self):
        count=0
        for lane,parent in (('simd256',False),('simd512',False),('simd512',True)):
            row,asm,_=self.normal_effect_fixture(lane);bodies=row[-1]
            proof=p.wipe_calls(bodies,asm,lane,parent);name=proof['function'];lines=p.s.lines(bodies[name])
            for call in proof['calls']:
                at=call['line'];first=at-2 if lines[at-1]=='vzeroupper' else at-1
                bad=lines[:];bad[first]='movq %rdx, %rcx'
                with self.assertRaises(ValueError):p.wipe_calls(bodies|{name:'\n'.join(bad)},asm,lane,parent)
                # Jump into the call after skipping its pointer preparation.
                bad=lines[:1]+['jne injected']+lines[1:at]+['injected:']+lines[at:]
                with self.assertRaises(ValueError):p.wipe_calls(bodies|{name:'\n'.join(bad)},asm,lane,parent)
                count+=2
            if lane=='simd512' and not parent:
                for at,write in ((proof['calls'][0]['line']-2,'movb $0, %dil'),
                    (lines.index('movq 1168(%rbp), %rdi'),'movq %rax, 1168(%rbp)')):
                    bad=lines[:at]+[write]+lines[at:]
                    with self.assertRaises(ValueError):p.wipe_calls(bodies|{name:'\n'.join(bad)},asm,lane,parent)
                    count+=1
        self.assertEqual(count,26)

    def test_actual_normal_temporal_reuse_rejects_backedge_after_result_construction(self):
        row,asm,prior=self.normal_effect_fixture('simd256');bodies=row[-1]
        name=prior['simd_first_output_frame_cell']['function'];lines=p.s.lines(bodies[name])
        end=prior['simd_dynamic_clearing_descriptors']['copies'][0]['last_line']
        begin=prior['simd_first_output_frame_cell']['begin']
        # Keep all reviewed call offsets intact, change an instruction following
        # the result copy into a backedge to the old control-counter lifetime.
        bad=lines[:];bad[end+1]='jmp '+begin
        with self.assertRaisesRegex(ValueError,'normal helper writes exclude'):
            p.inspect(bodies|{name:'\n'.join(bad)},asm,'simd256',prior)

    def test_actual_normal_early_effect_and_nested_stack_mutations_reject(self):
        row,asm,prior=self.normal_effect_fixture('simd512');count=0
        for mutation in ('offset','duplicate','missing','child_overlap','parent_overlap'):
            bad=copy.deepcopy(prior);calls=bad['simd_earlier_call_effects']['calls']
            if mutation=='offset':calls[0]['line']+=1
            elif mutation=='duplicate':calls.append(copy.deepcopy(calls[0]))
            elif mutation=='missing':calls.pop()
            else:
                if mutation=='child_overlap':calls[0]['footprints'].append(['writes','frame',816,817])
                else:
                    # Unknown aliases must not be accepted merely because they
                    # are outside the declared child-frame coordinate range.
                    calls[0]['footprints'].append(['writes','frame',1488,1489])
            with self.assertRaises(ValueError):p.inspect(row[-1],asm,'simd512',bad)
            count+=1
        for lane in ('simd256','simd512'):
            row,asm,prior=self.normal_effect_fixture(lane)
            for key in ('simd_tracked_callee_stack','simd_vector_callee_stack'):
                if lane=='simd256' and key=='simd_vector_callee_stack':continue
                bad=copy.deepcopy(prior)
                bad[key]['caller_frame_relative_stack_span']=[0,880 if lane=='simd512' else 992]
                with self.assertRaises(ValueError):p.inspect(row[-1],asm,lane,bad)
                count+=1
        self.assertEqual(count,8)

    def test_actual_normal_missing_lifetime_and_stack_prerequisites_reject(self):
        count=0
        for lane in ('simd256','simd512'):
            row,asm,prior=self.normal_effect_fixture(lane)
            fields=[('simd_dynamic_clearing_descriptors','normal_direct_descriptor_write_lifetimes_checked'),
                ('simd_dynamic_clearing_descriptors','exact_pointer_length_pair_and_all_loop_indices_checked'),
                ('simd_physical_allocation_lifetimes','conditional_physical_separation'),
                ('simd_physical_allocation_lifetimes','constructor_result_and_worker_use_joined'),
                ('simd_metadata_preservation','conditional_input_and_authority_field_preservation_checked'),
                ('simd_tracked_callee_stack','normal_private_stack_effects_exclude_saved_pointer')]
            fields.append(('simd_narrow_pointer_lifetimes','normal_cfg_pointer_definition_lifetimes_checked') if
                          lane=='simd256' else ('simd_helper_slot_origins','direct_cfg_origins_and_preservation_checked'))
            if lane=='simd512':fields += [('simd_wide_descriptor_handoff','conditional_direct_descriptor_handoff_checked'),
                ('simd_earlier_call_effects','conditional_argument_effects_and_reviewed_stacks_disjoint'),
                ('simd_vector_callee_stack','normal_stack_effects_disjoint')]
            for key,field in fields:
                bad=copy.deepcopy(prior);bad[key][field]=False
                with self.assertRaises(ValueError):p.inspect(row[-1],asm,lane,bad)
                count+=1
        self.assertEqual(count,17)
