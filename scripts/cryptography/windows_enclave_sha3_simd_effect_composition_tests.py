"""Closed call population, write envelopes and remaining-scope regressions."""
import copy
from unittest.mock import patch
import windows_enclave_sha3_simd_effect_composition as t


class SimdEffectCompositionSavedTests:
    def simd_effect_composition_fixture(self):
        import windows_enclave_sha3_batch_chains as c
        r=c.inspect_route(self.saved,self.root,'simd',self.spec['simd']);b=self.routes['simd'][-1]
        fields={'frame':'frame_alias_effects','clear':'clear_call_effects','copy':'copy_call_effects',
            'scalar':'scalar_call_effects','squeeze':'squeeze_call_effects',
            'absorb':'internal_absorption_call_effects','source':'source_call_effects',
            'transfer':'transfer_call_effects','services':'service_call_effects'}
        return b,{k:r['simd_'+v] for k,v in fields.items()},r['simd_physical_allocation_lifetimes']

    def test_simd_effect_composition_missing_duplicate_or_new_call_rejected(self):
        b,stages,_=self.simd_effect_composition_fixture();n=t.o.reconcile.terminal.shape.names(b)
        code=t.life.code(b[n['executor']]);assigned,_=t.calls(code,stages)
        self.assertEqual(len(assigned),57)
        for name,stage in stages.items():
            key='runtime_frame_call_sites' if name=='frame' else 'service_effects' if name=='services' else 'call_sites'
            with patch.dict(stage,{key:stage[key][1:]}):
                with self.assertRaises(ValueError):t.calls(code,stages)
            with patch.dict(stage,{key:stage[key]+stage[key][:1]}):
                with self.assertRaises(ValueError):t.calls(code,stages)
        bad=code.copy();bad[0]='callq new_unknown_callee'
        with self.assertRaises(ValueError):t.calls(bad,stages)

    def test_simd_effect_composition_every_protected_cell_rejects_aliases(self):
        b,stages,allocations=self.simd_effect_composition_fixture();r=t.inspect(b,stages,allocations)
        physical=allocations['physical_allocations'];parent=physical['parent_rbp'];count=0
        for a,z in r['separation']['protected_physical_ranges']:
            for start,end in ((a,a+1),(z-1,z),(a-1,a+1),(z-1,z+1)):
                bad=[dict(site=1129,space='parent',write=[start-parent,end-parent])]
                with self.assertRaises(ValueError):t.separation(bad,physical)
                count+=1
        for a,z in ((8,9),(15,17),(17,18),(0,24)):
            with self.assertRaises(ValueError):t.separation([dict(site=1129,space='authority',write=[a,z])],physical)
        self.assertEqual(count,144)

    def test_simd_effect_composition_mutated_replayed_footprints_rejected(self):
        b,stages,allocations=self.simd_effect_composition_fixture()
        for key,field,target in (('clear','parent_relative_effects','span'),
            ('copy','parent_relative_effects','write'),('scalar','kernel_parent_relative_effects','span'),
            ('squeeze','physical_copy_envelopes','destination_envelope')):
            rows=copy.deepcopy(stages[key][field]);rows[0][target]=[8144,8145]
            with patch.dict(stages[key],{field:rows}):
                with self.assertRaises(ValueError):t.inspect(b,stages,allocations)
        bad=copy.deepcopy(stages['transfer']['physical_envelopes']);bad['metadata_parent_ranges'][0]=[-608,-600]
        with patch.dict(stages['transfer'],{'physical_envelopes':bad}):
            with self.assertRaises(ValueError):t.inspect(b,stages,allocations)
        bad=copy.deepcopy(stages['services']['service_effects'])
        next(v for v in bad if v['site']==1129)['write_roots']['authority']=[[8,16]]
        with patch.dict(stages['services'],{'service_effects':bad}):
            with self.assertRaises(ValueError):t.inspect(b,stages,allocations)

    def test_simd_effect_composition_prerequisites_integration_and_no_promotion(self):
        b,stages,allocations=self.simd_effect_composition_fixture();r=t.inspect(b,stages,allocations)
        self.assertTrue(r['all_57_executor_call_footprints_composed'])
        self.assertFalse(r['final_three_route_private_frame_composition_complete'])
        self.assertFalse(r['complete_private_frame_erasure_qualified'])
        for obj,key in ((allocations,'original_payload_and_authority_allocations_joined'),
            (allocations,'conditional_page_payload_frame_nonoverlap_checked'),
            (stages['services'],'all_executor_call_site_footprints_assigned'),
            (stages['absorb'],'all_four_destinations_within_original_lane_rate'),
            (stages['source'],'source_length_pairing_and_two_unsigned_read_guards_checked')):
            with patch.dict(obj,{key:False}):
                with self.assertRaises(ValueError):t.inspect(b,stages,allocations)
        import windows_enclave_sha3_batch_chains as c
        with patch.object(t,'inspect',side_effect=ValueError('composition failed')):
            with self.assertRaisesRegex(ValueError,'composition failed'):c.inspect_route(self.saved,self.root,'simd',self.spec['simd'])
