"""Saved narrow final-output interfaces, lifetime and noninterference regressions."""
import copy
from unittest.mock import patch
import windows_enclave_sha2_narrow_outputs as b
x=b.exports


class NarrowOutputSavedTests:
    def narrow_output_fixture(self):return self.normal_effect_fixture('simd256')

    def test_actual_narrow_outputs_complete_inventory_and_integration(self):
        import windows_enclave_sha2_batch_chains as main
        row,asm,prior=self.narrow_output_fixture();proof=b.inspect(row[-1],asm,prior)
        self.assertEqual([v['line'] for v in proof['assigned']],
            [636,643,650,654,656,1336,1348,1360,1372,1384,1396,1408,1420,1567,1575,1596,1617,1653])
        self.assertEqual(proof['assigned_narrow_returning_interfaces'],62)
        self.assertEqual(proof['remaining_narrow_calls'],[])
        self.assertEqual(proof['normal_stack_span'],[-72,0]);self.assertEqual(proof['normal_callee_count'],6)
        self.assertEqual(len(proof['shared_runtime_calls']),7)
        for field in ('individual_stack_erasure_qualified','arbitrary_unwind_qualified','whole_frame_qualified',
                      'shared_runtime_implementations_qualified'):self.assertFalse(proof[field])
        with patch.object(b,'inspect',side_effect=ValueError('narrow outputs failed')) as check:
            with self.assertRaisesRegex(ValueError,'narrow outputs failed'):
                main.inspect_route(self.saved,self.root,'simd256',row[1],False)
            check.assert_called_once()

    def test_actual_narrow_outputs_exports_without_region_snapshot(self):
        row,asm,_=self.narrow_output_fixture();bodies=row[-1];proof=x.exports(bodies,asm)
        name=proof['function'];lines=b.s.lines(bodies[name]);count=0
        for call in proof['calls']:
            at=call['line'];i=call['lane'];load=call['length_load']
            first=load+(1 if i<3 else 2);second=first+2
            changes=[]
            for site in (call['destination_loads'][0],call['capacity_loads'][0],load,call['source_origins'][0]):
                bad=lines[:];bad[site]=bad[site].replace('(%rbx)','1(%rbx)');changes.append(bad)
            for site in (first,second):
                bad=lines[:];bad[site]=bad[site].replace('$32','$33').replace('$28','$27');changes.append(bad)
            bad=lines[:];bad[at-1]='movq %rsi, %r8' if i==0 else 'movq %rsi, %r9';changes.append(bad)
            changes.append(lines[:1]+[f'jne .B{222+3*i}']+lines[1:])
            for bad in changes:
                # The independent definition/guard checks must reject this,
                # not only the preexisting whole-region text comparison.
                with patch.object(x.commit,'narrow',return_value=None):
                    with self.assertRaises(ValueError):x.exports(bodies|{name:'\n'.join(bad)},asm)
                count+=1
        self.assertEqual(count,64)

    def test_actual_narrow_outputs_only_original_null_edges_are_excluded(self):
        row,asm,_=self.narrow_output_fixture();bodies=row[-1]
        name,lines,admitted,_,_,excluded=x.prepare(bodies,asm,True)
        self.assertEqual(len(excluded),8)
        self.assertEqual([i for i,(a,c) in enumerate(zip(lines,admitted,strict=True)) if a!=c],excluded)
        for at in excluded:
            bad=lines[:];bad[at-1]=bad[at-1].replace('$0','$1')
            with self.assertRaises(ValueError):x.prepare(bodies|{name:'\n'.join(bad)},asm,True)

    def test_actual_narrow_outputs_owner_loop_and_cursor_mutations(self):
        row,asm,prior=self.narrow_output_fixture();bodies=row[-1];desc=prior['simd_dynamic_clearing_descriptors']
        proof=x.owner_transfer(bodies,asm,desc);name=b.s.one(bodies,r'Resident6digest$');lines=b.s.lines(bodies[name])
        start=b.o.unique(lines,'.B261:');count=0
        for at in range(start,start+25):
            bad=lines[:];bad[at]='nop'
            with self.assertRaises(ValueError):x.owner_transfer(bodies|{name:'\n'.join(bad)},asm,desc)
            count+=1
        seed=proof['cursor_seed']
        for at,replacement in ((seed-1,'leaq 2921(%rbx), %rax'),(seed,'movq %rcx, 176(%rbx)')):
            bad=lines[:];bad[at]=replacement
            with self.assertRaises(ValueError):x.owner_transfer(bodies|{name:'\n'.join(bad)},asm,desc)
            count+=1
        bad=lines[:1]+['jne .B262']+lines[1:]
        with self.assertRaises(ValueError):x.owner_transfer(bodies|{name:'\n'.join(bad)},asm,desc)
        count+=1
        self.assertEqual(count,28)

    def test_actual_narrow_outputs_cleanup_arguments_and_preserved_roots(self):
        row,asm,prior=self.narrow_output_fixture();bodies=row[-1];desc=prior['simd_dynamic_clearing_descriptors']
        calls=b.cleanup(bodies,asm,desc);name,lines,_,_=b.a.prepare(bodies,asm);count=0
        for call in calls:
            at=call['line'];changes=[]
            bad=lines[:];bad[at]='callq unassigned';changes.append(bad)
            if call['role'] in ('identity_clear','scratch_clear','output_drop'):
                for site in range(at-2,at):
                    if lines[site]=='vzeroupper':continue
                    bad=lines[:];bad[site]='nop';changes.append(bad)
            if call['role'] in ('scalar_wipe','cpu_wipe','identity_clear'):
                for site in call['pointer_origins']:
                    bad=lines[:];bad[site]=bad[site].replace('leaq ','leaq 1',1);changes.append(bad)
            for bad in changes:
                with self.assertRaises(ValueError):b.cleanup(bodies|{name:'\n'.join(bad)},asm,desc)
                count+=1
        self.assertEqual(count,41)

    def test_actual_narrow_outputs_transfer_reads_reject_overwritten_descriptors(self):
        row,asm,prior=self.narrow_output_fixture();bodies=row[-1];desc=prior['simd_dynamic_clearing_descriptors']
        proof=b.inspect(bodies,asm,prior);calls=proof['assigned'];name=proof['function'];lines=b.s.lines(bodies[name])
        # Exercise direct-write liveness independently of the frozen instruction
        # patterns, argument tracers and earlier descriptor-read population.
        for role,offset in (('final_copy',864),('owner_transfer',2912)):
            call=next(c for c in calls if c['role']==role)
            for text in (f'movb $0, {offset}(%rbx)',f'movq %rax, {offset-1}(%rbx)',
                         f'vmovups %ymm0, {offset}(%rbx)'):
                bad=lines[:];bad[call['line']-1]=text
                with self.assertRaisesRegex(ValueError,'descriptor read before construction or after overwrite'):
                    b.descriptor_reads(bodies|{name:'\n'.join(bad)},asm,desc,calls)

    def test_actual_narrow_outputs_prerequisites_bounds_and_inventory(self):
        row,asm,prior=self.narrow_output_fixture();count=0
        for key,field in b.PREREQUISITES:
            bad=copy.deepcopy(prior);bad[key][field]=False
            with self.assertRaises(ValueError):b.inspect(row[-1],asm,bad)
            count+=1
        for field,value in (('exact_lane_pointers_and_widths',False),('ordered_disjoint_in_bounds',False),
                            ('maximum_slot_bytes',33),('scratch_bytes',257)):
            bad=copy.deepcopy(prior);bad['simd_dynamic_clearing_descriptors']['geometry'][field]=value
            with self.assertRaises(ValueError):b.inspect(row[-1],asm,bad)
            count+=1
        for change in ('missing','extra','duplicate'):
            bad=copy.deepcopy(prior);previous=bad['simd_narrow_vector_interfaces']
            if change=='missing':previous['remaining_narrow_calls'].pop()
            elif change=='extra':previous['remaining_narrow_calls'].append(previous['assigned'][0])
            else:previous['assigned'].append(previous['assigned'][0])
            with self.assertRaises(ValueError):b.inspect(row[-1],asm,bad)
            count+=1
        self.assertEqual(count,20)

    def test_actual_narrow_outputs_live_storage_effect_overlap_rejections(self):
        row,asm,prior=self.narrow_output_fixture();bodies=row[-1];proof=b.inspect(bodies,asm,prior)
        for region in proof['protected_live_objects']:
            calls=b.cleanup(bodies,asm,prior['simd_dynamic_clearing_descriptors']);low=region['span'][0]
            calls[0]['footprints'].append(['writes','frame',low,low+1])
            with patch.object(b,'cleanup',return_value=calls):
                with self.assertRaisesRegex(ValueError,'normal helper writes exclude'):
                    b.inspect(bodies,asm,prior)
