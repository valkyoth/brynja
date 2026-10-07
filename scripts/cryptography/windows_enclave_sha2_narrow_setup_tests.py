"""Narrow SDK setup argument and temporal non-reentry regressions."""
import copy
from unittest.mock import patch
import windows_enclave_sha2_narrow_setup as b


class NarrowSetupSavedTests:
    def narrow_setup_fixture(self):return self.normal_effect_fixture('simd256')

    def test_actual_narrow_setup_complete_population_and_integration(self):
        import windows_enclave_sha2_batch_chains as main
        row,asm,prior=self.narrow_setup_fixture();proof=b.inspect(row[-1],asm,prior)
        self.assertEqual([v['line'] for v in proof['assigned']],[190,194,229,252,257,275])
        self.assertEqual(proof['assigned_narrow_returning_interfaces'],38)
        self.assertEqual(len(proof['remaining_narrow_calls']),24)
        self.assertEqual(len(proof['shared_runtime_calls']),7)
        self.assertTrue(proof['SDK_memory_semantics_and_stack_contracts_still_required'])
        self.assertFalse(proof['memset_is_volatile_erasure']);self.assertFalse(proof['whole_frame_qualified'])
        with patch.object(b,'inspect',side_effect=ValueError('narrow setup failed')) as check:
            with self.assertRaisesRegex(ValueError,'narrow setup failed'):
                main.inspect_route(self.saved,self.root,'simd256',row[1],False)
            check.assert_called_once()

    def test_actual_narrow_setup_pointer_count_and_bypass_changes(self):
        row,asm,prior=self.narrow_setup_fixture();bodies=row[-1];proof=b.inspect(bodies,asm,prior)
        name,lines,states,_=b.a.prepare(bodies,asm);count=0
        for call in proof['assigned']:
            at=call['line'];size=next(iter(states[at]['r8']));changes=[]
            for roots in call['pointer_origins'].values():
                self.assertEqual(len(roots),1);site=roots[0]
                bad=lines[:];bad[site]=bad[site].replace('leaq ','leaq 1',1);changes.append(bad)
            bad=lines[:];bad[size]=f'movl ${call["bytes"]+1}, %r8d';changes.append(bad)
            changes.append(lines[:1]+['jne setup_bypass']+lines[1:at]+['setup_bypass:']+lines[at:])
            if call['target']=='memset':
                site=next(iter(states[at]['rdx']));bad=lines[:];bad[site]='movl $1, %edx';changes.append(bad)
            for bad in changes:
                with self.assertRaises(ValueError):b.inspect(bodies|{name:'\n'.join(bad)},asm,prior)
                count+=1
        self.assertEqual(count,24)

    def test_actual_narrow_setup_late_reentry_keeps_lifetime_check_load_bearing(self):
        row,asm,prior=self.narrow_setup_fixture();bodies=row[-1];proof=b.inspect(bodies,asm,prior)
        name,lines,_,_=b.a.prepare(bodies,asm)
        for call in proof['assigned']:
            # Keep the last call's pinned staging prefix intact. Refresh coordinates so a
            # stale-number comparison cannot masquerade as the real CFG check.
            entry=call['line']-5 if call['line']==275 else call['line']
            bad=lines[:];bad.insert(entry,'setup_replay:')
            end=b.o.unique(bad,'movq $0, 992(%rbx)');bad.insert(end+1,'jne setup_replay')
            changed=bodies|{name:'\n'.join(bad)};edges=b.p.result.d.graph(bad,asm)
            first,last,_=b.p.result.d.constructor(changed,name,'simd256',edges)
            altered=copy.deepcopy(prior);altered['simd_dynamic_clearing_descriptors']['construction']=[first,last]
            with self.assertRaisesRegex(ValueError,'no normal path from output construction'):
                b.inspect(changed,asm,altered)

    def test_actual_narrow_setup_prerequisites_and_missing_assignment(self):
        row,asm,prior=self.narrow_setup_fixture();count=0
        for key,field in (*b.a.PREREQUISITES,
            ('simd_narrow_admission_interfaces','original_admission_authority_and_tail_arguments_joined')):
            bad=copy.deepcopy(prior);bad[key][field]=False
            with self.assertRaises(ValueError):b.inspect(row[-1],asm,bad)
            count+=1
        bad=copy.deepcopy(prior);bad['simd_narrow_admission_interfaces']['remaining_narrow_calls']=[]
        with self.assertRaises(ValueError):b.inspect(row[-1],asm,bad)
        self.assertEqual(count+1,8)
