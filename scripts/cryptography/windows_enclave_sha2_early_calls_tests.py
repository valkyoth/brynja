"""Earlier argument replay, pointer-base origins and conditional effect tests."""
import copy
from unittest.mock import patch
import windows_enclave_sha2_early_calls as p


class EarlyCallTests:
    def test_precise_32_bit_shift_rejects_wrap_pointer_and_wrong_width(self):
        def check(line,value):
            snapshots=[]
            p.e.evaluate([line,'callq copy'],{'rcx':value},{},'copy',snapshots,precise=True)
            return snapshots[0][1]['rcx']
        self.assertEqual(check('shll $6, %ecx',p.v(3)),p.v(192))
        for line,value in (('shll $6, %rcx',p.v(3)),('shll $32, %ecx',p.v(3)),
                           ('shll $6, %ecx',p.v(1<<30)),('shll $6, %ecx',p.v(3,'workspace'))):
            with self.assertRaises(ValueError):check(line,value)

    def test_all_earlier_copy_geometry_has_bounded_disjoint_writes(self):
        counts=[]
        for role in range(3):
            cases=list(p.copy_cases(role));counts.append(len(cases))
            for _,_,args in cases:
                effects=p.transfer.effects('copy',args)
                dst,=effects['writes'];src,=effects['reads']
                self.assertEqual(dst['object'],'workspace')
                self.assertTrue(0<=dst['span'][0]<dst['span'][1]<=1024)
                self.assertLessEqual(src['span'][1],1024)
        self.assertEqual(counts,[24,48,24])


class EarlyCallSavedTests:
    def early_call_fixture(self):
        import windows_enclave_sha2_vector_stack as vector
        row,asm,early,layout=self.early_write_fixture();bodies=row[-1]
        control=self.stack_fixture(row)[-1]
        return row,asm,early,layout,vector.inspect(bodies,asm,'simd512',control)

    def test_actual_early_calls_and_parent_integration(self):
        import windows_enclave_sha2_batch_chains as parent
        row,*args=self.early_call_fixture();lane,pin,_,_,_,_,bodies=row
        result=p.inspect(bodies,*args)
        self.assertEqual(result['public_copy_cases'],96)
        self.assertEqual([v['role'] for v in result['calls']],
                         ['cancel','pack_states','pack_blocks','cancel','session','unpack_states'])
        self.assertTrue(result['session_argument_origins_checked']);self.assertFalse(result['whole_frame_qualified'])
        combined=parent.inspect_route(self.saved,self.root,lane,pin,False)['semantics']
        self.assertFalse(combined['simd_earlier_indirect_stores']['callee_argument_effects_pending'])
        composed=combined['simd_helper_slot_origins']['conditional_memory_composition']
        self.assertFalse(composed['earlier_vector_phase_effects_for_slot984_pending'])
        self.assertTrue(composed['original_lifetimes_indices_authority_and_external_separation_still_required'])
        with patch.object(p,'inspect',side_effect=ValueError('early calls failed')) as check:
            with self.assertRaisesRegex(ValueError,'early calls failed'):
                parent.inspect_route(self.saved,self.root,lane,pin,False)
            check.assert_called_once()

    def test_actual_copy_arguments_reject_mutations_without_snapshot_shortcut(self):
        row,*args=self.early_call_fixture();bodies=row[-1]
        result=p.inspect(bodies,*args);lines=p.s.lines(bodies[p.vector.authority.role(bodies,'executor')])
        jobs=[v for v in result['calls'] if v['role'] in ('pack_states','pack_blocks','unpack_states')]
        count=0
        for ordinal,job in enumerate(jobs):
            prefix=(6,7,7)[ordinal];changes=[]
            for at in range(job['line']-prefix,job['line']):
                line=lines[at]
                if line=='vzeroupper':continue
                changed=lines[:]
                if '$64' in line or '$128' in line:
                    changed[at]=line.replace('$64','$65').replace('$128','$129')
                elif line.startswith('shl'):changed[at]=line.replace('$6','$5').replace('$7','$6')
                elif '984(%rbp)' in line:changed[at]=line.replace('984','1000')
                elif '(%rax)' in line:changed[at]=line.replace('(%rax)','8(%rax)')
                else:changed[at]=line.replace('%rbx','%rbp').replace('%r15','%r14')
                self.assertNotEqual(changed[at],line);changes.append(changed)
            changed=lines[:];changed[job['line']]='callq unassigned';changes.append(changed)
            for changed in changes:
                # No complete-region snapshot validation here: this exercises
                # the actual independent address/capacity interpreter.
                with self.assertRaises(ValueError):p.replay_copy(changed,job,ordinal)
                count+=1
        self.assertEqual(count,20)
        print('Earlier copy argument/address/capacity mutations rejected: '+str(count))

    def test_actual_early_saved_bases_session_and_effect_placement_fail_closed(self):
        row,*args=self.early_call_fixture();bodies=row[-1];name=p.vector.authority.role(bodies,'executor')
        lines=p.s.lines(bodies[name]);count=0
        for before,after in (('leaq 768(%rdi), %rax','leaq 769(%rdi), %rax'),
                             ('leaq 1280(%rdi), %r10','leaq 1281(%rdi), %r10'),
                             ('movq %rax, 1000(%rbp)','movq %rcx, 1000(%rbp)')):
            at=lines.index(before);changed=lines[:];changed[at]=after
            # The full loop snapshot remains independently mandatory; origin
            # tracing also rejects changed bases outside its reviewed region.
            with self.assertRaises(ValueError):p.inspect(bodies|{name:'\n'.join(changed)},*args)
            count+=1
        for slot in (920,960,984,1040,1048,1168,1176):
            layout=copy.deepcopy(args[2]);layout['workspace']['offset']=-1136+slot-768
            with self.assertRaises(ValueError):p.inspect(bodies,args[0],args[1],layout,args[3])
            count+=1
        bad=copy.deepcopy(args[3]);bad['caller_frame_relative_stack_span']=[-416,1000]
        with self.assertRaises(ValueError):p.inspect(bodies,*args[:3],bad)
        count+=1
        self.assertEqual(count,11)
        print('Earlier call base/effect/stack mutations rejected: '+str(count))
