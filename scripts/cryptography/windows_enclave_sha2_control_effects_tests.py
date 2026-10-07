"""Control-call effects and honest fail-stop/precondition regression checks."""
import copy
import re
from unittest.mock import patch
import windows_enclave_sha2_control_effects as t
from windows_enclave_sha2_effect_placement_tests import EffectPlacementTests, EffectPlacementSavedTests


class ControlEffectTests(EffectPlacementTests):
    def test_callback_leaf_cannot_hide_memory_stack_or_extra_instructions(self):
        code=['xorl %eax, %eax','retq']
        t.leaf({'leaf':'leaf:\n'+ '\n'.join(code)},'leaf',code)
        for addition in ('movq (%rcx), %rax','movq %rax, (%rcx)','pushq %rbx',
                         'callq helper','subq $32, %rsp','nop'):
            with self.assertRaises(ValueError):t.leaf({'leaf':addition+'\n'+'\n'.join(code)},'leaf',code)

    def test_padding_effects_include_all_scalar_cleanup_and_accounting(self):
        for lane in ('simd256','simd512'):
            regs,_,expected=t.seed(lane,'padding',0)
            result=t.footprint('padding',expected,lane)
            self.assertEqual(len(result['writes']),5)
            self.assertEqual(result['writes'][2]['span'][1]-result['writes'][2]['span'][0],640)
            self.assertEqual(result['writes'][0]['span'][1]-result['writes'][0]['span'][0],128)
            for reg in ('rcx','rdx','r8'):
                for bad in (None,t.val((1<<64)-1,'bad')):
                    with self.assertRaises(ValueError):t.footprint('padding',expected|{reg:bad},lane)


class ControlEffectSavedTests(EffectPlacementSavedTests):
    def control_fixture(self,row):
        import windows_enclave_sha2_batch_chains as parent
        lane,pin,data,image,_,functions,bodies=row
        records=parent.bind_all(data,image,functions)
        runtime={'memcpy','memset','memcmp','__chkstk','PublicProbeAbort'} | {
            parent.PREFIX[lane]+v for v in ('Input','Output','Source','Observe')}
        tables=parent.data_bindings(data,image,records,functions,runtime,lane)[3]
        frame=parent.frame_cell.inspect(bodies,lane)
        prior=parent.transfer_effects.inspect(bodies,lane,frame,parent.call_effects.inspect(bodies,lane,frame))
        return frame,prior,tables

    def test_remaining_calls_reject_argument_target_and_population_mutations(self):
        total=0
        for row in self.routes:
            lane,_,_,_,_,_,bodies=row
            if not lane.startswith('simd'):continue
            frame,prior,tables=self.control_fixture(row)
            result=t.inspect(bodies,lane,frame,prior,tables)
            self.assertEqual(result['conditional_control_call_count'],5)
            self.assertEqual(result['unassigned_call_effects'],[])
            self.assertEqual(len(result['failstop_paths']),int(lane=='simd256'))
            self.assertFalse(result['whole_frame_qualified'])
            self.assertTrue(result['original_live_slot_and_physical_alias_preconditions_required'])
            full=t.s.lines(bodies[frame['function']]);a=full.index(frame['begin']+':');b=full.index(frame['end']+':')
            lines=full[a:b]
            for job in result['calls']:
                changes={(job['line'],'callq unreviewed')}
                for i in range(job['begin'],job['line']):
                    line=lines[i];m=re.search(r'(\d+)\(',line)
                    if m:changes.add((i,line[:m.start(1)]+str(int(m[1])+1)+line[m.end(1):]))
                    if line.startswith(('movq ','leaq ')) and line.endswith(('%rax','%rcx','%rdx','%r8')):
                        changes.add((i,'movq %r11, '+line.rsplit(', ',1)[1]))
                for at,line in changes:
                    changed=lines[:];changed[at]=line
                    with self.assertRaises(ValueError):t.replay(changed,lane,job)
                    total+=1
                at=a+job['line']
                for changed in (full[:at]+full[at+1:],full[:at]+[full[at]]+full[at:]):
                    with self.assertRaises(ValueError):
                        t.inspect(bodies|{frame['function']:'\n'.join(changed)},lane,frame,prior,tables)
                    total+=1
            for bad in ({},copy.deepcopy(tables)):
                if bad:next(iter(bad.values()))['slots']['32']='unreviewed_callback'
                with self.assertRaises(ValueError):t.inspect(bodies,lane,frame,prior,bad)
                total+=1
            for name in result['leaf_targets'].values():
                with self.assertRaises(ValueError):
                    t.inspect(bodies|{name:bodies[name].replace('retq','movq %rax, (%rcx)\nretq')},lane,frame,prior,tables)
                total+=1
            bad=copy.deepcopy(prior);bad['remaining_call_effects'].append(dict(line=999,target='unassigned'))
            with self.assertRaises(ValueError):t.inspect(bodies,lane,frame,bad,tables)
            total+=1
        self.assertEqual(total,80)
        print('SIMD control-call argument/target/population mutations rejected: '+str(total))

    def test_failstop_keeps_both_guards_and_unfinished_lifetimes_explicit(self):
        row=next(r for r in self.routes if r[0]=='simd256');bodies=row[-1]
        frame,prior,tables=self.control_fixture(row)
        result=t.inspect(bodies,'simd256',frame,prior,tables)
        path=result['failstop_paths'][0]
        self.assertTrue(path['input_field_lifetime_pending'])
        self.assertNotIn('writes',path)
        name=frame['function'];full=t.s.lines(bodies[name]);start=full.index(frame['begin']+':');end=full.index(frame['end']+':')
        for old,new in (('cmpq $-1, %rax','cmpq $0, %rax'),('cmpb $7, %dil','cmpb $8, %dil'),
                        ('ja .B190','jmp .B190'),('ud2','retq')):
            changed=[v.replace(old,new) for v in full];self.assertNotEqual(changed,full)
            with self.assertRaises(ValueError):t.failstop(bodies|{name:'\n'.join(changed)},'simd256',changed[start:end])
        changed=full[:start]+['jmp .B190']+full[start:]
        with self.assertRaises(ValueError):t.failstop(bodies|{name:'\n'.join(changed)},'simd256',full[start:end])

    def test_control_composition_cannot_be_skipped_by_parent(self):
        import windows_enclave_sha2_batch_chains as parent
        for lane,pin,_,_,_,_,_ in self.routes:
            if not lane.startswith('simd'):continue
            with patch.object(t,'inspect',side_effect=ValueError('control composition failed')) as check:
                with self.assertRaisesRegex(ValueError,'control composition failed'):
                    parent.inspect_route(self.saved,self.root,lane,pin,False)
                check.assert_called_once()
