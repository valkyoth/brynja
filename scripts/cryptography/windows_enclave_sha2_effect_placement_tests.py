"""Frame-geometry and exhaustive effect-assignment regressions."""
import copy
from unittest.mock import patch
import windows_enclave_sha2_effect_placement as p


class EffectPlacementTests:
    def test_placement_rejects_unassigned_and_out_of_object_ranges(self):
        layout={'child':dict(root='parent',offset=-1136,bounds=[-128,1064])}
        self.assertEqual(p.place(dict(object='child',span=[976,984]),layout),
                         dict(root='parent',span=[-160,-152]))
        for obj,span in (('unknown',[0,8]),('child',[-129,0]),('child',[1060,1065]),
                         ('child',[8,0]),('child',[0,True])):
            with self.assertRaises(ValueError):p.place(dict(object=obj,span=span),layout)


class EffectPlacementSavedTests:
    def placement_fixture(self,row):
        import windows_enclave_sha2_batch_chains as parent
        lane,_,_,_,_,_,bodies=row;frame,transfer,tables=self.control_fixture(row)
        primitive=parent.call_effects.inspect(bodies,lane,frame)
        control=parent.control_effects.inspect(bodies,lane,frame,transfer,tables)
        return frame,primitive,transfer,control

    def test_all_returning_calls_and_stores_have_nonoverlapping_conditional_placements(self):
        totals=[0,0,0]
        for row in self.routes:
            lane,pin,_,_,_,_,bodies=row
            if not lane.startswith('simd'):continue
            args=self.placement_fixture(row);result=p.inspect(bodies,lane,*args)
            totals=[a+b for a,b in zip(totals,[result['conditional_returning_calls'],
                result['conditional_indirect_stores'],result['terminal_paths']],strict=True)]
            self.assertTrue(result['caller_and_child_frame_relative_nonoverlap_checked'])
            self.assertTrue(result['original_pointer_slot_lifetimes_and_terminal_preconditions_pending'])
            self.assertTrue(result['external_allocations_disjoint_from_stack_required'])
            self.assertFalse(result['whole_frame_qualified'])
            self.assertEqual(result['saved_cell']['span'],[184,192] if lane=='simd256' else [-160,-152])
            import windows_enclave_sha2_batch_chains as parent
            with patch.object(p,'inspect',side_effect=ValueError('placement failed')) as check:
                with self.assertRaisesRegex(ValueError,'placement failed'):
                    parent.inspect_route(self.saved,self.root,lane,pin,False)
                check.assert_called_once()
        self.assertEqual(totals,[35,7,1])

    def test_effect_assignment_rejects_missing_duplicate_unknown_and_overlapping_writes(self):
        rejected=0
        for row in self.routes:
            lane,_,_,_,_,_,bodies=row
            if not lane.startswith('simd'):continue
            original=self.placement_fixture(row)
            for at in (1,2,3):
                for duplicate in (False,True):
                    args=copy.deepcopy(original);calls=args[at]['calls']
                    calls.append(copy.deepcopy(calls[0])) if duplicate else calls.pop()
                    with self.assertRaises(ValueError):p.inspect(bodies,lane,*args)
                    rejected+=1
            for obj,span in (('unassigned',[0,1]),('frame',original[0]['cell']),
                             ('frame',[-129,-128]),('frame',[20000,20001])):
                args=copy.deepcopy(original)
                args[1]['calls'][0]['writes'].append(dict(object=obj,span=span))
                with self.assertRaises(ValueError):p.inspect(bodies,lane,*args)
                rejected+=1
            args=copy.deepcopy(original);args[0]['conditional_indirect_store_effects']['stores'].pop()
            with self.assertRaises(ValueError):p.inspect(bodies,lane,*args)
            rejected+=1
        self.assertEqual(rejected,22)
        print('SIMD cross-check/effect-placement mutations rejected: '+str(rejected))

    def test_child_frame_and_callsite_layout_mutations_reject(self):
        row=next(row for row in self.routes if row[0]=='simd512');bodies=row[-1]
        name=p.authority.role(bodies,'executor');body='\n'.join(p.s.lines(bodies[name]))
        for old,new in (('pushq %rbx','pushq %rax'),('subq $1192, %rsp','subq $1184, %rsp'),
                        ('leaq 128(%rsp), %rbp','leaq 120(%rsp), %rbp')):
            self.assertIn(old,body)
            with self.assertRaises(ValueError):p.child_frame(body.replace(old,new))
        name=p.authority.role(bodies,'resident');body='\n'.join(p.s.lines(bodies[name]))
        for old,new in (('leaq 7200(%rbx), %rdi','leaq 7199(%rbx), %rdi'),
                        ('movq %rax, 40(%rsp)','movq %rax, 32(%rsp)'),
                        ('leaq 120(%rbx), %rdx','leaq 144(%rbx), %rdx'),
                        ('andq $-32, %rsp','andq $-16, %rsp')):
            self.assertIn(old,body)
            with self.assertRaises(ValueError):p.placements(bodies|{name:body.replace(old,new)},'simd512')
