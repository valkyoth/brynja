"""Regressions for actual scalar-helper slot origins and conditional effects."""
import copy
from unittest.mock import patch
import windows_enclave_sha2_slot_origins as p


class SlotOriginTests:
    def test_helper_slot_definitions_reject_partial_overwrite_bypass_and_volatile_clobber(self):
        good=['entry:','movq 1168(%rbp), %rdi','leaq 4580(%rdi), %rax','movq %rax, 760(%rbp)',
              'use:','movq 760(%rbp), %rcx','retq']
        def check(lines):
            states=p.definitions(lines,'entry',{},(760,))
            at=lines.index('movq 760(%rbp), %rcx')
            p.require_slot(lines,states,at,760,4580,{760:4580})
        check(good)
        for changed in (good[:3]+['callq helper']+good[3:],
                        good[:1]+['jne use']+good[1:],
                        good[:4]+['movb $0, 767(%rbp)']+good[4:],
                        good[:4]+['movq %rax, 759(%rbp)']+good[4:],
                        good[:3]+['cmovbq %rdx, %rax']+good[3:]):
            with self.assertRaises(ValueError):check(changed)
        check(good[:4]+['callq helper']+good[4:])  # Conditional callee memory contract.
        check(good[:4]+['movb $0, 768(%rbp)']+good[4:])

    def test_helper_slot_loop_backedge_and_register_reload_explanations(self):
        good=['entry:','movq 1168(%rbp), %rdi','leaq 4580(%rdi), %rbx','movq %rbx, 760(%rbp)',
              'again:','movq %rbx, %rcx','callq wipe','movq 760(%rbp), %rbx','jne again','retq']
        states=p.definitions(good,'entry',{},(760,))
        p.require_workspace(good,states,6,'rcx',4580,{760:4580})
        changed=good[:7]+['movq %rax, 760(%rbp)']+good[7:]
        states=p.definitions(changed,'entry',{},(760,))
        with self.assertRaises(ValueError):p.require_workspace(changed,states,6,'rcx',4580,{760:4580})
        with self.assertRaises(ValueError):p.require_workspace(good,p.definitions(good,'entry',{},(760,)),
            6,'rcx',4581,{760:4580})

    def test_helper_slot_unknown_computed_frame_effects_are_not_assumed_disjoint(self):
        lines=['entry:','movq %rax, 760(%rbp)','movb $1, (%rbp,%rcx)','retq']
        states=p.definitions(lines,'entry',{},(760,))
        self.assertEqual(states[3][760],{2})
        with self.assertRaises(ValueError):p.definitions(lines,'entry',{},(760,),{})
        states=p.definitions(lines,'entry',{},(760,),{2:(0,32)})
        self.assertEqual(states[3][760],{1})
        lines[2]='jmpq *%rax'
        with self.assertRaises(ValueError):p.definitions(lines,'entry',{},(760,))

    def test_helper_slot_abi_roots_and_reload_cycles_require_real_entry_provenance(self):
        lines=['entry:','movq %rdx, %r15','movq %r15, 1048(%rbp)','again:',
               'movq 1048(%rbp), %r15','movq %r15, 1048(%rbp)','jne again','retq']
        states=p.definitions(lines,'entry',{},(1048,))
        self.assertEqual(p.require_origin(lines,states,4,1048,'executor',0,{1048:('executor',0)}),
                         [('register','rdx')])
        for value in ('movq %r8, %r15','movl %edx, %r15d','callq overwrite',
                      'movq %r15, %r15'):
            bad=lines[:];bad[1]=value
            with self.assertRaises(ValueError):p.require_origin(bad,p.definitions(bad,'entry',{},(1048,)),
                4,1048,'executor',0,{1048:('executor',0)})
        bad=lines[:1]+['jne again']+lines[1:]
        with self.assertRaises(ValueError):p.require_origin(bad,p.definitions(bad,'entry',{},(1048,)),
            5,1048,'executor',0,{1048:('executor',0)})


class SlotOriginSavedTests:
    def helper_slot_fixture(self):
        import windows_enclave_sha2_batch_chains as parent
        row=next(v for v in self.routes if v[0]=='simd512');lane,pin,_,_,_,_,bodies=row
        asm=parent.load(self.saved,self.root,pin)[3]
        frame,primitive,transfer,control=self.stack_fixture(row)
        placement=parent.effect_placement.inspect(bodies,lane,frame,primitive,transfer,control)
        stack=parent.callee_stack.inspect(bodies,lane,frame,primitive,transfer,control)
        return row,asm,frame,placement,stack

    def test_actual_helper_slots_origins_and_parent_composition(self):
        import windows_enclave_sha2_batch_chains as parent
        row,asm,*args=self.helper_slot_fixture();lane,pin,_,_,_,_,bodies=row
        result=p.inspect(bodies,asm,*args)
        self.assertEqual({v['slot']:len(v['reads']) for v in result['pointer_slots']},
                         {760:1,1016:3,1024:2,968:1,928:2,984:1})
        self.assertEqual(list(result['indexed_frame_writes'].values()),[[553,556],[32,544]])
        self.assertEqual(len(result['owner_wipe_sites']),2)
        self.assertEqual({v['slot']:len(v['reads']) for v in result['original_abi_slots']},{1040:40,1048:12})
        self.assertTrue(result['conditional_memory_composition']['earlier_vector_phase_effects_for_slot984_pending'])
        self.assertFalse(result['whole_frame_qualified'])
        with patch.object(p,'inspect',side_effect=ValueError('slot origins failed')) as check:
            with self.assertRaisesRegex(ValueError,'slot origins failed'):
                parent.inspect_route(self.saved,self.root,lane,pin,False)
            check.assert_called_once()

    def test_actual_helper_slot_seed_lifetime_and_index_bounds_mutants(self):
        row,asm,*args=self.helper_slot_fixture();bodies=row[-1]
        result=p.inspect(bodies,asm,*args);name=args[0]['function'];lines=p.s.lines(bodies[name]);changes=[]
        for slot in result['pointer_slots']:
            init,=slot['reaching_stores'];offset=slot['slot'];value=slot['workspace_offset']
            bad=lines[:];bad[init]='nop';changes.append(bad)
            origin=max(i for i in range(init) if lines[i].startswith(f'leaq {value}(%rdi), '))
            bad=lines[:];bad[origin]=bad[origin].replace(str(value)+'(',str(value+1)+'(');changes.append(bad)
            changes.append(lines[:init+1]+[f'movb $0, {offset+7}(%rbp)']+lines[init+1:])
            for at in slot['reads']:
                changes.append(lines[:at]+[f'movq %rax, {offset}(%rbp)']+lines[at:])
        for original,replacement in (
            ('movl $11, %edx','movl $12, %edx'),('adcq $1, %rcx','adcq $2, %rcx'),
            ('cmovaeq %rdx, %rcx','movq %rdi, %rcx'),('cmpq $64, %rax','cmpq $65, %rax'),
            ('incq %rax','addq $2, %rax'),('movq %rcx, 32(%rbp,%rax,8)','movq %rcx, 800(%rbp,%rax,8)')):
            # Restrict ambiguous INC to the reviewed schedule induction.
            at=(p.unique(lines,'movq %rcx, 32(%rbp,%rax,8)')+1 if original=='incq %rax'
                else p.unique(lines,original))
            bad=lines[:];bad[at]=replacement;changes.append(bad)
        changes.append(lines[:1]+['jne .B118']+lines[1:])
        for original,replacement in (('movq %r8, 1040(%rbp)','movq %r9, 1040(%rbp)'),
                                     ('movq %rdx, %r15','movq %r8, %r15')):
            at=lines.index(original);self.assertLess(at,32)
            bad=lines[:];bad[at]=replacement;changes.append(bad)
        for slot in result['original_abi_slots']:
            for at in slot['reads']:
                changes.append(lines[:at]+[f'movb $0, {slot["slot"]+7}(%rbp)']+lines[at:])
        for changed in changes:
            with self.assertRaises(ValueError):p.inspect(bodies|{name:'\n'.join(changed)},asm,*args)
        self.assertEqual(len(changes),89)
        print('Wide helper-slot origin/overwrite/index mutations rejected: '+str(len(changes)))

    def test_actual_helper_slots_reject_overlapping_or_incomplete_composed_effects(self):
        _,_,_,placement,stack=self.helper_slot_fixture();count=0
        protected=p.compose(placement,stack)['protected_parent_relative_slots']
        for span in protected.values():
            bad=copy.deepcopy(placement);bad['distinct_effects'].append(['writes','resident-frame',*span])
            with self.assertRaises(ValueError):p.compose(bad,stack)
            count+=1
        bad=copy.deepcopy(stack);bad['caller_frame_relative_stack_span']=[760,768]
        with self.assertRaises(ValueError):p.compose(placement,bad)
        for key in ('conditional_returning_calls','conditional_indirect_stores'):
            bad=copy.deepcopy(placement);bad[key]-=1
            with self.assertRaises(ValueError):p.compose(bad,stack)
        self.assertEqual(count,11)
        bad=copy.deepcopy(placement);bad['distinct_effects'].append(['ignored','resident-frame',0,1])
        with self.assertRaises(ValueError):p.compose(bad,stack)
