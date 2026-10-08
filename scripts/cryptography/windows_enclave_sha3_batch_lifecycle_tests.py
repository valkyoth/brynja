"""Saved emitted lifecycle mutants; mixed into the batch chain test runner."""
from unittest.mock import patch
import copy

import windows_enclave_sha3_batch_chains as c


class LifecycleTests:
    def copy_fixture(self):
        _,_,_,ir,functions,bodies=self.routes['avx2']
        prior=c.reused_helpers(self.saved,self.root,'avx2',functions,ir,self.spec['avx2'])
        return bodies,ir,prior['changed_abi_requiring_explicit_review']

    def test_copy_complete_loop_and_wrapper_reject_instruction_changes(self):
        bodies,ir,changed=self.copy_fixture();count=0
        result=c.copies.inspect(bodies,ir,changed)
        self.assertFalse(result['caller_allocation_lifetime_and_nonoverlap_qualified'])
        self.assertFalse(result['destination_eventual_erasure_qualified'])
        for name in result['functions']:
            lines=c.copies.code(bodies[name])
            for at in range(len(lines)):
                for mutant in (lines[:at]+lines[at+1:],lines[:at]+['nop']+lines[at+1:]):
                    with self.assertRaises(ValueError):
                        c.copies.inspect(bodies|{name:name+':\n'+'\n'.join(mutant)},ir,changed)
                    count+=1
        self.assertEqual(count,78)
        print('Broadened SHA-3 copy loop/wrapper instruction mutations rejected:',count)

    def test_copy_broadened_abi_is_not_blanket_helper_reuse(self):
        bodies,ir,changed=self.copy_fixture();count=0
        for name in (c.copies.LEAF,c.copies.WRAPPER):
            declaration=next(l for l in ir.splitlines() if l.startswith('define ') and '@'+name+'(' in l)
            changes=[(c.copies.NEW,'range(i64 0, -1)'),('nonnull ',' '),('noundef ',' ')]
            if name==c.copies.WRAPPER:changes += [('noalias ',' '),('readonly ',' '),('nofree ',' ')]
            for old,new in changes:
                bad=ir.replace(declaration,declaration.replace(old,new));record=copy.deepcopy(changed)
                # Even a self-consistent current record cannot waive comparison to the old ABI.
                record[name]['current_abi']=c.c.reuse.abi(bad,name)
                with self.assertRaises(ValueError):c.copies.inspect(bodies,bad,record)
                count+=1
            record=copy.deepcopy(changed)
            record[name]['prior_abi']=record[name]['prior_abi'].replace(c.copies.OLD,c.copies.NEW)
            with self.assertRaises(ValueError):c.copies.inspect(bodies,ir,record)
            count+=1
        for name in changed:
            with self.assertRaises(ValueError):c.copies.inspect(bodies,ir,{k:v for k,v in changed.items() if k!=name})
            count+=1
        self.assertEqual(count,13)

    def test_lifecycle_every_instruction_and_branch_is_load_bearing(self):
        count=0
        for lane,(_,_,_,ir,_,bodies) in self.routes.items():
            if lane=='simd':continue
            report=c.lifecycle.inspect(bodies,ir,lane)
            for name in report['functions'].values():
                lines=c.lifecycle.code(bodies[name])
                for at in range(len(lines)):
                    for mutant in (lines[:at]+lines[at+1:],lines[:at]+['nop']+lines[at+1:]):
                        bad=bodies|{name:name+':\n'+'\n'.join(mutant)}
                        with self.assertRaises(ValueError):c.lifecycle.inspect(bad,ir,lane)
                        count+=1
        self.assertEqual(count,1496)
        print('Sequential SHA-3 lifecycle instruction/label deletions and substitutions rejected:',count)

    def test_lifecycle_operand_and_escape_mutations(self):
        count=0
        for lane,(_,_,_,ir,_,bodies) in self.routes.items():
            if lane=='simd':continue
            names,_=c.lifecycle.contracts(bodies,lane)
            for kind,name in names.items():
                body='\n'.join(c.c.shapes.lines(bodies[name]))
                changes=[('movl $1024, %edx','movl $1023, %edx'),
                         ('callq '+c.lifecycle.DROP[lane],'callq '+c.lifecycle.ZERO),
                         ('callq '+c.lifecycle.ZERO,'retq'),('retq','jmpq *%rax')]
                if kind=='operation':
                    changes += [('incq %rax','addq $2, %rax'),('setne %cl','sete %cl'),
                                ('cmpq %r8, %rax','cmpq %r8, %r8')]
                    if lane=='avx2':changes += [('cmpb $4, 9(%rax)','cmpb $0, 9(%rax)'),
                                               ('cmpb $1, 8(%rax)','cmpb $2, 8(%rax)')]
                if kind=='seal':changes += [('testb $64, %al','testb $32, %al'),('setns %al','sets %al')]
                if kind=='guard':changes += [('testb $1, %dl','testb $0, %dl')]
                if kind=='cancel':changes += [('cmpb $4, %al','cmpb $5, %al')]
                for old,new in changes:
                    self.assertIn(old,body)
                    with self.assertRaises(ValueError):c.lifecycle.inspect(bodies|{name:body.replace(old,new,1)},ir,lane)
                    count+=1
        self.assertEqual(count,56)

    def test_lifecycle_owner_result_phase_and_guard_abis(self):
        count=0
        for lane,(_,_,_,ir,_,bodies) in self.routes.items():
            if lane=='simd':continue
            names,_=c.lifecycle.contracts(bodies,lane);a=c.lifecycle.LAYOUT[lane]
            for kind,name in names.items():
                declaration=next(l for l in ir.splitlines() if l.startswith('define ') and '@'+name+'(' in l)
                changes=[('nonnull ',' ')]
                if kind=='guard':changes += [('range(i8 0, 2)','range(i8 0, 3)')]
                else:
                    changes += [('noalias ',' '),('nofree ',' '),('noundef ',' '),
                        (f'align {a["align"]}', 'align 1'),
                        (f'dereferenceable({a["size"]})',f'dereferenceable({a["size"]-1})')]
                if kind=='operation':
                    changes += [('dereferenceable(16)','dereferenceable(8)'),
                        ('range(i8 0, 6)','range(i8 0, 7)'),('captures(none)','captures(address)'),
                        ('writeonly ',' '),('dead_on_unwind ',' ')]
                if kind in ('seal','cancel'):changes += [('range(i8 -1, 7)','range(i8 -1, 8)')]
                for old,new in changes:
                    self.assertIn(old,declaration)
                    bad=ir.replace(declaration,declaration.replace(old,new))
                    with self.assertRaises(ValueError):c.lifecycle.inspect(bodies,bad,lane)
                    count+=1
        self.assertEqual(count,66)

    def test_lifecycle_cannot_promote_unreviewed_storage_or_unwind(self):
        for lane,(_,_,_,ir,_,bodies) in self.routes.items():
            if lane=='simd':
                with self.assertRaises(ValueError):c.lifecycle.inspect(bodies,ir,lane)
                continue
            report=c.lifecycle.inspect(bodies,ir,lane)
            for key in ('plan_padding_erased','state_destructor_composition_qualified',
                        'caller_storage_lifetimes_qualified','unwind_paths_qualified',
                        'complete_private_frame_erasure_qualified'):
                self.assertFalse(report[key])
            self.assertEqual(report['output_clear_bytes'],1024)
            self.assertEqual(report['authority_check_before_sequence_commit'],lane=='avx2')

    def test_saved_route_invokes_lifecycle_and_rejects_bad_transition(self):
        # Do not replay the expensive prior reviewer here; other tests enforce it.
        for lane in ('scalar','avx2'):
            with patch.object(c,'reused_helpers',return_value=None), \
                 patch.object(c.lifecycle,'inspect',side_effect=ValueError('lifecycle failed')) as check:
                with self.assertRaisesRegex(ValueError,'lifecycle failed'):
                    c.inspect_route(self.saved,self.root,lane,self.spec[lane])
                check.assert_called_once()
