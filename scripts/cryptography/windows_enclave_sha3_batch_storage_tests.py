"""Regression tests for emitted batch state cleanup and plan placement."""
import copy
from unittest.mock import patch

import windows_enclave_sha3_batch_chains as c


class StorageTests:
    def storage_fixture(self,lane):
        _,_,asm,ir,functions,bodies=self.routes[lane]
        prior=c.reused_helpers(self.saved,self.root,lane,functions,ir,self.spec[lane])
        return bodies,asm,ir,prior

    def test_storage_all_destructor_and_begin_instructions_reject_changes(self):
        count=0
        for lane in ('scalar','avx2'):
            bodies,asm,ir,prior=self.storage_fixture(lane)
            result=c.storage.inspect(bodies,asm,ir,lane,prior)
            for name in (result['state_destructor']['function'],result['begin']['function']):
                lines=c.lifecycle.code(bodies[name])
                for at in range(len(lines)):
                    for mutation in (lines[:at]+lines[at+1:],lines[:at]+['nop']+lines[at+1:]):
                        with self.assertRaises(ValueError):
                            c.storage.inspect(bodies|{name:name+':\n'+'\n'.join(mutation)},asm,ir,lane,prior)
                        count+=1
        self.assertEqual(count,518)
        print('SHA-3 state destructor/begin instruction mutations rejected:',count)

    def test_storage_scalar_destructor_table_rejects_each_wrong_state(self):
        bodies,asm,ir,prior=self.storage_fixture('scalar')
        table=c.storage.inspect(bodies,asm,ir,'scalar',prior)['state_destructor']['dispatch_table']
        at=asm.index(table+':\n')+len(table)+2
        lines=asm[at:].splitlines(keepends=True)
        for slot in range(8):
            bad=list(lines);bad[slot]='\t.long\t.LBB38_9-'+table+'\n'
            with self.assertRaises(ValueError):c.storage.inspect(bodies,asm[:at]+''.join(bad),ir,'scalar',prior)
        with self.assertRaises(ValueError):c.storage.inspect(bodies,asm.replace(table+':',table+'_missing:'),ir,'scalar',prior)

    def test_storage_full_state_and_disjoint_plan_abis_required(self):
        count=0
        for lane in ('scalar','avx2'):
            bodies,asm,ir,prior=self.storage_fixture(lane)
            result=c.storage.inspect(bodies,asm,ir,lane,prior)
            for kind in ('state_destructor','begin'):
                name=result[kind]['function'];a=c.lifecycle.LAYOUT[lane]
                declaration=next(l for l in ir.splitlines() if l.startswith('define ') and '@'+name+'(' in l)
                changes=[('noalias ',' '),('nofree ',' '),('noundef ',' '),('nonnull ',' '),
                         (f'align {a["align"]}','align 1')]
                size=a['size'] if kind=='begin' else c.storage.STATE_BYTES[lane]
                changes += [(f'dereferenceable({size})',f'dereferenceable({size-1})')]
                if kind=='begin':
                    changes += [('dead_on_return ',' '),('readonly ',' '),('captures(none)','captures(address)'),
                        ('dereferenceable(192)','dereferenceable(191)'),('range(i8 -1, 7)','range(i8 -1, 8)')]
                for old,new in changes:
                    self.assertIn(old,declaration)
                    with self.assertRaises(ValueError):
                        c.storage.inspect(bodies,asm,ir.replace(declaration,declaration.replace(old,new)),lane,prior)
                    count+=1
        self.assertEqual(count,34)

    def test_storage_all_wipe_callees_and_prior_semantics_required(self):
        count=0
        for lane in ('scalar','avx2'):
            bodies,asm,ir,prior=self.storage_fixture(lane)
            result=c.storage.inspect(bodies,asm,ir,lane,prior)
            for name in result['state_destructor']['reviewed_wipe_callees']:
                bad=copy.deepcopy(prior);del bad['exact_body_reference_extent_and_abi'][name]
                with self.assertRaises(ValueError):c.storage.inspect(bodies,asm,ir,lane,bad)
                count+=1
            for key in ('prior_semantics_replayed','state_destructor_rebinding'):
                bad=copy.deepcopy(prior)
                if key=='prior_semantics_replayed':bad[key]=False
                else:bad[key]['exact_code_references_extent_and_renamed_abi']=False
                with self.assertRaises(ValueError):c.storage.inspect(bodies,asm,ir,lane,bad)
                count+=1
        self.assertEqual(count,9)

    def test_storage_composition_replays_lifecycle_and_admission(self):
        for lane in ('scalar','avx2'):
            bodies,asm,ir,prior=self.storage_fixture(lane)
            for module in (c.lifecycle,c.plan):
                with patch.object(module,'inspect',side_effect=ValueError('required prior contract failed')) as check:
                    with self.assertRaisesRegex(ValueError,'required prior contract failed'):
                        c.storage.inspect(bodies,asm,ir,lane,prior)
                    check.assert_called_once()

    def test_storage_is_integrated_but_does_not_close_retained_lifetimes(self):
        for lane in ('scalar','avx2'):
            bodies,asm,ir,prior=self.storage_fixture(lane)
            result=c.storage.inspect(bodies,asm,ir,lane,prior)
            for key in ('retained_owner_lifetime_qualified','all_batch_callers_composed',
                        'private_frame_padding_and_moved_copy_erasure_qualified','unwind_paths_qualified'):
                self.assertFalse(result[key])
            self.assertFalse(result['state_destructor']['entire_state_allocation_erased'])
            self.assertTrue(result['state_destructor']['typed_payload_cleanup_composed'])
            with patch.object(c.storage,'inspect',side_effect=ValueError('storage failed')) as check:
                with self.assertRaisesRegex(ValueError,'storage failed'):
                    c.inspect_route(self.saved,self.root,lane,self.spec[lane])
                check.assert_called_once()


class RebindingTests:
    def test_destructor_rebinding_is_not_name_only(self):
        # Isolated comparison mechanics; saved tests additionally replay actual prior reviews.
        for lane in ('scalar','avx2'):
            now,old=c.lifecycle.DROP[lane],c.storage.PRIOR_DROP[lane]
            values=(b'code',[dict(symbol='wipe',offset=1,kind=4,addend=0)],True)
            current,prior={now:values},{old:values}
            ir='define void @'+now+'(ptr noalias %p) #1 {\nattributes #1 = { nounwind }'
            before=ir.replace(now,old)
            c.storage.rebind(lane,current,prior,ir,before)
            for mutation in ((b'codf',values[1],True),(b'code',[],True),(b'code',values[1],False)):
                with self.assertRaises(ValueError):c.storage.rebind(lane,{now:mutation},prior,ir,before)
            for bad in (ir.replace('noalias ',''),ir.replace('nounwind','noreturn')):
                with self.assertRaises(ValueError):c.storage.rebind(lane,current,prior,bad,before)
            with self.assertRaises(ValueError):c.storage.rebind(lane,current,{},ir,before)
