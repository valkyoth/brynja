"""Scalar fixed-constructor opcode, entry and byte-lifetime regression tests."""
from unittest.mock import patch
import windows_enclave_sha3_batch_chains as c

t=c.fixed_start


class FixedStartModelTests:
    def test_fixed_start_every_transfer_is_required(self):
        count=0
        for tag in t.LABELS:
            result=t.replay(tag);steps=t.schedule(tag)
            self.assertEqual(result['active_owner_bytes'],1040)
            self.assertEqual(result['overlapping_active_writes'],6)
            self.assertFalse(result['inactive_storage_initialization_qualified'])
            self.assertFalse(result['stack_copy_erasure_qualified'])
            for i in range(len(steps)):
                with self.assertRaises(ValueError):t.replay(tag,steps[:i]+steps[i+1:])
                count+=1
        self.assertEqual(count,220)
        print('Fixed constructor transfer deletions rejected:',count)
        for tag in (0,5,-1,True,'1'):
            with self.assertRaises(ValueError):t.replay(tag)

    def test_fixed_start_lifetimes_bounds_tag_and_destroy_order(self):
        for tag in t.LABELS:
            steps=t.schedule(tag)
            for bad in (
                [('copy','frame',1040,'frame',5861,200)]+steps,
                [('zero','frame',0,32)]+steps,
                [('zero','frame',7160,16)]+steps,
                steps+[('copy','frame',1040,'frame',1041,200)],
                steps+[('copy','frame',1,'owner',17,1)],
                steps+[('zero','owner',1057,1)],
                steps+[('zero','owner',16,1)],
                [('zero','owner',17,1)]+steps,
                steps+[('destroy',)],
                [('tag',5) if v[0]=='tag' else v for v in steps],
            ):
                with self.assertRaises(ValueError):t.replay(tag,bad)


class FixedStartTests:
    def test_fixed_start_every_initialization_and_staging_instruction_is_checked(self):
        _,_,asm,_,_,bodies=self.routes['scalar'];name,positions=t.check_shapes(bodies,asm)
        lines=c.lifecycle.code(bodies[name]);count=0
        for at in positions:
            for bad in (lines[:at]+lines[at+1:],lines[:at]+['ud2']+lines[at+1:]):
                with self.assertRaises(ValueError):t.check_shapes(bodies|{name:name+':\n'+'\n'.join(bad)},asm)
                count+=1
        self.assertEqual(count,706)
        print('Fixed constructor instruction mutants rejected:',count)

    def test_fixed_start_foreign_entry_and_nonzero_xmm_reject(self):
        _,_,asm,_,_,bodies=self.routes['scalar'];name,_=t.check_shapes(bodies,asm)
        lines=c.lifecycle.code(bodies[name])
        # This off-path instruction is deliberately outside the fixed contracts.
        at=lines.index('leaq 1681(%rsp), %rdx')
        for label in t.LABELS.values():
            for transfer in (f'jmp .B{label}',f'jne .B{label}'):
                bad=lines[:at]+[transfer]+lines[at+1:]
                with self.assertRaises(ValueError):t.check_shapes(bodies|{name:name+':\n'+'\n'.join(bad)},asm)
        at=lines.index('.B26:')+1
        bad=lines[:at]+['pcmpeqb %xmm0, %xmm0']+lines[at+1:]
        with self.assertRaises(ValueError):t.check_shapes(bodies|{name:name+':\n'+'\n'.join(bad)},asm)

    def test_fixed_start_replays_admission_placement_and_cleanup(self):
        args=self.start_fixture('scalar');bodies,asm,_,_,storage,_,_=args
        construction=c.start.inspect(*args);result=t.inspect(bodies,asm,construction,storage)
        self.assertTrue(result['active_fixed_constructor_initialization_qualified'])
        self.assertFalse(result['all_constructor_paths_qualified'])
        self.assertFalse(result['private_frame_erasure_qualified'])
        for key in ('function','successful_placement_destroys_previous_typed_state_first',
                    'successful_slot_and_phase_commit_after_state_copy'):
            with self.assertRaises(ValueError):t.inspect(bodies,asm,construction|{key:False},storage)
        for key in ('function','typed_payload_cleanup_composed'):
            changed=storage|{'state_destructor':storage['state_destructor']|{key:False}}
            with self.assertRaises(ValueError):t.inspect(bodies,asm,construction,changed)
        with patch.object(c.fixed_start,'inspect',side_effect=ValueError('fixed construction failed')) as check:
            with self.assertRaisesRegex(ValueError,'fixed construction failed'):
                c.inspect_route(self.saved,self.root,'scalar',self.spec['scalar'])
            check.assert_called_once()
