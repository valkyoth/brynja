"""Active byte provenance, inactive storage, pointer and publication regressions."""
from unittest.mock import patch
import windows_enclave_sha3_batch_chains as c

t=c.cshake_moves


class CshakeMovesModelTests:
    def test_cshake_moves_every_transfer_is_load_bearing(self):
        count=0
        for tag in (7,8):
            for mode in (False,True):
                result=t.replay(tag,mode);steps=t.schedule(tag,mode)
                self.assertEqual(result['active_setup_span'],[32,1141])
                self.assertEqual(result['matching_overlap_bytes'],8)
                self.assertFalse(result['padding_initialized'])
                self.assertFalse(result['inactive_bytes_initialized'])
                self.assertFalse(result['original_and_snapshot_erased'])
                for i in range(len(steps)):
                    with self.assertRaises(ValueError):t.replay(tag,mode,steps[:i]+steps[i+1:])
                    count+=1
        self.assertEqual(count,276)
        print('cSHAKE retained transfer deletions rejected:',count)

    def test_cshake_moves_unknown_bytes_cannot_enter_active_fields(self):
        count=0
        for tag in (7,8):
            for mode in (False,True):
                steps=t.schedule(tag,mode);base=3408 if tag==7 else 4528
                for old,new in (
                    (('copy','frame',base,'frame',301,1),('copy','frame',base+1109,'frame',301,1)),
                    (('copy','frame',base+33,'frame',5861,200),('copy','frame',base+34,'frame',5861,200)),
                    (('copy','frame',base+1104,'frame',2878,16),('copy','frame',base+1103,'frame',2878,16)),
                    (('copy','frame',1681,'frame',6061,1107),('copy','frame',1682,'frame',6061,1107)),
                    (('copy','frame',base+2,'saved',1,1),('copy','frame',base+3,'saved',1,1)),
                    (('tag',tag),('tag',15-tag)),(('inner_tag',6),('inner_tag',5)),
                ):
                    self.assertIn(old,steps)
                    with self.assertRaises(ValueError):t.replay(tag,mode,[new if v==old else v for v in steps])
                    count+=1
                at=next(i for i,v in enumerate(steps) if v[0]=='destroy')
                for extra in (
                    ('copy','frame',2789,'frame',301,1),('copy','frame',300,'frame',301,1),
                    ('copy','frame',1680,'frame',1681,100),('copy','frame',1680,'frame',32,1),
                    ('copy','frame',7168,'frame',301,1),('copy','frame',1680,'owner',15,1),
                    ('copy','frame',1680,'owner',1152,1),('copy','frame',1680,'saved',11,1),
                    ('copy','frame',1681,'frame',1680,1),('publish',),('destroy',),
                ):
                    # A bounded irrelevant write is deliberately accepted: this
                    # model proves listed lifetimes, not absence of all writes.
                    if extra==('copy','frame',1680,'frame',32,1):
                        t.replay(tag,mode,steps[:at]+[extra]+steps[at:]);continue
                    with self.assertRaises(ValueError):t.replay(tag,mode,steps[:at]+[extra]+steps[at:])
                    count+=1
                with self.assertRaises(ValueError):t.replay(tag,mode,steps+[('copy','frame',1680,'owner',32,1)])
                count+=1
        self.assertEqual(count,72)
        for args in ((6,False),(9,True),(True,False),(7,1)):
            with self.assertRaises(ValueError):t.replay(*args)


class CshakeMovesTests:
    def test_cshake_moves_instruction_and_complete_scalar_coverage(self):
        _,_,asm,_,_,bodies=self.routes['scalar'];name,positions,all_positions=t.check_shapes(bodies,asm)
        self.assertEqual(len(positions),145);self.assertEqual(all_positions,list(range(1361)))
        lines=c.lifecycle.code(bodies[name]);count=0
        for at in positions:
            for changed in (lines[:at]+lines[at+1:],lines[:at]+['ud2']+lines[at+1:]):
                with self.assertRaises(ValueError):t.check_shapes(bodies|{name:name+':\n'+'\n'.join(changed)},asm)
                count+=1
        self.assertEqual(count,290)
        print('cSHAKE retained transfer instruction mutants rejected:',count)

    def test_cshake_moves_pointer_extra_byte_and_entry_mutants(self):
        _,_,asm,_,_,bodies=self.routes['scalar'];name,_,_=t.check_shapes(bodies,asm)
        body='\n'.join(c.lifecycle.code(bodies[name]))
        for old,new in (
            ('leaq 3411(%rsp), %r12','leaq 3412(%rsp), %r12'),
            ('leaq 4531(%rsp), %r12','leaq 4532(%rsp), %r12'),
            ('leaq 4225(%rsp), %rax','leaq 4226(%rsp), %rax'),
            ('leaq 5345(%rsp), %rax','leaq 5346(%rsp), %rax'),
            ('movb %al, 301(%rsp)','movb %al, 300(%rsp)'),
            ('movups 78(%rdi), %xmm0','movups 79(%rdi), %xmm0'),
            ('movl 135(%rsp), %eax','movl 136(%rsp), %eax'),
            ('movb $7, 35(%rsp)','movb $8, 35(%rsp)'),
            ('movb $8, 35(%rsp)','movb $7, 35(%rsp)'),
            ('movb $6, %bpl','movb $5, %bpl'),
            ('movq 280(%rsp), %rsi','movq 281(%rsp), %rsi'),
        ):
            self.assertIn(old,body)
            with self.assertRaises(ValueError):t.check_shapes(bodies|{name:name+':\n'+body.replace(old,new)},asm)
        for label in (42,43,44,45,46):
            bad=body.replace('jmp .B39',f'jmp .B{label}')
            self.assertNotEqual(body,bad)
            with self.assertRaises(ValueError):t.check_shapes(bodies|{name:name+':\n'+bad},asm)

    def test_cshake_moves_prerequisites_and_integrated_failure(self):
        bodies,asm,ir,prior,construction,initialized=self.cshake_flow_fixture()
        prefix=c.cshake_flow.inspect(bodies,asm,ir,prior,construction,initialized)
        placement=self.start_fixture('scalar')[4]
        args=(bodies,asm,construction,initialized,prefix,placement)
        result=t.inspect(*args)
        self.assertTrue(result['scalar_start_instruction_coverage_complete'])
        self.assertTrue(result['scalar_active_constructor_transfers_qualified'])
        self.assertFalse(result['all_constructor_paths_qualified'])
        self.assertFalse(result['private_frame_erasure_qualified'])
        for index,keys in ((2,('function','successful_slot_and_phase_commit_after_state_copy',
            'successful_placement_destroys_previous_typed_state_first')),
            (3,('function','cshake_initial_arithmetic_and_fields_qualified')),
            (4,('function','success_only_after_both_prefix_updates_and_advance'))):
            for key in keys:
                changed=list(args);changed[index]=changed[index]|{key:False}
                with self.assertRaises(ValueError):t.inspect(*changed)
        bad=placement|{'state_destructor':placement['state_destructor']|{'typed_payload_cleanup_composed':False}}
        with self.assertRaises(ValueError):t.inspect(*args[:5],bad)
        with patch.object(c.cshake_moves,'inspect',side_effect=ValueError('cSHAKE moves failed')) as check:
            with self.assertRaisesRegex(ValueError,'cSHAKE moves failed'):
                c.inspect_route(self.saved,self.root,'scalar',self.spec['scalar'])
            check.assert_called_once()
