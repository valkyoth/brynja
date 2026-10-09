"""SHAKE construction origin, extra-byte, error restoration and ABI regressions."""
import copy
from unittest.mock import patch
import windows_enclave_sha3_batch_chains as c

t=c.shake_start


class ShakeStartModelTests:
    def test_shake_start_every_transfer_is_required(self):
        count=0
        for tag in (5,6):
            result=t.replay(tag);steps=t.schedule(tag)
            self.assertEqual(result['wrapper_span'],[17,1058])
            self.assertEqual(result['same_source_overlap_bytes'],6)
            self.assertFalse(result['helper_result_erased'])
            for i in range(len(steps)):
                with self.assertRaises(ValueError):t.replay(tag,steps[:i]+steps[i+1:])
                count+=1
        self.assertEqual(count,134)
        print('SHAKE constructor transfer deletions rejected:',count)
        for tag in (0,4,7,-1,True,'5'):
            with self.assertRaises(ValueError):t.replay(tag)

    def test_shake_start_origins_detect_swapped_fields_and_missing_extra_byte(self):
        count=0
        for tag in (5,6):
            steps=t.schedule(tag)
            for at,step in enumerate(steps):
                if step[0]=='copy':
                    _,src,start,dst,end,size=step
                    if src=='frame' and 1680<=start and start+size<=2721:
                        bad=list(steps);bad[at]=('copy',src,start+1,dst,end,size)
                        with self.assertRaises(ValueError):t.replay(tag,bad)
                        count+=1
            for extra in (
                ('copy','frame',1681,'saved',0,1),
                ('copy','frame',2719,'frame',120,1),
                ('copy','frame',1681,'frame',1680,1),
                ('copy','frame',1680,'frame',1681,1040),
                ('copy','frame',0,'owner',17,1),
                ('copy','frame',1680,'frame',7168,1),
                ('copy','saved',9,'owner',17,1),
                ('copy','frame',2721,'owner',17,1),
            ):
                # Insert after all reads into saved registers but before staging.
                at=next(i for i,v in enumerate(steps) if v[0]=='tag')
                with self.assertRaises(ValueError):t.replay(tag,steps[:at]+[extra]+steps[at:])
                count+=1
            for bad in ([('copy','frame',1680,'saved',0,1)]+steps,
                        [('copy','frame',1680,'owner',17,1)]+steps,
                        steps+[('destroy',)],steps+[('result',)],
                        [('tag',4) if v[0]=='tag' else v for v in steps]):
                with self.assertRaises(ValueError):t.replay(tag,bad)
                count+=1
        self.assertEqual(count,66)


class ShakeStartTests:
    def shake_start_fixture(self):
        args=self.start_fixture('scalar');bodies,asm,ir,_,storage,_,_=args
        construction=c.start.inspect(*args)
        data=self.routes['scalar'][0]
        previous=c.empty.inspect(data,bodies,asm,ir,construction)
        return bodies,asm,previous,construction,storage

    def test_shake_start_all_result_and_failure_instructions_are_checked(self):
        _,_,asm,_,_,bodies=self.routes['scalar'];name,positions=t.check_shapes(bodies,asm)
        self.assertEqual(len(positions),194)
        lines=c.lifecycle.code(bodies[name]);count=0
        for at in positions:
            for bad in (lines[:at]+lines[at+1:],lines[:at]+['ud2']+lines[at+1:]):
                with self.assertRaises(ValueError):t.check_shapes(bodies|{name:name+':\n'+'\n'.join(bad)},asm)
                count+=1
        self.assertEqual(count,388)
        print('SHAKE constructor instruction mutants rejected:',count)

    def test_shake_start_mode_result_error_and_plan_pointer_are_distinct(self):
        _,_,asm,_,_,bodies=self.routes['scalar'];name,_=t.check_shapes(bodies,asm)
        body='\n'.join(c.lifecycle.code(bodies[name]))
        for old,new in (
            ('movzbl 1680(%rsp), %ebp','movzbl 1681(%rsp), %ebp'),
            ('cmpb $-1, %bpl','cmpb $0, %bpl'),('je .B58','jne .B58'),
            ('movq %rbp, %rdi','movq %rbp, %rax'),('movq %rdi, %rbp','movq %rax, %rbp'),
            ('movzbl 2720(%rsp), %eax','movzbl 2719(%rsp), %eax'),
            ('movb $5, 35(%rsp)','movb $6, 35(%rsp)'),('movb $6, 35(%rsp)','movb $5, 35(%rsp)'),
            ('.B58:\nmovb $6, %al','.B58:\nmovb $-1, %al'),
        ):
            self.assertIn(old,body)
            with self.assertRaises(ValueError):t.check_shapes(bodies|{name:name+':\n'+body.replace(old,new)},asm)

    def test_shake_start_constructor_and_placement_prerequisites_required(self):
        args=self.shake_start_fixture();result=t.inspect(*args)
        self.assertTrue(result['scalar_shake_constructor_joins_qualified'])
        self.assertFalse(result['all_constructor_paths_qualified'])
        self.assertFalse(result['private_frame_erasure_qualified'])
        for bits in ('128','256'):
            for key,value in (('function','wrong'),('result_success_tag',1),('result_bytes',1040),('owner_bytes',1039)):
                changed=copy.deepcopy(args[2]);changed['helpers'][bits][key]=value
                with self.assertRaises(ValueError):t.inspect(*args[:2],changed,*args[3:])
        for key in ('caller','empty_constructor_paths_qualified'):
            with self.assertRaises(ValueError):t.inspect(*args[:2],args[2]|{key:False},*args[3:])
        changed=copy.deepcopy(args[2]);changed['geometry']['result_entirely_initialized']=False
        with self.assertRaises(ValueError):t.inspect(*args[:2],changed,*args[3:])
        for key in ('function','successful_placement_destroys_previous_typed_state_first',
                    'successful_slot_and_phase_commit_after_state_copy','rejection_clears_output_bytes'):
            with self.assertRaises(ValueError):t.inspect(*args[:3],args[3]|{key:False},args[4])
        for key in ('function','typed_payload_cleanup_composed'):
            changed=args[4]|{'state_destructor':args[4]['state_destructor']|{key:False}}
            with self.assertRaises(ValueError):t.inspect(*args[:4],changed)
        with patch.object(c.shake_start,'inspect',side_effect=ValueError('SHAKE construction failed')) as check:
            with self.assertRaisesRegex(ValueError,'SHAKE construction failed'):
                c.inspect_route(self.saved,self.root,'scalar',self.spec['scalar'])
            check.assert_called_once()
