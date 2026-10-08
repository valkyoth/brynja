"""Scalar setup moved-state, complete-body and composition regressions."""
import copy
from unittest.mock import patch
import windows_enclave_sha3_batch_chains as c
from windows_enclave_sha3_batch_setup_moves import replay,schedule


class ScalarSetupModelTests:
    def test_scalar_setup_byte_origins_and_pending_erasure(self):
        for tag in (7,8):
            result=replay(tag)
            self.assertEqual(result['installed_owner_bytes'],1040)
            self.assertEqual(result['result_variant'],tag-2)
            self.assertFalse(result['old_state_copy_erased'])
            self.assertFalse(result['temporary_copies_fully_erased'])
            steps=schedule(tag)
            for at,step in enumerate(steps):
                if step[0]!='copy':continue
                bad=steps.copy();changed=list(step);changed[2]+=1;bad[at]=tuple(changed)
                with self.assertRaises(ValueError):replay(tag,bad)
            # Erasing the old physical payload after changing only its tag
            # destroys subsequent reads, despite the logical move being valid.
            with self.assertRaises(ValueError):replay(tag,steps[:2]+[('zero','owner',32,1120)]+steps[2:])
            with self.assertRaises(ValueError):replay(tag,[v for v in steps if v!=('zero','frame',244,1040)])
            for badstep in [('copy','frame',200, 'frame',201,8),('copy','frame',32,'saved',0,1),
                            ('copy','owner',0,'frame',24,8),('zero','frame',5407,2)]:
                with self.assertRaises(ValueError):replay(tag,[badstep]+steps)
        for tag in (0,6,9):
            with self.assertRaises(ValueError):replay(tag)


class ScalarSetupTests:
    def test_scalar_setup_complete_instruction_contract(self):
        x=c.scalar_setup;bodies=self.routes['scalar'][-1];n,want=x.check_shape(bodies)
        self.assertEqual(len(want),411);name=n['finish_setup'];count=0
        for at in range(len(want)):
            for bad in (want[:at]+want[at+1:],want[:at]+['ud2']+want[at+1:]):
                with self.assertRaises(ValueError):x.check_shape(bodies|{name:name+':\n'+'\n'.join(bad)})
                count+=1
        self.assertEqual(count,822)
        print('Scalar SHA-3 batch setup-completion instruction mutants rejected:',count)

    def test_scalar_setup_copy_lifetime_predicate_and_cleanup_mutations(self):
        x=c.scalar_setup;bodies=self.routes['scalar'][-1];n,_=x.check_shape(bodies);name=n['finish_setup']
        body='\n'.join(c.lifecycle.s.lines(bodies[name]))
        pairs=[('movl $5408, %eax','movl $5400, %eax'),('movl $1136, %r8d','movl $1120, %r8d'),
            ('movl $1120, %r8d','movl $1136, %r8d'),('movl $988, %r8d','movl $989, %r8d'),
            ('movl $1040, %r8d','movl $1039, %r8d'),('leaq 4420(%rsp), %rcx','leaq 4421(%rsp), %rcx'),
            ('leaq 2444(%rsp), %rcx','leaq 3433(%rsp), %rcx'),('movq 87(%rsp), %rcx','movq 88(%rsp), %rcx'),
            ('movups %xmm1, 159(%rsp)','movups %xmm1, 160(%rsp)'),
            ('movb $0, 16(%r14)','movb $7, 16(%r14)'),('cmpb $6, 1296(%rsp)','cmpb $7, 1296(%rsp)'),
            ('cmpb $2, 242(%rsp)','cmpb $1, 242(%rsp)'),('orq 192(%rsp), %rax','orq %rax, %rax'),
            ('cmpb $0, 241(%rsp)','cmpb $1, 241(%rsp)'),('cmpl $65535, %eax','cmpl $255, %eax'),
            ('pcmpeqb 224(%rsp), %xmm0','pcmpeqb %xmm0, %xmm0'),
            ('cmpb $1, 243(%rsp)','cmpb $0, 243(%rsp)'),('movb $5, %dil','movb $6, %dil'),
            ('movb $6, %dil','movb $5, %dil'),('movb $3, 2384(%r14)','movb $4, 2384(%r14)'),
            ('callq '+x.WIPE,'nop'),('callq '+x.life.ZERO,'nop'),('callq '+x.life.DROP['scalar'],'nop')]
        for old,new in pairs:
            self.assertIn(old,body)
            with self.assertRaises(ValueError):x.check_shape(bodies|{name:body.replace(old,new)})
        self.assertEqual(len(pairs),23)

    def test_scalar_setup_prerequisites_abi_and_scope(self):
        x=c.scalar_setup;bodies,asm,ir,lane,prior,placement,transitions,receiver=self.update_fixture('scalar')
        chunks=c.chunks.inspect(bodies,asm,ir,lane,prior,placement,transitions,receiver)
        args=[bodies,ir,prior,placement,transitions,receiver,chunks];result=x.inspect(*args)
        for index,path in [(2,('prior_semantics_replayed',)),(3,('state_destructor','typed_payload_cleanup_composed')),
            (3,('state_pointer_inside_owner',)),(4,('checked_next_sequence',)),(4,('phase_match_before_admission',)),
            (4,('unfinished_guard_clears_and_quarantines',)),(6,('normal_rejection_typed_cleanup_and_quarantine_composed',)),
            (6,('input_pointer_and_length_preserved',))]:
            bad=args.copy();bad[index]=copy.deepcopy(args[index]);value=bad[index]
            for key in path[:-1]:value=value[key]
            value[path[-1]]=False
            with self.assertRaises(ValueError):x.inspect(*bad)
        for name in (x.WIPE,x.life.ZERO):
            bad=args.copy();bad[2]=copy.deepcopy(prior);del bad[2]['exact_body_reference_extent_and_abi'][name]
            with self.assertRaises(ValueError):x.inspect(*bad)
        for index,key in ((4,'operation'),(5,'finish_setup')):
            bad=args.copy();bad[index]=copy.deepcopy(args[index]);bad[index]['functions'][key]='wrong'
            with self.assertRaises(ValueError):x.inspect(*bad)
        n,_=x.check_shape(bodies)
        for name,old,new in [(n['finish_setup'],'noalias ',' '),(n['finish_setup'],'dereferenceable(2400)','dereferenceable(2399)'),
            (x.WIPE,'dereferenceable(1040)','dereferenceable(1039)'),(x.life.DROP['scalar'],'noalias ',' ')]:
            row=next(l for l in ir.splitlines() if l.startswith('define ') and '@'+name+'(' in l)
            self.assertIn(old,row);bad=args.copy();bad[1]=ir.replace(row,row.replace(old,new))
            with self.assertRaises(ValueError):x.inspect(*bad)
        original=x.life.reuse.abi
        for name in (x.WIPE,x.life.DROP['scalar']):
            def changed(text,callee):
                value=original(text,callee)
                return value.replace('nounwind','') if callee==name else value
            with patch.object(x.life.reuse,'abi',side_effect=changed):
                with self.assertRaises(ValueError):x.inspect(*args)
        for key in ('start_establishes_state_invariant_qualified','moved_copy_erasure_qualified',
                    'private_frame_erasure_qualified','all_unwind_paths_qualified','whole_image_qualified'):
            self.assertFalse(result[key])
        with patch.object(c.scalar_setup,'inspect',side_effect=ValueError('scalar completion failed')) as check:
            with self.assertRaisesRegex(ValueError,'scalar completion failed'):
                c.inspect_route(self.saved,self.root,'scalar',self.spec['scalar'])
            check.assert_called_once()
