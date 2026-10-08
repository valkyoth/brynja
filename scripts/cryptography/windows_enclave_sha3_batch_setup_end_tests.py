"""AVX2 setup completion mutations; scalar finalization stays pending."""
import copy
from unittest.mock import patch
import windows_enclave_sha3_batch_chains as c


class SetupEndTests:
    def test_setup_end_avx2_every_instruction_and_label_rejected(self):
        bodies=self.routes['avx2'][-1];n,want=c.setup_end.check_shape(bodies)
        self.assertEqual(len(want),137);lines=c.lifecycle.code(bodies[n['finish']]);count=0
        for at in range(len(lines)):
            for bad in (lines[:at]+lines[at+1:],lines[:at]+['ud2']+lines[at+1:]):
                with self.assertRaises(ValueError):
                    c.setup_end.check_shape(bodies|{n['finish']:n['finish']+':\n'+'\n'.join(bad)})
                count+=1
        self.assertEqual(count,274)
        print('AVX2 batch setup-completion instruction mutants rejected:',count)

    def test_setup_end_exact_completion_and_cleanup_cannot_be_weakened(self):
        bodies=self.routes['avx2'][-1];n,_=c.setup_end.check_shape(bodies);name=n['finish']
        body='\n'.join(c.lifecycle.s.lines(bodies[name]))
        changes=[('cmpb $2, 2154(%rsi)','cmpb $1, 2154(%rsi)'),
            ('orq 2088(%rsi), %rax','orq %rax, %rax'),('movq 2080(%rsi), %rax','xorq %rax, %rax'),
            ('cmpb $0, 2153(%rsi)','cmpb $1, 2153(%rsi)'),
            ('vpxor 2128(%rsi), %xmm0, %xmm0','vpxor %xmm0, %xmm0, %xmm0'),
            ('vmovdqa 2112(%rsi), %xmm0','vmovdqa 2128(%rsi), %xmm0'),
            ('cmpq 1800(%rsi), %rcx','cmpq %rcx, %rcx'),('cmpb $1, 8(%rax)','cmpb $2, 8(%rax)'),
            ('movb $1, 2178(%rsi)','movb $0, 2178(%rsi)'),('movb $3, 2249(%rsi)','movb $4, 2249(%rsi)'),
            ('callq '+c.lifecycle.ZERO,'nop'),('callq '+c.lifecycle.DROP['avx2'],'nop'),
            ('callq '+n['wipe'],'nop'),('cmpq $7, %rdi','cmpq $8, %rdi'),
            ('cmpq %rdi, 2240(%rsi)','cmpq %rdi, %rdi')]
        for old,new in changes:
            self.assertIn(old,body)
            with self.assertRaises(ValueError):c.setup_end.check_shape(bodies|{name:body.replace(old,new)})
        self.assertEqual(len(changes),15)

    def test_setup_end_composition_abis_and_pending_scope(self):
        bodies,asm,ir,lane,prior,storage,transitions,receiver=self.update_fixture('avx2')
        chunks=c.chunks.inspect(bodies,asm,ir,lane,prior,storage,transitions,receiver)
        args=[bodies,ir,prior,storage,transitions,receiver,chunks]
        result=c.setup_end.inspect(*args)
        for index,path in [(2,('prior_semantics_replayed',)),(3,('state_destructor','typed_payload_cleanup_composed')),
            (3,('state_pointer_inside_owner',)),(4,('checked_next_sequence',)),(4,('phase_match_before_admission',)),
            (4,('unfinished_guard_clears_and_quarantines',)),(6,('normal_rejection_typed_cleanup_and_quarantine_composed',)),
            (6,('input_pointer_and_length_preserved',))]:
            bad=args.copy();bad[index]=copy.deepcopy(args[index]);value=bad[index]
            for key in path[:-1]:value=value[key]
            value[path[-1]]=False
            with self.assertRaises(ValueError):c.setup_end.inspect(*bad)
        n=c.setup_end.names(bodies)
        for name in (n['wipe'],c.lifecycle.ZERO):
            bad=args.copy();bad[2]=copy.deepcopy(prior);del bad[2]['exact_body_reference_extent_and_abi'][name]
            with self.assertRaises(ValueError):c.setup_end.inspect(*bad)
        for index,key in ((4,'operation'),(5,'finish_setup')):
            bad=args.copy();bad[index]=copy.deepcopy(args[index]);bad[index]['functions'][key]='wrong'
            with self.assertRaises(ValueError):c.setup_end.inspect(*bad)
        for key,old,new in [('finish','noalias ',' '),('finish','dereferenceable(2272)','dereferenceable(2271)'),
                            ('wipe','dereferenceable(234)','dereferenceable(233)')]:
            row=next(l for l in ir.splitlines() if l.startswith('define ') and '@'+n[key]+'(' in l)
            self.assertIn(old,row);bad=args.copy();bad[1]=ir.replace(row,row.replace(old,new))
            with self.assertRaises(ValueError):c.setup_end.inspect(*bad)
        for key in ('scalar_setup_finalization_qualified','all_unwind_paths_qualified','private_frame_erasure_qualified','whole_image_qualified'):
            self.assertFalse(result[key])
        with patch.object(c.setup_end,'inspect',side_effect=ValueError('completion failed')) as check:
            with self.assertRaisesRegex(ValueError,'completion failed'):c.inspect_route(self.saved,self.root,'avx2',self.spec['avx2'])
            check.assert_called_once()
