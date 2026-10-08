"""Scalar XOF final-message tail/counter, emitted-body and composition tests."""
import copy
import random
from unittest.mock import patch
import windows_enclave_sha3_batch_chains as c

t=c.finish.scalar_xof


class ScalarXofModelTests:
    def test_scalar_xof_split_every_canonical_bounded_message(self):
        count=0
        for length in range(1025):
            for last in ((0,) if length==0 else range(1,9)):
                bits=0 if length==0 else (length-1)*8+last
                prefix,tail=t.input_partition(length,last)
                self.assertEqual(prefix,bits//8)
                self.assertEqual(tail,length-1 if bits%8 else None)
                self.assertTrue(0<=prefix<=length)
                if tail is not None:self.assertTrue(0<=tail<length)
                count+=1
        self.assertEqual(count,8193)
        for args in ((-1,0),(1025,8),(0,1),(1,0),(1,9),(True,1),(0,False)):
            with self.assertRaises(ValueError):t.input_partition(*args)

    def test_scalar_xof_counter_carry_against_unbounded_reference(self):
        limit=(1<<128)-1;count=0
        for bits in range(8193):
            additional=bits//8
            counters=[0,1,(1<<64)-1,1<<64,limit,limit-additional,max(0,limit-additional-1),
                      min(limit,limit-additional+1)]
            for counter in counters:
                self.assertEqual(t.admit(counter,bits),counter+additional<=limit);count+=1
        rng=random.Random(0x584f46)
        for _ in range(4096):
            counter=rng.getrandbits(128);bits=rng.randrange(8193)
            self.assertEqual(t.admit(counter,bits),counter+bits//8<=limit);count+=1
        self.assertEqual(count,69640)
        for args in ((-1,0),(1<<128,0),(0,-1),(0,8193),(False,0),(0,True)):
            with self.assertRaises(ValueError):t.admit(*args)


class ScalarXofTests:
    def test_scalar_xof_all_emitted_instructions_are_load_bearing(self):
        bodies=self.routes['scalar'][-1];n,lines=t.check_shape(bodies);count=0
        for at in range(len(lines)):
            for bad in (lines[:at]+lines[at+1:],lines[:at]+['ud2']+lines[at+1:]):
                with self.assertRaises(ValueError):
                    t.check_shape(bodies|{n['finish']:n['finish']+':\n'+'\n'.join(bad)})
                count+=1
        self.assertEqual(count,326)

    def test_scalar_xof_lifetimes_rates_suffixes_failure_and_cleanup(self):
        bodies=self.routes['scalar'][-1];n,lines=t.check_shape(bodies);body='\n'.join(lines)
        changes=[('cmpl $6, %r8d','cmpl $7, %r8d'),('cmpl $5, %r8d','cmpl $4, %r8d'),
            ('cmpb $0, 1(%rcx)','cmpb $1, 1(%rcx)'),('leaq 2(%rcx), %rsi','leaq 1(%rcx), %rsi'),
            ('movq 16(%rdx), %r8','movq 8(%rdx), %r8'),('movq 10(%rcx), %r10','movq 18(%rcx), %r10'),
            ('shrq $3, %r8','shrq $2, %r8'),('adcq $0, %r10','addq $0, %r10'),('jb .B33','ja .B33'),
            ('testb $-9, %dil','testb $-8, %dil'),('adcq $-1, %rax','addq $-1, %rax'),
            ('cmovneq %rcx, %rbx','cmoveq %rcx, %rbx'),('movq %rax, %r8','movq %r9, %r8'),
            ('movq %r9, %rdx','movq %rcx, %rdx'),('movq %rbx, %rdx','movq %rsi, %rdx'),
            ('callq '+n['updatea8'],'callq '+n['update88']),('callq '+n['finalize88'],'callq '+n['finalizea8']),
            ('testb %al, %al','testb %cl, %cl'),('jne .B33','je .B33'),
            ('movb $3, 32(%rsp)','movb $3, 31(%rsp)'),('movb $5, 32(%rsp)','movb $4, 32(%rsp)'),
            ('movb $4, %r9b','movb $6, %r9b'),('movb $31, %r9b','movb $30, %r9b'),
            ('cmpb $1, 1038(%r14)','cmpb $0, 1038(%r14)'),('movl %edi, %r8d','movl $0, %r8d'),
            ('leaq 34(%r14), %rcx','leaq 35(%r14), %rcx'),('movl $16, %edx','movl $15, %edx'),
            ('leaq 1038(%r14), %rcx','leaq 1039(%r14), %rcx'),('callq '+c.lifecycle.ZERO,'nop'),
            ('movb $1, 1(%r14)','movb $0, 1(%r14)')]
        for old,new in changes:
            self.assertIn(old,body)
            with self.assertRaises(ValueError):t.check_shape(bodies|{n['finish']:n['finish']+':\n'+body.replace(old,new)})
        self.assertEqual(len(changes),30)

    def test_scalar_xof_helper_abi_and_replay_bindings(self):
        args=self.update_fixture('scalar');caller=c.finish.inspect(*args)
        bodies,_,ir,_,prior=args[:5];result=t.inspect(bodies,ir,prior,caller);count=0
        for name in result['helpers']:
            row=next(l for l in ir.splitlines() if l.startswith('define ') and '@'+name+'(' in l)
            self.assertIn('nonnull',row)
            with self.assertRaises(ValueError):t.inspect(bodies,ir.replace(row,row.replace('nonnull','')),prior,caller)
            bad=copy.deepcopy(prior);bad['exact_body_reference_extent_and_abi'][name]['abi_sha256']='0'*64
            with self.assertRaises(ValueError):t.inspect(bodies,ir,bad,caller)
            count+=2
        n=t.names(bodies)
        for rate in ('a8','88'):
            changes=[('update'+rate,'dereferenceable(1040)','dereferenceable(1039)'),
                ('update'+rate,'zeroext i1','zeroext i8'),('update'+rate,'readonly ',' '),
                ('finalize'+rate,'dereferenceable_or_null(1)','dereferenceable(1)'),
                ('finalize'+rate,'range(i8 4, 32)','range(i8 0, 32)'),
                ('finalize'+rate,'range(i8 3, 6)','range(i8 3, 7)')]
            for key,old,new in changes:
                row=next(l for l in ir.splitlines() if l.startswith('define ') and '@'+n[key]+'(' in l)
                self.assertIn(old,row)
                with self.assertRaises(ValueError):t.arguments(ir.replace(row,row.replace(old,new)),n)
                count+=1
        self.assertEqual(count,22)

    def test_scalar_xof_actual_caller_and_incomplete_scope(self):
        args=self.update_fixture('scalar');caller=c.finish.inspect(*args)
        bodies,_,ir,_,prior=args[:5];result=t.inspect(bodies,ir,prior,caller)
        for key,value in (('input_pointer_preserved_to_descriptor',False),
            ('partial_tail_only_after_nonempty_shape_check',False),
            ('outer_rejection_clears_entire_output_and_quarantines',False),('maximum_input_bytes',1025),
            ('maximum_input_bits',8193),('descriptor_bytes',31),('state_span',[16,1151])):
            with self.assertRaises(ValueError):t.inspect(bodies,ir,prior,caller|{key:value})
        bad=copy.deepcopy(caller);bad['functions']['finish_xof']='wrong'
        with self.assertRaises(ValueError):t.inspect(bodies,ir,prior,bad)
        with self.assertRaises(ValueError):t.inspect(bodies,ir,prior|{'prior_semantics_replayed':False},caller)
        for name in result['helpers']:
            bad=copy.deepcopy(prior);del bad['exact_body_reference_extent_and_abi'][name]
            with self.assertRaises(ValueError):t.inspect(bodies,ir,bad,caller)
        with patch.object(t,'inspect',side_effect=ValueError('scalar XOF failed')):
            with self.assertRaisesRegex(ValueError,'scalar XOF failed'):c.finish.inspect(*args)
        self.assertEqual(len(caller['lower_finalizer_review_pending']),2)
        for key in ('output_squeeze_qualified','state_construction_qualified','private_frame_erasure_qualified',
                    'all_unwind_paths_qualified','whole_image_qualified'):
            self.assertFalse(result[key])
