"""Saved AVX2 cSHAKE arithmetic, scratch reuse and normal-failure regressions."""
import copy
import random
from unittest.mock import patch
import windows_enclave_sha3_batch_chains as c

t=c.avx2_cshake


def reference(rate,name,custom):
    def width(value):
        n=1
        while value>=256:n+=1;value//=256
        return n+1
    bits=(width(rate)+width(name)+width(custom))*8+name+custom
    if bits>=1<<128:return None
    n=(bits+7)//8
    return dict(bits=bits,bytes=n,expected=((n+rate-1)//rate)*rate if name or custom else 0,
        remaining=name,custom_bits=custom,phase=0 if name or custom else 2,
        customized=bool(name or custom),prefix=[1,rate] if name or custom else [])


class Avx2CshakeModelTests:
    def test_avx2_cshake_counts_and_two_carry_failures(self):
        rng=random.Random(0xc54a2);maximum=(1<<128)-1;pairs={(0,0)}
        for bit in range(129):
            for delta in (-1,0,1):
                value=(1<<bit)+delta
                if 0<=value<=maximum:pairs.update(((value,0),(0,value),(value,maximum-value)))
        for rate in (136,168):
            for n in range(4096):pairs.add((n,4095-n))
            for boundary in (rate,2*rate,1<<64,1<<125):
                for delta in range(-33,34):
                    value=8*boundary+delta
                    if 0<=value<=maximum:pairs.add((value,0))
        for _ in range(5000):pairs.add((rng.getrandbits(128),rng.getrandbits(128)))
        for rate in (136,168):
            for name,custom in pairs:self.assertEqual(t.counts(rate,name,custom),reference(rate,name,custom))
            self.assertIsNone(t.counts(rate,maximum,0));self.assertIsNone(t.counts(rate,0,maximum))
            n=(maximum-288)//2;custom=maximum-288-n;result=t.counts(rate,n,custom)
            self.assertEqual(result['bits'],maximum);self.assertEqual(result['bytes'],1<<125)
            self.assertLessEqual(result['expected'],(1<<125)+167)
            self.assertIsNone(t.counts(rate,n,custom+1))
        for args in ((136,-1,0),(168,1<<128,0),(135,0,0),(136,True,0),(True,0,0)):
            with self.assertRaises(ValueError):t.counts(*args)
        print('AVX2 cSHAKE arithmetic comparisons:',2*len(pairs))

    def test_avx2_cshake_snapshot_origins_and_reuse_order(self):
        steps=t.snapshot_schedule();deleted=changed=0
        for rate in (136,168):
            for name,custom in ((0,0),(1,0),(0,1),(1<<64,1<<80)):
                result=t.snapshot(rate,name,custom)
                self.assertEqual(result['authority_local_span'],[1280,1288])
                self.assertTrue(result['all_result_origins_saved_before_reuse'])
                self.assertFalse(result['retained_transfers_qualified'])
                for at in range(len(steps)):
                    with self.assertRaises(ValueError):t.snapshot(rate,name,custom,steps[:at]+steps[at+1:])
                    deleted+=1
                for at,step in enumerate(steps):
                    if step[0]!='copy':continue
                    for index in (2,4,5):
                        bad=list(step);bad[index]+=(-1 if index==5 else 1)
                        with self.assertRaises(ValueError):t.snapshot(rate,name,custom,steps[:at]+[tuple(bad)]+steps[at+1:])
                        changed+=1
                for extra in (('encode','custom',1696),('fields',),
                    ('copy','frame',1696,'frame',1697,992),('copy','frame',1696,'frame',31,1),
                    ('copy','frame',4888,'saved',0,1),('copy','frame',1696,'saved',16,1)):
                    with self.assertRaises(ValueError):t.snapshot(rate,name,custom,steps[:4]+[extra]+steps[4:])
                    changed+=1
                # Metadata must not replace the public name encoding before its
                # length is consumed, nor may the original result be reused early.
                for first,second in ((13,14),(11,15),(4,13)):
                    bad=steps.copy();bad[first],bad[second]=bad[second],bad[first]
                    with self.assertRaises(ValueError):t.snapshot(rate,name,custom,bad)
                    changed+=1
        self.assertEqual(deleted,128);self.assertEqual(changed,240)
        print('AVX2 cSHAKE snapshot deletions/bounds/order rejected:',deleted,changed)

    def test_avx2_cshake_prefix_success_and_each_failure_stage(self):
        count=0;values=(0,1,7,8,255,256,65535,65536,1<<64,(1<<120)-1)
        for rate in (136,168):
            for name in values:
                for custom in values:
                    result=t.prefix_path(rate,name,custom)
                    self.assertEqual(result['result'],-1);self.assertFalse(result['published'])
                    self.assertEqual(result['used'],0)
                    self.assertEqual(result['remaining'],name or custom)
                    self.assertEqual(result['phase'],0 if name else 1 if custom else 2)
                    if name or custom:
                        self.assertEqual(result['calls'],['initial','rate_update','name_update','advance'])
                        self.assertEqual(result['emitted'],2+len(t.encode(name))+(len(t.encode(custom)) if name==0 else 0))
                    else:self.assertEqual(result['calls'],['initial'])
                    count+=1
            for name,custom in ((1,0),(0,1),(1<<64,1<<80)):
                for at,fail in enumerate(('initial','rate_update','name_update','advance'),1):
                    result=t.prefix_path(rate,name,custom,fail)
                    self.assertEqual(result['result'],6);self.assertEqual(len(result['calls']),at)
                    self.assertFalse(result['published'])
                    self.assertEqual(result['caller_memory_wipes'],0 if at==1 else 2 if at==4 else 3)
                    self.assertEqual(result['caller_scratch_wipes'],int(at!=1))
                    self.assertEqual(result['prefix_pending_clear'],at!=1)
            for name,custom in (((1<<128)-1,0),(0,(1<<128)-1)):
                result=t.prefix_path(rate,name,custom)
                self.assertFalse(result['prefix_initialized']);self.assertFalse(result['prefix_pending_clear'])
                self.assertTrue(result['local_core_dead']);self.assertEqual(result['caller_memory_wipes'],2)
                self.assertEqual(result['caller_scratch_wipes'],1);self.assertEqual(result['restored_plan_base'],1024)
        self.assertEqual(count,200)
        with self.assertRaises(ValueError):t.prefix_path(136,0,0,'rate_update')


class Avx2CshakeTests:
    def test_avx2_cshake_each_instruction_and_entry_matters(self):
        _,_,asm,_,_,bodies=self.routes['avx2'];name,covered,total=t.shapes.check(bodies,asm)
        self.assertEqual(len(covered),239);self.assertEqual(len(total),467)
        lines=c.lifecycle.code(bodies[name]);count=0
        for at in covered:
            for bad in (lines[:at]+lines[at+1:],lines[:at]+['ud2']+lines[at+1:]):
                with self.assertRaises(ValueError):t.shapes.check(bodies|{name:name+':\n'+'\n'.join(bad)},asm)
                count+=1
        self.assertEqual(count,478)
        body='\n'.join(lines)
        for label in (18,22,23,34,35,37,39,42,43,44,46):
            bad=body.replace('jmp .B49',f'jmp .B{label}')
            self.assertNotEqual(bad,body)
            with self.assertRaises(ValueError):t.shapes.check(bodies|{name:name+':\n'+bad},asm)
        print('AVX2 cSHAKE instruction/entry mutants rejected:',count,11)

    def test_avx2_cshake_carry_helpers_cleanup_and_pointer_mutants(self):
        _,_,asm,_,_,bodies=self.routes['avx2'];name,_,_=t.shapes.check(bodies,asm)
        body='\n'.join(c.lifecycle.code(bodies[name]))
        changes=(('movb $7, %r8b','movb $6, %r8b'),('movl $168, %eax','movl $136, %eax'),
            ('movq 2640(%rsp), %r12','movq 2648(%rsp), %r12'),('leaq 705(%rsp), %rcx','leaq 704(%rsp), %rcx'),
            ('adcq %r14, %r12','addq %r14, %r12'),('jb .B44','jae .B44'),
            ('shldq $61, %rax, %rcx','shldq $60, %rax, %rcx'),('testb $7, %al','testb $3, %al'),
            ('movq %r14, 192(%rsp)','movq %r14, 208(%rsp)'),('leaq 208(%rsp), %rcx','leaq 192(%rsp), %rcx'),
            ('cmoveq %r10, %rax','cmovneq %r10, %rax'),('movw $0, 376(%rsp)','movw $1, 376(%rsp)'),
            ('leaq 704(%rsp), %rcx','leaq 705(%rsp), %rcx'),('cmpb $-1, %al','cmpb $0, %al'),
            ('leaq 376(%rsp), %rcx','leaq 377(%rsp), %rcx'),('callq '+t.shapes.storage.MEMORY_WIPE,'nop'),
            ('callq '+t.shapes.storage.SCRATCH_WIPE,'nop'),('leaq 1024(%rsi), %r13','leaq 1025(%rsi), %r13'),
            ('movb $-1, 1642(%rsp)','movb $0, 1642(%rsp)'),('movb $3, 1666(%rsp)','movb $0, 1666(%rsp)'),
            ('leaq 304(%rsp), %rcx','leaq 305(%rsp), %rcx'),('decq %r12','incq %r12'),
            ('movl 379(%rsp), %eax','movl 378(%rsp), %eax'),('movq %r12, %r8','movq %r14, %r8'))
        for old,new in changes:
            self.assertIn(old,body)
            with self.assertRaises(ValueError):t.shapes.check(bodies|{name:name+':\n'+body.replace(old,new)},asm)
        self.assertEqual(len(changes),24)

    def avx2_cshake_fixture(self):
        bodies,asm,ir,lane,prior,placement,transitions,receiver=self.update_fixture('avx2')
        construction=c.start.inspect(bodies,asm,ir,lane,placement,transitions,receiver)
        direct=c.avx2_start.inspect(bodies,asm,ir,prior,construction,placement)
        return bodies,asm,ir,prior,construction,direct

    def test_avx2_cshake_helpers_abis_and_composition_required(self):
        args=self.avx2_cshake_fixture();bodies,asm,ir,prior,construction,direct=args
        result=t.inspect(*args)
        self.assertTrue(result['cshake_prefix_calls_and_failure_joins_qualified'])
        self.assertFalse(result['retained_constructor_transfers_qualified'])
        self.assertFalse(result['private_frame_erasure_qualified'])
        required=(t.shapes.ENCODE,t.shapes.ABSORB,t.shapes.PREFIX+'4bits',t.shapes.PREFIX+'7advance',
            t.shapes.storage.MEMORY_WIPE,t.shapes.storage.SCRATCH_WIPE,t.life.ZERO)
        for helper in required:
            bad=copy.deepcopy(prior);del bad['exact_body_reference_extent_and_abi'][helper]
            with self.assertRaises(ValueError):t.geometry(ir,bad)
        for old,new in (('noalias',''),('nounwind',''),('align 16','align 8'),('align 32','align 16'),
            ('dereferenceable(258)','dereferenceable(257)'),('dereferenceable(80)','dereferenceable(79)'),
            ('dereferenceable(864)','dereferenceable(863)'),('dereferenceable(234)','dereferenceable(233)'),
            ('dereferenceable(576)','dereferenceable(575)'),('initializes((0, 258))',''),
            ('writeonly',''),('i128 noundef %1','i64 noundef %1'),('readonly captures(address, read_provenance)',''),
            ('range(i64 0, -9223372036854775808)','range(i64 0, -1)')):
            self.assertIn(old,ir)
            with self.assertRaises(ValueError):t.geometry(ir.replace(old,new),prior)
        paths=[(3,('prior_semantics_replayed',))]+[(4,(k,)) for k in ('function',
            'slot_equality_before_indexed_plan_read','rejection_clears_output_bytes','rejection_quarantines_authority')]
        paths += [(4,('geometry','home_offsets_from_entry'))]+[(5,(k,)) for k in ('function','direct_constructor_caller_transfers_qualified')]
        for index,path in paths:
            changed=list(args);changed[index]=copy.deepcopy(changed[index]);node=changed[index]
            for key in path[:-1]:node=node[key]
            node[path[-1]]=False
            with self.assertRaises(ValueError):t.inspect(*changed)
        helper=t.shapes.direct.initial.NAME
        bad=bodies|{helper:bodies[helper].replace('movb\t$-1, 938(%rdi)','movb\t$0, 938(%rdi)')}
        self.assertNotEqual(bad,bodies)
        with self.assertRaises(ValueError):t.inspect(bad,*args[1:])
        with patch.object(c.avx2_cshake,'inspect',side_effect=ValueError('AVX2 prefix failed')) as check:
            with self.assertRaisesRegex(ValueError,'AVX2 prefix failed'):
                c.inspect_route(self.saved,self.root,'avx2',self.spec['avx2'])
            check.assert_called_once()
