"""Scalar cSHAKE setup arithmetic, scratch lifetime and emitted-body regressions."""
import random
from unittest.mock import patch
import windows_enclave_sha3_batch_chains as c

t=c.cshake_init


def reference(rate,name,custom):
    def encoded_length(value):
        width=1
        while value>=256:width+=1;value//=256
        return width+1
    bits=8*(2+encoded_length(name)+encoded_length(custom))+name+custom
    if bits>=1<<128:return None
    byte_count=(bits+7)//8
    return dict(bits=bits,bytes=byte_count,expected=((byte_count+rate-1)//rate)*rate if name or custom else 0,
        remaining=name,custom_bits=custom,phase=0 if name or custom else 2,
        customized=bool(name or custom),prefix=[1,rate] if name or custom else [])


class CshakeInitModelTests:
    def test_cshake_init_counts_match_independent_framing(self):
        maximum=(1<<128)-1;rng=random.Random(0xc5a4e);pairs={(0,0)}
        for bit in range(129):
            for d in (-1,0,1):
                n=(1<<bit)+d
                if 0<=n<=maximum:pairs.update(((n,0),(0,n),(n,maximum-n)))
        for n in range(4096):pairs.add((n,4095-n));pairs.add((n,0))
        for rate in (136,168):
            for boundary in (rate,rate*2,rate*65536,1<<64,1<<125):
                for d in range(-65,66):
                    n=boundary*8+d
                    if 0<=n<=maximum:pairs.add((n,0))
        for _ in range(10000):pairs.add((rng.getrandbits(128),rng.getrandbits(128)))
        for rate in (136,168):
            for name,custom in pairs:self.assertEqual(t.counts(rate,name,custom),reference(rate,name,custom))
        print('cSHAKE initialization arithmetic comparisons:',2*len(pairs))

    def test_cshake_init_two_carry_rejections_and_rounding_bounds(self):
        maximum=(1<<128)-1
        self.assertEqual(t.add128(t.MASK,1),1<<64)
        self.assertIsNone(t.add128(maximum,1))
        for rate in (136,168):
            self.assertIsNone(t.counts(rate,maximum,0))
            self.assertIsNone(t.counts(rate,0,maximum))
            self.assertIsNone(t.counts(rate,maximum//2,maximum//2))
            # Two17-byte encodings + two-byte rate prefix =288 bits.
            n=(maximum-288)//2;custom=maximum-288-n
            exact=t.counts(rate,n,custom)
            self.assertEqual(exact['bits'],maximum)
            self.assertEqual(exact['bytes'],1<<125)
            self.assertLessEqual(exact['expected'],(1<<125)+167)
            self.assertIsNone(t.counts(rate,n,custom+1))
        for args in ((136,-1,0),(136,1<<128,0),(0,0,0),(136,True,0),(True,0,0)):
            with self.assertRaises(ValueError):t.counts(*args)

    def test_cshake_init_active_fields_prefix_and_padding_are_distinct(self):
        for rate in (136,168):
            for name,custom in ((0,0),(1,0),(0,1),(1<<64,1<<63)):
                result=t.initialization(rate,name,custom)
                self.assertEqual(result['active_setup_span'],[1680,2789])
                self.assertEqual(result['owner_span'],[1748,2788])
                self.assertEqual(result['first_prefix_bytes'],[1,rate] if name or custom else [])
                self.assertFalse(result['padding_initialized'])
                self.assertFalse(result['private_frame_erasure_qualified'])
            self.assertIsNone(t.initialization(rate,(1<<128)-1,0))
        with patch.object(t.setup,'remainder136',return_value=136):
            with self.assertRaises(ValueError):t.counts(136,1,1)


class CshakeInitTests:
    def test_cshake_init_every_instruction_required(self):
        _,_,asm,_,_,bodies=self.routes['scalar'];name,positions=t.check_shapes(bodies,asm)
        self.assertEqual(len(positions),248)
        lines=c.lifecycle.code(bodies[name]);count=0
        for at in positions:
            for changed in (lines[:at]+lines[at+1:],lines[:at]+['ud2']+lines[at+1:]):
                with self.assertRaises(ValueError):t.check_shapes(bodies|{name:name+':\n'+'\n'.join(changed)},asm)
                count+=1
        self.assertEqual(count,496)
        print('cSHAKE initializer instruction mutants rejected:',count)

    def test_cshake_init_checks_carry_rounding_owner_and_prefix(self):
        _,_,asm,_,_,bodies=self.routes['scalar'];name,_=t.check_shapes(bodies,asm)
        body='\n'.join(c.lifecycle.code(bodies[name]))
        for old,new in (
            ('jb .B77','jae .B77'),('jb .B85','jae .B85'),
            ('adcq %r15, %r8','addq %r15, %r8'),('adcq %r15, %rbx','addq %r15, %rbx'),
            ('testb $7, %al','testb $3, %al'),('shldq $61, %rax, %rcx','shldq $60, %rax, %rcx'),
            ('movq $168, 1344(%rsp)','movq $136, 1344(%rsp)'),
            ('-1085102592571150095','-1085102592571150094'),
            ('movl $1040, %r8d','movl $1039, %r8d'),('movb $1, 1747(%rsp)','movb $0, 1747(%rsp)'),
            ('movw $-30719, 1390(%rsp)','movw $-30718, 1390(%rsp)'),
            ('movw $-22527, 1390(%rsp)','movw $-22526, 1390(%rsp)'),
            ('setne 2788(%rsp)','sete 2788(%rsp)'),('cmoveq %rax, %rsi','cmovneq %rax, %rsi'),
            ('leaq 1748(%rsp), %r15','leaq 1747(%rsp), %r15'),
            ('movw $2, 1646(%rsp)','movw $3, 1646(%rsp)'),
        ):
            self.assertIn(old,body)
            with self.assertRaises(ValueError):t.check_shapes(bodies|{name:name+':\n'+body.replace(old,new)},asm)

    def test_cshake_init_rejects_constructor_reentry(self):
        _,_,asm,_,_,bodies=self.routes['scalar'];name,_=t.check_shapes(bodies,asm)
        body='\n'.join(c.lifecycle.code(bodies[name]))
        for label in (18,28):
            bad=body.replace('jmp .B80',f'jmp .B{label}')
            self.assertNotEqual(bad,body)
            with self.assertRaises(ValueError):t.check_shapes(bodies|{name:name+':\n'+bad},asm)

    def test_cshake_init_exact_helpers_and_input_admission_required(self):
        args=self.start_fixture('scalar');bodies,asm=args[:2]
        construction=c.start.inspect(*args)
        prior={'prior_semantics_replayed':True,'exact_body_reference_extent_and_abi':{
            t.ENCODE:None,**{t.UPDATE+f'{r:x}_E6updateB6_':None for r in (136,168)}}}
        result=t.inspect(bodies,asm,prior,construction)
        self.assertTrue(result['cshake_initial_arithmetic_and_fields_qualified'])
        self.assertFalse(result['all_constructor_paths_qualified'])
        for helper in prior['exact_body_reference_extent_and_abi']:
            bad=prior|{'exact_body_reference_extent_and_abi':{k:v for k,v in
                prior['exact_body_reference_extent_and_abi'].items() if k!=helper}}
            with self.assertRaises(ValueError):t.inspect(bodies,asm,bad,construction)
        with self.assertRaises(ValueError):t.inspect(bodies,asm,prior|{'prior_semantics_replayed':False},construction)
        for changed in (construction|{'function':'wrong'},construction|{'slot_equality_before_indexed_plan_read':False},
            construction|{'geometry':construction['geometry']|{'home_offsets_from_entry':[32,40,48]}}):
            with self.assertRaises(ValueError):t.inspect(bodies,asm,prior,changed)
        with patch.object(c.cshake_init,'inspect',side_effect=ValueError('cSHAKE init failed')) as check:
            with self.assertRaisesRegex(ValueError,'cSHAKE init failed'):
                c.inspect_route(self.saved,self.root,'scalar',self.spec['scalar'])
            check.assert_called_once()
