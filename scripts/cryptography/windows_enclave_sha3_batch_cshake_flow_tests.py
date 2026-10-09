"""Saved cSHAKE prefix, helper geometry and normal failure regression checks."""
from unittest.mock import patch
import windows_enclave_sha3_batch_chains as c

t=c.cshake_flow


class CshakeFlowModelTests:
    def test_cshake_flow_success_and_empty_prefixes(self):
        count=0
        values=[0,1,7,8,255,256,65535,65536,1<<64,(1<<120)-1]
        for rate in (136,168):
            for name in values:
                for custom in values:
                    result=t.prefix_path(rate,name,custom)
                    self.assertEqual(result['result'],-1)
                    self.assertFalse(result['published'])
                    self.assertEqual(result['used'],0)
                    if not (name or custom):
                        self.assertEqual(result['calls'],[]);self.assertEqual(result['phase'],2)
                        continue
                    data=result['encoded_name'];width=data[0]
                    self.assertEqual(int.from_bytes(bytes(data[1:]),'big'),name)
                    self.assertEqual(len(data),width+1)
                    self.assertTrue(1<=width<=16)
                    self.assertEqual([v[0] for v in result['calls']],['rate_update','name_update','advance'])
                    self.assertEqual(result['remaining'],name or custom)
                    self.assertEqual(result['phase'],0 if name else 1)
                    self.assertEqual(result['emitted'],2+len(data)+(max(1,(custom.bit_length()+7)//8)+1 if name==0 else 0))
                    count+=1
        self.assertEqual(count,198)

    def test_cshake_flow_each_helper_failure_is_terminal(self):
        for rate in (136,168):
            for name,custom in ((0,1),(1,0),(1<<64,1<<80)):
                for index,fail in enumerate(('rate_update','name_update','advance'),1):
                    result=t.prefix_path(rate,name,custom,fail)
                    self.assertEqual(result['result'],6)
                    self.assertFalse(result['published']);self.assertFalse(result['private_frame_erased'])
                    self.assertTrue(result['pending_clear']);self.assertTrue(result['metadata_zero'])
                    self.assertEqual(result['local_wipes'],2);self.assertEqual(result['optional_owner'],0)
                    self.assertEqual(result['phase'],3);self.assertEqual(result['emitted'],0)
                    self.assertEqual(len(result['calls']),index)
            for name,custom in (((1<<128)-1,0),(0,(1<<128)-1)):
                result=t.prefix_path(rate,name,custom)
                self.assertFalse(result['initialized']);self.assertEqual(result['local_wipes'],0)
                self.assertFalse(result['published']);self.assertEqual(result['result'],6)
        with self.assertRaises(ValueError):t.prefix_path(136,1,0,'ignored')


class CshakeFlowTests:
    def test_cshake_flow_every_instruction_is_required(self):
        _,_,asm,_,_,bodies=self.routes['scalar'];name,positions=t.check_shapes(bodies,asm)
        self.assertEqual(len(positions),203)
        lines=c.lifecycle.code(bodies[name]);count=0
        for at in positions:
            for changed in (lines[:at]+lines[at+1:],lines[:at]+['ud2']+lines[at+1:]):
                with self.assertRaises(ValueError):t.check_shapes(bodies|{name:name+':\n'+'\n'.join(changed)},asm)
                count+=1
        self.assertEqual(count,406)
        print('cSHAKE prefix/failure instruction mutants rejected:',count)

    def test_cshake_flow_cleanup_and_status_mutations(self):
        _,_,asm,_,_,bodies=self.routes['scalar'];name,_=t.check_shapes(bodies,asm)
        body='\n'.join(c.lifecycle.code(bodies[name]))
        for old,new in (
            ('movq $2, 1680(%rsp)','movq $3, 1680(%rsp)'),
            ('cmpb $-1, %al','cmpb $0, %al'),('cmpb $0, 1747(%rsp)','cmpb $1, 1747(%rsp)'),
            ('movb $0, 1747(%rsp)','movb $1, 1747(%rsp)'),
            ('leaq 1744(%rsp), %rsi','leaq 1745(%rsp), %rsi'),
            ('movw $768, 1745(%rsp)','movw $512, 1745(%rsp)'),
            ('movb $0, 2788(%rsp)','movb $1, 2788(%rsp)'),
            ('movaps %xmm0, 1728(%rsp)','movaps %xmm0, 1712(%rsp)'),
            ('movzbl 35(%rsp), %r12d','movzbl 36(%rsp), %r12d'),
            ('leaq 1152(%r13), %rbp','leaq 1153(%r13), %rbp'),
            ('movb $6, %al','movb $-1, %al'),
            ('movl $1107, %r8d','movl $1108, %r8d'),
            ('movq 2789(%rsp), %rax','movq 2788(%rsp), %rax'),
            ('movl 2796(%rsp), %eax','movl 2797(%rsp), %eax'),
            ('incq %rbx','decq %rbx'),('decq %rdi','incq %rdi'),
        ):
            self.assertIn(old,body)
            with self.assertRaises(ValueError):t.check_shapes(bodies|{name:name+':\n'+body.replace(old,new)},asm)
        for label in (48,53,72,80):
            bad=body.replace('jmp .B39',f'jmp .B{label}')
            self.assertNotEqual(bad,body)
            with self.assertRaises(ValueError):t.check_shapes(bodies|{name:name+':\n'+bad},asm)

    def cshake_flow_fixture(self):
        args=self.start_fixture('scalar');bodies,asm,ir=args[:3]
        construction=c.start.inspect(*args)
        prior=c.reused_helpers(self.saved,self.root,'scalar',self.routes['scalar'][4],ir,self.spec['scalar'])
        initialized=c.cshake_init.inspect(bodies,asm,prior,construction)
        return bodies,asm,ir,prior,construction,initialized

    def test_cshake_flow_prerequisite_and_abi_changes_rejected(self):
        args=self.cshake_flow_fixture();bodies,asm,ir,prior,construction,initialized=args
        result=t.inspect(*args)
        self.assertTrue(result['initialized_failure_clears_pending_and_typed_owner'])
        self.assertFalse(result['retained_constructor_transfers_qualified'])
        self.assertFalse(result['private_frame_erasure_qualified'])
        required=[t.init.ENCODE,t.WIPE,t.life.ZERO,*[t.init.UPDATE+f'{r:x}_E6updateB6_' for r in (136,168)],
            *[t.init.setup.name(k,r) for k in ('bits','advance') for r in (136,168)]]
        for helper in required:
            changed=prior|{'exact_body_reference_extent_and_abi':{k:v for k,v in
                prior['exact_body_reference_extent_and_abi'].items() if k!=helper}}
            with self.assertRaises(ValueError):t.geometry(ir,changed)
        with self.assertRaises(ValueError):t.geometry(ir,prior|{'prior_semantics_replayed':False})
        for old,new in (('dereferenceable(1040)','dereferenceable(1039)'),('dereferenceable(1120)','dereferenceable(1109)'),
            ('dereferenceable(258)','dereferenceable(257)'),('nounwind',''),('noalias',''),
            ('initializes((0, 258))','initializes((0, 257))'),('writeonly','')):
            self.assertIn(old,ir)
            with self.assertRaises(ValueError):t.geometry(ir.replace(old,new),prior)
        for key in ('function','cshake_initial_arithmetic_and_fields_qualified'):
            with self.assertRaises(ValueError):t.inspect(*args[:5],initialized|{key:False})
        for key in ('function','rejection_clears_output_bytes','successful_placement_destroys_previous_typed_state_first'):
            with self.assertRaises(ValueError):t.inspect(*args[:4],construction|{key:False},initialized)
        with patch.object(c.cshake_flow,'inspect',side_effect=ValueError('cSHAKE prefix failed')) as check:
            with self.assertRaisesRegex(ValueError,'cSHAKE prefix failed'):
                c.inspect_route(self.saved,self.root,'scalar',self.spec['scalar'])
            check.assert_called_once()
