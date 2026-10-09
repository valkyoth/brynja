"""Framing addresses must retain their original root, guarded lane and extent."""
import copy
import re
from unittest.mock import patch
import windows_enclave_sha3_simd_workspace_effects as t


class SimdWorkspaceEffectsModelTests:
    def test_simd_workspace_effects_affine_origins_and_rejections(self):
        code=['movq 1104(%rbp), %rbx','leaq 3584(%rbx), %rax',
            'movq %rax, 824(%rbp)','callq helper','movq 824(%rbp), %r14','retq']
        edges={i:[i+1] for i in range(5)}|{5:[]};spans={2:(824,832)}
        states=t.definitions(code,edges,spans)
        self.assertEqual(t.expression(code,states,5,'r14'),{('workspace',3584,0)})
        for at,line in ((0,'movq 1112(%rbp), %rbx'),(0,'movl 1104(%rbp), %ebx'),
            (2,'movb %al, 824(%rbp)'),(4,'movq %rax, %r14'),(4,'movl 824(%rbp), %r14d')):
            bad=code.copy();bad[at]=line
            with self.assertRaises(ValueError):t.expression(bad,t.definitions(bad,edges,spans),5,'r14')
        bad=code.copy();bad[3]='movq %rcx, 820(%rbp)'
        with self.assertRaises(ValueError):
            t.expression(bad,t.definitions(bad,edges,spans|{3:(820,828)}),5,'r14')
        code=['nop','movq 1104(%rbp), %rax','movq %rax, %rsi','retq']
        edges={0:[1,2],1:[2],2:[3],3:[]}
        with self.assertRaises(ValueError):t.expression(code,t.definitions(code,edges,{}),3,'rsi')
        code=['movq %rax, %rsi','movq %rsi, %rax','retq'];edges={0:[1],1:[0,2],2:[]}
        with self.assertRaises(ValueError):t.expression(code,t.definitions(code,edges,{}),2,'rax')


class SimdWorkspaceEffectsSavedTests:
    def simd_workspace_effects_fixture(self):
        import windows_enclave_sha3_batch_chains as c
        r=c.inspect_route(self.saved,self.root,'simd',self.spec['simd'])
        _,_,asm,_,_,b=self.routes['simd']
        return (b,asm,*[r[k] for k in ('simd_digest','simd_public_framing','simd_control_write_effects')])

    def test_simd_workspace_effects_all_store_destinations(self):
        b,asm,*rest=self.simd_workspace_effects_fixture();name=rest[-1]['function'];code=t.life.code(b[name]);count=0
        for at in sorted(t.SITES):
            op,args=t.origins.instruction(code[at]);dest=args[-1]
            width=2 if at==149 else 1 if at in (364,423,424,447) else 8
            replacements=[re.sub(r'\(%\w+', '(%rbp',code[at]),
                code[at].rsplit(dest,1)[0]+re.sub(r'^\d*\(',lambda m:str(int(m[0][:-1] or 0)+1)+'(',dest),
                ('movw %ax, ' if width!=2 else 'movb %al, ')+dest]
            for line in replacements:
                bad=code.copy();bad[at]=line
                with self.assertRaises(ValueError):t.inspect(b|{name:name+':\n'+'\n'.join(bad)},asm,*rest)
                count+=1
        self.assertEqual(count,57)
        print('Keccak framing workspace store base/offset/width mutants rejected: 57')

    def test_simd_workspace_effects_guard_and_cfg_bypass(self):
        b,asm,*rest=self.simd_workspace_effects_fixture();name=rest[-1]['function'];code=t.life.code(b[name])
        edges,_=t.origins.reconcile.graph(code,asm);spans,_,_=t.origins.frame_writes(code,edges)
        states=t.definitions(code,edges,spans);t.guarded_lane(code,edges,states)
        for at,line in ((86,'movq %rsi, %rax'),(89,'leaq 2(%rax), %r12'),
            (94,'cmpq $4, %rax'),(95,'jae .B212'),(98,'imulq $155, %rax, %rdi')):
            bad=code.copy();bad[at]=line
            with self.assertRaises(ValueError):t.guarded_lane(bad,edges,states)
        for dest in (89,94,95,96,98,149,425,448):
            bad=copy.deepcopy(edges);bad[0].append(dest)
            with self.assertRaises(ValueError):t.guarded_lane(code,bad,states)
        bad=copy.deepcopy(states);bad[98]['rax']=frozenset({86,90})
        with self.assertRaises(ValueError):t.guarded_lane(code,edges,bad)
        print('Keccak lane guard/definition/CFG bypass mutants rejected: 14')

    def test_simd_workspace_effects_original_roots_spills_and_strides(self):
        b,asm,*rest=self.simd_workspace_effects_fixture();name=rest[-1]['function'];code=t.life.code(b[name])
        changes=((14,'movq 1112(%rbp), %rbx'),(74,'leaq 3585(%rbx), %rax'),
            (75,'movq %rax, 832(%rbp)'),(99,'movq 936(%rbp), %r15'),
            (100,'leaq (%r15,%rsi), %rbx'),(101,'leaq (%r15,%rsi), %rcx'),
            (102,'addq $33, %rcx'),(104,'movl %ecx, 944(%rbp)'),
            (106,'leaq (%r15,%rsi), %r14'),(107,'addq $105, %r14'),
            (112,'movq %rbx, 944(%rbp)'),(150,'movq 936(%rbp), %rax'),
            (220,'movq 944(%rbp), %r14'),(297,'movq 944(%rbp), %r14'),
            (352,'movq 1112(%rbp), %rbx'),(354,'movq 944(%rbp), %r14'),
            (423,'setae 5251(%rbx,%r12,2)'),(425,'movq %r11, 3512(%rbx,%r12,4)'))
        for at,line in changes:
            bad=code.copy();bad[at]=line
            with self.assertRaises(ValueError):t.inspect(b|{name:name+':\n'+'\n'.join(bad)},asm,*rest)
        print('Keccak workspace root/spill/stride mutants rejected: '+str(len(changes)))

    def test_simd_workspace_effects_geometry_prerequisites_and_integration(self):
        args=self.simd_workspace_effects_fixture();b,asm,caller,framing,previous=args;r=t.inspect(*args)
        self.assertEqual(len(r['write_effects']),19)
        self.assertEqual(sum(len(e['lane_write_spans']) for e in r['write_effects']),76)
        self.assertEqual(len(r['pending_non_frame_store_sites']),14)
        self.assertEqual(len(r['pending_callee_effect_sites']),53)
        self.assertTrue(r['indirect_effects_and_nonvolatile_abi_preservation_required'])
        self.assertFalse(r['allocation_lifetimes_and_private_frame_exception_cleanup_qualified'])
        for obj,key in ((framing,'public_framing_fields_and_output_offsets_checked'),
            (previous,'original_control_executor_result_and_authority_pointer_roots_checked')):
            with patch.dict(obj,{key:False}):
                with self.assertRaises(ValueError):t.inspect(*args)
        for key,span in (('workspace',[-64,5195]),('result',[3520,4000]),('workspace',[-1200,4060])):
            bad=copy.deepcopy(caller['geometry']);bad['executor_entry_objects'][key]=span
            with patch.dict(caller,{'geometry':bad}),patch.object(t.origins.reconcile.terminal.shape.reject.digest,
                    'geometry',return_value=bad):
                with self.assertRaises(ValueError):t.inspect(*args)
        import windows_enclave_sha3_batch_chains as c
        with patch.object(t,'inspect',side_effect=ValueError('workspace effects failed')) as check:
            with self.assertRaisesRegex(ValueError,'workspace effects failed'):
                c.inspect_route(self.saved,self.root,'simd',self.spec['simd'])
            check.assert_called_once()
