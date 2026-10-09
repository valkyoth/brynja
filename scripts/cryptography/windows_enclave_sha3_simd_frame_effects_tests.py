"""Frame effect bounds, complete reaching origins and physical separation negatives."""
from unittest.mock import patch
import windows_enclave_sha3_simd_frame_effects as t


class SimdFrameEffectsModelTests:
    def test_simd_frame_effects_predecessors_cycles_and_clobbers(self):
        code=['leaq -80(%rbp), %r8','nop','leaq 784(%rbp), %r8','movq %r8, %rax','retq']
        edges={0:[1],1:[2,3],2:[3],3:[4],4:[]};states=t.definitions(code,edges)
        self.assertEqual(t.frame_origins(code,states,4,'rax'),{-80,784})
        for replacement in ('movl %r8d, %r8d','callq helper','leaq (%r8,%rax), %r8','divq %rbx'):
            bad=code.copy();bad[2]=replacement
            # DIV changes RAX/RDX but correctly preserves a live R8.
            if replacement.startswith('div'):
                states=t.definitions(bad,edges)
                self.assertEqual(states[3]['rax'],{-1,2});continue
            with self.assertRaises(ValueError):t.frame_origins(bad,t.definitions(bad,edges),4,'rax')
        code=['movq %rax, %r8','movq %r8, %rax','retq'];edges={0:[1],1:[0,2],2:[]}
        with self.assertRaises(ValueError):t.frame_origins(code,t.definitions(code,edges),2,'rax')

    def test_simd_frame_effects_physical_overlap_rejections(self):
        t.disjoint([(-80,175),(177,432),(784,792)])
        for span in ((-129,-120),(992,1001),(448,449),(455,457),(447,449),(456,464),
            (1104,1112),(1112,1120),(0,0),(10,9)):
            with self.assertRaises(ValueError):t.disjoint([span])
        for spans,protected in (([],t.PROTECTED),([(-80,175)],())):
            with self.assertRaises(ValueError):t.disjoint(spans,protected)
        for skip in (7,16,-1,True):
            with self.assertRaises(ValueError):t.encoding_effects([],skip)


class SimdFrameEffectsSavedTests:
    def simd_frame_effects_fixture(self):
        import windows_enclave_sha3_batch_chains as c
        r=c.inspect_route(self.saved,self.root,'simd',self.spec['simd'])
        _,_,asm,_,_,b=self.routes['simd']
        return b,asm,r['simd_digest'],r['simd_wipe_pointer_origins'],r['simd_public_framing']

    def test_simd_frame_effects_runtime_slices_and_semantic_mutations(self):
        b,asm,*rest=self.simd_frame_effects_fixture();name=rest[1]['function'];code=t.life.code(b[name]);count=0
        for begin,end in ((187,200),(264,277)):
            for skip in range(8,16):
                r=t.encoding_effects(code[begin:end],skip)
                self.assertEqual(r[0]['write'][1],175);self.assertEqual(r[1]['read'][1],800)
            for at in range(begin,end):
                bad=code[begin:end].copy();bad[at-begin]='ud2'
                with self.assertRaises(ValueError):t.encoding_effects(bad,8)
                count+=1
            for old,new in (('movl $16, %ebx','movl $17, %ebx'),('addq $239, %r8','addq $240, %r8'),
                ('addq $784, %r14','addq $783, %r14'),('addq $-80, %rcx','addq $-79, %rcx'),
                ('leaq -80(%rbp), %rcx','leaq -79(%rbp), %rcx'),
                ('xorl %edx, %edx','movl $1, %edx'),('callq memset','callq memcpy')):
                bad=[new if line==old else line for line in code[begin:end]]
                with self.assertRaises(ValueError):t.encoding_effects(bad,8)
                count+=1
        self.assertEqual(count,40)
        print('Keccak public frame runtime effects: 16 cases; 40 slice/semantic mutants rejected')

    def test_simd_frame_effects_actual_definitions_and_store_mutations(self):
        b,asm,*rest=self.simd_frame_effects_fixture();name=rest[1]['function'];code=t.life.code(b[name])
        r=t.inspect(b,asm,*rest);count=0
        self.assertEqual(len(r['frame_alias_store_sites']),17)
        for at in t.VECTOR_SITES:
            for replacement in ('vmovups %ymm0, 448(%rax)','vmovups %ymm0, (%rcx)','movq %rax, (%rax)'):
                bad=code.copy();bad[at]=replacement
                with self.assertRaises(ValueError):t.inspect(b|{name:name+':\n'+'\n'.join(bad)},asm,*rest)
                count+=1
        for at,line in ((205,'leaq 178(%rbp), %rax'),(282,'leaq 178(%rbp), %rax'),
            (1026,'leaq 448(%rbp), %r8'),(1030,'leaq 456(%rbp), %r8'),
            (1033,'movl %r9d, (%r8)'),(184,'movl $1, %r8d'),(261,'movl $1, %r8d'),
            (185,'adcq $15, %r8'),(262,'adcq $15, %r8'),(178,'movl $14, %r8d')):
            bad=code.copy();bad[at]=line
            with self.assertRaises(ValueError):t.inspect(b|{name:name+':\n'+'\n'.join(bad)},asm,*rest)
            count+=1
        self.assertEqual(count,58)
        print('Keccak all-predecessor frame alias/encoding domain mutants rejected: 58')

    def test_simd_frame_effects_caller_geometry_and_integration(self):
        args=self.simd_frame_effects_fixture();b,asm,caller,wipe,framing=args;r=t.inspect(*args)
        self.assertEqual(r['child_frame_origin_in_parent'],-1200)
        self.assertEqual(len(r['pending_non_frame_store_sites']),57)
        self.assertEqual(len(r['pending_callee_effect_sites']),53)
        self.assertFalse(r['other_indirect_effects_and_original_allocation_lifetimes_qualified'])
        self.assertFalse(r['private_frame_and_exception_cleanup_qualified'])
        for obj,key in ((wipe,'all_normal_predecessor_direct_pointer_origins_checked'),
            (framing,'public_framing_fields_and_output_offsets_checked')):
            with patch.dict(obj,{key:False}):
                with self.assertRaises(ValueError):t.inspect(*args)
        with patch.dict(caller['geometry'],{'frame_allocation_bytes':9104}):
            with self.assertRaises(ValueError):t.inspect(*args)
        name=caller['functions']['digest'];parent=t.life.code(b[name]);parent[8]='movl $9104, %eax'
        with self.assertRaises(ValueError):t.inspect(b|{name:name+':\n'+'\n'.join(parent)},*args[1:])
        import windows_enclave_sha3_batch_chains as c
        with patch.object(t,'inspect',side_effect=ValueError('frame effects failed')) as check:
            with self.assertRaisesRegex(ValueError,'frame effects failed'):
                c.inspect_route(self.saved,self.root,'simd',self.spec['simd'])
            check.assert_called_once()
