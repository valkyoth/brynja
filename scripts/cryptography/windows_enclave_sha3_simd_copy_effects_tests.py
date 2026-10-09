"""Copies reject clobbered origins, partial lengths, guard bypass and overlap."""
import copy
from unittest.mock import patch
import windows_enclave_sha3_simd_copy_effects as t


class SimdCopyEffectsModelTests:
    def test_simd_copy_effects_constant_lengths_on_all_predecessors(self):
        for reg,low in (('rdx','edx'),('r9','r9d')):
            code=[f'movl $200, %{low}',f'movq $200, %{reg}']
            t.exact_length(code,{2:{reg:{0,1}}},2,reg,low)
            for defs in (set(),{-1},{0,-1}):
                with self.assertRaises(ValueError):t.exact_length(code,{2:{reg:defs}},2,reg,low)
            for line in (f'movl $201, %{low}',f'movl $0, %{low}',f'movw $200, %{low}',
                f'movq %rax, %{reg}',f'movl $200, %{reg}',f'movq $200, %{low}','callq clobber'):
                with self.assertRaises(ValueError):t.exact_length([line],{1:{reg:{0}}},1,reg,low)

    def test_simd_copy_effects_physical_ranges_and_nonoverlap(self):
        geometry=t.o.reconcile.terminal.shape.reject.digest.geometry()
        effects=[dict(site=1,read_root='workspace',read=[1920,2120],write_root='workspace',write=[2720,2920],bytes=200),
            dict(site=2,read_root='child_frame',read=[176,185],write_root='workspace',write=[3705,3714],bytes=9)]
        self.assertEqual(len(t.physical_effects(effects,geometry,-1200)),2)
        for key,value in (('read',[-1,199]),('read',[5061,5261]),('read',[2721,2921]),
            ('read',[1920,2119]),('write',[5260,5460]),('write',[1,1]),
            ('bytes',0),('bytes',201),('bytes',True),('read_root','unknown'),('write_root','child_frame')):
            bad=copy.deepcopy(effects);bad[0][key]=value
            with self.assertRaises(ValueError):t.physical_effects(bad,geometry,-1200)
        for span in ((-129,-120),(992,1001)):
            bad=copy.deepcopy(effects);bad[1]['read']=list(span)
            with self.assertRaises(ValueError):t.physical_effects(bad,geometry,-1200)
        with self.assertRaises(ValueError):t.physical_effects([],geometry,-1200)
        with self.assertRaises(ValueError):t.physical_effects(effects,geometry,-1192)
        bad=copy.deepcopy(geometry);bad['executor_entry_objects']['result']=[-1024,-1000]
        with self.assertRaises(ValueError):t.physical_effects(effects,bad,-1200)


class SimdCopyEffectsSavedTests:
    def simd_copy_effects_fixture(self):
        import windows_enclave_sha3_batch_chains as c
        r=c.inspect_route(self.saved,self.root,'simd',self.spec['simd']);_,_,asm,_,_,b=self.routes['simd']
        return (b,asm,*[r[k] for k in ('simd_digest','simd_public_framing','simd_vector_caller',
            'simd_frame_alias_effects','simd_clear_call_effects')])

    def simd_copy_effects_state(self,b,asm,caller):
        name=caller['functions']['executor'];code=t.life.code(b[name])
        edges,_=t.o.reconcile.graph(code,asm);spans,_,_=t.o.frame_writes(code,edges)
        return name,code,edges,t.w.definitions(code,edges,spans,t.SLOTS)

    def test_simd_copy_effects_framing_length_origin_and_callee_mutations(self):
        b,asm,caller,*rest=self.simd_copy_effects_fixture();name,code,_,states=self.simd_copy_effects_state(b,asm,caller)
        count=0
        for site,(begin,increment,field) in t.FRAMING.items():
            changes=((site,'callq memmove'),(begin,'movl $17, %ebx'),(begin+1,'subq %r9, %rbx'),
                (increment,'leal 2(%rbx), %r8d'),(increment,'leaw 1(%rbx), %r8w'),
                (site-3,f'leaq {field+1}(%r14), %rcx'),(site-2,'leaq 177(%rbp), %rdx'),
                (site-4,'movq 944(%rbp), %r14'),(site-1,'movb $1, %r8b'))
            for at,line in changes:
                bad=code.copy();bad[at]=line
                with self.assertRaises(ValueError):t.inspect(b|{name:name+':\n'+'\n'.join(bad)},asm,caller,*rest)
                count+=1
            for key,defs in (('r8',{-1}),('r8',{increment,-1})):
                bad=copy.deepcopy(states);bad[site][key]=defs
                with self.assertRaises(ValueError):t.framing_lengths(code,bad,site,begin,increment)
        self.assertEqual(count,18)
        print('Keccak framing copy mutations rejected: 18; stale/unknown length predecessors: 4')

    def test_simd_copy_effects_vector_callees_lengths_and_stride_mutations(self):
        b,asm,caller,*rest=self.simd_copy_effects_fixture();name,code,_,states=self.simd_copy_effects_state(b,asm,caller);count=0
        for site,(load,cmp,branch,mul,add,lane) in (t.GATHER|t.SCATTER).items():
            index='rax' if site in t.GATHER else 'rbx';address='r8' if site in t.GATHER else 'rcx'
            changes=[(site,'callq wrong_copy'),(load,f'movl {176+8*lane}(%rbp), %eax'),
                (cmp,f'cmpq $5, %{index}'),(branch,'jg .B227'),
                (mul,f'imulq $201, %{index}, %{address}'),(add,f'addq 944(%rbp), %{address}')]
            for reg,low in (('rdx','edx'),('r9','r9d')):
                self.assertEqual(len(states[site][reg]),1);at=next(iter(states[site][reg]))
                changes.extend(((at,f'movl $201, %{low}'),(at,f'movw $200, %{low}')))
            for at,line in changes:
                bad=code.copy();bad[at]=line
                with self.assertRaises(ValueError):t.inspect(b|{name:name+':\n'+'\n'.join(bad)},asm,caller,*rest)
                count+=1
        self.assertEqual(count,80)
        print('Keccak vector copy callee/guard/stride/length mutations rejected: 80')

    def test_simd_copy_effects_original_roots_and_pointer_restores(self):
        b,asm,caller,*rest=self.simd_copy_effects_fixture();name,code,_,_=self.simd_copy_effects_state(b,asm,caller)
        changes=((589,'leaq 1921(%rbx), %rax'),(590,'movl %eax, 960(%rbp)'),
            (591,'leaq 2721(%rbx), %rax'),(603,'leaq 2921(%rbx), %rax'),
            (605,'leaq 3121(%rbx), %rax'),(607,'leaq 3321(%rbx), %rax'),
            (1083,'movq 728(%rbp), %rcx'),(1094,'movq 736(%rbp), %rcx'),
            (1107,'movq 752(%rbp), %rcx'),(1120,'movq 776(%rbp), %rcx'),
            (1141,'movq 728(%rbp), %r8'),(1160,'movq 736(%rbp), %r8'),
            (1184,'movq 752(%rbp), %r8'),(1205,'movq 776(%rbp), %r8'))
        for at,line in changes:
            bad=code.copy();bad[at]=line
            with self.assertRaises(ValueError):t.inspect(b|{name:name+':\n'+'\n'.join(bad)},asm,caller,*rest)
        print('Keccak copy root/restore mutations rejected: 14')

    def test_simd_copy_effects_guard_bypasses(self):
        b,asm,caller,*_=self.simd_copy_effects_fixture();_,code,edges,states=self.simd_copy_effects_state(b,asm,caller)
        for site in t.FRAMING:
            bad=copy.deepcopy(edges);bad[0].append(site)
            with self.assertRaises(ValueError):t.framing_copies(code,bad,states)
        count=0
        for site,(load,cmp,branch,mul,add,lane) in (t.GATHER|t.SCATTER).items():
            for target in (branch+1,site):
                bad=copy.deepcopy(edges);bad[0].append(target)
                with self.assertRaises(ValueError):t.vector_copies(code,bad,states,caller['helpers']['functions']['copy'])
                count+=1
        self.assertEqual(count,16)
        print('Keccak copy framing guard bypasses: 2; vector guard bypasses: 16 rejected')

    def test_simd_copy_effects_scope_prerequisites_and_integration(self):
        args=self.simd_copy_effects_fixture();b,asm,caller,framing,vector,frame,previous=args;r=t.inspect(*args)
        self.assertEqual(len(r['call_sites']),10);self.assertEqual(len(r['copy_cases']),96)
        self.assertEqual(len(r['pending_callee_effect_sites']),27)
        self.assertEqual(r['pending_non_frame_store_sites'],[])
        self.assertTrue(r['runtime_memcpy_and_win64_nonvolatile_abi_required'])
        self.assertFalse(r['allocation_lifetimes_and_private_frame_exception_cleanup_qualified'])
        for obj,key in ((caller['helpers'],'copy_wrapper_checks_equal_lengths'),
            (framing,'public_framing_fields_and_output_offsets_checked'),
            (vector,'scatter_returns_each_group_lane_to_original_slot'),
            (frame,'bounded_frame_effects_exclude_live_pointer_cells_and_caller_objects'),
            (previous,'original_all_predecessor_receivers_and_lengths_checked')):
            with patch.dict(obj,{key:False}):
                with self.assertRaises(ValueError):t.inspect(*args)
        for obj,key,value in ((caller['helpers'],'copy_leaf_length_limit',199),
            (previous,'pending_callee_effect_sites',[]),(previous,'pending_non_frame_store_sites',[619])):
            with patch.dict(obj,{key:value}):
                with self.assertRaises(ValueError):t.inspect(*args)
        import windows_enclave_sha3_batch_chains as c
        with patch.object(t,'inspect',side_effect=ValueError('copy effects failed')) as check:
            with self.assertRaisesRegex(ValueError,'copy effects failed'):
                c.inspect_route(self.saved,self.root,'simd',self.spec['simd'])
            check.assert_called_once()
