"""Wipe calls reject changed lengths, stale roots and crossed allocations."""
import copy
import re
from unittest.mock import patch
import windows_enclave_sha3_simd_clear_effects as t


class SimdClearEffectsModelTests:
    def test_simd_clear_effects_length_predecessors_and_widths(self):
        code=['movl $1024, %edx','movq $1024, %rdx','callq zero']
        t.constant_length(code,{2:{'rdx':{0,1}}},2,1024)
        for defs in (set(),{-1},{0,-1}):
            with self.assertRaises(ValueError):t.constant_length(code,{2:{'rdx':defs}},2,1024)
        for line in ('movl $1025, %edx','movl $0, %edx','movw $1024, %dx',
            'movq %rax, %rdx','movl $1024, %rdx','movq $1024, %edx','callq helper'):
            with self.assertRaises(ValueError):t.constant_length([line],{1:{'rdx':{0}}},1,1024)
        for value in (0,5261):
            with self.assertRaises(ValueError):t.constant_length([f'movl ${value}, %edx'],{1:{'rdx':{0}}},1,value)

    def test_simd_clear_effects_physical_separation_and_bounds(self):
        geometry=t.o.reconcile.terminal.shape.reject.digest.geometry()
        effects=[dict(site=1,root='workspace',write_spans=[[0,5260]]),
            dict(site=2,root='staging',write_spans=[[0,1024]])]
        self.assertEqual(len(t.separate(effects,geometry)),2)
        for root,span in (('workspace',[-1,1]),('workspace',[0,5261]),('staging',[0,1025]),
            ('staging',[1,1]),('staging',[2,1]),('unknown',[0,1])):
            with self.assertRaises(ValueError):t.separate([dict(site=1,root=root,write_spans=[span])],geometry)
        with self.assertRaises(ValueError):t.separate([],geometry)
        for key,span in (('result',[0,136]),('inputs',[5200,5216]),('workspace',[-1200,4060]),('staging',[5200,6225])):
            bad=copy.deepcopy(geometry);bad['executor_entry_objects'][key]=span
            with self.assertRaises(ValueError):t.separate(effects,bad)


class SimdClearEffectsSavedTests:
    def simd_clear_effects_fixture(self):
        import windows_enclave_sha3_batch_chains as c
        r=c.inspect_route(self.saved,self.root,'simd',self.spec['simd']);_,_,asm,_,_,b=self.routes['simd']
        return (b,asm,*[r[k] for k in ('simd_digest','simd_wipe_pointer_origins','simd_scalar_fallback','simd_loop_write_effects')])

    def test_simd_clear_effects_callees_receivers_and_lengths(self):
        b,asm,*rest=self.simd_clear_effects_fixture();name=rest[-1]['function'];code=t.life.code(b[name]);count=0
        for at in sorted(t.SITES):
            for site,line in ((at,'callq wrong_wipe'),(at-1,'movq %rbp, %rcx')):
                bad=code.copy();bad[site]=line
                with self.assertRaises(ValueError):t.inspect(b|{name:name+':\n'+'\n'.join(bad)},asm,*rest)
                count+=1
        edges,_=t.o.reconcile.graph(code,asm);spans,_,_=t.o.frame_writes(code,edges)
        states=t.w.definitions(code,edges,spans,t.SLOTS)
        for at in set(t.FRAMES)|set(t.SCRATCH)|set(t.STAGING):
            self.assertEqual(len(states[at]['rdx']),1)
            site=next(iter(states[at]['rdx']));line=code[site]
            for replacement in (re.sub(r'\$(\d+)',lambda m:'$'+str(int(m[1])+1),line),'movb $0, %dl'):
                bad=code.copy();bad[site]=replacement
                with self.assertRaises(ValueError):t.inspect(b|{name:name+':\n'+'\n'.join(bad)},asm,*rest)
                count+=1
        self.assertEqual(count,54)
        print('Keccak clearing callee/receiver/length mutations rejected: 54')

    def test_simd_clear_effects_frame_guard_and_subobject_origins(self):
        b,asm,*rest=self.simd_clear_effects_fixture();name=rest[-1]['function'];code=t.life.code(b[name])
        changes=((74,'leaq 3585(%rbx), %rax'),(75,'movl %eax, 824(%rbp)'),
            (99,'movq 936(%rbp), %r15'),(102,'addq $33, %rcx'),(107,'addq $105, %r14'),
            (116,'addq $156, %rcx'),(591,'leaq 2721(%rbx), %rax'),(593,'leaq 4209(%rbx), %rax'),
            (597,'leaq 4961(%rbx), %rax'),(599,'leaq 5001(%rbx), %rax'),(601,'leaq 5041(%rbx), %rax'),
            (1073,'movq 496(%rbp), %r14'),(1307,'movq 496(%rbp), %rsi'),
            (1316,'movq 720(%rbp), %rcx'),(1319,'movq 712(%rbp), %rcx'),(1328,'movq 488(%rbp), %rcx'))
        for at,line in changes:
            bad=code.copy();bad[at]=line
            with self.assertRaises(ValueError):t.inspect(b|{name:name+':\n'+'\n'.join(bad)},asm,*rest)
        edges,_=t.o.reconcile.graph(code,asm);spans,_,_=t.o.frame_writes(code,edges)
        states=t.w.definitions(code,edges,spans,t.SLOTS)
        for site in t.FRAMES:
            bad=copy.deepcopy(edges);bad[0].append(site)
            with self.assertRaises(ValueError):t.guarded_frame_calls(code,bad,states)
        print('Keccak clear subobject/root mutations rejected: 16; guard bypasses: 4')

    def test_simd_clear_effects_complete_scope_prerequisites_and_integration(self):
        args=self.simd_clear_effects_fixture();b,asm,caller,wipe,scalar,previous=args;r=t.inspect(*args)
        self.assertEqual(len(r['call_sites']),16);self.assertEqual(len(r['pending_callee_effect_sites']),37)
        self.assertEqual(len(r['parent_relative_effects']),28)
        self.assertTrue(r['volatile_clear_runtime_and_win64_nonvolatile_abi_required'])
        self.assertFalse(r['allocation_lifetimes_and_private_frame_exception_cleanup_qualified'])
        self.assertEqual(r['pending_non_frame_store_sites'],[])
        for obj,key in ((wipe,'all_normal_predecessor_direct_pointer_origins_checked'),
            (scalar,'whole_scalar_owner_wiped_before_checked_report_increment'),(previous,'direct_executor_store_inventory_assigned')):
            with patch.dict(obj,{key:False}):
                with self.assertRaises(ValueError):t.inspect(*args)
        for obj,key,value in ((caller['helpers']['geometry'],'scalar_owner_bytes',1041),
            (caller['helpers']['functions'],'workspace_wipe','wrong'),
            (previous,'pending_callee_effect_sites',[]),(previous,'pending_non_frame_store_sites',[619])):
            with patch.dict(obj,{key:value}):
                with self.assertRaises(ValueError):t.inspect(*args)
        import windows_enclave_sha3_batch_chains as c
        with patch.object(t,'inspect',side_effect=ValueError('clear effects failed')) as check:
            with self.assertRaisesRegex(ValueError,'clear effects failed'):
                c.inspect_route(self.saved,self.root,'simd',self.spec['simd'])
            check.assert_called_once()
