"""Scalar footprints reject stale lanes, clobbered pointers and aliased buffers."""
import copy
from unittest.mock import patch
import windows_enclave_sha3_simd_scalar_effects as t
m=t.m


class SimdScalarEffectsModelTests:
    def test_simd_scalar_effects_numeric_lane_spill_and_pointer_clobbers(self):
        state={k:m.UNKNOWN for k in (*t.o.REGS,*t.SLOTS)}
        state.update(rsi=m.one('number',3),rax=m.one('workspace',4256))
        after=t.transfer('movq %rax, 952(%rbp)',state,(952,960))
        self.assertEqual(after[952],m.one('workspace',4256))
        after=t.transfer('movq %rsi, 952(%rbp)',after,(952,960))
        self.assertEqual(after[952],m.one('number',3))
        after=t.transfer('movq %rax, %rsi',after)
        self.assertEqual(t.transfer('movq 952(%rbp), %rsi',after)['rsi'],m.one('number',3))
        self.assertEqual(t.transfer('movl 952(%rbp), %esi',after)['rsi'],m.one('number',3))
        for line,span in (('movl %esi, 952(%rbp)',(952,956)),
            ('movq %rax, 948(%rbp)',(948,956)),('movb %al, 959(%rbp)',(959,960))):
            self.assertEqual(t.transfer(line,after,span)[952],m.UNKNOWN)
        for line in ('movl %eax, %esi','movb %al, %sil'):
            self.assertEqual(t.transfer(line,state)['rsi'],m.UNKNOWN)
        self.assertEqual(t.transfer('callq helper',state)['rax'],m.UNKNOWN)
        self.assertEqual(t.transfer('callq helper',state)['rsi'],state['rsi'])
        for lane in (-1,4,True):
            with self.assertRaises(ValueError):t.check_lane([],{}, {},lane,{})

    def test_simd_scalar_effects_four_buffer_noalias_and_geometry(self):
        geometry=t.o.reconcile.terminal.shape.reject.digest.geometry()
        self.assertEqual(len(t.kernel_separation(t.KERNEL,geometry)),4)
        for regions in ((),t.KERNEL[:3],t.KERNEL+(t.KERNEL[0],),
            ((4256,4457),*t.KERNEL[1:]),(t.KERNEL[0],(4400,4440),*t.KERNEL[2:]),
            (*t.KERNEL[:3],(5040,5249))):
            with self.assertRaises(ValueError):t.kernel_separation(regions,geometry)
        for key,span in (('workspace',[-64,5195]),('workspace',[-1200,4060]),('result',[4900,5100])):
            bad=copy.deepcopy(geometry);bad['executor_entry_objects'][key]=span
            with self.assertRaises(ValueError):t.kernel_separation(t.KERNEL,bad)


class SimdScalarEffectsSavedTests:
    def simd_scalar_effects_fixture(self):
        import windows_enclave_sha3_batch_chains as c
        r=c.inspect_route(self.saved,self.root,'simd',self.spec['simd']);_,_,asm,_,_,b=self.routes['simd']
        return (b,asm,*[r[k] for k in ('simd_digest','simd_scalar_fallback',
            'simd_frame_alias_effects','simd_copy_call_effects')])

    def simd_scalar_effects_state(self,b,asm):
        n=t.shape.names(b);code=t.life.code(b[n['executor']]);edges,_=t.o.reconcile.graph(code,asm)
        spans,_,_=t.o.frame_writes(code,edges);states=t.w.definitions(code,edges,spans,t.SLOTS)
        return n,code,edges,spans,states

    def test_simd_scalar_effects_copy_and_kernel_call_mutations(self):
        b,asm,*rest=self.simd_scalar_effects_fixture();n,code,_,_,_=self.simd_scalar_effects_state(b,asm)
        changes=[(at,'callq wrong_callee') for at in t.SITES]
        changes.extend(((1296,'imulq $201, %rsi, %rbx'),(1297,'addq 704(%rbp), %rbx'),
            (1300,'movq 960(%rbp), %rcx'),(1301,'movl %ecx, %esi'),(1302,'movq %rsi, %r8'),
            (1306,'movq %rbx, %rcx'),(1307,'movq 712(%rbp), %rsi'),(1308,'movq %rbx, %rdx'),
            (1309,'movq 488(%rbp), %r8'),(1310,'movq 704(%rbp), %r9'),
            (1323,'movq %rsi, %rcx'),(1324,'movq 960(%rbp), %r8')))
        for at,reg in ((1298,'edx'),(1299,'r9d'),(1321,'edx'),(1322,'r9d')):
            changes.extend(((at,f'movl $201, %{reg}'),(at,f'movw $200, %{reg}')))
        for at,line in changes:
            bad=code.copy();bad[at]=line
            with self.assertRaises(ValueError):t.inspect(b|{n['executor']:n['executor']+':\n'+'\n'.join(bad)},asm,*rest)
        self.assertEqual(len(changes),23)
        print('Keccak scalar callee/stride/argument/length mutations rejected: 23')

    def test_simd_scalar_effects_original_roots_and_lane_restore_mutations(self):
        b,asm,*rest=self.simd_scalar_effects_fixture();n,code,_,_,_=self.simd_scalar_effects_state(b,asm)
        changes=((589,'leaq 1921(%rbx), %rax'),(595,'leaq 4257(%rbx), %rax'),
            (597,'leaq 4961(%rbx), %rax'),(599,'leaq 5001(%rbx), %rax'),(601,'leaq 5041(%rbx), %rax'),
            (596,'movl %eax, 704(%rbp)'),(1254,'movl $1, %esi'),(1257,'addq $2, %rsi'),
            (1258,'cmpq $5, %rsi'),(1259,'jne .B206'),(1261,'movq 704(%rbp), %rax'),
            (1295,'movl %esi, 952(%rbp)'),(1295,'movq %rax, 952(%rbp)'),
            (1333,'movq 960(%rbp), %rsi'),(1333,'movq 952(%rbp), %rdi'))
        for at,line in changes:
            bad=code.copy();bad[at]=line
            with self.assertRaises(ValueError):t.inspect(b|{n['executor']:n['executor']+':\n'+'\n'.join(bad)},asm,*rest)
        print('Keccak scalar root/induction/restore mutations rejected: 15')

    def test_simd_scalar_effects_external_entry_and_internal_bypasses(self):
        b,asm,*_=self.simd_scalar_effects_fixture();n,code,edges,spans,states=self.simd_scalar_effects_state(b,asm)
        for at in (1254,1255,1257,1258,1259,1260,1295,1303,1311,1325,1333):
            bad=copy.deepcopy(edges);bad[0].append(at)
            with self.assertRaises(ValueError):t.entry(code,bad,states)
        for at,dest in ((1260,1303),(1295,1311),(1307,1337),(1333,1260),(1260,1325)):
            bad=copy.deepcopy(edges);bad[at].append(dest)
            with self.assertRaises(ValueError):t.check_lane(code,bad,spans,0,n)
        print('Keccak scalar external-entry bypasses rejected: 11; internal bypasses: 5')

    def test_simd_scalar_effects_four_lane_population_and_restore_proof(self):
        args=self.simd_scalar_effects_fixture();r=t.inspect(*args)
        self.assertEqual(r['call_sites'],[1303,1311,1325])
        self.assertEqual([v['reachable_positions'] for v in r['per_lane_effects']],[82]*4)
        self.assertEqual([v['backedges'] for v in r['per_lane_effects']],[[1259],[1259],[1259],[]])
        self.assertEqual(len(r['copy_parent_relative_effects']),8)
        self.assertEqual(len(r['kernel_parent_relative_effects']),4)
        self.assertEqual(len(r['pending_callee_effect_sites']),24)
        self.assertTrue(r['callback_memory_effects_and_win64_nonvolatile_abi_required'])
        self.assertFalse(r['allocation_lifetimes_and_private_frame_exception_cleanup_qualified'])
        b,asm,*_=args;n,code,edges,spans,_=self.simd_scalar_effects_state(b,asm)
        for lane in range(4):
            bad=code.copy();bad[1333]='movq 704(%rbp), %rsi'
            with self.assertRaises(ValueError):t.check_lane(bad,edges,spans,lane,n)

    def test_simd_scalar_effects_prerequisites_and_integration(self):
        args=self.simd_scalar_effects_fixture();b,asm,caller,scalar,frame,previous=args
        for obj,key in ((caller['helpers'],'copy_wrapper_checks_equal_lengths'),
            (scalar,'scratch_wipes_before_copyback'),(scalar,'whole_scalar_owner_wiped_before_checked_report_increment'),
            (scalar['scalar_kernel'],'linked_constants_independently_derived'),
            (frame,'bounded_frame_effects_exclude_live_pointer_cells_and_caller_objects'),
            (previous,'original_source_destination_and_length_definitions_checked')):
            with patch.dict(obj,{key:False}):
                with self.assertRaises(ValueError):t.inspect(*args)
        for obj,key,value in ((scalar['scalar_kernel'],'scratch_bytes',[40,40,201]),
            (scalar['scalar_kernel'],'opaque_stack_accesses',1),(scalar['scalar_kernel'],'function','wrong'),
            (caller['helpers'],'copy_leaf_length_limit',199),(previous,'pending_callee_effect_sites',[]),
            (previous,'pending_non_frame_store_sites',[619])):
            with patch.dict(obj,{key:value}):
                with self.assertRaises(ValueError):t.inspect(*args)
        import windows_enclave_sha3_batch_chains as c
        with patch.object(t,'inspect',side_effect=ValueError('scalar effects failed')) as check:
            with self.assertRaisesRegex(ValueError,'scalar effects failed'):
                c.inspect_route(self.saved,self.root,'simd',self.spec['simd'])
            check.assert_called_once()
