"""Paired payload/prefix bounds reject root substitution and split-read drift."""
import copy
from unittest.mock import patch
import windows_enclave_sha3_simd_source_effects as t


class SimdSourceEffectsModelTests:
    def test_simd_source_effects_all_bounded_byte_indexes_and_u64_extremes(self):
        count=0
        for length in range(1025):
            for index in range(length+2):
                for low in (0,7):
                    bit=index*8+low;got=t.byte_window(length,bit)
                    self.assertEqual(got,[index if index<length else None,index+1 if index+1<length else None])
                    count+=1
            for bit in (1<<32,(1<<63)-1,1<<63,t.MASK):
                self.assertEqual(t.byte_window(length,bit),[None,None])
                self.assertLessEqual((bit>>3)+1,1<<61)
        self.assertEqual(count,1053700)
        for length,bit in ((-1,0),(1025,0),(True,0),(1,-1),(1,t.MASK+1),(1,True)):
            with self.assertRaises(ValueError):t.byte_window(length,bit)
        print('Keccak paired-source byte-window comparisons: '+str(count)+'; u64 boundary cases: 4100')

    def test_simd_source_effects_prefix_selection_is_three_disjoint_fields(self):
        n=dict(executor='example',xor='helper');code=['nop']*648+t.previous.absorb.shape.shape(n)
        self.assertEqual([t.prefix_offset(code,p) for p in (0,1,3)],[0,17,34])
        for part in (-1,2,4,5,6,7,8,9,True):
            with self.assertRaises(ValueError):t.prefix_offset(code,part)
        for at in range(719,732):
            bad=code.copy();bad[at]='nop'
            with self.assertRaises(ValueError):t.prefix_offset(bad,0)


class SimdSourceEffectsSavedTests:
    def simd_source_effects_fixture(self):
        import windows_enclave_sha3_batch_chains as c
        r=c.inspect_route(self.saved,self.root,'simd',self.spec['simd']);_,_,asm,_,_,b=self.routes['simd']
        return (b,asm,*[r[k] for k in ('simd_digest','simd_receiver','simd_descriptors','simd_lane_absorption','simd_internal_absorption_call_effects')])

    def simd_source_effects_state(self,b,asm,code=None):
        n=t.previous.absorb.shape.names(b);code=t.life.code(b[n['executor']]) if code is None else code
        edges,_=t.o.reconcile.graph(code,asm);spans,_,_=t.o.frame_writes(code,edges)
        states=t.w.definitions(code,edges,spans,t.SLOTS)
        return n,code,edges,spans,states

    def simd_source_effects_initial(self,b,asm):
        n,code,edges,spans,states=self.simd_source_effects_state(b,asm)
        initial=t.previous.entry(code,edges,spans,states,2,168)
        initial.update(t.source_cells(code,edges,spans,states,2))
        return n,code,edges,spans,states,initial

    def test_simd_source_effects_original_array_and_saved_cell_mutations(self):
        b,asm,*_=self.simd_source_effects_fixture();n,code,_,_,_=self.simd_source_effects_state(b,asm)
        changes=((39,'movq %r9, %r14'),(46,'movl %r14d, %r8d'),(51,'movq %rdx, %r14'),
            (70,'movl %r14d, 968(%rbp)'),(504,'movq 960(%rbp), %r14'),(634,'movq 960(%rbp), %r14'),
            (1174,'movq 960(%rbp), %r14'),(1195,'movq 960(%rbp), %r14'),(1215,'movq 960(%rbp), %r14'))
        for at,line in changes:
            bad=code.copy();bad[at]=line;_,_,_,_,states=self.simd_source_effects_state(b,asm,bad)
            with self.assertRaises(ValueError):t.input_root(bad,states,669,'r14')
        for at,(_,slot,_) in t.LOADS.items():
            for target in (at,at+1):
                bad=code.copy();bad[target]='movq %rsi, %rax' if target==at else f'movl %eax, {slot}(%rbp)'
                _,_,e,p,d=self.simd_source_effects_state(b,asm,bad)
                with self.assertRaises(ValueError):t.source_cells(bad,e,p,d,2)
        print('Keccak source-root/reload and descriptor-cell mutations rejected: 21')

    def test_simd_source_effects_selected_source_and_length_cannot_be_crossed(self):
        b,asm,*_=self.simd_source_effects_fixture();_,code,_,_,_,initial=self.simd_source_effects_initial(b,asm)
        cases=((714,'movq 536(%rbp), %rsi',2,718),(715,'movq 544(%rbp), %r8',2,718),
            (753,'movq 552(%rbp), %rsi',2,759),(754,'movq 560(%rbp), %rcx',2,759),
            (761,'movq 536(%rbp), %rsi',4,718),(762,'movq 544(%rbp), %rax',4,759),
            (794,'movq 816(%rbp), %rsi',6,718),(795,'movq 760(%rbp), %rax',6,759),
            (797,'movq %rcx, 840(%rbp)',0,718))
        for at,line,part,dispatch in cases:
            bad=code.copy();bad[at]=line
            with self.assertRaises(ValueError):t.selected_source(bad,initial,part,dispatch)
        print('Keccak selected-source/matching-length mutations rejected: 9')

    def test_simd_source_effects_guard_and_split_read_restoration_mutations(self):
        b,asm,*_=self.simd_source_effects_fixture();n,code,edges,spans,_,initial=self.simd_source_effects_initial(b,asm)
        chosen,base,length=t.selected_source(code,initial,2,718)
        changes=((799,'movq %rax, 768(%rbp)'),(814,'shrq $4, %r14'),(815,'movq 544(%rbp), %rax'),
            (816,'cmpq %rcx, %r14'),(817,'ja .B207'),(818,'movq %rcx, %rsi'),
            (819,'movq 536(%rbp), %rax'),(820,'leaq 1(%rax,%r14), %rdx'),
            (836,'addq $2, %r14'),(836,'incl %r14d'),(837,'cmpq %r12, %r14'),(840,'ja .B207'),
            (841,'movq 552(%rbp), %rdx'),(842,'addq %r12, %rdx'),(849,'xorl %edx, %edx'))
        for at,line in changes:
            bad=code.copy();bad[at]=line;_,_,e,p,_=self.simd_source_effects_state(b,asm,bad)
            with self.assertRaises(ValueError):t.guarded_reads(bad,e,p,chosen,base,length,n)
        print('Keccak paired-source guard/index/restore mutations rejected: 15')

    def test_simd_source_effects_guard_entries_and_stable_cell_writes_reject(self):
        args=self.simd_source_effects_fixture();b,asm,*_=args;n,code,edges,spans,states=self.simd_source_effects_state(b,asm)
        for at in (798,799,815,818,820,827,836,841,842,851):
            bad=copy.deepcopy(edges);bad[0].append(at)
            with self.assertRaises(ValueError):t.previous.flow(code,bad,n)
        for slot in t.STABLE:
            bad=spans|{799:(slot+7,slot+8)}
            with self.assertRaises(ValueError):t.source_cells(code,edges,bad,states,2)
        print('Keccak source-guard entry and stable-cell overlap mutations rejected: 17')

    def test_simd_source_effects_scope_and_prerequisites(self):
        args=self.simd_source_effects_fixture();b,asm,caller,receiver,descriptors,absorbing,prior=args
        result=t.inspect(*args)
        self.assertEqual(result['call_sites'],[827,851]);self.assertEqual(len(result['source_cases']),48)
        self.assertEqual(len(result['pending_callee_effect_sites']),18)
        self.assertTrue(result['caller_descriptor_payload_placement_nonoverlap_and_lifetimes_required'])
        self.assertFalse(result['allocation_lifetimes_and_private_frame_exception_cleanup_qualified'])
        for obj,key,value in ((receiver,'actual_bitstring_inputs_use_local_buffers_not_host_addresses',False),
            (receiver,'all_twelve_inputs_bounded_to_separate_1024_byte_worker_slots',False),
            (descriptors,'pointer_length_bits_and_last_preserved_on_success',False),(descriptors,'bounded_bit_count_maximum',0),
            (absorbing,'readonly_bit_sources_and_two_byte_splits_checked',False),(prior,'all_four_destinations_within_original_lane_rate',False),
            (prior,'external_source_sites_pending',[]),(prior,'pending_callee_effect_sites',[])):
            with patch.dict(obj,{key:value}):
                with self.assertRaises(ValueError):t.inspect(*args)

    def test_simd_source_effects_integration_failure_is_not_ignored(self):
        import windows_enclave_sha3_batch_chains as c
        with patch.object(t,'inspect',side_effect=ValueError('source effects failed')) as check:
            with self.assertRaisesRegex(ValueError,'source effects failed'):
                c.inspect_route(self.saved,self.root,'simd',self.spec['simd'])
            check.assert_called_once()
