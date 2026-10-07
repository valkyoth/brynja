"""Argument, lifetime, effect and inventory regressions for narrow vector calls."""
import copy
from unittest.mock import patch
import windows_enclave_sha2_narrow_vector as b


class NarrowVectorTests:
    def test_narrow_vector_complete_public_copy_geometry(self):
        counts=[]
        for ordinal in range(3):
            cases=list(b.cases(ordinal));counts.append(len(cases))
            for _,_,args in cases:
                effects=b.copies.transfer.effects('copy',args)
                source,=effects['reads'];dest,=effects['writes']
                self.assertEqual(dest['object'],'frame')
                self.assertTrue(6688<=dest['span'][0]<dest['span'][1]<=7712)
                self.assertLessEqual(source['span'][1],1024 if ordinal==1 else 7712)
                if ordinal!=1:
                    self.assertFalse(b.p.p.cells.overlaps(source['span'],dest['span']))
        self.assertEqual(counts,[96,192,96])
        for ordinal in (-1,3):
            with self.assertRaises(ValueError):list(b.cases(ordinal))


class NarrowVectorSavedTests:
    def narrow_vector_fixture(self):return self.normal_effect_fixture('simd256')

    def test_actual_narrow_vector_complete_interfaces_and_integration(self):
        import windows_enclave_sha2_batch_chains as main
        row,asm,prior=self.narrow_vector_fixture();proof=b.inspect(row[-1],asm,prior)
        self.assertEqual([v['line'] for v in proof['assigned']],[734,818,865,873,893,929])
        self.assertEqual([v['role'] for v in proof['assigned']],
                         ['cancel','pack_states','pack_blocks','cancel','session','unpack_states'])
        self.assertEqual(proof['public_copy_cases'],384)
        self.assertEqual(proof['assigned_narrow_returning_interfaces'],44)
        self.assertEqual(len(proof['remaining_narrow_calls']),18)
        self.assertEqual(len(proof['shared_runtime_calls']),7)
        for key in ('arbitrary_unwind_qualified','individual_stack_erasure_qualified','whole_frame_qualified'):
            self.assertFalse(proof[key])
        with patch.object(b,'inspect',side_effect=ValueError('narrow vector failed')) as check:
            with self.assertRaisesRegex(ValueError,'narrow vector failed'):
                main.inspect_route(self.saved,self.root,'simd256',row[1],False)
            check.assert_called_once()

    def test_actual_narrow_vector_copy_replay_without_region_shortcut(self):
        row,asm,prior=self.narrow_vector_fixture();bodies=row[-1]
        calls=b.arguments(bodies,asm);name=b.s.one(bodies,r'Resident6digest$');lines=b.s.lines(bodies[name])
        copies=[v for v in calls if v['role'] in ('pack_states','pack_blocks','unpack_states')];count=0
        for ordinal,call in enumerate(copies):
            for at in range(call['line']-b.PREFIX[ordinal],call['line']+1):
                bad=lines[:];bad[at]='nop'
                # This is the address/capacity interpreter alone, not the
                # frozen-region comparison or complete image hash check.
                with self.assertRaises(ValueError):b.replay(bad,call,ordinal)
                count+=1
        self.assertEqual(count,22)

    def test_actual_narrow_vector_bases_cursors_and_callback_bodies(self):
        row,asm,_=self.narrow_vector_fixture();bodies=row[-1]
        name,lines,_,_=b.a.prepare(bodies,asm);count=0
        changes=[('leaq 7456(%rbx), %rdi','leaq 7457(%rbx), %rdi'),
                 ('leaq 6688(%rbx), %rdi','leaq 6689(%rbx), %rdi'),
                 ('addq $32, %rdi','addq $31, %rdi'),('addq $64, %rdi','addq $65, %rdi'),
                 ('leaq 7456(%rbx), %rax','leaq 7457(%rbx), %rax'),
                 ('movq %rax, 72(%rbx)','movq %rcx, 72(%rbx)'),
                 ('addq $32, 72(%rbx)','addq $31, 72(%rbx)')]
        # Select the unpack phase's initializer: slot 72 has earlier counter roles.
        roles={v['role']:v['line'] for v in b.arguments(bodies,asm)};unpack=roles['unpack_states']
        for before,after in changes:
            selected={'movq %rax, 72(%rbx)':unpack-14,'addq $64, %rdi':roles['pack_blocks']+1}
            at=selected[before] if before in selected else b.o.unique(lines,before)
            self.assertEqual(lines[at],before);bad=lines[:];bad[at]=after
            with self.assertRaises(ValueError):b.arguments(bodies|{name:'\n'.join(bad)},asm)
            count+=1
        poll=b.s.one(bodies,r'^_RNC.*Owner6digests2_0');leaf=b.s.lines(bodies[poll])
        for change in ('movb $0, (%rcx)','movl $1, %eax'):
            bad=leaf[:];bad[bad.index('xorl %eax, %eax')]=change
            with self.assertRaises(ValueError):b.arguments(bodies|{poll:'\n'.join(bad)},asm)
            count+=1
        self.assertEqual(count,9)

    def test_actual_narrow_vector_session_and_cancel_origin_rejections(self):
        row,asm,_=self.narrow_vector_fixture();bodies=row[-1];calls=b.arguments(bodies,asm)
        name,lines,_,_=b.a.prepare(bodies,asm);session=calls[4];count=0
        roots=[at for values in session['pointer_roots'].values() for at in values]
        for at in roots:
            bad=lines[:];bad[at]=bad[at].replace('leaq ','leaq 1',1)
            with self.assertRaises(ValueError):b.arguments(bodies|{name:'\n'.join(bad)},asm)
            count+=1
        for call in (calls[0],calls[3]):
            at=call['line']-1;bad=lines[:];bad[at]='leaq 71(%rbx), %rcx'
            with self.assertRaises(ValueError):b.arguments(bodies|{name:'\n'.join(bad)},asm)
            count+=1
        at=session['line']-6;self.assertEqual(lines[at],'movq 88(%rbx), %rcx')
        for replacement in ('movq 152(%rbx), %rcx','movq %rdx, %rcx'):
            bad=lines[:];bad[at]=replacement
            with self.assertRaises(ValueError):b.arguments(bodies|{name:'\n'.join(bad)},asm)
            count+=1
        self.assertEqual(count,7)

    def test_actual_narrow_vector_effects_stacks_and_inventory_reject(self):
        row,asm,prior=self.narrow_vector_fixture();bodies=row[-1];proof=b.inspect(bodies,asm,prior);count=0
        for region in proof['protected_live_objects']:
            calls=copy.deepcopy(proof['assigned']);low=region['span'][0]
            calls[4]['footprints'].append(['writes','frame',low,low+1])
            with patch.object(b,'arguments',return_value=calls):
                with self.assertRaisesRegex(ValueError,'normal helper writes exclude'):
                    b.inspect(bodies,asm,prior)
            count+=1
        for field,value in (('normal_stack_effects_disjoint',False),('normal_callee_count',11),
            ('caller_frame_relative_stack_span',[-288,89]),('outgoing_home_span',[0,89])):
            bad=copy.deepcopy(prior);bad['simd_vector_callee_stack'][field]=value
            with self.assertRaises(ValueError):b.inspect(bodies,asm,bad)
            count+=1
        for field in ('remaining_narrow_calls','assigned'):
            bad=copy.deepcopy(prior)
            bad['simd_narrow_setup_interfaces'][field]=[] if field=='remaining_narrow_calls' else [proof['assigned'][0]]
            with self.assertRaises(ValueError):b.inspect(bodies,asm,bad)
            count+=1
        self.assertEqual(count,11)

    def test_actual_narrow_vector_prerequisites_and_original_gather_reject(self):
        row,asm,prior=self.narrow_vector_fixture();count=0
        for key,field in b.PREREQUISITES:
            bad=copy.deepcopy(prior);bad[key][field]=False
            with self.assertRaises(ValueError):b.inspect(row[-1],asm,bad)
            count+=1
        for field,value in (('vector_gather_call',864),('argument_definitions_and_fresh_index_guards_checked',False)):
            bad=copy.deepcopy(prior);bad['simd_narrow_pointer_lifetimes']['input_consumers'][field]=value
            with self.assertRaises(ValueError):b.inspect(row[-1],asm,bad)
            count+=1
        self.assertEqual(count,13)
