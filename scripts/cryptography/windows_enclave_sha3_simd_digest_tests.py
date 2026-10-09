"""Fail-closed mutations for the saved resident digest and cleanup call graph."""
import copy
from unittest.mock import patch
import windows_enclave_sha3_simd_digest as t


class SimdDigestModelTests:
    def test_simd_digest_workspace_coverage_and_phase_geometry(self):
        report=t.helpers.geometry()
        covered=[i for start,size in report['workspace_wipe_ranges'] for i in range(start,start+size)]
        self.assertEqual(sorted(covered),list(range(5260)))
        self.assertFalse(report['secret_output_descriptor_pointers_erased'])
        frame=t.geometry();self.assertEqual(frame['workspace_and_scratch_erasure_bytes'],7308)
        spans=frame['executor_entry_objects']
        for name,(start,end) in spans.items():
            for other,(a,b) in spans.items():
                if other!=name:self.assertFalse(max(a,start)<min(b,end),(name,other))
        for bits in range(2049):
            # The four emitted shr/and/cmp/sbb sequences round up independently.
            emitted=(bits>>3)+int((bits&7)>=1)
            self.assertEqual(emitted,(bits+7)//8)
            self.assertLessEqual(emitted,256)
        self.assertFalse(frame['complete_frame_erasure_qualified'])


class SimdDigestSavedTests:
    def simd_digest_fixture(self):
        import windows_enclave_sha3_batch_chains as c
        b,ir,constants,worker,owner=self.simd_receive_fixture()
        receiver=t.helpers.receive.inspect(b,ir,constants,worker,owner)
        descriptors=c.simd_descriptors.inspect(b,ir,receiver)
        data,image,asm,_,functions,_=self.routes['simd']
        runtime={'memcpy','memset','memcmp','__chkstk','__umodti3','PublicProbeAbort'}|{
            'PublicKeccakSimd'+part for part in ('Input','Output','Source','Observe')}
        vtables=c.binding.data_bindings(data,image,c.binding.bind_all(data,image,functions),functions,runtime,'simd')[3]
        session=c.simd_session.inspect(b,asm,ir,c.simd_kernel.inspect(b,ir,constants))
        return b,asm,ir,vtables,session,receiver,descriptors

    def test_simd_digest_every_caller_position(self):
        args=self.simd_digest_fixture();b,asm,ir,*rest=args;r=t.inspect(*args)
        name=r['functions']['digest'];lines=t.life.code(b[name]);count=0
        for at in range(len(lines)):
            for replacement in ([],['ud2'],['retq',lines[at]]):
                mutant=lines[:at]+replacement+lines[at+1:]
                with self.assertRaises(ValueError):t.inspect(b|{name:name+':\n'+'\n'.join(mutant)},asm,ir,*rest)
                count+=1
        self.assertEqual(count,1533)
        print('Keccak resident digest instruction mutations rejected:',count)

    def test_simd_digest_every_destruction_helper_position(self):
        b,_,ir,_,session,_,_=self.simd_digest_fixture();n=t.helpers.names(b);count=0
        expected=t.helpers.shapes(n)
        expected[n['copy']]=t.helpers.copy.WRAPPER_CODE
        expected[n['copy_leaf']]=t.helpers.copy.code(b[n['copy_leaf']])
        for name,lines in expected.items():
            for at in range(len(lines)):
                for replacement in ([],['ud2'],['retq',lines[at]]):
                    mutant=lines[:at]+replacement+lines[at+1:]
                    with self.assertRaises(ValueError):
                        t.helpers.inspect(b|{name:name+':\n'+'\n'.join(mutant)},ir,session)
                    count+=1
        self.assertEqual(count,3*sum(map(len,expected.values())))
        print('Keccak workspace/output/copy helper mutations rejected:',count)

    def test_simd_digest_exception_funclets_tables_and_sites(self):
        b,asm,_,_,_,_,_=self.simd_digest_fixture();n=t.helpers.names(b)
        report=t.cleanup.inspect(b,asm,n);_,expected=t.cleanup.shapes(b,n);count=0
        for name,lines in expected.items():
            for at in range(len(lines)):
                for replacement in ([],['ud2'],['retq',lines[at]]):
                    mutant=lines[:at]+replacement+lines[at+1:]
                    with self.assertRaises(ValueError):t.cleanup.inspect(b|{name:name+':\n'+'\n'.join(mutant)},asm,n)
                    count+=1
        print('Keccak resident exception funclet mutations rejected:',count)
        tables=0
        for label,values in report['expected_tables'].items():
            begin=asm.index(label+':\n');end=begin+len(label)+2
            for value in values:
                start=asm.index('.long',end);end=asm.index('\n',start)
                old=asm[start:end]
                with self.assertRaises(ValueError):t.cleanup.inspect(b,asm[:start]+'.long 999'+asm[end:],n)
                self.assertIn(value,old);tables+=1
        self.assertEqual(tables,34)
        for label in (54,55,56,57,58,59,60,61,62,63):
            old=f'.Ltmp{label}:';self.assertIn(old,b[n['digest']])
            with self.assertRaises(ValueError):
                t.cleanup.inspect(b|{n['digest']:b[n['digest']].replace(old,old.replace(':','_wrong:'))},asm,n)
        chains=report['ordered_cleanup_chains'];handlers=report['funclets']
        self.assertEqual(chains['.Ltmp54'],[handlers[73],handlers[74]])
        self.assertEqual(chains['.Ltmp58'],[handlers[71],handlers[74]])
        self.assertEqual(chains['.Ltmp60'],[handlers[68],handlers[71],handlers[74]])

    def test_simd_digest_internal_callbacks_and_identity_dispatch(self):
        b,asm,ir,vtables,*_=self.simd_digest_fixture();r=t.callbacks(b,ir,vtables)
        for name in r['slots'].values():
            for wrong in ('retq','movb $1, %al\nretq','movb $0, (%rcx)\nxorl %eax, %eax\nretq'):
                with self.assertRaises(ValueError):t.callbacks(b|{name:name+':\n'+wrong},ir,vtables)
            row=next(l for l in ir.splitlines() if l.startswith('define ') and '@'+name+'(' in l)
            for token in ('captures(none)','zeroext'):
                self.assertIn(token,row)
                with self.assertRaises(ValueError):t.callbacks(b,ir.replace(row,row.replace(token,'')),vtables)
        for token in ('memory(none)','nounwind'):
            self.assertIn(token,ir)
            with self.assertRaises(ValueError):t.callbacks(b,ir.replace(token,''),vtables)
        for key,value in (('bytes',32),('metadata',[0,1,1]),('slots',{'24':'host','32':'host'})):
            bad=copy.deepcopy(vtables);bad[t.shape.VTABLE][key]=value
            with self.assertRaises(ValueError):t.callbacks(b,ir,bad)
        original=t.dispatch(asm);self.assertEqual(len(original['targets']),8)
        table=asm.index('.LJTI40_0:\n');end=table
        for _ in range(8):
            at=asm.index('.long',end);end=asm.index('\n',at)
            with self.assertRaises(ValueError):t.dispatch(asm[:at]+'.long .LBB40_67-.LJTI40_0'+asm[end:])

    def test_simd_digest_helper_abis_prerequisites_and_nonpromotion(self):
        args=self.simd_digest_fixture();b,asm,ir,vtables,session,receiver,descriptors=args
        report=t.inspect(*args);count=0
        for role in ('workspace_drop','workspace_wipe','scalar_wipe','output_drop','copy','copy_leaf','executor'):
            name=report['functions'][role]
            row=next(l for l in ir.splitlines() if l.startswith('define ') and '@'+name+'(' in l)
            for token in ('noundef','noalias','nonnull','nounwind','readonly','captures(none)',
                'dereferenceable(5260)','dereferenceable(104)','dereferenceable(1040)',
                'range(i64 0, 1025)','fastcc'):
                if token not in row:continue
                with self.assertRaises(ValueError):t.inspect(b,asm,ir.replace(row,row.replace(token,'')),vtables,session,receiver,descriptors)
                count+=1
        print('Keccak digest/helper ABI mutations rejected:',count)
        for key in ('actual_bitstring_inputs_use_local_buffers_not_host_addresses',
                    'all_twelve_inputs_bounded_to_separate_1024_byte_worker_slots'):
            bad=copy.deepcopy(receiver);bad[key]=False
            with self.assertRaises(ValueError):t.inspect(b,asm,ir,vtables,session,bad,descriptors)
        bad=copy.deepcopy(descriptors);bad['no_input_pointer_published_to_global_or_heap_storage']=False
        with self.assertRaises(ValueError):t.inspect(b,asm,ir,vtables,session,receiver,bad)
        bad=copy.deepcopy(session);bad['full_scratch_wipe_ranges'][-1]=[1120,1919]
        with self.assertRaises(ValueError):t.inspect(b,asm,ir,vtables,bad,receiver,descriptors)
        for flag in ('executor_body_pointer_lifetimes_and_nonoverlap_qualified',
                     'private_frame_erasure_qualified','whole_image_cleanup_qualified'):
            self.assertFalse(report[flag])
        import windows_enclave_sha3_batch_chains as c
        with patch.object(t,'inspect',side_effect=ValueError('digest review failed')) as call:
            with self.assertRaisesRegex(ValueError,'digest review failed'):
                c.inspect_route(self.saved,self.root,'simd',self.spec['simd'])
            call.assert_called_once()

    def test_simd_digest_direct_suffixes_cannot_skip_retirement(self):
        b,_,_,_,_,_,_=self.simd_digest_fixture();n=t.helpers.names(b)
        body=n['digest']+':\n'+'\n'.join(t.life.code(b[n['digest']]))
        for start in ('.B46','.B47','.B67'):
            self.assertEqual(t.s.normal_returns(body,start,t.shape.retire(n)),1)
            with self.assertRaises(ValueError):
                t.s.normal_returns(body.replace(start+':',start+':\nretq'),start,t.shape.retire(n))
