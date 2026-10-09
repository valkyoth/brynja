"""Output ownership, all-slot preflight and saved-code mutation regressions."""
import copy
import itertools
import re
from unittest.mock import patch
import windows_enclave_sha3_simd_output as t
import windows_enclave_sha3_simd_output_model as model


class SimdOutputModelTests:
    def test_simd_output_preflight_independent_slot_oracle(self):
        code=t.prepare_shape();count=0
        for present in itertools.product((False,True),repeat=4):
            for lengths in itertools.product((0,1,256,1024,1025),repeat=4):
                expected=sum(v for p,v in zip(present,lengths) if p)<=1024
                self.assertEqual(model.evaluate(code,present,lengths)['accepted'],expected)
                count+=1
            for slot in range(4):
                for extreme in ((1<<63)-1,1<<63,(1<<64)-1):
                    lengths=[0]*4;lengths[slot]=extreme
                    self.assertEqual(model.evaluate(code,present,lengths)['accepted'],not present[slot])
                    count+=1
        self.assertEqual(count,10192)
        print('Keccak emitted all-slot preflight comparisons:',count)

    def test_simd_output_preflight_load_bearing_guards_and_pointers(self):
        code=t.prepare_shape();count=0
        # The final source has two equivalent bailouts. Test all guards with a
        # failing occupied lane while the other lanes remain empty.
        for old,new,slot in (('ja .B269','jmp .B246',0),
            ('jb .B269','jmp .B250',1),('cmpq %rax, %rdx','cmpq %rdx, %rdx',3)):
            at=code.index(old);bad=code[:at]+[new]+code[at+1:]
            lengths=[0]*4;lengths[slot]=1025
            with self.assertRaises(ValueError):model.evaluate(bad,[True]*4,lengths)
            count+=1
        at=code.index('movq %r12, %r8')
        with self.assertRaises(ValueError):model.evaluate(code[:at]+['leaq 1(%r12), %r8']+code[at+1:],[True]*4,[1]*4)
        for old,new in (('movq %rbx, 944(%rbp)','movq %r12, 944(%rbp)'),
            ('movq %rbx, 960(%rbp)','movq %r12, 960(%rbp)'),
            ('movq 616(%rbp), %rdi','movq 600(%rbp), %rdi')):
            at=code.index(old)
            with self.assertRaises(ValueError):model.evaluate(code[:at]+[new]+code[at+1:],[True]*4,[1,2,3,4])
            count+=1
        self.assertEqual(count,6)


class SimdOutputSavedTests:
    def simd_output_fixture(self):
        args=self.simd_digest_fixture();caller=t.digest.inspect(*args)
        return args[0],args[2],caller

    def test_simd_output_saved_validator_and_commit_region_mutations(self):
        b,ir,caller=self.simd_output_fixture();r=t.inspect(b,ir,caller);n=r['functions'];count=0
        for role in ('validate','executor'):
            name=n[role];lines=t.life.code(b[name])
            ranges=[(0,len(lines))] if role=='validate' else [r['output_prepare_region'],r['output_copy_and_cleanup_region']]
            for start,end in ranges:
                for at in range(start,end):
                    for replacement in ([],['ud2'],['retq',lines[at]]):
                        mutant=lines[:at]+replacement+lines[at+1:]
                        with self.assertRaises(ValueError):t.inspect(b|{name:name+':\n'+'\n'.join(mutant)},ir,caller)
                        count+=1
        print('Keccak output validator/preflight/commit instruction mutations rejected:',count)
        self.assertEqual(count,3*(len(t.validate_shape())+len(t.prepare_shape())+len(t.copy_shape(n))))

    def test_simd_output_ir_aliases_reads_writes_and_escapes(self):
        b,ir,caller=self.simd_output_fixture();r=t.inspect(b,ir,caller);n=r['functions'];graph=t.provenance.graph
        lines=graph.function(ir,n['executor']);aliases=r['ir_provenance']['aliases'];count=0
        header=lines[0];begin=ir.index(header);end=ir.index('\n}',begin)+2;original=ir[begin:end]
        def rejects(old,new):
            nonlocal count
            self.assertIn(old,original)
            bad=ir[:begin]+original.replace(old,new,1)+ir[end:]
            with self.assertRaises(ValueError):t.provenance.inspect(bad,n)
            count+=1
        for alias in aliases:
            if alias=='%17':continue
            row=next(l for l in lines if l.startswith(alias+' = '))
            if 'i64 %904' in row:rejects(row,row.replace('%904','%905'))
            else:rejects(row,re.sub(r'i64 (\d+)$',lambda m:'i64 '+str(int(m[1])+1),row))
        for row in r['ir_provenance']['reads']:
            line=lines[row['line']]
            rejects(line,line.replace('load '+row['type'],'load i32'))
        for row in r['ir_provenance']['writes']:
            line=lines[row['line']];rejects(line,re.sub(r', ptr %[^,]+,',', ptr %17,',line))
        for alias in aliases:
            for suffix in ('store ptr '+alias+', ptr @escaped, align 8',
                'call void @unreviewed(ptr '+alias+')',
                '%escape = ptrtoint ptr '+alias+' to i64'):
                rejects('\n920:', '\n'+suffix+'\n920:')
        # A loaded integer cannot be used to smuggle a pointer out of the typed
        # inventory, and an extra root read cannot hide behind existing uses.
        rejects('%806 = load ptr, ptr %17, align 8','%806 = load i64, ptr %17, align 8')
        rejects('\n920:','\n%escape = load i64, ptr %17, align 8\n920:')
        for ptr in r['ir_provenance']['pointer_uses']:
            rejects('\n920:',f'\nstore ptr {ptr}, ptr @escaped, align 8\n920:')
        print('Keccak exhaustive descriptor IR mutations rejected:',count)

    def test_simd_output_ir_consumers_and_cleanup_index(self):
        b,ir,caller=self.simd_output_fixture();r=t.inspect(b,ir,caller);n=r['functions']
        lines=t.provenance.graph.function(ir,n['executor']);start=ir.index(lines[0]);end=ir.index('\n}',start)+2
        body=ir[start:end];count=0
        for record in r['ir_provenance']['consumers']:
            row=lines[record['line']];self.assertIn(row,body)
            for new in ('',row.replace('@','@wrong_',1)):
                with self.assertRaises(ValueError):t.provenance.inspect(ir[:start]+body.replace(row,new,1)+ir[end:],n)
                count+=1
        for old,new in (('%904, 64','%904, 80'),('%904, 16','%904, 8'),
            ('[ 0, %901 ]','[ 16, %901 ]'),('br label %903','br label %920')):
            self.assertIn(old,body)
            with self.assertRaises(ValueError):t.provenance.inspect(ir[:start]+body.replace(old,new,1)+ir[end:],n)
            count+=1
        self.assertEqual(count,24)

    def test_simd_output_bounded_model_uses_actual_saved_region(self):
        b,ir,caller=self.simd_output_fixture();r=t.inspect(b,ir,caller);start,end=r['output_prepare_region']
        code=t.life.code(b[r['functions']['executor']])[start:end]
        for present in itertools.product((False,True),repeat=4):
            for lengths in ([256]*4,[0]*4,[1,256,255,512],[1,256,256,512]):
                got=model.evaluate(code,present,lengths)
                self.assertEqual(got['accepted'],sum(v for p,v in zip(present,lengths) if p)<=1024)

    def test_simd_output_prerequisites_abis_and_integrated_nonpromotion(self):
        b,ir,caller=self.simd_output_fixture();r=t.inspect(b,ir,caller);n=r['functions']
        row=next(l for l in ir.splitlines() if l.startswith('define ') and '@'+n['validate']+'(' in l)
        for token in ('noalias','nofree','nonnull','readonly','captures(none)','align 8','dereferenceable(64)','fastcc'):
            self.assertIn(token,row)
            with self.assertRaises(ValueError):t.inspect(b,ir.replace(row,row.replace(token,'')),caller)
        for key in ('copy_wrapper_checks_equal_lengths',):
            bad=copy.deepcopy(caller);bad['helpers'][key]=False
            with self.assertRaises(ValueError):t.inspect(b,ir,bad)
        self.assertFalse(r['remaining_executor_instructions_and_machine_aliases_qualified'])
        self.assertFalse(r['private_frame_erasure_qualified'])
        self.assertTrue(caller['helpers']['output_drop_clears_output_bits_and_identities_not_slice_descriptors'])
        import windows_enclave_sha3_batch_chains as c
        with patch.object(t,'inspect',side_effect=ValueError('output ownership review failed')) as call:
            with self.assertRaisesRegex(ValueError,'output ownership review failed'):
                c.inspect_route(self.saved,self.root,'simd',self.spec['simd'])
            call.assert_called_once()
