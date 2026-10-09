"""Constructor publication, page geometry, startup and callback regressions."""
import copy
from unittest.mock import patch
import windows_enclave_sha3_simd_resident as t
import windows_enclave_sha3_simd_kernel as k
from windows_enclave_sha3_simd_kernel_tests import constants


def tables():
    raw=t.kat.zero_permutation()
    return constants()|{t.KAT:dict(bytes=200,sha256=t.kat.digest(raw))}


class SimdResidentModelTests:
    def test_simd_resident_page_and_public_temporary_geometry(self):
        result=t.geometry()
        self.assertEqual(result['authority_page_span'],[0,24])
        self.assertEqual(result['owner_page_span'],[24,1136])
        self.assertEqual(24+result['owner_authority_pointer_offset'],88)
        self.assertEqual([24+n for n in result['owner_output_span']],result['output_page_span'])
        counter=set([0,7]+list(range(5,7))+list(range(1,5)))
        self.assertEqual(counter,set(range(8)))
        # The active constructor fields, not the padding/absent plan payload.
        active=set(range(18))|{24,32}|set(range(88,1129))
        self.assertTrue(active<=set(range(1136)))
        for label in (7,12):
            self.assertEqual(len(t.page_clear(label)),12)
            cleared=[base+byte for base in range(0,4096,8) for byte in range(8)]
            self.assertEqual(cleared,list(range(4096)))
        raw=t.kat.zero_permutation()
        self.assertEqual(len(raw),200)
        self.assertEqual(int.from_bytes(raw[:8],'little'),0xf1258f7940e1dde7)
        self.assertEqual(int.from_bytes(raw[-8:],'little'),0xeaf1ff7b5ceca249)


class SimdResidentSavedTests:
    def simd_resident_fixture(self):
        _,_,asm,ir,_,bodies=self.routes['simd'];values=tables()
        leaf=k.inspect(bodies,ir,values)
        return bodies,ir,values,t.session.inspect(bodies,asm,ir,leaf)

    def test_simd_resident_all_constructor_and_callback_positions(self):
        bodies,ir,values,checked=self.simd_resident_fixture();result=t.inspect(bodies,ir,values,checked)
        count=0
        for name in (result['function'],result['compiled_callback']):
            lines=t.life.code(bodies[name])
            for at in range(len(lines)):
                for bad in (lines[:at]+lines[at+1:],lines[:at]+['ud2']+lines[at+1:]):
                    with self.assertRaises(ValueError):t.inspect(bodies|{name:name+':\n'+'\n'.join(bad)},ir,values,checked)
                    count+=1
        self.assertEqual(count,402)
        self.assertEqual(result['instruction_positions'],198)

    def test_simd_resident_cfg_requires_all_kats_before_publication(self):
        bodies,_,_,_=self.simd_resident_fixture();n=t.names(bodies);lines=t.life.code(bodies[n['new']])
        paths=t.paths(lines,n);self.assertEqual(len(paths),9)
        self.assertEqual(sum('publish_owner' in p for p in paths),1)
        self.assertEqual(sum('page_clear' in p for p in paths),8)
        count=0
        for at,line in enumerate(lines):
            # B8 immediately falls through a second identical wipe at B6.
            # Removing only its first wipe changes code, not cleanup semantics.
            if line=='callq '+n['wipe'] and lines[at-2]=='.B8:':
                bad=lines.copy();bad[at]='nop'
                self.assertEqual(len(t.paths(bad,n)),9)
                continue
            if (line.startswith('callq ') and line not in ('callq __chkstk','callq memset','callq memcpy')) or line in (
                'movq %rax, 8(%rdi)','movw $1, 16(%rdi)','movq %rdi, 88(%rdi)',
                'movq $0, 1120(%rdi)','movb $0, 1128(%rdi)','movq %rdi, (%rsi)',
                'movq %rdi, 8(%rsi)','movq %r15, 16(%rsi)','movq $0, (%rsi)'):
                bad=lines.copy();bad[at]='nop'
                with self.assertRaises(ValueError):t.paths(bad,n)
                count+=1
        # A failure is not allowed to publish even just the backing pointer.
        for label in ('.B8:','.B6:','.B11:'):
            at=lines.index(label)+1
            with self.assertRaises(ValueError):t.paths(lines[:at]+['movq %rdi, (%rsi)']+lines[at:],n)
            count+=1
        print('Keccak resident CFG event mutations rejected:',count)

    def test_simd_resident_kat_table_and_abis_are_bound(self):
        bodies,ir,values,checked=self.simd_resident_fixture();result=t.inspect(bodies,ir,values,checked)
        raw=t.kat.zero_permutation()
        for at in range(200):
            changed=bytearray(raw);changed[at]^=1
            with self.assertRaises(ValueError):t.inspect(bodies,ir,values|{t.KAT:dict(bytes=200,sha256=t.kat.digest(changed))},checked)
        for bad in ({},values|{t.KAT:values[t.KAT]|{'bytes':199}}):
            with self.assertRaises(ValueError):t.inspect(bodies,ir,bad,checked)
        count=0
        for name in (result['function'],result['compiled_callback']):
            row=next(l for l in ir.splitlines() if l.startswith('define ') and '@'+name+'(' in l)
            for token in ('noundef','noalias','nofree','nonnull','writeonly','writable','captures(none)',
                          'align 4096','dereferenceable(4096)','dereferenceable(24)','zeroext'):
                if token not in row:continue
                with self.assertRaises(ValueError):t.inspect(bodies,ir.replace(row,row.replace(token,'')),values,checked)
                count+=1
        for token in ('memory(none)','nosync','nounwind','willreturn'):
            with self.assertRaises(ValueError):t.inspect(bodies,ir.replace(token,''),values,checked)
            count+=1
        print('Keccak resident ABI mutations rejected:',count)

    def test_simd_resident_callee_preconditions_and_integrated_failure(self):
        args=self.simd_resident_fixture();result=t.inspect(*args)
        for role in ('wipe','pack','unpack','wrapper'):
            bad=copy.deepcopy(args[3]);bad['functions'][role]='other'
            with self.assertRaises(ValueError):t.inspect(*args[:3],bad)
        bad=copy.deepcopy(args[3]);bad['full_scratch_wipe_ranges']=[[0,1919]]
        with self.assertRaises(ValueError):t.inspect(*args[:3],bad)
        for key in ('worker_page_admission_and_resident_lifetime_qualified',
                    'owner_operation_and_digest_callers_qualified','private_frame_erasure_qualified'):
            self.assertFalse(result[key])
        import windows_enclave_sha3_batch_chains as c
        with patch.object(t,'inspect',side_effect=ValueError('resident review failed')) as call:
            with self.assertRaisesRegex(ValueError,'resident review failed'):
                c.inspect_route(self.saved,self.root,'simd',self.spec['simd'])
            call.assert_called_once()
