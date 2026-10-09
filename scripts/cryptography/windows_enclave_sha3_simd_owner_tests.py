"""Owner/check/cancel and callback cleanup-table regressions."""
import copy
import re
from unittest.mock import patch
import windows_enclave_sha3_simd_owner as t


class SimdOwnerSavedTests:
    def simd_owner_fixture(self):
        bodies,ir,constants,checked=self.simd_resident_fixture()
        construction=t.resident.inspect(bodies,ir,constants,checked)
        return bodies,self.routes['simd'][2],ir,construction,checked

    def test_simd_owner_complete_instructions_and_cleanup_funclets(self):
        bodies,asm,ir,construction,checked=self.simd_owner_fixture()
        report=t.inspect(bodies,asm,ir,construction,checked);count=0
        names=[*report['functions'].values(),*report['cleanup']['invoked_funclets']]
        for name in names:
            original=bodies[name].splitlines(keepends=True)
            for at,line in enumerate(original):
                v=line.strip()
                if not v or v.startswith(('#','.')) or v.endswith(':'):continue
                for replacement in ('\tud2\n','\tretq\n'+line):
                    bad=original.copy();bad[at]=replacement
                    with self.assertRaises(ValueError):t.inspect(bodies|{name:''.join(bad)},asm,ir,construction,checked)
                    count+=1
        self.assertGreater(count,350)
        print('Keccak owner/check/cancel/funclet instruction mutations rejected:',count)

    def test_simd_owner_callback_tables_labels_and_abis(self):
        args=self.simd_owner_fixture();bodies,asm,ir,construction,checked=args
        report=t.inspect(*args);count=0
        for label,entries in report['cleanup']['expected_tables'].items():
            found=re.search(r'^'+re.escape(label)+r':\n((?:\s*\.long[^\n]*\n)+)',asm,re.M)
            self.assertIsNotNone(found)
            for at in range(len(entries)):
                changed=entries.copy();changed[at]='123456789'
                bad=asm[:found.start()]+label+':\n'+''.join('\t.long\t'+v+'\n' for v in changed)+asm[found.end():]
                with self.assertRaises(ValueError):t.inspect(bodies,bad,ir,construction,checked)
                count+=1
            for bad in (asm[:found.start()]+asm[found.end():],asm+'\n'+found[0]):
                with self.assertRaises(ValueError):t.inspect(bodies,bad,ir,construction,checked)
                count+=1
        self.assertEqual(count,58)
        for role,labels in (('check',range(46,50)),('operation',range(50,54))):
            name=report['functions'][role]
            for label in labels:
                with self.assertRaises(ValueError):
                    t.inspect(bodies|{name:bodies[name].replace(f'.Ltmp{label}:','.Ltmp999:')},asm,ir,construction,checked)
        count=0
        for name in report['functions'].values():
            row=next(l for l in ir.splitlines() if l.startswith('define ') and '@'+name+'(' in l)
            for token in ('noundef','noalias','nofree','nonnull','writeonly','writable','captures(none)',
                          'align 8','dereferenceable(16)','dereferenceable(1112)','range(i8 0, 2)','fastcc'):
                if token not in row:continue
                with self.assertRaises(ValueError):t.inspect(bodies,asm,ir.replace(row,row.replace(token,'')),construction,checked)
                count+=1
        print('Keccak owner/check/cancel ABI mutations rejected:',count)

    def test_simd_owner_requires_constructor_binding_and_integrates(self):
        args=self.simd_owner_fixture();result=t.inspect(*args)
        for key in ('callback_is_pure_compiled_tag_check','public_callback_not_host_supplied'):
            bad=list(args);bad[3]=copy.deepcopy(args[3]);bad[3][key]=False
            with self.assertRaises(ValueError):t.inspect(*bad)
        for key in ('owner_authority_pointer_offset','owner_page_span','authority_page_span'):
            bad=list(args);bad[3]=copy.deepcopy(args[3]);bad[3]['placement'][key]=None
            with self.assertRaises(ValueError):t.inspect(*bad)
        bad=list(args);bad[4]=copy.deepcopy(args[4]);bad[4]['functions']['zero']='wrong'
        with self.assertRaises(ValueError):t.inspect(*bad)
        self.assertTrue(result['already_quarantined_cancellation_does_not_repeat_wipe'])
        self.assertTrue(result['standalone_check_wrong_kernel_returns_error_without_quarantine'])
        self.assertFalse(result['digest_and_worker_provenance_qualified'])
        import windows_enclave_sha3_batch_chains as c
        with patch.object(t,'inspect',side_effect=ValueError('owner review failed')) as call:
            with self.assertRaisesRegex(ValueError,'owner review failed'):
                c.inspect_route(self.saved,self.root,'simd',self.spec['simd'])
            call.assert_called_once()
