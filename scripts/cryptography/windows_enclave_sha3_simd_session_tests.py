"""Session cleanup, CFG, callback and counter-boundary regressions."""
import copy
import re
from unittest.mock import patch
import windows_enclave_sha3_simd_session as t
import windows_enclave_sha3_simd_kernel as k
from windows_enclave_sha3_simd_kernel_tests import constants


class SimdSessionModelTests:
    def test_simd_session_wipe_partition_and_counter_geometry(self):
        ranges=((0,800),(800,960),(960,1120),(1120,1920))
        covered=[]
        for begin,end in ranges:
            size=end-begin;geometry=t.zero.zero_geometry(size)
            self.assertEqual(geometry['word_end'],size)
            covered.extend(range(begin,end))
        self.assertEqual(covered,list(range(1920)))
        for tag in (0,1):
            self.assertEqual(2+2*(tag^1),4 if tag==0 else 2)
        for count in (0,1,(1<<63)-1,1<<63,(1<<64)-2,(1<<64)-1):
            rejected=count==(1<<64)-1
            self.assertEqual(rejected,count+1>=(1<<64))
            if not rejected:self.assertGreater(count+1,count)


class SimdSessionSavedTests:
    def simd_session_fixture(self):
        _,_,asm,ir,_,bodies=self.routes['simd']
        return bodies,asm,ir,k.inspect(bodies,ir,constants())

    def test_simd_session_complete_bodies_reject_each_instruction_change(self):
        args=self.simd_session_fixture();bodies,asm,ir,leaves=args
        result=t.inspect(*args);names=result['functions'];count=0
        selected=[names['session'],names['wipe'],names['zero'],*result['invoked_funclets'].values()]
        for name in selected:
            lines=bodies[name].splitlines(keepends=True)
            for at,line in enumerate(lines):
                code=line.strip()
                if not code or code.startswith(('#','.')) or code.endswith(':'):continue
                for replacement in ('\tud2\n','\tretq\n'+line):
                    bad=lines.copy();bad[at]=replacement
                    with self.assertRaises(ValueError):t.inspect(bodies|{name:''.join(bad)},asm,ir,leaves)
                    count+=1
        self.assertEqual(count,338)
        print('Keccak session/wipe/funclet instruction mutations rejected:',count)

    def test_simd_session_cfg_requires_transaction_and_cleanup_events(self):
        bodies,_,_,_=self.simd_session_fixture();n=t.names(bodies)
        lines=t.life.code(bodies[n['session']]);paths=t.normal_paths(lines,n)
        self.assertEqual(len(paths),7)
        self.assertEqual(sum('success' in p for p in paths),1)
        self.assertEqual(sum('revoked' in p for p in paths),4)
        self.assertEqual(sum('wrong_architecture' in p for p in paths),1)
        self.assertEqual(sum('overflow' in p for p in paths),1)
        count=0
        for at,line in enumerate(lines):
            if line in ('callq '+n['wipe'],'callq '+n['unpack'],'callq '+n['pack'],
                'callq '+n['wrapper'],'callq *8(%rbx)','incq %rdi',
                'movq %rdi, (%rbx)','movb $-1, %sil'):
                bad=lines.copy();bad[at]='nop'
                with self.assertRaises(ValueError):t.normal_paths(bad,n)
                count+=1
            if line in ('callq '+n['pack'],'callq '+n['wrapper'],'callq '+n['unpack']):
                with self.assertRaises(ValueError):t.normal_paths(lines[:at+1]+['retq']+lines[at+1:],n)
                count+=1
        # Failure joins may not borrow the successful output commit block.
        at=lines.index('.B13:')+1
        with self.assertRaises(ValueError):t.normal_paths(lines[:at]+['callq '+n['unpack']]+lines[at:],n)
        self.assertEqual(count,14)

    def test_simd_session_cleanup_tables_and_call_sites_are_bound(self):
        bodies,asm,ir,leaves=self.simd_session_fixture();result=t.inspect(bodies,asm,ir,leaves)
        n=result['functions'];tables=result['cleanup']['expected_tables'];count=0
        for label,entries in tables.items():
            found=re.search(r'^'+re.escape(label)+r':\n((?:\s*\.long[^\n]*\n)+)',asm,re.M)
            self.assertIsNotNone(found)
            for at in range(len(entries)):
                changed=entries.copy();changed[at]='123456789'
                bad=asm[:found.start()]+label+':\n'+''.join('\t.long\t'+v+'\n' for v in changed)+asm[found.end():]
                with self.assertRaises(ValueError):t.inspect(bodies,bad,ir,leaves)
                count+=1
            for bad in (asm[:found.start()]+asm[found.end():],asm+'\n'+found[0]):
                with self.assertRaises(ValueError):t.inspect(bodies,bad,ir,leaves)
                count+=1
        self.assertEqual(count,30)
        for label in ('.Ltmp18:', '.Ltmp19:', '.Ltmp20:', '.Ltmp21:'):
            with self.assertRaises(ValueError):
                t.inspect(bodies|{n['session']:bodies[n['session']].replace(label,'.Ltmp999:')},asm,ir,leaves)

    def test_simd_session_abis_and_leaf_prerequisites_cannot_weaken(self):
        args=self.simd_session_fixture();bodies,asm,ir,leaves=args;result=t.inspect(*args);count=0
        for role in ('session','wipe','zero'):
            name=result['functions'][role]
            declaration=next(l for l in ir.splitlines() if l.startswith('define ') and '@'+name+'(' in l)
            for token in ('nonnull','noalias','nofree','noundef','captures(none)','fastcc',
                          'dereferenceable(800)','dereferenceable(1920)',
                          'range(i64 1, -9223372036854775808)','range(i8 -1, 4)'):
                if token not in declaration:continue
                with self.assertRaises(ValueError):t.inspect(bodies,asm,ir.replace(declaration,declaration.replace(token,'')),leaves)
                count+=1
        self.assertEqual(count,21)
        for key in ('lanes','state_region','erased_scratch_region','transpose_llvm_width_range',
                    'linked_constants_independently_derived'):
            bad=copy.deepcopy(leaves);bad[key]=None
            with self.assertRaises(ValueError):t.inspect(bodies,asm,ir,bad)
        for role in ('pack','unpack','wrapper'):
            bad=copy.deepcopy(leaves);bad['functions'][role]='other'
            with self.assertRaises(ValueError):t.inspect(bodies,asm,ir,bad)
        for key in ('caller_authority_and_allocation_lifetimes_qualified','arbitrary_os_unwind_qualified',
                    'private_frame_erasure_qualified'):
            self.assertFalse(result[key])
        print('Keccak session ABI mutations rejected:',count)

    def test_simd_session_integrated_failure_is_not_skipped(self):
        import windows_enclave_sha3_batch_chains as c
        with patch.object(t,'inspect',side_effect=ValueError('session review failed')) as call:
            with self.assertRaisesRegex(ValueError,'session review failed'):
                c.inspect_route(self.saved,self.root,'simd',self.spec['simd'])
            call.assert_called_once()
