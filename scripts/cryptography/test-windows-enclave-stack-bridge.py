"""C/SDK joins must not erase unresolved depth or relabel aborts as returns."""
import copy
from pathlib import Path
import unittest

import windows_enclave_stack_bridge as r

ROOT=Path(__file__).resolve().parents[2]
SAVED=ROOT/'release-reports/windows-local-20261004'
DISASSEMBLY=ROOT/'release-reports/windows-worker-review-20261006/stack-disassembly-20261012'


class BoundaryTests(unittest.TestCase):
    def test_identity_cannot_move_between_incoming_edges(self):
        values={};r.identity(values,'callee',4096);r.identity(values,'callee',4096)
        for address in (4097,None,0,-1,1<<32,True):
            with self.subTest(address=address),self.assertRaises(ValueError):r.identity(values,'callee',address)

    def test_direct_call_requires_exact_reference_and_bytes(self):
        raw=b'\xe8'+bytes(4);refs=[dict(offset=1,symbol='callee',addend=0,trailing=0)]
        call=dict(site=0,kind='call',target=4096)
        self.assertEqual(r.transfer(raw,refs,call,{'callee':4096}),'callee')
        for changed in ([],refs*2,[refs[0]|{'offset':2}],
                        [refs[0]|{'addend':1}],[refs[0]|{'trailing':1}]):
            with self.assertRaises(ValueError):r.transfer(raw,changed,call,{'callee':4096})
        for code in (b'\xe9'+bytes(4),b'\xe8\x01'+bytes(3),b'\xc3'):
            with self.assertRaises(ValueError):r.transfer(code,refs,call,{'callee':4096})
        with self.assertRaises(ValueError):r.transfer(raw,refs,call,{'callee':4097})

    def test_indirect_call_must_be_named_scheduler_iat(self):
        raw=b'\xff\x15'+bytes(4);ref=dict(offset=2,symbol='__imp_CallEnclave',addend=0,trailing=0)
        call=dict(site=0,kind='call',target=None)
        self.assertEqual(r.transfer(raw,[ref],call,{}),'__imp_CallEnclave')
        for code,refs,edge in ((b'\xff\x25'+bytes(4),[ref],call),
            (raw,[ref|{'symbol':'unknown'}],call),(raw,[ref],call|{'kind':'tail'})):
            with self.assertRaises(ValueError):r.transfer(code,refs,edge,{})

    def test_fastfail_is_not_balanced_success(self):
        raw=bytes.fromhex('b907000000cd29c3');node=r.fatal(raw,[])
        for scan in node['scans']:self.assertEqual(scan['normal_returns'],[])
        result=r.worker.composition.compose({'abort':node})['abort']['8']
        self.assertIsNone(result['complete_stack_bytes'])
        self.assertIn('boundary:fatal:int29',result['unresolved_boundaries'])
        for at in range(len(raw)):
            bad=bytearray(raw);bad[at]^=1
            with self.assertRaises(ValueError):r.fatal(bytes(bad),[])
        with self.assertRaises(ValueError):r.fatal(raw,[{}])

    def test_syscall_ret_does_not_prove_kernel_depth(self):
        for name in ('copy_syscall_stub','call_syscall_stub'):
            raw=bytes.fromhex(r.sdk.status.sdk.BODIES[name][1])
            node=dict(incoming_bytes=32,scans=r.sdk_stack.syscall(raw,name))
            result=r.worker.composition.compose({'syscall':node})['syscall']['8']
            self.assertIsNone(result['complete_stack_bytes'])
            self.assertIn('boundary:os:'+name,result['unresolved_boundaries'])
            for at in range(len(raw)):
                bad=bytearray(raw);bad[at]^=1
                with self.assertRaises(ValueError):r.sdk_stack.syscall(bytes(bad),name)

    def test_join_rejects_namespace_collision_and_missing_export(self):
        for nodes,sdk in (({'sdk:a':{}},{'sdk:a':{}}),({'a':dict(scans=[dict(calls=[
            dict(targets=['boundary:sdk:missing'])])])},{}),({'a':dict(scans=[])},{})):
            with self.assertRaises(ValueError):r.sdk_stack.join(nodes,sdk)


class SavedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.report=r.collect(SAVED,ROOT,DISASSEMBLY)

    def test_complete_boundary_and_internal_population(self):
        records=self.report['records'];self.assertEqual(len(records),19)
        seeds={n for row in records for n in row['seed_boundaries']}
        names={n for row in records for n in row['c_bodies']}
        self.assertEqual(len(seeds),54);self.assertEqual(names-seeds,{'scheduler_complete'})
        self.assertEqual(sum(len(v['c_bodies']) for v in records),93)
        self.assertEqual(sum(x['fatal_boundary'] for v in records for x in v['c_bodies'].values()),12)
        self.assertFalse(self.report['completion_package_closed'])
        self.assertFalse(self.report['whole_image_qualified'])

    def test_only_named_sdk_os_and_fatal_suffixes_remain(self):
        found=set()
        for row in self.report['records']:
            for variants in row['roots'].values():
                for result in variants.values():
                    found.update(result['unresolved_boundaries'])
                    for pending in result['unresolved_boundaries'].values():
                        self.assertTrue(pending['unknown_suffix_depth']);self.assertTrue(pending['path'])
                    if result['unresolved_boundaries']:self.assertIsNone(result['complete_stack_bytes'])
            self.assertFalse(row['complete_protected_window_bound_proven'])
            self.assertFalse(row['loaded_iat_attested'])
        self.assertEqual(found,{'boundary:sdk:diagnostic_retry','boundary:os:copy_syscall_stub',
            'boundary:os:call_syscall_stub','boundary:os:debug_trap','boundary:fatal:int29'})

    def test_copy_tail_and_concurrent_calls_keep_real_return_slots(self):
        first=self.report['records'][0]
        tail=first['c_bodies']['PublicRetainedCopy']['scans'][0]['calls'][0]
        self.assertEqual((tail['kind'],tail['entry_offset']),('tail',0))
        last=self.report['records'][-1]
        calls=last['c_bodies']['PrivateWaveDispatch']['scans'][0]['calls']
        imported=[v for v in calls if v['targets']==['sdk:CallEnclave']]
        self.assertEqual(len(imported),3)
        self.assertTrue(all(v['entry_offset']==-80 for v in imported))
        self.assertIn('scheduler_complete',last['c_bodies'])
        for row in self.report['records']:
            for name,node in row['function_geometry'].items():
                if name.startswith('import:'):
                    for scan in node['scans']:
                        self.assertEqual(scan['calls'][0]['entry_offset'],0)

    def test_sdk_error_diagnostic_and_debug_paths_not_success_only(self):
        sdk=self.report['sdk_geometry'];self.assertEqual(len(sdk['bodies']),12)
        self.assertEqual(sdk['bodies']['RtlCallEnclave']['scans'][0]['local_low'],-312)
        for name in ('EnclaveCopyIntoEnclave','EnclaveCopyOutOfEnclave','CallEnclave'):
            result=sdk['composed']['sdk:'+name]['8']
            self.assertIn('boundary:sdk:diagnostic_retry',result['unresolved_boundaries'])
        self.assertIn('boundary:os:debug_trap',
            sdk['composed']['sdk:CallEnclave']['8']['unresolved_boundaries'])
        self.assertTrue(sdk['thread_relative_writes'])
        self.assertFalse(sdk['loaded_module_identity_proven'])

    def test_incoming_c_address_and_linked_body_corruption_reject(self):
        row=r.worker.workers.catalog.catalog()[0];record=self.report['records'][0]
        native=(SAVED/row['object']).read_bytes();image=(SAVED/row['image']).read_bytes()
        name='PublicInputCopy';entry=record['c_bodies'][name]['rva']
        raw,refs,targets=r.bind(native,image,name,entry)
        self.assertTrue(refs);self.assertTrue(targets)
        with self.assertRaises(ValueError):r.bind(native,image,name,entry+1)
        sections,_=r.caller.pe.linked(image)
        section=next(v for v in sections if v['rva']<=entry<v['rva']+len(v['code']))
        # Locate the complete raw section once; alter a non-relocation opcode.
        location=image.find(section['code'])
        self.assertGreaterEqual(location,0);self.assertEqual(image.count(section['code']),1)
        bad=bytearray(image);bad[location+entry-section['rva']]^=1
        with self.assertRaises(ValueError):r.bind(native,bytes(bad),name,entry)
        self.assertTrue(raw)

    def test_named_import_slot_and_thunk_mutations_reject(self):
        row=r.worker.workers.catalog.catalog()[0];record=self.report['records'][0]
        image=(SAVED/row['image']).read_bytes();sdk=(SAVED/'sdk-system32-review/vertdll.dll').read_bytes()
        name='EnclaveCopyOutOfEnclave';entry=record['imports'][name]['thunk_rva']
        table=r.sdk.imports(image);r.import_node(image,sdk,name,entry,table)
        bad=copy.deepcopy(table);bad['vertdll.dll'][name]+=8
        with self.assertRaises(ValueError):r.import_node(image,sdk,name,entry,bad)
        with self.assertRaises(ValueError):r.import_node(image,sdk,name,entry+1,table)
        with self.assertRaises(ValueError):r.import_node(image,sdk,'unexpected',entry,table)

    def test_sdk_byte_and_disassembly_mutations_reject(self):
        path=SAVED/'sdk-system32-review/vertdll.dll';image=path.read_bytes()
        text=(DISASSEMBLY/(r.digest(image)+'.txt')).read_text()
        bad=bytearray(image);bad[-1]^=1
        with self.assertRaises(ValueError):r.sdk_stack.inspect(bytes(bad),text)
        with self.assertRaises(ValueError):r.sdk_stack.inspect(image,'')


if __name__=='__main__':unittest.main()
