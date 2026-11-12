#!/usr/bin/env python3
"""Startup review controls. Synthetic policies cannot approve production code."""
import importlib.util
import contextlib
import io
import json
from pathlib import Path
import shutil
import struct
import tempfile
import tomllib
from types import SimpleNamespace
import unittest
from unittest.mock import patch


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


r = module('startup_test_review', 'aes_accelerated_startup_arm.py')
runner = module('startup_test_runner', 'check-aes-accelerated-startup.py')
fixtures = module('startup_test_fixture', 'test-aes-accelerated-linked.py')


def synthetic():
    _, _, original, _ = fixtures.fixture(r.TARGET)
    image = bytearray(original); lines, raw, refs = [], bytearray(), []
    start, pos = 0x1500, 0x800
    targets = {role: (role,0x1600+i*16,4) for i,role in enumerate(
        ['bcmp', *(k+str(b) for k in ('expand','round') for b in (128,192,256))])}
    def emit(line, word):
        lines.append(line); raw.extend(word.to_bytes(4,'little'))
    for role, (_,address,_) in targets.items():
        delta = address-(start+len(raw)); emit(f'bl 0x{address:x} <{role}>', 0x94000000 | ((delta//4)&0x3ffffff))
    for role,data in r.REFERENCE.items():
        address = 0x1000+pos; image[pos:pos+len(data)] = data
        refs.append(dict(role=role,offset=pos,size=len(data)))
        if role.startswith('schedule'):
            delta = address-(start+len(raw))
            emit(f'adr x20, 0x{address:x} <data>', 0x10000014 | ((delta&3)<<29) | ((delta>>2)<<5))
        else:
            emit('adrp x8, 0x1000 <data>', 0x90000008)
            emit(f'add x8, x8, #{pos}', 0x91000108 | (pos<<10))
        pos += len(data)
    emit('ret',0xd65f03c0)
    image[0x500:0x500+len(raw)] = raw
    return (lines,bytes(raw),('startup',start,len(raw)),bytes(image),targets),refs


class AcceleratedStartupTests(unittest.TestCase):
    def test_fixed_reference_population_and_sizes(self):
        self.assertEqual(set(r.REFERENCE), {'plain','cipher128','cipher192','cipher256','schedule128','schedule192','schedule256'})
        for bits,size in ((128,176),(192,208),(256,240)):
            data = r.REFERENCE[f'schedule{bits}']
            self.assertEqual(len(data),size)
            self.assertEqual(data[:bits//8],bytes(range(bits//8)))
            self.assertEqual(len(r.REFERENCE[f'cipher{bits}']),16)
        self.assertEqual(r.REFERENCE['plain'].hex(),'00112233445566778899aabbccddeeff')

    def test_policies_pin_whole_bodies_and_comparators(self):
        self.assertEqual(set(r.POLICY), {'1.90.0','1.99.1'})
        for compiler, policies in r.POLICY.items():
            self.assertEqual(set(policies), {'startup','bcmp','memcmp'})
            self.assertEqual(policies['startup']['instructions'],196 if compiler=='1.90.0' else 193)
            self.assertEqual(policies['startup']['calls'],12)
            self.assertEqual(policies['startup']['branches'],2)
            self.assertEqual(policies['startup']['address_constants'],7)
            self.assertEqual(policies['startup']['constants'],3)
            self.assertEqual(policies['bcmp']['tail_calls'],1)
            for p in policies.values():
                for field in ('text_sha256','encoding_sha256'): self.assertRegex(p[field],r'^[0-9a-f]{64}$')

    def test_synthetic_is_never_a_production_pass(self):
        args,_ = synthetic()
        for compiler in r.POLICY:
            with self.assertRaisesRegex(ValueError,'startup stream changed'): r.check(*args,compiler)

    def test_every_instruction_byte_target_and_constant_is_checked(self):
        args,refs = synthetic(); lines,raw,row,image,targets=args
        actual = r.observe(*args)[0]
        with patch.dict(r.POLICY, {'1.99.1':{'startup':actual}}):
            self.assertEqual(r.mutations(r.check,*args,'1.99.1'),len(lines)+len(raw))
            for ref in refs:
                for i in range(ref['size']):
                    pos=ref['offset']+i; changed=image[:pos]+bytes([image[pos]^1])+image[pos+1:]
                    with self.assertRaisesRegex(ValueError,'reference changed'):
                        r.check(lines,raw,row,changed,targets,'1.99.1')
            for role,(name,address,size) in targets.items():
                for value in ((name,address+4,size),('wrong',address,size),row):
                    with self.assertRaises(ValueError): r.check(lines,raw,row,image,{**targets,role:value},'1.99.1')
                with self.assertRaisesRegex(ValueError,'call population'):
                    r.check(lines,raw,row,image,{k:v for k,v in targets.items() if k!=role},'1.99.1')
            with self.assertRaises(ValueError):
                r.check(lines,raw,row,image,{**targets,'expand128':targets['expand192'],'expand192':targets['expand128']},'1.99.1')

    def test_address_text_must_agree_with_bytes_and_read_only_mapping(self):
        args,refs=synthetic();lines,raw,row,image,targets=args
        for i,line in enumerate(lines):
            if line.startswith(('adr ','adrp ','add x8')):
                changed=lines.copy();changed[i]=line.replace('x20','x21').replace('x8','x9')
                with self.assertRaises(ValueError):r.observe(changed,raw,row,image,targets)
        ref=refs[0]
        with self.assertRaises(ValueError):r.reference_at(image,[(0x1000,len(image),0,len(image),6)],0x1000+ref['offset'],True)
        with self.assertRaises(ValueError):r.reference_at(image,r.arm.segments(image),0x1000+ref['offset']+1,True)
        with self.assertRaises(ValueError):r.observe(lines,raw[:-4],row,image,targets)
        changed=bytearray(image);changed[0x500]^=1
        with self.assertRaisesRegex(ValueError,'decoded bytes'):r.observe(lines,raw,row,bytes(changed),targets)

    def test_corruption_cases_touch_exactly_one_reference_byte(self):
        args,refs=synthetic();image=args[3]
        cases=list(r.corruption_cases(image,refs))
        self.assertEqual(len(cases),628)
        self.assertEqual(len({name for name,_ in cases}),628)
        for name,changed in cases:
            role,index=name.split(':');ref=next(r for r in refs if r['role']==role)
            self.assertEqual(len(changed),len(image))
            self.assertEqual([i for i,(a,b) in enumerate(zip(image,changed)) if a!=b],[ref['offset']+int(index)])
        for bad in (refs[:-1],refs+[refs[0]],[{**ref,'offset':-1} for ref in refs],
                    [{**ref,'size':0} for ref in refs]):
            with self.assertRaises(ValueError):list(r.corruption_cases(image,bad))

    def test_symbols_and_dependencies_fail_closed(self):
        for name in ('_ZN30brynja_aes_accelerated_fixture7startup17h0000000000000000E',
                     '_RNvCs123_30brynja_aes_accelerated_fixture7startup'):
            table=f'00001500 00000004 t {name}\n00001600 00000004 T bcmp\n00001700 00000004 T memcmp'
            self.assertEqual(set(r.candidates(table)),{'startup','bcmp','memcmp'})
            for bad in ('',table+'\n'+table.splitlines()[0],table.replace('7startup','8startup'),
                        table.replace('00001600','00001500'),table.replace('00000004','00000003'),table.replace(' T ',' D ')):
                with self.assertRaises(ValueError):r.candidates(bad)
            with patch.object(r.c.kernels,'inspect',side_effect=ValueError('round rejected')):
                with patch.object(r,'check') as check:
                    with self.assertRaisesRegex(ValueError,'round rejected'):r.inspect(table,'',b'','1.99.1','abort')
                    check.assert_not_called()

    def test_runner_rejects_unknown_compiler_before_packaging(self):
        with patch.object(runner.packaged,'package_sources') as package:
            with self.assertRaises(ValueError):runner.check('unknown')
            package.assert_not_called()

    def test_native_runner_rejects_wrong_host_and_other_modes_before_packaging(self):
        for mode, system, machine in (('arm-native', 'Linux', 'x86_64'),
                                      ('arm-native', 'Darwin', 'arm64'),
                                      ('native', 'Linux', 'x86_64'),
                                      ('arm-qemu', 'Linux', 'aarch64')):
            with patch.object(runner.platform, 'system', return_value=system), \
                 patch.object(runner.platform, 'machine', return_value=machine), \
                 patch.object(runner.packaged, 'package_sources') as package:
                with self.assertRaises(ValueError):runner.check('1.99.1', mode=mode)
                package.assert_not_called()

    def test_native_static_probe_is_baseline_compiled_and_requires_exact_success(self):
        from types import SimpleNamespace
        for stdout, stderr in (('AES_STATIC_HOST_BUNDLE_PASS\n', ''),
                               ('', ''), ('AES_STATIC_HOST_BUNDLE_PASS\nextra\n', ''),
                               ('AES_STATIC_HOST_BUNDLE_PASS\n', 'warning')):
            with patch.object(runner.packaged.archives, 'run', side_effect=[
                    SimpleNamespace(), SimpleNamespace(stdout=stdout, stderr=stderr)]) as run:
                if stdout == 'AES_STATIC_HOST_BUNDLE_PASS\n' and not stderr:
                    runner.native_probe(Path('/private'), Path('/private'), {}, '1.90.0')
                else:
                    with self.assertRaises(ValueError):
                        runner.native_probe(Path('/private'), Path('/private'), {}, '1.90.0')
                build, execute = [call.args[0] for call in run.call_args_list]
                self.assertEqual(build[:2], ['rustc', '+1.90.0'])
                self.assertIn('aarch64-unknown-linux-musl', build)
                self.assertFalse(any('target-feature' in arg for arg in build))
                self.assertEqual(execute, ['/private/baseline-probe'])

    def test_registry_pins_inputs_and_success_marker(self):
        registry=tomllib.loads((runner.ROOT/'verification/checks.toml').read_text())
        checks={c['id']:c for c in registry['checks'] if c.get('category')=='aes-linked-arm-startup'}
        self.assertEqual(set(checks),{'accelerated-arm-startup-msrv','accelerated-arm-startup-current'})
        for endpoint,compiler in (('msrv','1.90.0'),('current','1.99.1')):
            check=checks['accelerated-arm-startup-'+endpoint]
            self.assertEqual(check['command'],['python3','scripts/aes/check-aes-accelerated-startup.py','--toolchain',compiler])
            self.assertEqual(check['success']['unique_lines'],[f'AES_ARM_STARTUP_LINKED_PASS: {compiler}; four static emulated consumers'])
            self.assertTrue({'aes-build','aes-accelerated-startup','aes-accelerated-linked','aes-accelerated-campaigns',
                             'aes-accelerated-arm-constructors','aes-accelerated-arm-cleanup','aes-packaged','aes-kernel-qemu'} <= set(check['inputs']))
        paths=set(registry['groups']['aes-accelerated-startup']['paths'])
        self.assertEqual(paths,{'assurance/aes-accelerated-campaigns/startup.rs','scripts/aes/check-aes-accelerated-startup.py',
            'scripts/aes/aes_accelerated_startup_arm.py','scripts/aes/startup-arm-reference.json','scripts/aes/startup-arm-review.json',
            'scripts/aes/test-aes-accelerated-startup.py','docs/assurance/aes-accelerated-startup.md'})

    def test_apple_requires_native_host_and_capture_only_before_packaging(self):
        for system, machine, capture in (('Linux','aarch64',True), ('Darwin','x86_64',True),
                                          ('Darwin','arm64',False)):
            with patch.object(runner.platform,'system',return_value=system), \
                 patch.object(runner.platform,'machine',return_value=machine), \
                 patch.object(runner.packaged,'package_sources') as package:
                with self.assertRaises(ValueError):
                    runner.check('1.99.1',capture_only=capture,mode='apple-native')
                package.assert_not_called()

    def test_apple_probe_does_not_force_linux_linker_or_aes(self):
        with patch.object(runner.packaged.archives,'run',side_effect=[SimpleNamespace(),
                SimpleNamespace(stdout='AES_STATIC_HOST_BUNDLE_PASS\n',stderr='')]) as run:
            runner.native_probe(Path('/private'),Path('/private'),{},'1.90.0','aarch64-apple-darwin')
        build=run.call_args_list[0].args[0]
        self.assertIn('aarch64-apple-darwin',build)
        self.assertFalse(any('linker=' in arg or 'target-feature' in arg for arg in build))

    def test_apple_capture_pipeline_never_claims_review(self):
        # Synthetic process responses test runner wiring, not native correctness.
        cases=[(admission,failure) for admission in ('static','hosted')
               for failure in (None,'execution-diagnostic','missing-marker','inspection-diagnostic')]
        for admission,failure in cases:
            with self.subTest(admission=admission,failure=failure), tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary); calls=[]
                fixture=root/'assurance/aes-accelerated-campaigns'
                fixture.mkdir(parents=True)
                for name in ('startup.rs','startup-hosted.rs'):
                    shutil.copyfile(runner.ROOT/'assurance/aes-accelerated-campaigns'/name,fixture/name)
                tool=root/'inspection-tool'; tool.write_bytes(b'synthetic test tool')
                def run(argv,directory,env):
                    calls.append((argv,dict(env)))
                    stdout,stderr='',''
                    if 'metadata' in argv: stdout='{}'
                    elif 'build' in argv:
                        binary=Path(env['CARGO_TARGET_DIR'])/'aarch64-apple-darwin/release'/runner.campaigns.NAME
                        binary.parent.mkdir(parents=True); binary.write_bytes(b'synthetic non-executable')
                    elif len(argv)==1:
                        stdout=('AES_ARM_HOSTED_STARTUP_PASS' if admission=='hosted' else 'AES_ARM_STARTUP_PASS')+'\n'
                        if failure=='execution-diagnostic': stderr='unexpected diagnostic'
                        if failure=='missing-marker': stdout=''
                    elif argv[0]==str(tool) and failure=='inspection-diagnostic':
                        stderr='inspection failed'
                    return SimpleNamespace(stdout=stdout,stderr=stderr)
                output=io.StringIO()
                with contextlib.ExitStack() as stack:
                    for obj,name,value in ((runner,'ROOT',root),): stack.enter_context(patch.object(obj,name,value))
                    stack.enter_context(patch.dict(runner.os.environ,{},clear=True))
                    stack.enter_context(patch.object(runner.platform,'system',return_value='Darwin'))
                    stack.enter_context(patch.object(runner.platform,'machine',return_value='arm64'))
                    stack.enter_context(patch.object(runner.shutil,'which',return_value=str(tool)))
                    stack.enter_context(patch.object(runner.packaged.archives.cargo_environment,'private_directory',
                        side_effect=lambda _: tempfile.TemporaryDirectory(dir=root)))
                    stack.enter_context(patch.object(runner.packaged.archives,'isolated_env',return_value={}))
                    stack.enter_context(patch.object(runner.packaged,'package_sources',return_value={}))
                    stack.enter_context(patch.object(runner.campaigns,'manifest',return_value=''))
                    graph=stack.enter_context(patch.object(runner.campaigns,'graph'))
                    probe=stack.enter_context(patch.object(runner,'native_probe'))
                    reviewer=stack.enter_context(patch.object(runner.packaged,'module'))
                    stack.enter_context(patch.object(runner.packaged.archives,'run',side_effect=run))
                    stack.enter_context(contextlib.redirect_stdout(output))
                    if failure:
                        with self.assertRaises(ValueError):runner.check('1.99.1',True,admission,'apple-native')
                    else:
                        runner.check('1.99.1',True,admission,'apple-native')
                self.assertEqual(probe.call_count,1 if admission=='static' else 0)
                reviewer.assert_not_called()
                reports=[json.loads(p.read_text()) for p in (root/'target').rglob('*.json') if 'metadata' not in p.name]
                if failure:
                    self.assertEqual(reports,[])
                    self.assertNotIn('CAPTURE ONLY',output.getvalue())
                    self.assertNotIn('LINKED_PASS',output.getvalue())
                    continue
                self.assertEqual(graph.call_count,2)
                self.assertEqual({(r['route'],r['panic']) for r in reports},
                                 {(r,p) for r in ('direct','facade') for p in ('abort','unwind')})
                self.assertEqual(len(reports),4)
                for report in reports:
                    self.assertEqual(report['machine_review'],'not-performed')
                    self.assertEqual(report['target'],'aarch64-apple-darwin')
                    self.assertEqual(report['execution'],'native')
                    self.assertEqual(report['admission'],admission)
                    self.assertNotIn('--print-size',report['symbol_command'])
                    self.assertTrue(report['execution_command'][0].endswith('.macho'))
                    self.assertNotIn('review',report)
                    self.assertNotIn('executed_quarantine_cases',report)
                    source=fixture/('startup-hosted.rs' if admission=='hosted' else 'startup.rs')
                    self.assertEqual(report['fixture_sha256'],runner.linked.digest(source))
                for argv,env in calls:
                    self.assertNotIn('CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER',env)
                    if 'build' in argv:
                        self.assertEqual(env['RUSTFLAGS'],'-Ctarget-feature=-aes' if admission=='hosted' else '-Ctarget-feature=+aes,+neon')
                        self.assertIn('--offline',argv); self.assertIn('--locked',argv)
                self.assertIn('CAPTURE ONLY',output.getvalue())
                self.assertNotIn('LINKED_PASS',output.getvalue())


if __name__=='__main__':unittest.main()
