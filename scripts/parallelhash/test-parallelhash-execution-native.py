#!/usr/bin/env python3
"""Reject incomplete, replayed and misclassified native observations."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import parallelhash_execution_native as evidence

spec = importlib.util.spec_from_file_location('capture', Path(__file__).with_name('capture-parallelhash-execution-native.py'))
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)
COMMIT = 'a' * 40
SOURCES = {'test-only.rs': 'b' * 64}


def oracle(modes, *, static=False, hosted=False):
    return '\n'.join([*evidence.oracle_lines(modes),
        'Required static routes: ' + ('PASS' if static else 'NOT REQUESTED'),
        'Required native routes: ' + ('PASS' if hosted else 'NOT REQUESTED; preferred routes may be portable')])


def record(lane):
    target, kernel = evidence.LANES[lane]
    results = {'baseline': oracle(evidence.BASE_MODES),
               'static': oracle((*evidence.BASE_MODES, *evidence.STATIC_MODES), static=True),
               'kernel_tests': f'HARDENED_KECCAK_EXECUTION: {kernel}; permutations=1024\n'
                               'test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.1s\n'}
    if kernel == 'ArmKeccak':
        results['hosted'] = oracle((*evidence.BASE_MODES, *evidence.HOSTED_MODES), hosted=True)
    return {'schema': 1, 'commit': COMMIT, 'lane': lane, 'target': target, 'kernel': kernel,
            'cpu': 'test-only synthetic CPU', 'os': 'test-only OS',
            'compiler': f'rustc 1.98.1 (test)\nhost: {target}\nrelease: 1.98.1\n',
            'sources': SOURCES, 'native_attestation': 'operator asserts native, not QEMU', 'results': results}


class NativeTests(unittest.TestCase):
    def test_index_requires_reviewed_committed_all_lane_evidence(self):
        head = 'd' * 40
        source = b'test-only source'
        expected = {'test-only.rs': evidence.digest('test-only.rs', source)}
        objects = {COMMIT + ':test-only.rs': source}
        index = {'schema': 1, 'capture_commit': COMMIT, 'lanes': {}}
        for lane in evidence.LANES:
            value = record(lane)
            value['sources'] = expected
            name = 'assurance/parallelhash-execution-native/' + lane + '.json'
            raw = json.dumps(value).encode()
            objects[head + ':' + name] = raw
            index['lanes'][lane] = {'artifact': name, 'sha256': evidence.hashlib.sha256(raw).hexdigest(),
                                   'cpu': value['cpu'], 'reviewed': True}

        def git(root, *args):
            if args == ('rev-parse', 'HEAD'):
                return head.encode()
            if args[0] == 'status':
                return b''
            if args[0] == 'merge-base':
                if args[2:] != (COMMIT, head):
                    raise ValueError('test-only capture is not an ancestor')
                return b''
            if args[:2] == ('cat-file', '-s'):
                return str(len(objects[args[2]])).encode()
            if args[0] == 'show':
                return objects[args[1]]
            raise AssertionError(args)

        mutants = []
        for key, value in (('schema', True), ('capture_commit', None), ('capture_commit', 'c' * 40),
                           ('lanes', {})):
            changed = copy.deepcopy(index)
            changed[key] = value
            mutants.append(changed)
        for lane in evidence.LANES:
            for key, value in (('reviewed', False), ('sha256', '0' * 64), ('cpu', 'unreviewed CPU'),
                               ('artifact', '../outside.json')):
                changed = copy.deepcopy(index)
                changed['lanes'][lane][key] = value
                mutants.append(changed)
        with patch.object(evidence.shared, 'git', side_effect=git), \
                patch.object(evidence.shared, 'bounded', side_effect=lambda root, name: objects[head + ':' + name]), \
                patch.object(evidence, 'sources', return_value=expected):
            objects[head + ':' + evidence.INDEX] = json.dumps(index).encode()
            evidence.validate()
            for changed in mutants:
                objects[head + ':' + evidence.INDEX] = json.dumps(changed).encode()
                with self.assertRaises(ValueError):
                    evidence.validate()
            objects[head + ':' + evidence.INDEX] = json.dumps(index).encode()
            objects[COMMIT + ':test-only.rs'] += b'drift'
            with self.assertRaisesRegex(ValueError, 'changed native input'):
                evidence.validate()

    def test_schema_and_every_required_result_line(self):
        rejected = 0
        for lane in evidence.LANES:
            original = record(lane)
            evidence.record_check(original, lane, COMMIT, SOURCES)
            mutants = []
            for key in original:
                changed = copy.deepcopy(original)
                del changed[key]
                mutants.append(changed)
            for key, value in (('schema', True), ('commit', 'c' * 40), ('lane', 'wrong'),
                               ('target', 'wasm32-unknown-unknown'), ('kernel', 'X86Sha256'),
                               ('sources', {}), ('cpu', ''), ('cpu', 'spoof\nCPU'),
                               ('os', []), ('native_attestation', 'QEMU'), ('compiler', 'rustc 1.90.0')):
                changed = copy.deepcopy(original)
                changed[key] = value
                mutants.append(changed)
            for mode, text in original['results'].items():
                for line in text.splitlines():
                    changed = copy.deepcopy(original)
                    changed['results'][mode] = text.replace(line, 'omitted')
                    mutants.append(changed)
                for value in (None, '', 'x' * 65536):
                    changed = copy.deepcopy(original)
                    changed['results'][mode] = value
                    mutants.append(changed)
                changed = copy.deepcopy(original)
                del changed['results'][mode]
                mutants.append(changed)
            # A preferred portable campaign cannot replace required worker execution.
            changed = copy.deepcopy(original)
            changed['results']['static'] = changed['results']['baseline']
            mutants.append(changed)
            changed = copy.deepcopy(original)
            marker = evidence.oracle_lines(evidence.BASE_MODES)[0]
            changed['results']['baseline'] += '\n' + marker
            mutants.append(changed)
            for value in mutants:
                with self.assertRaises(ValueError):
                    evidence.record_check(value, lane, COMMIT, SOURCES)
                rejected += 1
        print(f'ParallelHash native schema rejects {rejected} incomplete/identity/result regressions')

    def test_lock_projection_covers_parallel_and_transitive_dependencies(self):
        def lock(*, parallel_version='0.1.0', dependency='2.1.0', facade='0.24.39'):
            rows = ['version = 4']
            for name in evidence.PACKAGES:
                version = parallel_version if name == 'brynja-hash-parallel' else '0.1.0'
                rows.append(f'[[package]]\nname="{name}"\nversion="{version}"')
                if name == 'brynja-hash-parallel-std':
                    rows.append('dependencies=["test-transitive"]')
            rows += [f'[[package]]\nname="test-transitive"\nversion="{dependency}"',
                     f'[[package]]\nname="brynja"\nversion="{facade}"']
            return '\n'.join(rows).encode()
        first = evidence.digest('Cargo.lock', lock())
        self.assertEqual(first, evidence.digest('Cargo.lock', lock(facade='0.24.40')))
        self.assertNotEqual(first, evidence.digest('Cargo.lock', lock(parallel_version='0.1.1')))
        self.assertNotEqual(first, evidence.digest('Cargo.lock', lock(dependency='2.2.0')))
        with self.assertRaises(ValueError):
            evidence.digest('Cargo.lock', lock().replace(b'"test-transitive"', b'"absent"', 1))
        with self.assertRaises(ValueError):
            evidence.digest('Cargo.lock', lock() + b'\n[[package]]\nname="brynja"\nversion="9"')
        self.assertEqual(evidence.digest('source.rs', b'a\r\nb'), evidence.digest('source.rs', b'a\nb'))
        with self.assertRaises(ValueError):
            evidence.shared.document(b'{"schema":1,"schema":1}')

    def test_every_x86_cpu_requires_avx2_and_xsave(self):
        capture.x86_features('flags : avx2 xsave\nflags : xsave avx2')
        for text in ('', 'flags : avx2', 'flags : xsave', 'flags : avx2 xsave\nflags : xsave'):
            with self.assertRaises(ValueError):
                capture.x86_features(text)

    def test_arm_hosted_failure_prevents_static_execution_and_artifact(self):
        lane = 'apple-aarch64'
        commands = []

        def execute(command, env):
            commands.append(command)
            if command[0] == 'rustc':
                return record(lane)['compiler']
            if command[:3] == ['sysctl', '-n', 'machdep.cpu.brand_string']:
                return 'test-only CPU'
            if command[0] == 'sysctl':
                return '1'
            if '--native' in command:
                raise ValueError('test-only hosted authority denied')
            return oracle(evidence.BASE_MODES)

        def git(root, *args):
            return (COMMIT + '\n').encode() if args[0] == 'rev-parse' else b''

        with tempfile.TemporaryDirectory() as directory, \
                patch.object(capture.platform, 'system', return_value='Darwin'), \
                patch.object(capture.platform, 'machine', return_value='arm64'), \
                patch.object(evidence.host, 'clean_environment', return_value={}), \
                patch.object(evidence.host, 'execute', side_effect=execute), \
                patch.object(evidence.shared, 'git', side_effect=git), \
                patch.object(evidence, 'sources', return_value=SOURCES):
            output = Path(directory) / 'never.json'
            with self.assertRaisesRegex(ValueError, 'authority denied'):
                capture.capture(lane, output)
            self.assertFalse(output.exists())
        self.assertFalse(any('--static' in command or command[0] == 'cargo' for command in commands))

    def test_real_libtest_output_and_serial_prefix_rejection(self):
        options = capture.kernel_command()[capture.kernel_command().index('--') + 1:]
        self.assertEqual(options, ['--show-output', '--test-threads=1'])
        with tempfile.TemporaryDirectory(prefix='brynja-parallel-formatter-') as directory:
            root = Path(directory)
            source = root / 'formatter.rs'
            binary = root / ('formatter.exe' if os.name == 'nt' else 'formatter')
            source.write_text('''#[test] fn execution() {
                println!("HARDENED_KECCAK_EXECUTION: {}; permutations=1024",
                         std::env::var("TEST_KERNEL").unwrap());
            }
            #[test] fn cleanup() {} #[test] fn quarantine() {} #[test] fn ownership() {}
            ''')
            subprocess.run(['rustc', '+1.98.1', '--test', str(source), '-o', str(binary)],
                           check=True, capture_output=True, timeout=60)
            for lane in evidence.LANES:
                value = record(lane)
                env = dict(os.environ, TEST_KERNEL=value['kernel'])
                for threads in (1, 2):
                    result = subprocess.run([str(binary), '--show-output', f'--test-threads={threads}'],
                        env=env, text=True, capture_output=True, check=True, timeout=30)
                    value['results']['kernel_tests'] = result.stdout
                    evidence.record_check(value, lane, COMMIT, SOURCES)
                result = subprocess.run([str(binary), '--nocapture', '--test-threads=1'],
                    env=env, text=True, capture_output=True, check=True, timeout=30)
                value['results']['kernel_tests'] = result.stdout
                with self.assertRaises(ValueError):
                    evidence.record_check(value, lane, COMMIT, SOURCES)

    def test_native_gate_is_tag_only(self):
        gate = (evidence.ROOT / 'scripts/tag_gate.sh').read_text()
        checks = (evidence.ROOT / 'scripts/checks.sh').read_text()
        self.assertIn('\npython3 scripts/parallelhash/check-parallelhash-execution-native.py\n', gate)
        self.assertNotIn('\npython3 scripts/parallelhash/check-parallelhash-execution-native.py\n', checks)
        self.assertIn('\npython3 scripts/parallelhash/test-parallelhash-execution-native.py\n', checks)


if __name__ == '__main__':
    unittest.main()
