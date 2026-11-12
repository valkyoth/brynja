#!/usr/bin/env python3
"""Fail-closed controls for isolated expansion acceptance; no hardware runs here."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('expansion_candidate', Path(__file__).with_name('check-aes-expansion-candidate.py'))
r = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(r)


def output():
    return '\n'.join([*(f'test {name} ... ok' for name in sorted(r.TESTS)), *r.MARKERS,
        'test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s'])


def diagnostic(target='x86_64-unknown-linux-gnu', code='E0080', primary=True, status=1):
    source = 'aarch64_expand.rs' if target.startswith('aarch64') else 'x86_expand.rs'
    row = {'level': 'error', 'code': {'code': code}, 'spans': [{'is_primary': primary,
           'file_name': '/checkout/crates/brynja-crypto-cpu/src/aes/' + source}]}
    return subprocess.CompletedProcess([], status, '', json.dumps(row))


class ExpansionCandidateTests(unittest.TestCase):
    def test_complete_population(self):
        r.validate(output())
        self.assertEqual(len(r.TESTS), 10)
        self.assertEqual(len(r.MARKERS), 9)

    def test_missing_duplicate_partial_or_prefixed_markers_fail(self):
        for marker in r.MARKERS:
            for text in (output().replace(marker, ''), output() + '\n' + marker,
                         output().replace(marker, 'skipped ' + marker)):
                with self.assertRaises(ValueError): r.validate(text)

    def test_test_names_counts_and_outcomes_are_required(self):
        for text in ('', output().replace('10 passed', '9 passed'), output().replace('0 ignored', '1 ignored'),
                     output().replace('0 filtered out', '1 filtered out'), output().replace('... ok', '... FAILED', 1),
                     output().replace('expansion::aes128_schedule_and_vectors ... ok', 'other ... ok'),
                     output() + '\n' + output().splitlines()[0], output() + '\n' + output().splitlines()[-1]):
            with self.assertRaises(ValueError): r.validate(text)

    def test_constant_domain_diagnostics_are_exact_and_target_specific(self):
        for target in ('x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-musl'):
            good = diagnostic(target)
            self.assertTrue(r.rejected_domain(good, target))
            aborted = {'level': 'error', 'code': None, 'spans': [], 'message': 'aborting due to 1 previous error'}
            self.assertTrue(r.rejected_domain(subprocess.CompletedProcess([], 1, '', good.stderr + '\n' + json.dumps(aborted)), target))
            for bad in (diagnostic(target, code='E0308'), diagnostic(target, primary=False), diagnostic(target, status=0),
                        diagnostic(target, status=101), subprocess.CompletedProcess([], 1, '', good.stderr + '\n' + good.stderr),
                        subprocess.CompletedProcess([], 1, '', 'not json'), subprocess.CompletedProcess([], 1, '', '{}'),
                        subprocess.CompletedProcess([], 1, '', good.stderr.replace('expand.rs', 'other.rs'))):
                self.assertFalse(r.rejected_domain(bad, target))
        self.assertFalse(r.rejected_domain(diagnostic(), 'aarch64-unknown-linux-musl'))

    def test_configuration_or_environment_rejected_before_compilation(self):
        with patch.object(r, 'execute') as execute:
            for compiler, mode in (('stable', 'x86'), ('1.90.0', 'native-arm')):
                with self.assertRaises(ValueError): r.check(compiler, mode)
            for name in r.REJECT:
                with patch.dict(r.os.environ, {name: 'injected'}), self.assertRaises(ValueError): r.check('1.90.0', 'x86')
            with patch.object(r.platform, 'machine', return_value='aarch64'), self.assertRaises(ValueError): r.check('1.90.0', 'x86')
            execute.assert_not_called()

    def test_failed_execution_retains_both_streams(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            expected = subprocess.CompletedProcess([], 101, 'failed test', 'stderr')
            with patch.object(r.packaged.archives.cargo_environment, 'check') as guard, patch.object(r.subprocess, 'run', return_value=expected) as run:
                self.assertIs(r.execute(['binary'], directory, {}, directory, 'tests'), expected)
            guard.assert_called_once_with(directory, {})
            record = json.loads((directory / 'tests.json').read_text())
            self.assertEqual(record, {'command': ['binary'], 'returncode': 101, 'stdout': 'failed test', 'stderr': 'stderr'})
            self.assertEqual(run.call_args.kwargs['timeout'], 180)
            with self.assertRaises(ValueError): r.successful(expected, 'test')

    def test_timeout_retains_partial_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with patch.object(r.packaged.archives.cargo_environment, 'check'), \
                 patch.object(r.subprocess, 'run', side_effect=subprocess.TimeoutExpired('binary', 180, output=b'partial', stderr=b'error')):
                with self.assertRaises(subprocess.TimeoutExpired): r.execute(['binary'], directory, {}, directory, 'tests')
            record = json.loads((directory / 'tests.json').read_text())
            self.assertTrue(record['timeout'])
            self.assertEqual((record['stdout'], record['stderr']), ('partial', 'error'))

    def test_compile_fixture_covers_valid_and_invalid_domains(self):
        source = (r.FIXTURE / 'expansion-compile.rs').read_text()
        self.assertIn('#![no_std]', source)
        for case in r.INVALID:
            self.assertEqual(source.count('#[cfg(' + case + ')]'), 1)
        for width, k, s in ((128, 16, 176), (192, 24, 208), (256, 32, 240)):
            self.assertIn(f'probe!(aes_expansion_{width}, {k}, {s});', source)

    def test_integrated_expansion_uses_admission_not_portable_fallback(self):
        source = (r.ROOT / 'crates/brynja-crypto-cpu/src/aes/mod.rs').read_text()
        self.assertIn('mod x86_expand;', source)
        self.assertIn('mod aarch64_expand;', source)
        self.assertIn('dispatch_expansion(self.owner, key, schedule)?;', source)
        owner = (r.ROOT / 'crates/brynja-crypto/src/aes/execution.rs').read_text()
        self.assertNotIn('portable::', owner)
        self.assertIn('session.$expand(key, output)?;', owner)
        self.assertIn('session.check()?;', owner)
        startup = (r.ROOT / 'crates/brynja-crypto-cpu/src/aes/kat.rs').read_text()
        for key, size in ((16, 176), (24, 208), (32, 240)):
            self.assertIn(f'expansion_answer::<{key}, {size}>', startup)

    def test_registry_requires_all_domains_tests_and_markers(self):
        registry = tomllib.loads((r.ROOT / 'verification/checks.toml').read_text())
        checks = {c['id']: c for c in registry['checks'] if c.get('category') == 'aes-expansion-candidate'}
        self.assertEqual(set(checks), {f'expansion-{mode}-{endpoint}' for mode in ('x86', 'arm-qemu') for endpoint in ('msrv', 'current')})
        for mode in ('x86', 'arm-qemu'):
            for endpoint, compiler in (('msrv', '1.90.0'), ('current', '1.99.1')):
                check = checks[f'expansion-{mode}-{endpoint}']
                self.assertEqual(check['command'], ['python3', 'scripts/aes/check-aes-expansion-candidate.py', '--toolchain', compiler, '--mode', mode])
                self.assertTrue(set(r.REJECT) <= set(check['reject_environment']))
                self.assertTrue({'aes-expansion-candidate', 'aes-kernel-candidate', 'aes-packaged', 'hkdf-public-api-modern'} <= set(check['inputs']))
                if mode == 'arm-qemu': self.assertIn('aes-kernel-qemu', check['inputs'])
                self.assertEqual(check['success']['exact_tests'], 10)
                self.assertEqual(set(check['success']['unique_lines']), set(r.MARKERS) | {
                    'AES_EXPANSION_DOMAIN_PASS: 3 valid shapes; 5 rejected shapes; no_std',
                    f'AES_EXPANSION_CANDIDATE_PASS: {compiler} {mode}; correctness only; not public admission'})


if __name__ == '__main__':
    unittest.main()
