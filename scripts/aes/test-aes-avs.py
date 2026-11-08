#!/usr/bin/env python3
"""Offline negative controls for the AESAVS package campaign runner."""
import importlib.util
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import tomllib
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('aes_avs', Path(__file__).with_name('check-aes-avs.py'))
avs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(avs)


def success():
    return ('\n'.join(f'test {name} ... ok' for name in sorted(avs.TESTS)) + '\n'
            + '\n'.join(avs.MARKERS)
            + '\ntest result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.0s\n')


class AvsTests(unittest.TestCase):
    def test_exact_success_population(self):
        avs.check_output(success())
        self.assertEqual(len(avs.TESTS), 12)
        self.assertEqual(len(avs.MARKERS), 6)
        for name in avs.TESTS:
            for status in ('ignored', 'FAILED'):
                with self.subTest(name=name, status=status), self.assertRaises(ValueError):
                    avs.check_output(success().replace(f'test {name} ... ok', f'test {name} ... {status}'))
        for bad in ('', success() * 2, success().replace('12 passed', '0 passed'),
                    success().replace('0 filtered out', '1 filtered out'),
                    success().replace('test aes128::monte_carlo ... ok\n', ''),
                    success().replace('aes256::monte_carlo', 'unrelated')):
            with self.subTest(output=bad), self.assertRaises(ValueError):
                avs.check_output(bad)

    def test_each_marker_is_required_exactly_once(self):
        for marker in avs.MARKERS:
            for output in (success().replace(marker, ''), success() + marker + '\n',
                           success().replace(marker, marker + ' not really')):
                with self.subTest(marker=marker), self.assertRaises(ValueError):
                    avs.check_output(output)

    def test_pinned_fixtures_copied_exactly(self):
        self.assertEqual(set(avs.HASHES), {f'ECB{kind}{bits}.rsp' for kind in ('MCT', 'MMT') for bits in (128, 192, 256)})
        self.assertEqual({p.name for p in (avs.FIXTURE / 'fixtures').iterdir()}, set(avs.HASHES))
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            avs.prepare(directory)
            for name in ('avs.rs', *(f'fixtures/{name}' for name in avs.HASHES)):
                self.assertEqual((directory / 'tests' / name).read_bytes(), (avs.FIXTURE / name).read_bytes())

    def test_corrupt_missing_or_symlinked_fixture_never_reaches_cargo(self):
        for name in avs.HASHES:
            for mutation in ('missing', 'symlink', 'corrupt'):
                with tempfile.TemporaryDirectory() as temporary, self.subTest(name=name, mutation=mutation):
                    root = Path(temporary)
                    fixture = root / 'fixture'
                    shutil.copytree(avs.FIXTURE, fixture)
                    path = fixture / 'fixtures' / name
                    path.unlink()
                    if mutation == 'symlink':
                        path.symlink_to(avs.FIXTURE / 'fixtures' / name)
                    elif mutation == 'corrupt':
                        path.write_text('COUNT = 0\n')
                    with patch.object(avs, 'FIXTURE', fixture), \
                         patch.object(avs.packaged.archives, 'run') as run, self.assertRaises(ValueError):
                        avs.prepare(root / 'consumer')
                    run.assert_not_called()

    def test_unknown_compiler_or_route_rejected_before_packaging(self):
        for compiler, route in (('stable', 'direct'), ('1.99.1', 'unknown')):
            with patch.object(avs.packaged, 'package_sources') as package, self.assertRaises(ValueError):
                avs.check(compiler, route)
            package.assert_not_called()

    def test_injected_environment_rejected_before_packaging(self):
        for name in (*avs.packaged.archives.REJECT_ENV, 'PYTHONOPTIMIZE', 'PYTHONPATH'):
            with patch.dict(avs.os.environ, {name: 'untrusted'}), \
                 patch.object(avs.packaged, 'package_sources') as package, self.assertRaises(ValueError):
                avs.check('1.99.1', 'direct')
            package.assert_not_called()

    def test_campaign_failure_does_not_emit_pass(self):
        for output in ('', success().replace('12 passed', '0 passed')):
            with tempfile.TemporaryDirectory() as temporary, \
                 patch.object(avs.packaged.archives.cargo_environment, 'private_directory') as private, \
                 patch.object(avs.packaged.archives, 'isolated_env', return_value={}), \
                 patch.object(avs.packaged, 'package_sources', return_value={}), \
                 patch.object(avs.packaged, 'prepare'), patch.object(avs, 'prepare'), \
                 patch.object(avs.packaged, 'graph'), \
                 patch.object(avs.packaged.archives, 'run', side_effect=[None, SimpleNamespace(stdout='{}'), SimpleNamespace(stdout=output)]), \
                 patch('builtins.print') as emit, self.assertRaises(ValueError):
                private.return_value.__enter__.return_value = temporary
                avs.check('1.99.1', 'direct')
            self.assertFalse(any('AESAVS packaged: PASS' in str(call) for call in emit.call_args_list))

    def test_registration_matrix_binds_sources_tools_and_all_populations(self):
        doc = tomllib.loads((avs.ROOT / 'verification/checks.toml').read_text())
        checks = {c['id']: c for c in doc['checks'] if c['component'] == 'aes' and c['id'].startswith('avs-')}
        self.assertEqual(set(checks), {f'avs-{endpoint}-{route}' for endpoint in ('msrv', 'current') for route in ('direct', 'facade')})
        for endpoint, compiler in (('msrv', '1.90.0'), ('current', '1.99.1')):
            for route in ('direct', 'facade'):
                check = checks[f'avs-{endpoint}-{route}']
                self.assertEqual(check['command'], ['python3', 'scripts/aes/check-aes-avs.py', '--toolchain', compiler, '--route', route])
                self.assertEqual(set(check['inputs']), {'aes-packaged', 'aes-avs', 'hkdf-public-api-modern', 'compiler', 'hkdf-msrv'})
                self.assertEqual(check['success']['exact_tests'], 12)
                self.assertEqual(check['success']['minimum_tests'], 12)
                self.assertEqual(set(check['success']['unique_lines']), set(avs.MARKERS) | {avs.marker(compiler, route)})
                self.assertGreaterEqual(check['timeout_seconds'], 300)
        self.assertEqual(set(doc['groups']['aes-avs']['paths']), {
            'assurance/aes-avs', 'scripts/aes/check-aes-avs.py', 'scripts/aes/test-aes-avs.py'})


if __name__ == '__main__':
    unittest.main()
