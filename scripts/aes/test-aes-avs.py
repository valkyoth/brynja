#!/usr/bin/env python3
"""Offline negative controls for the AESAVS package campaign runner."""
import contextlib
import importlib.util
import hashlib
import io
from pathlib import Path
import shutil
import stat
import tempfile
from types import SimpleNamespace
import tomllib
import unittest
import warnings
import zipfile
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('aes_avs', Path(__file__).with_name('check-aes-avs.py'))
avs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(avs)

spec = importlib.util.spec_from_file_location('avs_provenance', Path(__file__).with_name('check-aes-avs-provenance.py'))
provenance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(provenance)


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
            'assurance/aes-avs', 'scripts/aes/check-aes-avs.py', 'scripts/aes/test-aes-avs.py',
            'scripts/aes/check-aes-avs-provenance.py'})

    def archive(self, kind='MCT', mutation=None):
        stream = io.BytesIO()
        names = [f'ECB{kind}{bits}.rsp' for bits in (128, 192, 256)]
        with zipfile.ZipFile(stream, 'w') as archive, warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            for name in names:
                if mutation == 'missing' and name == names[0]:
                    continue
                raw = (avs.FIXTURE / 'fixtures' / name).read_bytes()
                if mutation == 'content' and name == names[0]:
                    raw += b'CHANGED\n'
                info = zipfile.ZipInfo(name)
                info.external_attr = (stat.S_IFLNK | 0o777) << 16 if mutation == 'symlink' else (stat.S_IFREG | 0o600) << 16
                archive.writestr(info, raw.replace(b'\n', b'\r\n') + b'\r\n\r\n')
            if mutation == 'duplicate':
                archive.writestr(names[0], b'duplicate')
            if mutation == 'traversal':
                archive.writestr('../outside', b'no extraction')
        return stream.getvalue()

    def check(self, data, kind='MCT'):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'original.zip'
            path.write_bytes(data)
            # Synthetic archives test admission after the original-digest guard.
            # The command line offers no hash override.
            with patch.dict(provenance.ARCHIVES, {kind: hashlib.sha256(data).hexdigest()}):
                return provenance.check_archive(path, kind)

    def test_original_archive_pins_match_documented_downloads(self):
        readme = (avs.FIXTURE / 'README.md').read_text()
        self.assertEqual(set(provenance.ARCHIVES), {'MCT', 'MMT'})
        for digest in provenance.ARCHIVES.values():
            self.assertIn(digest, readme)

    def test_normalization_reproduces_each_checked_in_fixture(self):
        for kind in ('MCT', 'MMT'):
            self.assertEqual(self.check(self.archive(kind), kind), 3)

    def test_wrong_original_digest_fails_before_zip_parsing(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'wrong.zip'
            path.write_bytes(self.archive())
            with patch.object(provenance.zipfile, 'ZipFile') as opened, self.assertRaisesRegex(ValueError, 'ZIP hash mismatch'):
                provenance.check_archive(path, 'MCT')
            opened.assert_not_called()

    def test_malformed_archives_and_response_changes_fail(self):
        for mutation in ('missing', 'duplicate', 'traversal', 'symlink', 'content'):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.check(self.archive(mutation=mutation))
        with self.assertRaises(zipfile.BadZipFile):
            self.check(b'not a zip')

    def test_size_limits_and_nonregular_inputs_fail(self):
        with patch.object(provenance, 'MAX_ARCHIVE', 10), self.assertRaisesRegex(ValueError, 'size limit'):
            self.check(self.archive())
        with patch.object(provenance, 'MAX_MEMBER', 10), self.assertRaisesRegex(ValueError, 'oversized'):
            self.check(self.archive())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'original.zip'
            source.write_bytes(self.archive())
            link = root / 'link.zip'
            link.symlink_to(source)
            for path in (root / 'missing', root, link):
                with self.assertRaisesRegex(ValueError, 'provenance input'):
                    provenance.check_archive(path, 'MCT')

    def test_checked_in_bytes_and_symlinks_cannot_be_substituted(self):
        data = self.archive()
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary) / 'fixtures'
            shutil.copytree(avs.FIXTURE / 'fixtures', fixture)
            first = fixture / 'ECBMCT128.rsp'
            first.write_bytes(b'changed')
            with patch.object(provenance.avs, 'FIXTURE', fixture.parent), self.assertRaisesRegex(ValueError, 'differs from original'):
                self.check(data)
            first.unlink()
            first.symlink_to(avs.FIXTURE / 'fixtures/ECBMCT128.rsp')
            with patch.object(provenance.avs, 'FIXTURE', fixture.parent), self.assertRaisesRegex(ValueError, 'symlinked'):
                self.check(data)

    def test_cli_success_requires_both_archives_and_emits_one_marker(self):
        stream = io.StringIO()
        args = ['provenance', '--mct', 'mct.zip', '--mmt', 'mmt.zip']
        with patch('sys.argv', args), patch.object(provenance, 'check_archive', return_value=3) as check, contextlib.redirect_stdout(stream):
            provenance.main()
        self.assertEqual(check.call_args_list[0].args, (Path('mct.zip'), 'MCT'))
        self.assertEqual(check.call_args_list[1].args, (Path('mmt.zip'), 'MMT'))
        self.assertEqual(stream.getvalue().splitlines(), [provenance.MARKER])

    def test_cli_failed_second_archive_never_emits_success(self):
        stream = io.StringIO()
        args = ['provenance', '--mct', 'mct.zip', '--mmt', 'mmt.zip']
        with patch('sys.argv', args), patch.object(provenance, 'check_archive', side_effect=[3, ValueError('bad MMT')]), contextlib.redirect_stdout(stream), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            provenance.main()
        self.assertEqual(error.exception.code, 2)
        self.assertNotIn(provenance.MARKER, stream.getvalue())


if __name__ == '__main__':
    unittest.main()
