#!/usr/bin/env python3
"""Fail-closed controls for the archive-only provider consumer."""
from contextlib import redirect_stdout
import copy
import importlib.util
import io
from pathlib import Path
import tempfile
import tomllib
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('provider_packaged', Path(__file__).with_name('check-aes-provider-packaged.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
base_tests = runner.packaged.module('provider_archive_tests', Path(__file__).with_name('test-aes-packaged.py'))


class ProviderPackagedTests(unittest.TestCase):
    def test_both_routes_copy_all_widths_and_exact_archive_dependencies(self):
        for route in runner.packaged.consumer.ROUTES:
            with tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary) / 'consumers' / route
                versions = {name: '0.1.0' for name in runner.packaged.archives.MODERN}
                runner.prepare(directory, versions, route)
                manifest = tomllib.loads((directory / 'Cargo.toml').read_text())
                for dep in manifest['dependencies'].values():
                    self.assertEqual(dep, {'version': '=0.1.0', 'optional': True,
                                          'default-features': False,
                                          'features': ['hazmat-aes-block', 'external-key-provider']})
                for name in runner.FILES:
                    text = runner.source(name)
                    if route == 'facade':
                        text = text.replace('brynja_crypto::', 'brynja::crypto::')
                    self.assertEqual((directory / 'tests' / name.split('/tests/')[1]).read_text(), text)
                self.assertEqual((directory / 'src/lib.rs').read_text(), runner.source(runner.EXAMPLE))

    def test_missing_or_symlinked_fixtures_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'actual').write_text('fixture')
            (root / 'link').symlink_to(root / 'actual')
            (root / 'linked-parent').symlink_to(root, target_is_directory=True)
            with patch.object(runner, 'ROOT', root):
                self.assertEqual(runner.source('actual'), 'fixture')
                for name in ('missing', 'link', 'linked-parent/actual'):
                    with self.subTest(name=name), self.assertRaises(ValueError):
                        runner.source(name)

    def test_graph_requires_provider_feature_without_loosening_archive_policy(self):
        for route in runner.packaged.consumer.ROUTES:
            directory, unpacked, versions, original = base_tests.PackagedTests().metadata(route)
            by_id = {p['id']: p['name'] for p in original['packages']}
            with self.assertRaises(ValueError):
                runner.packaged.graph(original, route, directory, unpacked, versions, provider=True)
            for node in original['resolve']['nodes']:
                if by_id[node['id']] in ('brynja', 'brynja-crypto'):
                    node['features'].append('external-key-provider')
            runner.packaged.graph(original, route, directory, unpacked, versions, provider=True)
            with self.assertRaises(ValueError):
                runner.packaged.graph(original, route, directory, unpacked, versions)
            for field, value in (('source', 'registry+unexpected'), ('manifest_path', '/tmp/checkout/Cargo.toml')):
                changed = copy.deepcopy(original)
                next(p for p in changed['packages'] if p['name'] == 'brynja-crypto')[field] = value
                with self.assertRaises(ValueError):
                    runner.packaged.graph(changed, route, directory, unpacked, versions, provider=True)

    def test_exact_test_names_statuses_and_summary_are_required(self):
        names = sorted('contracts::' + name for name in runner.TESTS)
        rows = [f'test {name} ... ok' for name in names]
        summary = 'test result: ok. 17 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0s'
        valid = '\n'.join(rows + [summary])
        runner.check_tests(valid)
        for text in (valid.replace(rows[0], ''), valid + '\n' + rows[0],
                     valid.replace(rows[0], rows[1]), valid.replace('... ok', '... ignored', 1),
                     valid.replace('17 passed', '0 passed'), valid + '\n' + summary):
            with self.subTest(text=text), self.assertRaises(ValueError):
                runner.check_tests(text)

    def test_failure_never_prints_success_marker(self):
        with patch.object(runner.packaged, 'package_sources', side_effect=ValueError('bad archive')), \
             redirect_stdout(io.StringIO()) as output:
            with self.assertRaisesRegex(ValueError, 'bad archive'):
                runner.check()
        self.assertNotIn(runner.MARKER, output.getvalue())

    def test_registry_binds_runner_fixture_and_completion(self):
        registry = tomllib.loads((runner.ROOT / 'verification/checks.toml').read_text())
        check = next(c for c in registry['checks'] if c['component'] == 'aes' and c['id'] == 'provider-packaged')
        self.assertEqual(check['command'], ['python3', 'scripts/aes/check-aes-provider-packaged.py'])
        self.assertEqual(check['success']['unique_lines'], [runner.MARKER])
        paths = registry['groups']['aes-provider-packaged']['paths']
        self.assertIn(runner.EXAMPLE, paths)
        self.assertIn('scripts/aes/check-aes-provider-packaged.py', paths)
        self.assertTrue({'aes-provider', 'aes-packaged', 'hkdf-public-api-modern', 'compiler', 'hkdf-msrv'} <= set(check['inputs']))


if __name__ == '__main__':
    unittest.main()
