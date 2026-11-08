#!/usr/bin/env python3
"""Fail-closed controls for archive-only portable AES consumers."""
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import tomllib
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('aes_packaged', Path(__file__).with_name('check-aes-packaged.py'))
packaged = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packaged)
consumer_tests = packaged.module('aes_checkout_tests', Path(__file__).with_name('test-aes-consumer.py'))


class PackagedTests(unittest.TestCase):
    def metadata(self, route):
        directory, metadata = consumer_tests.ConsumerTests().metadata(route)
        unpacked = directory.parent / 'unpacked'
        versions = {name: '0.1.0' for name in packaged.archives.MODERN}
        for row in metadata['packages']:
            name = row['name']
            row['version'] = '0.0.0' if name == packaged.consumer.NAME else versions[name]
            if name != packaged.consumer.NAME:
                row['manifest_path'] = str(unpacked / f'{name}-{versions[name]}' / 'Cargo.toml')
        return directory, unpacked, versions, metadata

    def test_archive_graphs_accept_only_the_expected_closure(self):
        for route in packaged.consumer.ROUTES:
            directory, unpacked, versions, original = self.metadata(route)
            packaged.graph(original, route, directory, unpacked, versions)
            for field, value in (
                    ('manifest_path', str(packaged.ROOT / 'crates/brynja-crypto/Cargo.toml')),
                    ('manifest_path', '/tmp/unrelated/Cargo.toml'),
                    ('version', '99.0.0'), ('source', 'registry+fake')):
                changed = copy.deepcopy(original)
                next(row for row in changed['packages'] if row['name'] == 'brynja-crypto')[field] = value
                with self.subTest(route=route, field=field, value=value), self.assertRaises(ValueError):
                    packaged.graph(changed, route, directory, unpacked, versions)

    def test_graph_rejects_duplicate_missing_accelerated_or_wrong_root_nodes(self):
        directory, unpacked, versions, original = self.metadata('facade')
        mutations = []
        changed = copy.deepcopy(original)
        changed['packages'].append(changed['packages'][0])
        mutations.append(changed)
        changed = copy.deepcopy(original)
        changed['resolve']['nodes'].append(changed['resolve']['nodes'][0])
        mutations.append(changed)
        changed = copy.deepcopy(original)
        changed['resolve']['nodes'].pop()
        mutations.append(changed)
        changed = copy.deepcopy(original)
        changed['resolve']['nodes'][0]['features'].append('cpu')
        mutations.append(changed)
        changed = copy.deepcopy(original)
        changed['resolve']['nodes'][0]['id'] = 'unknown'
        mutations.append(changed)
        changed = copy.deepcopy(original)
        changed['resolve']['root'] = 'brynja-core'
        mutations.append(changed)
        changed = copy.deepcopy(original)
        changed['workspace_root'] = '/tmp/not-consumer'
        mutations.append(changed)
        changed = copy.deepcopy(original)
        changed['workspace_members'].append('brynja-core')
        mutations.append(changed)
        for changed in mutations:
            with self.subTest(metadata=changed), self.assertRaises(ValueError):
                packaged.graph(changed, 'facade', directory, unpacked, versions)

    def test_inactive_packages_are_also_archive_bound(self):
        directory, unpacked, versions, metadata = self.metadata('direct')
        metadata['packages'].append({'id': 'extra', 'name': 'brynja-crypto-cpu',
                                    'version': versions['brynja-crypto-cpu'], 'source': None,
                                    'manifest_path': '/tmp/checkout/Cargo.toml'})
        with self.assertRaises(ValueError):
            packaged.graph(metadata, 'direct', directory, unpacked, versions)

    def test_fixture_bytes_are_unchanged_and_dependencies_are_exact_archives(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / 'consumers/aes'
            versions = {name: '0.1.0' for name in packaged.archives.MODERN}
            packaged.prepare(directory, versions)
            doc = tomllib.loads((directory / 'Cargo.toml').read_text())
            self.assertEqual(doc['workspace'], {})
            self.assertEqual(doc['profile']['release'], {'overflow-checks': True})
            for name, dependency in doc['dependencies'].items():
                self.assertEqual(dependency, {'version': '=0.1.0', 'optional': True,
                                             'default-features': False, 'features': ['hazmat-aes-block']})
            self.assertEqual(set(doc['patch']['crates-io']), set(packaged.archives.MODERN))
            for name, declaration in doc['patch']['crates-io'].items():
                self.assertEqual(declaration, {'path': f'../../unpacked/{name}-0.1.0'})
            self.assertFalse((directory / 'Cargo.lock').exists())
            for name in packaged.consumer.FILES:
                if name not in ('Cargo.toml', 'Cargo.lock'):
                    self.assertEqual((directory / name).read_bytes(), (packaged.consumer.FIXTURE / name).read_bytes())

    def test_missing_and_symlinked_fixture_files_are_rejected(self):
        for name in packaged.consumer.FILES:
            for symlink in (False, True):
                with self.subTest(name=name, symlink=symlink), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    fixture = root / 'fixture'
                    shutil.copytree(packaged.consumer.FIXTURE, fixture, ignore=shutil.ignore_patterns('target'))
                    (fixture / name).unlink()
                    if symlink:
                        (fixture / name).symlink_to(packaged.consumer.FIXTURE / name)
                    with patch.object(packaged.consumer, 'FIXTURE', fixture), self.assertRaises((ValueError, FileNotFoundError)):
                        packaged.prepare(root / 'output', {'brynja': '0.1.0', 'brynja-crypto': '0.1.0'})

    def test_probes_cover_all_owners_and_both_routes_without_private_modules(self):
        for route in packaged.consumer.ROUTES:
            cases = packaged.probes(route)
            self.assertEqual(len(cases), 134)
            source = '\n'.join(negative + positive for _, negative, positive, _ in cases)
            for owner in packaged.consumer.OWNERS:
                self.assertIn(owner, source)
            self.assertNotIn('include!', source)
            if route == 'facade':
                self.assertNotIn('brynja_crypto', source)
                self.assertIn('brynja::crypto::aes', source)
        with self.assertRaises(ValueError):
            packaged.probes('unknown')

    def diagnostic(self, code='E0308', status=101, filename='src/bin/probe.rs'):
        return SimpleNamespace(returncode=status, stderr='', stdout=json.dumps({
            'reason': 'compiler-message', 'message': {
                'level': 'error', 'code': {'code': code},
                'spans': [{'is_primary': True, 'file_name': filename}]}}))

    def test_negative_probes_require_the_paired_positive_and_exact_diagnostic(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            calls = []
            def positive(*args):
                calls.append((directory / 'src/bin/probe.rs').read_text())
            with patch.object(packaged, 'probes', return_value=[('width', 'negative', 'positive', 'E0308')]), \
                 patch.object(packaged.archives, 'run', side_effect=positive), \
                 patch.object(packaged.archives.cargo_environment, 'check'), \
                 patch.object(packaged.subprocess, 'run', return_value=self.diagnostic()):
                packaged.public_negatives(directory, ['cargo'], [], {}, 'direct')
            self.assertEqual(calls, ['positive'])
            self.assertFalse((directory / 'src/bin/probe.rs').exists())

    def test_unrelated_errors_success_and_killed_compiler_do_not_pass(self):
        for result in (self.diagnostic(code='E0432'), self.diagnostic(status=0),
                       self.diagnostic(status=-9), self.diagnostic(status=1),
                       self.diagnostic(filename='dependency.rs'),
                       SimpleNamespace(returncode=101, stdout='', stderr='build failed')):
            with tempfile.TemporaryDirectory() as temporary, \
                 patch.object(packaged, 'probes', return_value=[('width', 'bad', 'good', 'E0308')]), \
                 patch.object(packaged.archives, 'run'), \
                 patch.object(packaged.archives.cargo_environment, 'check'), \
                 patch.object(packaged.subprocess, 'run', return_value=result), self.assertRaises(ValueError):
                packaged.public_negatives(Path(temporary), ['cargo'], [], {}, 'direct')

    def test_positive_failure_stops_before_negative_and_cleans_probe(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with patch.object(packaged, 'probes', return_value=[('width', 'bad', 'good', 'E0308')]), \
                 patch.object(packaged.archives, 'run', side_effect=ValueError('positive failed')), \
                 patch.object(packaged.subprocess, 'run') as negative, self.assertRaises(ValueError):
                packaged.public_negatives(directory, ['cargo'], [], {}, 'direct')
            negative.assert_not_called()
            self.assertFalse((directory / 'src/bin/probe.rs').exists())

    def test_configuration_checks_both_graphs_profiles_api_and_target(self):
        directory, unpacked, versions, metadata = self.metadata('direct')
        with patch.object(packaged.archives, 'run', side_effect=[
                SimpleNamespace(stdout=json.dumps(metadata)), SimpleNamespace(stdout=json.dumps(metadata)),
                SimpleNamespace(stdout=consumer_tests.success()), SimpleNamespace(stdout=consumer_tests.success()),
                SimpleNamespace(stdout='')]) as run, \
             patch.object(packaged, 'public_negatives') as probes, \
             patch.object(packaged, 'readme_example') as readme, \
             patch.object(packaged, 'feature_probe') as features, patch('builtins.print') as emit:
            packaged.configuration(directory, unpacked.parent, versions, '1.90.0', 'direct', {})
        self.assertEqual(run.call_count, 5)
        self.assertIn('--filter-platform', run.call_args_list[1].args[0])
        self.assertIn('--release', run.call_args_list[3].args[0])
        self.assertIn('--target', run.call_args_list[4].args[0])
        probes.assert_called_once()
        readme.assert_called_once()
        features.assert_called_once()
        self.assertEqual(emit.call_count, 5)

    def test_readme_is_one_executable_example_with_all_owners(self):
        text = (packaged.ROOT / 'crates/brynja-crypto/README.md').read_text()
        for route in packaged.consumer.ROUTES:
            source = packaged.readme_source(text, route)
            for owner in packaged.consumer.OWNERS:
                self.assertIn(owner, source)
            if route == 'facade':
                self.assertNotIn('brynja_crypto::aes', source)
                self.assertIn('brynja::crypto::aes', source)
        for bad in ('', text * 2, text.replace('```rust', '```rust,ignore'),
                    text.replace('fn main()', 'fn unused()'), text.replace('Aes256Key', 'RemovedKey'),
                    text.replace('AES-PACKAGED-EXAMPLE-END', 'WRONG-END')):
            with self.subTest(text=bad), self.assertRaises(ValueError):
                packaged.readme_source(bad, 'direct')

    def test_readme_failure_cleans_temporary_binary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            readme = root / 'unpacked/brynja-crypto-0.2.0/README.md'
            readme.parent.mkdir(parents=True)
            shutil.copyfile(packaged.ROOT / 'crates/brynja-crypto/README.md', readme)
            with patch.object(packaged.archives, 'run', side_effect=ValueError('example failed')), self.assertRaises(ValueError):
                packaged.readme_example(root / 'consumers/aes', root, {'brynja-crypto': '0.2.0'}, [], [], {}, 'direct')
            self.assertFalse((root / 'consumers/aes/src/bin/readme.rs').exists())

    def test_packaged_feature_controls_use_archives_and_both_defaults(self):
        for route in packaged.consumer.ROUTES:
            seen = []
            def run(command, directory, env):
                seen.append(((directory / 'Cargo.toml').read_text(), (directory / 'src/lib.rs').read_text()))
            result = self.diagnostic('E0432', filename='src/lib.rs')
            message = json.loads(result.stdout)
            message['message']['message'] = 'unresolved import aes'
            result.stdout = json.dumps(message)
            with tempfile.TemporaryDirectory() as temporary, \
                 patch.object(packaged.archives, 'run', side_effect=run), \
                 patch.object(packaged.archives.cargo_environment, 'check'), \
                 patch.object(packaged.subprocess, 'run', return_value=result) as negative, \
                 patch('builtins.print') as emit:
                versions = {name: '0.1.0' for name in packaged.archives.MODERN}
                packaged.feature_probe(Path(temporary), versions, '1.90.0', route, {})
            self.assertEqual(negative.call_count, 2)
            self.assertEqual(len(seen), 6)
            for offset, defaults in ((0, True), (3, False)):
                doc = tomllib.loads(seen[offset][0])
                dependency = next(iter(doc['dependencies'].values()))
                self.assertEqual(dependency, {'version': '=0.1.0', 'default-features': defaults, 'features': []})
                self.assertEqual(set(doc['patch']['crates-io']), set(versions))
                self.assertIn('::hkdf;', seen[offset + 1][1])
                self.assertIn('features=["hazmat-aes-block"]', seen[offset + 2][0])
                for owner in packaged.consumer.OWNERS:
                    self.assertIn(owner, seen[offset + 2][1])
            emit.assert_called_once()

    def test_wrong_feature_diagnostic_never_emits_success(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(packaged.archives, 'run'), \
             patch.object(packaged.archives.cargo_environment, 'check'), \
             patch.object(packaged.subprocess, 'run', return_value=self.diagnostic()), \
             patch('builtins.print') as emit, self.assertRaises(ValueError):
            packaged.feature_probe(Path(temporary), {'brynja-crypto': '0.2.0'}, '1.90.0', 'direct', {})
        emit.assert_not_called()

    def test_failed_test_population_emits_no_success(self):
        directory, unpacked, versions, metadata = self.metadata('direct')
        with patch.object(packaged.archives, 'run', side_effect=[
                SimpleNamespace(stdout=json.dumps(metadata)), SimpleNamespace(stdout=json.dumps(metadata)),
                SimpleNamespace(stdout=consumer_tests.success().replace('18 passed', '0 passed'))]), \
             patch('builtins.print') as emit, self.assertRaises(ValueError):
            packaged.configuration(directory, unpacked.parent, versions, '1.90.0', 'direct', {})
        emit.assert_not_called()

    def test_registration_binds_scripts_sources_and_completion(self):
        registry = tomllib.loads((packaged.ROOT / 'verification/checks.toml').read_text())
        check = next(c for c in registry['checks'] if (c['component'], c['id']) == ('aes', 'packaged-portable'))
        self.assertEqual(check['command'], ['python3', 'scripts/aes/check-aes-packaged.py'])
        self.assertEqual(set(check['inputs']), {'aes-packaged', 'hkdf-public-api-modern', 'compiler', 'hkdf-msrv'})
        self.assertEqual(check['success']['unique_lines'], [packaged.MARKER])
        paths = registry['groups']['aes-packaged']['paths']
        for path in ('scripts/aes/check-aes-packaged.py', 'scripts/aes/test-aes-packaged.py',
                     'scripts/aes/check-aes-api.py', 'scripts/aes/check-aes-wide-api.py',
                     'scripts/hkdf/check-hkdf-public-api.py', 'scripts/repository/facade_cargo_environment.py',
                     'scripts/hmac/hmac_verifiers.py', 'scripts/aes/check-aes-consumer.py'):
            self.assertIn(path, paths)
        for name in packaged.consumer.FILES:
            self.assertIn('assurance/aes-public-api/' + name, paths)


if __name__ == '__main__':
    unittest.main()
