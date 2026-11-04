#!/usr/bin/env python3
"""Negative controls for isolated downstream acceptance; no compiler execution."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import tomllib
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('aes_consumer', Path(__file__).with_name('check-aes-consumer.py'))
consumer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(consumer)


def success():
    return '\n'.join('test ' + name + ' ... ok' for name in sorted(consumer.TESTS)) + (
        '\ntest result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n')


class ConsumerTests(unittest.TestCase):
    def missing_result(self):
        message = {'level': 'error', 'code': {'code': 'E0432'}, 'message': 'unresolved import aes',
                   'spans': [{'is_primary': True, 'file_name': 'src/lib.rs'}]}
        return SimpleNamespace(returncode=101, stdout=json.dumps({'reason': 'compiler-message', 'message': message}))

    def test_feature_failure_is_exact_and_not_a_build_problem(self):
        consumer.missing_aes(self.missing_result())
        for code, output in [(0, ''), (1, ''), (-9, ''), (101, ''),
                             (101, self.missing_result().stdout * 2),
                             (101, self.missing_result().stdout.replace('E0432', 'E0308')),
                             (101, self.missing_result().stdout.replace('src/lib.rs', 'other.rs')),
                             (101, self.missing_result().stdout.replace('aes', 'unrelated'))]:
            with self.subTest(code=code, output=output), self.assertRaises(ValueError):
                consumer.missing_aes(SimpleNamespace(returncode=code, stdout=output))

    def test_feature_probe_exercises_both_defaults_and_positive_controls(self):
        for route in consumer.ROUTES:
            seen = []
            def run(command, env, cwd):
                seen.append((command, (cwd / 'Cargo.toml').read_text(), (cwd / 'src/lib.rs').read_text()))
                return ''
            with tempfile.TemporaryDirectory() as temporary, \
                 patch.object(consumer.verifier, 'run', side_effect=run), \
                 patch.object(consumer.subprocess, 'run', return_value=self.missing_result()) as negative, \
                 patch('builtins.print') as emit:
                consumer.feature_probe('1.90.0', route, Path(temporary) / 'probe')
            self.assertEqual(negative.call_count, 2)
            self.assertEqual(len(seen), 6)
            for offset, defaults in ((0, 'true'), (3, 'false')):
                self.assertIn('default-features=' + defaults, seen[offset][1])
                self.assertIn('features=[]', seen[offset][1])
                self.assertIn('::hkdf;', seen[offset + 1][2])
                self.assertIn('features=["hazmat-aes-block"]', seen[offset + 2][1])
                self.assertIn('::aes::Aes128Key;', seen[offset + 2][2])
            emit.assert_called_once()

    def test_feature_probe_failure_never_prints_success(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(consumer.verifier, 'run'), \
             patch.object(consumer.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout='')), \
             patch('builtins.print') as emit, self.assertRaises(ValueError):
            consumer.feature_probe('1.90.0', 'direct', Path(temporary) / 'probe')
        emit.assert_not_called()

    def test_matrix_and_endpoint_populations(self):
        self.assertEqual(consumer.MATRIX, ('1.90.0', '1.91.0', '1.92.0', '1.93.0', '1.94.0', '1.95.0',
                                          '1.96.0', '1.96.1', '1.97.0', '1.97.1', '1.98.0', '1.98.1', '1.99.0', '1.99.1'))
        self.assertEqual(consumer.TOOLCHAINS, (consumer.MATRIX[0], consumer.MATRIX[-1]))

    def test_middle_compilers_do_not_claim_target_checks(self):
        directory, metadata = self.metadata('direct')
        with patch.object(consumer, 'prepare'), patch.object(consumer.verifier, 'environment', return_value={}), \
             patch.object(consumer.verifier, 'run', side_effect=[json.dumps(metadata), success(), success()]) as run, \
             patch('builtins.print') as emit:
            consumer.configuration('1.95.0', 'direct', directory, False)
        self.assertEqual(run.call_count, 3)
        self.assertEqual(emit.call_count, 2)
        self.assertTrue(all(call.args[0].startswith('AES_DOWNSTREAM_HOST:') for call in emit.call_args_list))

    def test_exact_test_population(self):
        consumer.check_tests(success())
        bad = ['', success().replace(' ... ok', ' ... ignored', 1),
               success().replace(' ... ok', ' ... FAILED', 1),
               success().replace('test output_outlives_key ... ok\n', ''),
               success() + 'test output_outlives_key ... ok\n',
               success().replace('0 filtered out', '1 filtered out'),
               success().replace('output_outlives_key', 'unrelated_test'), success() * 2]
        for output in bad:
            with self.subTest(output=output), self.assertRaises(ValueError):
                consumer.check_tests(output)

    def test_fixture_policy(self):
        original = tomllib.loads((consumer.FIXTURE / 'Cargo.toml').read_text())
        consumer.policy(original)
        mutations = []
        for field in original:
            changed = copy.deepcopy(original)
            del changed[field]
            mutations.append(changed)
        changed = copy.deepcopy(original)
        changed['dependencies']['brynja']['default-features'] = True
        mutations.append(changed)
        changed = copy.deepcopy(original)
        changed['patch'] = {'crates-io': {}}
        mutations.append(changed)
        for changed in mutations:
            with self.subTest(manifest=changed), self.assertRaises(ValueError):
                consumer.policy(changed)

    def metadata(self, route):
        directory = Path('/tmp/aes-consumer-fixture')
        names = (consumer.DIRECT if route == 'direct' else consumer.FACADE) | {consumer.NAME}
        packages, nodes = [], []
        for name in sorted(names):
            manifest = directory / 'Cargo.toml' if name == consumer.NAME else consumer.ROOT / 'crates' / name / 'Cargo.toml'
            features = [route] if name == consumer.NAME else ['default']
            if name == 'brynja' or (name == 'brynja-crypto' and route == 'direct'):
                features = []
            if name in ('brynja', 'brynja-crypto'):
                features.append('hazmat-aes-block')
            if name == 'brynja-hash-sha2':
                features.append('general-sha512-t')
            packages.append({'id': name, 'name': name, 'manifest_path': str(manifest), 'source': None})
            nodes.append({'id': name, 'features': features})
        return directory, {'packages': packages, 'resolve': {'root': consumer.NAME, 'nodes': nodes},
                           'workspace_root': str(directory), 'workspace_members': [consumer.NAME]}

    def test_exact_graphs_and_source_locations(self):
        for route in consumer.ROUTES:
            directory, metadata = self.metadata(route)
            consumer.graph(metadata, route, directory)
            for name, value in [('manifest_path', '/tmp/unrelated/Cargo.toml'), ('source', 'registry+fake')]:
                changed = copy.deepcopy(metadata)
                next(p for p in changed['packages'] if p['name'] == 'brynja-crypto')[name] = value
                with self.subTest(route=route, field=name), self.assertRaises(ValueError):
                    consumer.graph(changed, route, directory)

    def test_graph_rejects_features_missing_or_extra_nodes_and_wrong_workspace(self):
        directory, original = self.metadata('facade')
        mutations = []
        changed = copy.deepcopy(original)
        changed['resolve']['nodes'][0]['features'].append('cpu')
        mutations.append(changed)
        changed = copy.deepcopy(original)
        changed['resolve']['nodes'].pop()
        mutations.append(changed)
        changed = copy.deepcopy(original)
        changed['resolve']['nodes'].append(changed['resolve']['nodes'][0])
        mutations.append(changed)
        changed = copy.deepcopy(original)
        changed['packages'].append(changed['packages'][0])
        mutations.append(changed)
        changed = copy.deepcopy(original)
        changed['workspace_members'].append('unexpected')
        mutations.append(changed)
        changed = copy.deepcopy(original)
        changed['workspace_root'] = str(consumer.ROOT)
        mutations.append(changed)
        changed = copy.deepcopy(original)
        changed['resolve']['root'] = 'brynja'
        mutations.append(changed)
        for metadata in mutations:
            with self.subTest(metadata=metadata), self.assertRaises(ValueError):
                consumer.graph(metadata, 'facade', directory)

    def test_prepare_relocates_only_public_dependencies(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            consumer.prepare(directory)
            manifest = tomllib.loads((directory / 'Cargo.toml').read_text())
            for name in ('brynja', 'brynja-crypto'):
                self.assertEqual(manifest['dependencies'][name]['path'], str(consumer.ROOT / 'crates' / name))
            for name in consumer.FILES[1:]:
                self.assertEqual((directory / name).read_bytes(), (consumer.FIXTURE / name).read_bytes())

    def test_failed_host_run_never_prints_success_or_compiles_target(self):
        directory, metadata = self.metadata('direct')
        for output in ('', success().replace(' ... ok', ' ... ignored', 1)):
            with patch.object(consumer, 'prepare'), patch.object(consumer.verifier, 'environment', return_value={}), \
                 patch.object(consumer.verifier, 'run', side_effect=[json.dumps(metadata), output]) as run, \
                 patch('builtins.print') as emit, self.assertRaises(ValueError):
                consumer.configuration('1.90.0', 'direct', directory)
            self.assertEqual(run.call_count, 2)
            emit.assert_not_called()

    def test_target_failure_never_prints_target_success(self):
        directory, metadata = self.metadata('direct')
        with patch.object(consumer, 'prepare'), patch.object(consumer.verifier, 'environment', return_value={}), \
             patch.object(consumer.verifier, 'run', side_effect=[json.dumps(metadata), success(), success(), RuntimeError('target')]), \
             patch('builtins.print') as emit, self.assertRaises(RuntimeError):
            consumer.configuration('1.90.0', 'direct', directory)
        self.assertEqual(emit.call_count, 2)
        self.assertTrue(all(call.args[0].startswith('AES_DOWNSTREAM_HOST:') for call in emit.call_args_list))

    def test_commands_pin_route_offline_lock_and_target(self):
        directory, metadata = self.metadata('facade')
        with patch.object(consumer, 'prepare'), patch.object(consumer.verifier, 'environment', return_value={}), \
             patch.object(consumer.verifier, 'run', side_effect=[json.dumps(metadata), success(), success(), '']) as run, \
             patch('builtins.print') as emit:
            consumer.configuration('1.99.1', 'facade', directory)
        self.assertEqual(run.call_count, 4)
        commands = [call.args[0] for call in run.call_args_list]
        for call in run.call_args_list:
            command, env, cwd = call.args
            self.assertEqual(command[:2], ['cargo', '+1.99.1'])
            for flag in ('--locked', '--offline', '--no-default-features'):
                self.assertIn(flag, command)
            self.assertEqual(command[command.index('--features') + 1], 'facade')
            self.assertEqual(env['RUSTUP_AUTO_INSTALL'], '0')
            self.assertEqual(env['CARGO_NET_OFFLINE'], 'true')
            self.assertEqual(cwd, directory)
        self.assertNotIn('--release', commands[1])
        self.assertIn('--release', commands[2])
        self.assertEqual(commands[3][-3:], ['--lib', '--target', 'thumbv7em-none-eabi'])
        self.assertEqual(emit.call_count, 3)

    def test_missing_or_symlinked_fixture_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = root / 'fixture'
            fixture.mkdir()
            consumer.prepare(fixture)
            # Restore the canonical manifest before exercising file admission.
            (fixture / 'Cargo.toml').write_bytes((consumer.FIXTURE / 'Cargo.toml').read_bytes())
            lock = fixture / 'Cargo.lock'
            saved = root / 'saved.lock'
            lock.rename(saved)
            with patch.object(consumer, 'FIXTURE', fixture):
                with self.assertRaisesRegex(ValueError, 'missing/nonregular fixture'):
                    consumer.prepare(root / 'missing')
                lock.symlink_to(saved)
                with self.assertRaisesRegex(ValueError, 'missing/nonregular fixture'):
                    consumer.prepare(root / 'symlink')


if __name__ == '__main__':
    unittest.main()
