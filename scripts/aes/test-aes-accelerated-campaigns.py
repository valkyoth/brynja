#!/usr/bin/env python3
"""Fail-closed checks for the forced-backend packaged campaign runner."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import tomllib
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('campaigns', Path(__file__).with_name('check-aes-accelerated-campaigns.py'))
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class AcceleratedCampaignTests(unittest.TestCase):
    def test_build_artifact_selection_rejects_wrong_or_ambiguous_tests(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            executable = root / 'avs-test'
            executable.write_bytes(b'test fixture, never executed')
            executable.chmod(0o700)
            artifact = {'reason': 'compiler-artifact', 'package_id': 'fixture-id',
                        'target': {'name': 'avs', 'kind': ['test']},
                        'profile': {'test': True}, 'executable': str(executable)}
            finished = {'reason': 'build-finished', 'success': True}
            encode = lambda rows: '\n'.join(json.dumps(row) for row in rows)
            self.assertEqual(runner.test_executable(encode([artifact, finished]),
                             'avs', 'fixture-id', root), executable)
            for rows in ([], [artifact], [finished], [artifact, artifact, finished],
                         [artifact, finished, finished],
                         [artifact, {**finished, 'success': False}]):
                with self.assertRaises(ValueError):
                    runner.test_executable(encode(rows), 'avs', 'fixture-id', root)
            for field, value in (('package_id', 'other'), ('profile', {'test': False}),
                                 ('target', {'name': 'differential', 'kind': ['test']}),
                                 ('target', {'name': 'avs', 'kind': ['bin']}),
                                 ('executable', 'relative-test'),
                                 ('executable', str(root / 'missing'))):
                with self.assertRaises(ValueError):
                    runner.test_executable(encode([{**artifact, field: value}, finished]),
                                           'avs', 'fixture-id', root)
            with self.assertRaises(ValueError):
                runner.test_executable(encode([artifact, finished]), 'avs', 'fixture-id', root / 'other')
            link = root / 'link'
            link.symlink_to(executable)
            with self.assertRaises(ValueError):
                runner.test_executable(encode([{**artifact, 'executable': str(link)}, finished]),
                                       'avs', 'fixture-id', root)
            executable.chmod(0o600)
            with self.assertRaises(ValueError):
                runner.test_executable(encode([artifact, finished]), 'avs', 'fixture-id', root)

    def test_adaptation_changes_only_import_authority_and_constructor_arguments(self):
        for suite, source in (('avs', runner.avs.FIXTURE / 'avs.rs'), ('differential', runner.diff.FIXTURE)):
            original = source.read_text()
            adapted = runner.adapt(original, suite)
            restored = adapted.replace(
                'use brynja_aes_accelerated_fixture::{aes::*, forced_authority};',
                'use brynja_aes_public_api_fixture::aes::*;')
            restored = restored.replace('\n    let authority = forced_authority()?;', '')
            for owner in ('$key', '$cached'):
                restored = restored.replace(owner + '::new(authority.get()?, ', owner + '::new(')
            self.assertEqual(restored, original)
            self.assertEqual(adapted.count('::new(authority.get()?, '), 4 if suite == 'avs' else 2)

    def test_missing_or_duplicate_adaptation_anchor_fails(self):
        source = (runner.avs.FIXTURE / 'avs.rs').read_text()
        for anchor in ('use brynja_aes_public_api_fixture::aes::*;', 'fn monte_carlo() -> Check<()> {',
                       'fn multiblock() -> Check<()> {', '$key::new(', '$cached::new('):
            for mutated in (source.replace(anchor, '', 1), source + anchor):
                with self.assertRaises(ValueError):
                    runner.adapt(mutated, 'avs')

    def test_configurations_rejected_before_packaging(self):
        for args in (('stable', 'direct', 'static', 'native', 'avs'),
                     ('1.99.1', 'unknown', 'static', 'native', 'avs'),
                     ('1.99.1', 'direct', 'prefer', 'native', 'avs'),
                     ('1.99.1', 'direct', 'hosted', 'riscv-qemu', 'avs'),
                     ('1.99.1', 'direct', 'static', 'riscv-qemu', 'differential'),
                     ('1.99.1', 'direct', 'static', 'native', 'oracle'),
                     ('1.99.1', 'direct', 'hosted', 'riscv-qemu', 'oracle'),
                     ('1.99.1', 'direct', 'hosted', 'arm-qemu', 'differential')):
            with patch.object(runner.packaged, 'package_sources') as package, self.assertRaises(ValueError):
                runner.check(*args)
            package.assert_not_called()

    def test_riscv_population_requires_exact_candidate_not_arm_or_portable(self):
        text = self.success('avs').replace('X86AesNi', 'RiscVScalarAes')
        runner.validate(text, 'avs', False, True)
        for wrong in ('X86AesNi', 'ArmAes', 'Portable'):
            with self.assertRaises(ValueError):
                runner.validate(text.replace('RiscVScalarAes', wrong), 'avs', False, True)
        for mutated in (text.replace('... ok', '... ignored', 1),
                        text.replace(runner.avs.MARKERS[0], ''),
                        text + '\nAES_FORCED_AUTHORITY: RiscVScalarAes'):
            with self.assertRaises(ValueError):
                runner.validate(mutated, 'avs', False, True)

    def test_riscv_oracle_requires_exact_forced_backend(self):
        text = '\n'.join([*(f'test {name} ... ok' for name in sorted(runner.corpus.TESTS)),
            'test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;',
            *runner.corpus.MARKERS, *(['AES_FORCED_AUTHORITY: RiscVScalarAes'] * 3)])
        runner.validate(text, 'oracle', False, True)
        for wrong in ('ArmAes', 'Portable', 'X86AesNi'):
            with self.assertRaises(ValueError):
                runner.validate(text.replace('RiscVScalarAes', wrong), 'oracle', False, True)

    def test_riscv_oracle_registry_pins_endpoints_routes_and_identity(self):
        registry = tomllib.loads((runner.ROOT / 'verification/checks.toml').read_text())
        rows = [row for row in registry['checks'] if row.get('category') == 'aes-riscv-oracle']
        self.assertEqual(len(rows), 4)
        configurations = set()
        for row in rows:
            command = row['command']
            version, route = command[3], command[5]
            configurations.add((version, route))
            self.assertEqual(command, ['python3', 'scripts/aes/check-aes-accelerated-campaigns.py',
                '--toolchain', version, '--route', route, '--admission', 'static', '--mode', 'riscv-qemu', '--suite', 'oracle'])
            self.assertEqual(row['success']['minimum_tests'], 8)
            self.assertEqual(row['success']['exact_tests'], 8)
            self.assertEqual(row['success']['unique_lines'], [runner.marker(version, route, 'static', 'riscv-qemu', 'oracle')])
            self.assertIn(runner.diff.oracle.SUCCESS, row['success']['contains'])
            self.assertTrue(set(runner.diff.oracle.FORBIDDEN) <= set(row['reject_environment']))
            self.assertTrue(set(runner.riscv.REJECT_ENV) <= set(row['reject_environment']))
            self.assertTrue({'aes-riscv', 'aes-oracle', 'aes-build', 'aes-accelerated-campaigns', 'aes-packaged'} <= set(row['inputs']))
        self.assertEqual(configurations, {(version, route) for version in ('1.90.0', '1.99.1') for route in ('direct', 'facade')})

    def test_riscv_overrides_rejected_before_packaging(self):
        for name in runner.riscv.REJECT_ENV:
            with patch.dict(runner.os.environ, {name: 'untrusted'}), \
                 patch.object(runner.packaged, 'package_sources') as package, self.assertRaises(ValueError):
                runner.check('1.99.1', 'direct', 'static', 'riscv-qemu', 'avs')
            package.assert_not_called()

    def test_riscv_registry_covers_archive_routes_and_endpoint_populations(self):
        registry = tomllib.loads((runner.ROOT / 'verification/checks.toml').read_text())
        rows = [row for row in registry['checks'] if row.get('category') == 'aes-riscv-avs']
        configurations = set()
        for row in rows:
            command = row['command']
            version = command[command.index('--toolchain') + 1]
            route = command[command.index('--route') + 1]
            configurations.add((version, route))
            self.assertEqual(command, ['python3', 'scripts/aes/check-aes-accelerated-campaigns.py',
                '--toolchain', version, '--route', route, '--admission', 'static',
                '--mode', 'riscv-qemu', '--suite', 'avs'])
            self.assertEqual(row['success']['exact_tests'], 12)
            self.assertEqual(row['success']['minimum_tests'], 12)
            self.assertEqual(row['success']['unique_lines'], [runner.marker(version, route, 'static', 'riscv-qemu', 'avs')])
            self.assertTrue({'aes-riscv', 'aes-build', 'aes-accelerated-campaigns', 'aes-packaged', 'aes-avs'} <= set(row['inputs']))
            self.assertTrue(set(runner.riscv.REJECT_ENV) <= set(row['reject_environment']))
        self.assertEqual(len(rows), 4)
        self.assertEqual(configurations, {(version, route) for version in ('1.90.0', '1.99.1') for route in ('direct', 'facade')})

    def test_injected_environment_rejected_before_packaging(self):
        for name in (*runner.packaged.archives.REJECT_ENV, 'PYTHONOPTIMIZE', 'PYTHONPATH'):
            with patch.dict(runner.os.environ, {name: 'untrusted'}), \
                 patch.object(runner.packaged, 'package_sources') as package, self.assertRaises(ValueError):
                runner.check('1.99.1', 'direct', 'static', 'native', 'avs')
            package.assert_not_called()

    def success(self, suite, arm=False):
        harness = runner.avs if suite == 'avs' else runner.diff
        count = len(harness.TESTS)
        return '\n'.join([*(f'test {name} ... ok' for name in sorted(harness.TESTS)),
            f'test result: ok. {count} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;',
            *harness.MARKERS, *(['AES_FORCED_AUTHORITY: ' + ('ArmAes' if arm else 'X86AesNi')]
                               * (6 if suite == 'avs' else 3))])

    def test_wrong_missing_duplicate_or_skipped_population_fails(self):
        for suite in ('avs', 'differential'):
            for arm in (False, True):
                text = self.success(suite, arm)
                runner.validate(text, suite, arm)
                for output in ('', text.replace('... ok', '... ignored', 1),
                               text.replace('AES_FORCED_AUTHORITY: ', 'not executed: '),
                               text + '\nAES_FORCED_AUTHORITY: ArmAes',
                               text.replace('X86AesNi', 'ArmAes') if not arm else text.replace('ArmAes', 'X86AesNi')):
                    with self.assertRaises(ValueError):
                        runner.validate(output, suite, arm)

    def metadata(self, route, admission, directory, versions):
        names = (runner.packaged.consumer.DIRECT if route == 'direct' else runner.packaged.consumer.FACADE) | {
            runner.NAME, 'brynja-crypto-cpu'}
        if admission == 'hosted':
            names |= {'brynja-crypto-cpu-std'}
        packages, nodes = [], []
        for name in sorted(names):
            version = '0.0.0' if name == runner.NAME else versions[name]
            path = directory if name == runner.NAME else directory.parent.parent / 'unpacked' / f'{name}-{version}'
            features = {'default'}
            if name == runner.NAME:
                features = {route} | ({'hosted'} if admission == 'hosted' else set())
            elif name == 'brynja':
                features = {'aes-runtime-execution' if admission == 'hosted' else 'aes-static-execution'}
            elif name == 'brynja-crypto':
                features = {'aes-static-execution', 'hazmat-aes-block'}
                features.add('cpu')
                if route == 'facade':
                    features.add('default')
                if admission == 'hosted':
                    features.add('aes-runtime-execution')
            elif name == 'brynja-crypto-cpu':
                features |= {'aes-static-execution'}
                if admission == 'hosted':
                    features.add('aes-runtime-execution')
            elif name == 'brynja-crypto-cpu-std':
                features = {'aes-runtime-execution'}
            elif name == 'brynja-hash-sha2':
                features.add('general-sha512-t')
                if admission == 'hosted':
                    features.add('cpu')
            packages.append({'id': name, 'name': name, 'version': version,
                             'manifest_path': str(path / 'Cargo.toml'), 'source': None})
            nodes.append({'id': name, 'features': sorted(features)})
        return {'packages': packages, 'resolve': {'nodes': nodes, 'root': runner.NAME},
                'workspace_members': [runner.NAME], 'workspace_root': str(directory)}

    def test_graph_rejects_checkout_sources_and_feature_drift(self):
        versions = {name: '0.1.0' for name in runner.packaged.archives.MODERN}
        directory = Path('/tmp/accelerated-unit/consumers/aes')
        for route in ('direct', 'facade'):
            for admission in ('static', 'hosted'):
                doc = self.metadata(route, admission, directory, versions)
                runner.graph(doc, versions, directory, route, admission)
                for mutation in ('path', 'feature', 'missing', 'duplicate', 'registry', 'workspace'):
                    bad = copy.deepcopy(doc)
                    if mutation == 'path':
                        bad['packages'][0]['manifest_path'] = '/checkout/Cargo.toml'
                    elif mutation == 'feature':
                        bad['resolve']['nodes'][0]['features'].append('unreviewed')
                    elif mutation == 'missing':
                        bad['resolve']['nodes'].pop()
                    elif mutation == 'duplicate':
                        bad['resolve']['nodes'].append(bad['resolve']['nodes'][0])
                    elif mutation == 'registry':
                        bad['packages'][0]['source'] = 'registry+untrusted'
                    else:
                        bad['workspace_members'].append('extra')
                    with self.assertRaises(ValueError):
                        runner.graph(bad, versions, directory, route, admission)

    def test_manifest_keeps_hosted_std_explicit_and_off_static_route(self):
        versions = {name: '0.1.0' for name in runner.packaged.archives.MODERN}
        for route in ('direct', 'facade'):
            dependency = 'brynja-crypto' if route == 'direct' else 'brynja'
            for admission in ('static', 'hosted'):
                doc = tomllib.loads(runner.manifest(versions, route, admission))
                self.assertFalse(doc['package']['publish'])
                self.assertEqual(set(doc['dependencies']), {dependency} | (
                    {'brynja-crypto-cpu-std'} if admission == 'hosted' else set()))
                self.assertFalse(doc['dependencies'][dependency]['default-features'])
                self.assertEqual(doc['dependencies'][dependency]['features'], [
                    'aes-runtime-execution' if admission == 'hosted' else 'aes-static-execution'])


if __name__ == '__main__':
    unittest.main()
