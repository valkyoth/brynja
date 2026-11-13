#!/usr/bin/env python3
"""Regression checks for archive-only no_std acceptance; no target execution."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('accelerated_no_std', Path(__file__).with_name('check-aes-accelerated-no-std.py'))
r = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(r)


def diagnostic(code='E0433', count=1, filename='src/lib.rs', primary=True, status=101):
    message = {'reason': 'compiler-message', 'message': {'level': 'error', 'code': {'code': code},
               'spans': [{'is_primary': primary, 'file_name': filename}]}}
    return subprocess.CompletedProcess([], status, '\n'.join([json.dumps(message)] * count), '')


class AcceleratedNoStdTests(unittest.TestCase):
    def test_manifest_pins_archive_versions_and_feature_selection(self):
        versions = {name: '0.1.0' for name in r.packaged.archives.MODERN}
        for route, dependency in (('direct', 'brynja-crypto'), ('facade', 'brynja')):
            for mode in r.FEATURES:
                for defaults in (False, True):
                    doc = tomllib.loads(r.manifest(versions, route, mode, defaults))
                    self.assertEqual(doc['dependencies'], {dependency: {'version': '=0.1.0',
                        'default-features': defaults, 'features': r.FEATURES[mode]}})
                    self.assertEqual(doc['features'], {'default': [], 'direct': [], 'facade': []})
                    self.assertEqual(doc['patch']['crates-io'], {name: {'path': '../../unpacked/' + name + '-0.1.0'} for name in versions})
                    self.assertTrue(doc['profile']['release']['overflow-checks'])

    def metadata(self, route, mode, defaults, directory, versions):
        packages, nodes = [], []
        for name, features in r.expected_graph(route, mode, defaults).items():
            version = '0.0.0' if name == r.NAME else versions[name]
            path = directory if name == r.NAME else directory.parent.parent / 'unpacked' / f'{name}-{version}'
            packages.append({'id': name, 'name': name, 'version': version,
                             'manifest_path': str(path / 'Cargo.toml'), 'source': None})
            nodes.append({'id': name, 'features': sorted(features)})
        return {'packages': packages, 'resolve': {'nodes': nodes, 'root': r.NAME},
                'workspace_members': [r.NAME], 'workspace_root': str(directory)}

    def test_graph_rejects_archive_escape_features_and_population_drift(self):
        versions = {name: '0.1.0' for name in r.packaged.archives.MODERN}
        directory = Path('/tmp/aes-no-std-unit/consumers/aes')
        for route in ('direct', 'facade'):
            for mode in r.FEATURES:
                for defaults in (False, True):
                    doc = self.metadata(route, mode, defaults, directory, versions)
                    self.assertEqual(r.graph(doc, versions, directory, route, mode, defaults), r.NAME)
                    for mutation in ('path', 'version', 'source', 'feature', 'missing', 'duplicate', 'workspace', 'root'):
                        bad = copy.deepcopy(doc)
                        if mutation == 'path': bad['packages'][0]['manifest_path'] = '/checkout/Cargo.toml'
                        elif mutation == 'version': bad['packages'][0]['version'] = '9.9.9'
                        elif mutation == 'source': bad['packages'][0]['source'] = 'registry+untrusted'
                        elif mutation == 'feature': bad['resolve']['nodes'][0]['features'].append('std')
                        elif mutation == 'missing': bad['resolve']['nodes'].pop()
                        elif mutation == 'duplicate': bad['resolve']['nodes'].append(bad['resolve']['nodes'][0])
                        elif mutation == 'workspace': bad['workspace_members'].append('extra')
                        else: bad['resolve']['root'] = 'missing'
                        with self.assertRaises(ValueError): r.graph(bad, versions, directory, route, mode, defaults)

    def test_no_hosted_adapter_and_runtime_does_not_enable_sha_cpu(self):
        for route in ('direct', 'facade'):
            for mode in r.FEATURES:
                graph = r.expected_graph(route, mode, False)
                self.assertNotIn('brynja-crypto-cpu-std', graph)
                self.assertNotIn('cpu', graph['brynja-hash-sha2'])
                self.assertEqual('brynja-crypto-cpu' in graph, mode in ('static', 'runtime'))
                if mode == 'static': self.assertNotIn('aes-runtime-execution', graph['brynja-crypto'])

    def test_diagnostics_require_exact_code_count_primary_source_and_exit(self):
        self.assertTrue(r.diagnostics(diagnostic(), 'E0433'))
        self.assertTrue(r.diagnostics(diagnostic('E0277', 3), ('E0277', 3)))
        for result in (diagnostic('E0000'), diagnostic(count=2), diagnostic(filename='dependency/src/lib.rs'),
                       diagnostic(primary=False), diagnostic(status=0), diagnostic(status=1),
                       subprocess.CompletedProcess([], 101, 'not json', ''),
                       subprocess.CompletedProcess([], 101, '{}', '')):
            self.assertFalse(r.diagnostics(result, 'E0433'))

    def test_feature_probes_have_positive_twins_and_expected_population(self):
        for route in ('direct', 'facade'):
            probes = list(r.feature_probes(route))
            self.assertEqual([p[0] for p in probes], ['none-defaults-off', 'none-defaults-on', 'portable-only', 'static-no-platform'])
            self.assertEqual([p[-1] for p in probes], ['E0433', 'E0433', 'E0432', 'E0599'])
            self.assertTrue(all(p[3] != p[4] for p in probes))
        self.assertEqual(len(r.api.probes()), 58)

    def test_pair_stops_after_failed_positive_or_wrong_negative(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / 'src').mkdir()
            with patch.object(r, 'execute', return_value=diagnostic()) as execute:
                with self.assertRaises(ValueError): r.pair([], directory, {}, directory, 'probe', 'bad', 'good', 'E0433')
                self.assertEqual(execute.call_count, 1)
                self.assertEqual((directory / 'src/lib.rs').read_text(), '#![no_std]\ngood')
            for result in (diagnostic(), diagnostic('E0000')):
                with patch.object(r, 'execute', side_effect=[subprocess.CompletedProcess([], 0, '', ''), result]) as execute:
                    if result.stdout == diagnostic().stdout:
                        r.pair([], directory, {}, directory, 'probe', 'bad', 'good', 'E0433')
                    else:
                        with self.assertRaises(ValueError): r.pair([], directory, {}, directory, 'probe', 'bad', 'good', 'E0433')
                    self.assertEqual(execute.call_count, 2)
                    self.assertEqual((directory / 'src/lib.rs').read_text(), '#![no_std]\nbad')

    def test_artifact_requires_success_unique_nonempty_library_in_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            library = directory / 'consumer.rlib'
            library.write_bytes(b'archive')
            row = {'reason': 'compiler-artifact', 'package_id': 'root', 'target': {'kind': ['lib']}, 'filenames': [str(library)]}
            result = subprocess.CompletedProcess([], 0, json.dumps(row), '')
            self.assertEqual(r.artifact(result, 'root', directory)['sha256'], r.hashlib.sha256(b'archive').hexdigest())
            for bad in (subprocess.CompletedProcess([], 101, result.stdout, 'compiler failure'),
                        subprocess.CompletedProcess([], 0, '', ''),
                        subprocess.CompletedProcess([], 0, result.stdout + '\n' + result.stdout, '')):
                with self.assertRaises(ValueError): r.artifact(bad, 'root', directory)
            with self.assertRaises(ValueError): r.artifact(result, 'root', directory / 'different-target')
            library.write_bytes(b'')
            with self.assertRaises(ValueError): r.artifact(result, 'root', directory)
            library.unlink()
            library.symlink_to(Path(__file__).resolve())
            with self.assertRaises(ValueError): r.artifact(result, 'root', directory)

    def test_execute_retains_both_streams_and_checks_environment(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            result = diagnostic()
            with patch.object(r.packaged.archives.cargo_environment, 'check') as check, patch.object(r.subprocess, 'run', return_value=result) as run:
                self.assertIs(r.execute(['cargo', 'check'], directory, {}, directory, 'probe'), result)
            check.assert_called_once_with(directory, {})
            record = json.loads((directory / 'probe.json').read_text())
            self.assertEqual(record, {'command': ['cargo', 'check'], 'returncode': 101, 'stdout': result.stdout, 'stderr': ''})
            self.assertEqual(run.call_args.kwargs['timeout'], 300)

    def test_invalid_configuration_and_ambient_injection_fail_before_packaging(self):
        with patch.object(r.packaged, 'package_sources') as package:
            for compiler, route in (('stable', 'direct'), ('1.99.1', 'other')):
                with self.assertRaises(ValueError): r.check(compiler, route)
            for name in r.REJECT:
                with patch.dict(r.os.environ, {name: 'injected'}), self.assertRaises(ValueError): r.check('1.99.1', 'direct')
            package.assert_not_called()
        for args in (('other', 'static', False), ('direct', 'other', False), ('direct', 'static', 'false')):
            with self.assertRaises(ValueError): r.expected_graph(*args)

    def test_target_population_and_no_abi_override(self):
        self.assertEqual(r.TARGETS, {'thumbv7em-none-eabi': '', 'x86_64-unknown-linux-gnu': '-Ctarget-feature=+aes,+sse2',
                                    'aarch64-unknown-linux-musl': '-Ctarget-feature=+aes,+neon'})
        source = (r.ROOT / 'assurance/aes-accelerated-campaigns/no-std.rs').read_text()
        self.assertIn('#![no_std]', source)
        self.assertIn('#![forbid(unsafe_code)]', source)

    def test_riscv_is_bare_metal_and_separates_evidence_from_ordinary(self):
        self.assertEqual(r.RISCV_BUILDS, [
            ('rv64-ordinary', 'riscv64imac-unknown-none-elf', ''),
            ('rv64-evidence', 'riscv64imac-unknown-none-elf', '--cfg brynja_cpu_evidence -Ctarget-feature=+zkne,+zknd')])
        for name in r.RISCV_REJECT:
            with patch.object(r.packaged, 'package_sources') as package, \
                 patch.dict(r.os.environ, {name: 'injected'}), self.assertRaises(ValueError):
                r.check('1.99.1', 'direct', True)
            package.assert_not_called()

    def test_riscv_registry_pins_every_build_and_probe_population(self):
        registry = tomllib.loads((r.ROOT / 'verification/checks.toml').read_text())
        checks = [c for c in registry['checks'] if c.get('category') == 'aes-riscv-no-std']
        self.assertEqual(len(checks), 4)
        configurations = set()
        for c in checks:
            compiler, route = c['command'][3], c['command'][5]
            configurations.add((compiler, route))
            self.assertEqual(c['command'], ['python3', 'scripts/aes/check-aes-accelerated-no-std.py',
                '--toolchain', compiler, '--route', route, '--riscv'])
            expected = {f'AES_RISCV_NO_STD_PASS: {compiler} {route}; 8 bare-metal library builds; 62 paired probes; compile only'}
            expected.update(f'AES_NO_STD_BUILD_PASS: {compiler} {route} {mode}-{name}-{profile}'
                for mode in ('static', 'runtime') for name, _, _ in r.RISCV_BUILDS for profile in ('debug', 'release'))
            self.assertEqual(set(c['success']['unique_lines']), expected)
            self.assertEqual(len(c['success']['unique_lines']), 9)
            self.assertTrue(set(r.RISCV_REJECT) <= set(c['reject_environment']))
            self.assertTrue({'aes-accelerated-no-std', 'aes-execution-api', 'aes-build', 'aes-accelerated-campaigns', 'aes-packaged'} <= set(c['inputs']))
            self.assertNotIn('exact_tests', c['success'])
        self.assertEqual(configurations, {(compiler, route) for compiler in ('1.90.0', '1.99.1') for route in ('direct', 'facade')})

    def test_registry_requires_all_builds_and_exact_final_population(self):
        registry = tomllib.loads((r.ROOT / 'verification/checks.toml').read_text())
        checks = [c for c in registry['checks'] if c.get('category') == 'aes-accelerated-no-std']
        self.assertEqual(len(checks), 4)
        for c in checks:
            compiler, route = c['command'][3], c['command'][5]
            self.assertEqual(c['command'], ['python3', 'scripts/aes/check-aes-accelerated-no-std.py', '--toolchain', compiler, '--route', route])
            self.assertIn(compiler, ('1.90.0', '1.99.1'))
            self.assertIn(route, ('direct', 'facade'))
            self.assertTrue(set(r.REJECT) <= set(c['reject_environment']))
            self.assertTrue({'aes-build', 'aes-accelerated-no-std', 'aes-execution-api', 'aes-runner', 'aes-packaged', 'compiler', 'hkdf-msrv'} <= set(c['inputs']))
            expected = {f'AES_ACCELERATED_NO_STD_PASS: {compiler} {route}; 12 library builds; 62 paired probes; compile only'}
            expected.update(f'AES_NO_STD_BUILD_PASS: {compiler} {route} {mode}-{target}-{profile}'
                            for mode in ('static', 'runtime') for target in r.TARGETS for profile in ('debug', 'release'))
            self.assertEqual(set(c['success']['unique_lines']), expected)
            self.assertNotIn('minimum_tests', c['success'])


if __name__ == '__main__':
    unittest.main()
