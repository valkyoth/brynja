#!/usr/bin/env python3
"""Strict HMAC graph, population, probe and restoration regressions."""
import copy
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('hmac_strict_checks', Path(__file__).with_name('check-hmac-strict.py'))
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)
import test_strict_public_consumer as fixtures


class StrictTests(unittest.TestCase):
    def test_generic_target_bundles_require_probe_and_separate_negative_control(self):
        for native in (False, True):
            for arch, features in (('x86_64', ['sse2']),
                                   ('aarch64', ['neon', 'sha2', 'sha3'])):
                cfg = f'target_arch="{arch}"\n' + ''.join(f'target_feature="{f}"\n' for f in features)
                with patch.object(checks.api, 'run', return_value=SimpleNamespace(stdout=cfg)), \
                        patch.object(checks.routes, 'prepare') as prepare, \
                        patch.object(checks, 'supported', return_value=native):
                    modes, env = checks.generic_modes(['cargo', '+1.99.1'], Path('/consumer'), {}, Path('/private'))
                expected = ('native' if native else 'unsupported-platform') if arch == 'aarch64' else 'missing-features'
                self.assertEqual(modes, dict.fromkeys(('sha256', 'sha512', 'keccak'), expected))
                self.assertEqual(prepare.call_count, 3 if arch == 'aarch64' else 0)
                self.assertEqual(env['RUSTFLAGS'], '-C target-feature=' +
                                 ('-sha2,-sha3' if arch == 'aarch64' else '-sha,-sha512,-avx2'))
                self.assertEqual(env['CARGO_TARGET_DIR'], '/private/target-negative-features')

    def test_exact_scalar_and_accelerated_graphs(self):
        for enabled in (False, True):
            document, roots, consumer = fixtures.document()
            if enabled:
                expected = checks.accelerated.expected_features()
                for node in document['resolve']['nodes']:
                    node['features'] = sorted(expected[node['id']])
            checks.graph(document, roots, consumer, compiled=enabled)
            for node in document['resolve']['nodes']:
                for feature in node['features']:
                    changed = copy.deepcopy(document)
                    next(n for n in changed['resolve']['nodes'] if n['id'] == node['id'])['features'].remove(feature)
                    with self.assertRaisesRegex(ValueError, 'exact feature closure'):
                        checks.graph(changed, roots, consumer, compiled=enabled)
                for feature in ('conformance-testing', 'macos-resident-hmac', 'runtime-execution'):
                    changed = copy.deepcopy(document)
                    next(n for n in changed['resolve']['nodes'] if n['id'] == node['id'])['features'].append(feature)
                    with self.assertRaisesRegex(ValueError, 'exact feature closure'):
                        checks.graph(changed, roots, consumer, compiled=enabled)
            changed = copy.deepcopy(document)
            package = next(p for p in changed['packages'] if p['name'] == 'brynja-mac-hmac')
            package['manifest_path'] = '/workspace/Cargo.toml'
            with self.assertRaisesRegex(ValueError, 'escaped extracted archive'):
                checks.graph(changed, roots, consumer, compiled=enabled)

    def test_current_package_closure_includes_hmac_once(self):
        old = checks.api.packaging.PACKAGING_PACKAGES
        packages = checks.scalar.specifications(checks.api)
        self.assertEqual(len(packages), 12)
        self.assertEqual(len({name for name, *_ in packages}), 12)
        self.assertEqual(sum(name == 'brynja-mac-hmac' for name, *_ in packages), 1)
        self.assertEqual(checks.api.packaging.PACKAGING_PACKAGES, old)
        with patch.object(checks.api.archives, 'specifications', return_value=old):
            with self.assertRaisesRegex(ValueError, 'closure missing'):
                checks.scalar.specifications(checks.api)

    def test_unification_is_not_facade_acceleration(self):
        document, roots, consumer = fixtures.document()
        for node in document['resolve']['nodes']:
            if node['id'] == 'brynja-crypto-cpu-std':
                node['features'].append('strict-hmac-acceleration')
            if node['id'] == 'brynja-mac-hmac':
                node['features'].append('hardened-execution')
            if node['id'] in ('brynja-crypto-cpu', 'brynja-hash-sha2', 'brynja-hash-sha3'):
                node['features'] += ['static-execution', 'hardened-execution']
        checks.graph(document, roots, consumer, unified=True)
        with self.assertRaisesRegex(ValueError, 'exact feature closure'):
            checks.graph(document, roots, consumer)
        next(n for n in document['resolve']['nodes'] if n['id'] == 'brynja-strict')['features'] = ['acceleration']
        with self.assertRaisesRegex(ValueError, 'exact feature closure'):
            checks.graph(document, roots, consumer, unified=True)

    def test_populations_require_zero_ignored_filtered_and_exit_success(self):
        for count in (1, 2, 4):
            output = f'test result: ok. {count} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;\n'
            checks.population(SimpleNamespace(returncode=0, stdout=output), count)
            for bad in ('', output + output, output.replace('0 ignored', '1 ignored'),
                        output.replace('0 failed', '1 failed'), output.replace('0 filtered', '1 filtered'),
                        output.replace(f'{count} passed', '0 passed')):
                with self.assertRaises(ValueError):
                    checks.population(SimpleNamespace(returncode=0, stdout=bad), count)
            with self.assertRaises(ValueError):
                checks.population(SimpleNamespace(returncode=101, stdout=output), count)

    def test_all_identities_have_positive_and_negative_controls(self):
        for compiled in (False, True):
            cases = list(checks.cases.negatives(compiled))
            self.assertEqual(len(cases), 138 if compiled else 140)
            self.assertEqual(len(set(cases)), len(cases))
            positive = checks.cases.positive(compiled)
            owner = 'CompiledSession' if compiled else 'Session'
            for identity in checks.cases.ALGORITHMS:
                self.assertIn(f'{owner}<{identity}>', positive)
                for bound in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
                    self.assertIn((f'fn bound<T:{bound}>(){{}} fn probe(){{bound::<{owner}<{identity}>>();}}', 'E0277'), cases)
            for name in checks.cases.FORBIDDEN:
                self.assertIn((f'use facade::hmac::{name};', 'E0432'), cases)

    def test_probe_failure_restores_consumer(self):
        with tempfile.TemporaryDirectory(prefix='hmac-strict-probes-') as directory:
            root = Path(directory)
            (root / 'src').mkdir()
            source = root / 'src/lib.rs'
            source.write_text('original')
            with patch.object(checks.api, 'run', side_effect=ValueError('injected compile error')):
                with self.assertRaisesRegex(ValueError, 'injected'):
                    checks.negatives(['cargo'], root, {}, False)
            self.assertEqual(source.read_text(), 'original')

    def test_scalar_fixture_uses_only_the_strict_facade(self):
        text = checks.cases.scalar_fixture(checks.ROOT)
        self.assertIn('use facade::hmac::*;', text)
        self.assertNotIn('brynja_crypto_cpu_std', text)
        self.assertNotIn('brynja_mac_hmac', text)
        self.assertNotIn('#[ignore', text)
        self.assertEqual(text.count('#[test]'), 5)  # Four Linux / two unsupported.
        self.assertIn('pub fn readme_example()', checks.cases.documentation(checks.ROOT))
        self.assertNotIn('brynja_strict', checks.cases.documentation(checks.ROOT))

    def test_mutant_failure_restores_archive_and_consumer(self):
        with tempfile.TemporaryDirectory(prefix='hmac-strict-mutants-') as directory:
            root = Path(directory)
            (root / 'src').mkdir()
            source = root / 'src/lib.rs'
            source.write_text('consumer')
            facade = root / 'facade'
            (facade / 'src').mkdir(parents=True)
            path = facade / 'src/hmac.rs'
            original = '#[cfg(feature = "acceleration")]\npub use host::CompiledSession;\n'
            for failure in ('baseline', 'compile', 'restore'):
                path.write_text(original)
                calls = []
                def run(*args, **kwargs):
                    calls.append(1)
                    at = {'baseline': 1, 'compile': 2, 'restore': 3}[failure]
                    if len(calls) == at:
                        raise RuntimeError('synthetic failure')
                    return SimpleNamespace(returncode=101 if len(calls) == 1 else 0)
                def diagnostic(result, _code):
                    if result.returncode == 0:
                        raise ValueError('successful mutant rejected by negative assertion')
                with patch.object(checks.api, 'run', side_effect=run), \
                        patch.object(checks.hmac_acceptance, 'diagnostic_rejection', side_effect=diagnostic):
                    with self.assertRaisesRegex(RuntimeError, 'synthetic failure'):
                        checks.exposure_mutants([], root, {}, {'brynja-strict': facade})
                self.assertEqual(source.read_text(), 'consumer')
                self.assertEqual(path.read_text(), original)


if __name__ == '__main__':
    unittest.main()
