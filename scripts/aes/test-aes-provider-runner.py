#!/usr/bin/env python3
"""Provider compiler-runner regression controls; no device/cryptographic claims."""
from contextlib import redirect_stdout
import importlib.util
import io
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('provider_api', Path(__file__).with_name('check-aes-provider-api.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class ProviderRunnerTests(unittest.TestCase):
    def test_exact_probe_population_and_distinct_controls(self):
        cases = runner.probes()
        self.assertEqual(len(cases), 87)
        self.assertEqual(len({row[0] for row in cases}), 87)
        for name, negative, positive, code in cases:
            self.assertNotEqual(negative, positive, name)
            self.assertRegex(code, '^E[0-9]{4}$')

    def test_both_routes_and_independent_feature_sets(self):
        with patch.object(runner.api, 'run_probes') as run, redirect_stdout(io.StringIO()) as output:
            runner.run('1.90.0')
        self.assertEqual(run.call_count, 8)
        self.assertEqual(sum(len(call.kwargs['cases']) for call in run.call_args_list), 180)
        for call in run.call_args_list:
            self.assertEqual(call.args[0], '1.90.0')
            self.assertEqual(call.args[2]['CARGO_NET_OFFLINE'], 'true')
            self.assertEqual(call.args[2]['RUSTUP_AUTO_INSTALL'], '0')
            for _, negative, positive, _ in call.kwargs['cases']:
                if call.kwargs['package'] == 'brynja':
                    self.assertNotIn('brynja_crypto', negative + positive)
                    self.assertIn('brynja::crypto', negative + positive)
        self.assertEqual({call.kwargs['features'] for call in run.call_args_list},
                         {'', 'external-key-provider', 'hazmat-aes-block',
                          'hazmat-aes-block,external-key-provider'})
        self.assertIn('180 paired probes; direct and facade; independent opt-ins', output.getvalue())

    def test_any_probe_failure_prevents_completion_marker(self):
        with patch.object(runner.api, 'run_probes', side_effect=ValueError('wrong diagnostic')), \
             redirect_stdout(io.StringIO()) as output:
            with self.assertRaisesRegex(ValueError, 'wrong diagnostic'):
                runner.run('1.99.1')
        self.assertNotIn('AES_PROVIDER_API_PASS', output.getvalue())

    def test_thread_traits_follow_backend_not_unconditional_rejection(self):
        cases = {name: (negative, positive) for name, negative, positive, _ in runner.aes128_probes()}
        for owner in ('Aes128ProviderKey<Backend>', 'ExternalKey<Backend>'):
            negative, positive = cases[owner + '-Send']
            self.assertIn('std::rc::Rc<()>', negative)
            self.assertIn('std::cell::Cell<u8>', positive)
            self.assertIn('T:Send', positive)
            negative, positive = cases[owner + '-Sync']
            self.assertIn('std::cell::Cell<u8>', negative)
            self.assertIn('struct Backend;', positive)
            self.assertIn('T:Sync', positive)

    def test_all_width_pairs_reject_cross_binding_with_positive_control(self):
        cases = {name: (negative, positive, code) for name, negative, positive, code in runner.probes()}
        for bits in (128, 192, 256):
            for other in (128, 192, 256):
                if bits == other:
                    continue
                negative, positive, code = cases[f'{bits}/reject-{other}-binding']
                self.assertIn(f'impl Aes{bits}Backend for Backend', negative)
                self.assertNotIn(f'impl Aes{other}Backend', negative)
                self.assertIn(f'Aes{other}ProviderKey::new', negative)
                self.assertIn(f'Aes{bits}ProviderKey::new', positive)
                self.assertEqual(code, 'E0277')

    def test_width_rewrite_preserves_128_probe_semantics(self):
        base = runner.aes128_probes()
        for bits in (128, 192, 256):
            cases = [row for row in runner.probes() if row[0].startswith(f'{bits}/')][:25]
            restored = [(name.split('/', 1)[1].replace(f'Aes{bits}', 'Aes128'), negative.replace(f'Aes{bits}', 'Aes128'),
                         positive.replace(f'Aes{bits}', 'Aes128'), code)
                        for name, negative, positive, code in cases]
            self.assertEqual(restored, base)

    def test_multi_trait_backends_are_allowed_but_owner_types_remain_distinct(self):
        cases = [row for row in runner.probes() if '/multi-trait-' in row[0]]
        self.assertEqual(len(cases), 6)
        for name, negative, positive, code in cases:
            bits, other = name.split('/')[0], name.split('-')[3]
            for width in (128, 192, 256):
                self.assertIn(f'impl Aes{width}Backend for Backend', positive)
                self.assertIn(f'impl Aes{width}Backend for Backend', negative)
            self.assertIn(f'let _:Aes{bits}ProviderKey<Backend>=Aes{bits}ProviderKey::new', positive)
            self.assertIn(f'let _:Aes{other}ProviderKey<Backend>=Aes{bits}ProviderKey::new', negative)
            self.assertEqual(code, 'E0308')

    def test_registry_covers_every_width_and_shared_fixture(self):
        root = Path(__file__).resolve().parents[2]
        registry = tomllib.loads((root / 'verification/checks.toml').read_text())
        checks = {c['id']: c for c in registry['checks'] if c['component'] == 'aes'}
        paths = registry['groups']['aes-provider']['paths']
        self.assertIn('crates/brynja-crypto/tests/aes_provider_common', paths)
        for bits in (128, 192, 256):
            self.assertIn(f'crates/brynja-crypto/tests/aes{bits}_provider.rs', paths)
        for name in ('provider-native', 'provider-msrv', 'provider-asan', 'provider-miri'):
            check = checks[name]
            targets = [check['command'][i + 1] for i, arg in enumerate(check['command']) if arg == '--test']
            self.assertEqual(targets, ['aes128_provider', 'aes192_provider', 'aes256_provider'])
            self.assertEqual(check['success']['exact_tests'], 51)
        for endpoint, name in (('1.90.0', 'provider-api-msrv'), ('1.99.1', 'provider-api-current')):
            self.assertEqual(checks[name]['success']['unique_lines'],
                             [f'AES_PROVIDER_API_PASS: {endpoint} 180 paired probes; direct and facade; independent opt-ins'])

    def test_new_permission_variant_requires_an_explicit_authorization_decision(self):
        root = Path(__file__).resolve().parents[2]
        text = (root / 'crates/brynja-crypto/src/aes/provider.rs').read_text()
        enum = 'pub enum Permissions {' + text.split('pub enum Permissions {', 1)[1].split('\n}', 1)[0] + '\n}'
        body = text.split('let allowed = match (self.permissions, inverse) {', 1)[1].split('\n                };', 1)[0]
        function = 'fn allowed(p: Permissions, inverse: bool) -> bool { match (p, inverse) {' + body + '\n} }'
        positive = enum + '\n' + function + '\nfn main() { assert!(allowed(Permissions::Encrypt, false)); }'
        negative = positive.replace('pub enum Permissions {', 'pub enum Permissions {\n    Revoked,')
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / 'permission.rs'
            command = ['rustc', '--edition=2024', str(source), '-o', str(Path(temporary) / 'probe')]
            source.write_text(positive)
            result = subprocess.run(command, capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            source.write_text(negative)
            result = subprocess.run(command, capture_output=True, text=True, timeout=60)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('E0004', result.stderr)
            self.assertIn('non-exhaustive patterns', result.stderr)


if __name__ == '__main__':
    unittest.main()
