"""Static/mocked registration tests, not original policy or crypto campaigns."""
import contextlib
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import verification_record_policy_bindings as bindings
from verification_additional_tests import validate_inputs
from verification_legacy_policy_tests import policy
from verification_package_tests import covered

ROOT = Path(__file__).resolve().parents[2]


class RecordPolicyBindingTests(unittest.TestCase):
    def setUp(self):
        self.rows = json.loads((ROOT / 'verification/catalog.json').read_text())['entries']
        self.doc = bindings.build(self.rows)

    def test_eight_exact_offline_nonexecuting_selectors(self):
        with patch('subprocess.Popen', side_effect=AssertionError('no execution')):
            doc = bindings.build(self.rows)
        self.assertEqual(len(doc['checks']), 8)
        validate_inputs(doc)
        for check in doc['checks']:
            self.assertEqual([t for k in check['inputs'] for t in doc['groups'][k].get('tools', [])], [{'program': 'python3'}])
            row = next(r for r in self.rows if r['id'] == check['id'])
            for key, value in [('command', row['command'] + ['--online']),
                               ('environment', {'PYTHONOPTIMIZE': '1'}), ('stdin', 'unchecked')]:
                with self.assertRaises(ValueError):
                    bindings.build([{**row, key: value}])

    def test_batch_inputs_cover_original_enumeration_and_future_helpers(self):
        for stem, family in [('sha256', 'sha2'), ('sha512', 'sha2'), ('keccak', 'sha3')]:
            path = f'scripts/{family}/test-{stem}-batch' + ('-policy' if stem == 'keccak' else '') + '.py'
            declared = bindings.definitions()[('python3', path)]
            with patch('subprocess.Popen', side_effect=AssertionError('no execution')):
                module = policy('binding_' + stem, f'scripts/{family}/{stem}_batch_policy.py')
                original = module.paths(ROOT)
            matches = {str(p.relative_to(ROOT)) for pattern in declared['patterns'] for p in ROOT.glob(pattern)}
            for name in [*original, module.REVIEW]:
                self.assertTrue(name in matches or any(name == p or name.startswith(p + '/') for p in declared['paths']), name)
            self.assertEqual(declared['patterns'], [f'scripts/{family}/*{stem}*batch*.py'])
            if stem == 'keccak':
                count = 3 + sum(map(len, module.CONTRACTS.values())) + sum(map(len, module.COMMANDS.values())) + 3 + 9
                self.assertIn(f'rejects {count} ', declared['markers'][0])
            if stem == 'sha512':
                self.assertTrue(any(m.startswith(str(sum(map(len, module.CONTRACTS.values()))) + ' ') for m in declared['markers']))

    def test_sanitizer_regressions_do_not_start_sanitizers(self):
        for stem in ('sha256', 'sha512'):
            with patch.object(sys, 'path', [str(ROOT / 'scripts/sha2'), *sys.path]), \
                    patch('subprocess.Popen', side_effect=AssertionError('no real sanitizer')), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                module = policy('binding_' + stem + '_test', f'scripts/sha2/test-{stem}-batch.py')
                module.sanitizer_regressions()
            self.assertIn('Eight native batch sanitizer clean/hostile-environment/failure cases passed', output.getvalue())

    def test_hash_policy_inventory_is_exact_and_does_not_run_the_milestone(self):
        module = policy('binding_final_hash', 'scripts/hash/final_acceptance.py')
        spec = bindings.definitions()[('python3', 'scripts/hash/test-final-acceptance.py')]
        self.assertEqual(set(spec['paths']), {str(p) for p in (*module.FILES, module.HASHES)} | {'scripts/hash/final_acceptance.py'})
        self.assertEqual(spec['patterns'], [])

    def test_admission_scope_is_manifest_only_and_not_network_or_package_execution(self):
        for mode in ('check', 'test'):
            spec = bindings.definitions()[('python3', f'scripts/sanitization/{mode}-sanitization-admission.py')]
            self.assertEqual(spec['patterns'], ['crates/*/Cargo.toml'])
            self.assertIn('Cargo.lock', spec['paths'])  # Original policy checks prohibited lock entries.
            self.assertNotIn('crates', spec['paths'])
            self.assertFalse(any(p.startswith(('verification/', 'target/')) for p in spec['paths']))

    def test_cpu_policy_source_inventory_and_optional_build_scripts_not_a_native_campaign(self):
        with patch.object(sys, 'path', [str(ROOT / 'scripts/cpu'), *sys.path]), \
                patch('subprocess.Popen', side_effect=AssertionError('no execution')):
            module = policy('binding_cpu_boundary', 'scripts/cpu/cpu_boundary_policy.py')
        for mode in ('check', 'test'):
            check = next(c for c in self.doc['checks'] if c['command'] ==
                ['python3', f'scripts/cpu/{mode}-cpu-boundary.py'])
            groups = [self.doc['groups'][k] for k in check['inputs']]
            for name in module.EVIDENCE_STATUS:
                self.assertTrue(covered(name, groups), name)
            for crate, path in module.SOURCE_STATUS:
                self.assertTrue(covered('crates/' + crate + '/' + path, groups), (crate, path))
            self.assertEqual({p for g in groups for p in g.get('optional_paths', [])}, {
                'crates/brynja-crypto-cpu/build.rs', 'crates/brynja-crypto-cpu-std/build.rs'})
            self.assertFalse(covered('crates/unrelated-aes/src/lib.rs', groups))
            self.assertFalse(covered('verification/results.json', groups))
