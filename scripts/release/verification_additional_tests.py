"""Static binding regressions only: no compiler, sanitizer or proof campaign."""
import copy
import json
from pathlib import Path
import re
import tomllib
import unittest
from unittest.mock import patch
import verification_matrix_bindings as matrix
import verification_extra_sanitizers as sanitizers
import verification_repository_bindings as repository
import verification_manual_diagnostics as manual

ROOT = Path(__file__).resolve().parents[2]


def validate_inputs(document):
    for check in document['checks']:
        for name in check['inputs']:
            group = document['groups'][name]
            for path in group.get('paths', []):
                assert (ROOT / path).exists(), path
                assert not path.startswith(('verification/', 'target/')), path
            for path in group.get('toml', {}):
                assert (ROOT / path).is_file(), path
            for selection in group.get('locks', []):
                rows = tomllib.loads((ROOT / selection['path']).read_text())['package']
                present = {p['name'] for p in rows}
                assert set(selection['packages']) <= present, (selection, present)
        assert check['success']['contains'] and check['timeout_seconds'] > 0


class AdditionalBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = json.loads((ROOT / 'verification/catalog.json').read_text())['entries']
        cls.base = tomllib.loads((ROOT / 'verification/checks.toml').read_text())

    def test_matrix_selection_is_finite_offline_and_nonexecuting(self):
        with patch('subprocess.Popen', side_effect=AssertionError('must not execute')):
            doc = matrix.build(self.rows)
        self.assertEqual(len(doc['checks']), 350)
        validate_inputs(doc)
        for check in doc['checks']:
            self.assertIn('--offline', check['command'])
            self.assertIn('--locked', check['command'])
            self.assertNotIn('--workspace', check['command'])
            if check['command'][2] == 'test':
                self.assertEqual(check['success']['minimum_tests'], 1)
                self.assertTrue(check['success']['allow_ignored'])
            if 'macos_resident::hmac' in check['command']:
                self.assertEqual(check['platform'], 'macos-aarch64')
            if check['stdin']:
                self.assertEqual(check['stdin'], 'crates/brynja-hash-sha2/tests/vectors/general-sha512-t-digest.txt')
        ids = {c['id'] for c in doc['checks']}
        remaining = [r for r in self.rows if r['phase'] == 'matrix' and r['id'] not in ids]
        self.assertEqual(len(remaining), 14)
        self.assertTrue(all(manual.reason(r) for r in remaining))

    def test_historical_milestone_rollups_are_exact_manual_campaigns(self):
        selected = []
        for row in self.rows:
            argv = row['command']
            if (len(argv) != 2 or argv[0] != 'python3' or argv[1] not in manual.MILESTONE_CAMPAIGNS
                    or row['phase'] != 'repository'):
                continue
            original = copy.deepcopy(row)
            reason = manual.reason(row)
            self.assertIn('compile and execute real tests', reason)
            self.assertIn('separate bindings or unresolved', reason)
            self.assertEqual(row, original)
            self.assertIsNone(manual.reason({**row, 'command': row['command'] + ['--write']}))
            selected.append(row)
        self.assertEqual(len(selected), 5)
        # Do not hide the package checks or the actual regression suites merely
        # because a historical rollup also calls them.
        for path in ('scripts/legacy-hash/test-legacy-acceptance.py',
                     'scripts/legacy-hash/test-legacy-final-acceptance.py',
                     'scripts/legacy-hash/check-legacy-package.py',
                     'scripts/hash/test-final-acceptance.py',
                     'scripts/sp800185/test-portable-acceptance.py',
                     'scripts/sp800185/test-execution-acceptance.py'):
            self.assertIsNone(manual.reason(dict(phase='repository', command=['python3', path])))

    def test_unreviewed_matrix_command_or_stdin_is_rejected(self):
        source = next(r for r in self.rows if r['phase'] == 'matrix' and r.get('stdin'))
        for field, value in [('command', ['cargo', '+1.99.1', 'test', '--workspace']), ('stdin', 'unknown')]:
            changed = copy.deepcopy(source)
            changed[field] = value
            with self.assertRaises(ValueError):
                matrix.build([changed])

    def test_remaining_sanitizers_retain_leak_policy_and_signals(self):
        original = {c['id'] for c in self.base['checks']}
        doc = sanitizers.build(self.rows, original)
        self.assertEqual(len(doc['checks']), 16)
        validate_inputs(doc)
        for c in doc['checks']:
            self.assertIn('detect_leaks=1', c['environment']['ASAN_OPTIONS'])
            self.assertEqual(c['platform'], 'linux-x86_64')
            if c['command'][0] == 'cargo':
                self.assertEqual(c['environment']['RUSTFLAGS'], '-Zsanitizer=address')
            else:
                self.assertTrue(c['success']['unique_lines'])
        ids = original | {c['id'] for c in doc['checks']}
        remaining = {r['id'] for r in self.rows if r['phase'] == 'asan' and r['id'] not in ids}
        self.assertEqual(remaining, set(sanitizers.MANUAL))

    def test_repository_cargo_fixtures_are_component_scoped(self):
        doc = repository.build(self.rows)
        self.assertEqual(len(doc['checks']), 27)
        validate_inputs(doc)
        for c in doc['checks']:
            self.assertNotIn('--workspace', c['command'])
            self.assertIn('--offline', c['command'])
            self.assertEqual(c['command'][1], '+1.99.1')
        hmac = next(c for c in doc['checks'] if 'assurance/hmac-policy/Cargo.toml' in c['command'])
        paths = {p for key in hmac['inputs'] for p in doc['groups'][key].get('paths', [])}
        self.assertIn('crates/brynja-mac-hmac/src/policy.rs', paths)

    def test_fixture_external_source_includes_are_declared(self):
        for doc in (matrix.build(self.rows), repository.build(self.rows)):
            checked = set()
            for check in doc['checks']:
                groups = [doc['groups'][k] for k in check['inputs']]
                paths = [ROOT / p for g in groups for p in g.get('paths', []) + g.get('optional_paths', [])]
                for directory in paths:
                    if not directory.is_dir() or not directory.relative_to(ROOT).as_posix().startswith('assurance/'):
                        continue
                    identity = (str(directory), tuple(map(str, paths)))
                    if identity in checked:
                        continue
                    checked.add(identity)
                    for source in directory.rglob('*.rs'):
                        for name in re.findall(r'(?:include(?:_str|_bytes)?!\(\s*|#\[path\s*=\s*)"([^"]+)"', source.read_text()):
                            target = (source.parent / name).resolve()
                            self.assertTrue(any(target == p or (p.is_dir() and target.is_relative_to(p)) for p in paths),
                                            (check['id'], source, name))

    def test_manual_disposition_does_not_hide_component_tests_or_change_history(self):
        for phase, argv in [('repository', ['python3', 'scripts/md5/check-md5-differential.py']),
                            ('matrix', ['cargo', '+1.99.1', 'test', '--workspace'])]:
            self.assertIsNone(manual.reason(dict(id='new', phase=phase, command=argv)))
        for row in self.rows:
            before = copy.deepcopy(row)
            manual.reason(row)
            self.assertEqual(row, before)

    def test_registration_fragments_match_without_duplicate_groups(self):
        groups = set(self.base['groups'])
        identities = {(c['component'], c['id']) for c in self.base['checks']}
        for name in self.base['includes']:
            doc = json.loads((ROOT / name).read_text())
            self.assertFalse(groups.intersection(doc['groups']), name)
            groups.update(doc['groups'])
            for c in doc['checks']:
                identity = (c['component'], c['id'])
                self.assertNotIn(identity, identities)
                identities.add(identity)

    def test_evidence_diagnostics_are_exact_and_do_not_hide_native_execution(self):
        selected = manual.NATIVE_RECORD_TESTS | manual.EVIDENCE_DIAGNOSTICS
        self.assertEqual(len(selected), 15)
        for path in selected:
            row = next(r for r in self.rows if r['phase'] == 'repository' and r['command'] == ['python3', path])
            before = copy.deepcopy(row)
            self.assertTrue(manual.reason(row))
            self.assertEqual(row, before)
            self.assertIsNone(manual.reason({**row, 'command': row['command'] + ['--write']}))
        for path in ('scripts/legacy-hmac/test-legacy-hmac-native.py',
                     'scripts/legacy-hmac/test-legacy-hmac-md5-native.py',
                     'scripts/hmac/check-hmac-hosted-native.py',
                     'scripts/sha3/test-keccak-batch-asan.py',
                     'scripts/md5/test-md5-execution-asan.py',
                     'scripts/cpu/check-backend-contract.py'):
            self.assertIsNone(manual.reason(dict(phase='repository', command=['python3', path])))

    def test_orchestration_dispositions_are_exact_and_keep_execution_variants(self):
        for argv in manual.ORCHESTRATION_DIAGNOSTICS:
            row = next(r for r in self.rows if r['phase'] == 'repository' and tuple(r['command']) == argv)
            before = copy.deepcopy(row)
            self.assertTrue(manual.reason(row))
            self.assertEqual(row, before)
            self.assertIsNone(manual.reason({**row, 'command': [*argv, '--write']}))
            if argv[-1] == '--policy-only':
                self.assertIsNone(manual.reason({**row, 'command': list(argv[:-1])}))


if __name__ == '__main__':
    unittest.main()
