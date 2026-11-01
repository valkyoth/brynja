"""Registration-only regressions; never execute the registered hash checks."""
import ast
import copy
import json
from pathlib import Path
import random
import unittest
from unittest.mock import patch
import verification_script_bindings as scripts
from verification_additional_tests import validate_inputs

ROOT = Path(__file__).resolve().parents[2]


class ScriptBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = json.loads((ROOT / 'verification/catalog.json').read_text())['entries']
        cls.doc = scripts.build(cls.rows)

    def test_generation_is_nonexecuting_and_selects_only_known_commands(self):
        with patch('subprocess.Popen', side_effect=AssertionError('registration executed a process')):
            doc = scripts.build(self.rows)
        self.assertEqual(len(doc['checks']), 38)
        self.assertEqual({c['command'][1] for c in doc['checks']}, set(scripts.definitions()))
        validate_inputs(doc)
        by_id = {r['id']: r for r in self.rows}
        for check in doc['checks']:
            self.assertEqual(check['command'], by_id[check['id']]['command'])
            self.assertEqual(check['success']['contains'], check['success']['unique_lines'])
            self.assertEqual(check['environment']['PYTHONOPTIMIZE'], '0')
            self.assertEqual(check['environment']['PYTHONNOUSERSITE'], '1')

    def test_unknown_arguments_environment_or_write_mode_cannot_be_registered(self):
        row = copy.deepcopy(next(r for r in self.rows if r['command'] == ['python3', 'scripts/md5/check-md5-differential.py']))
        for field, value in [('command', row['command'] + ['--write']), ('environment', {'PYTHONOPTIMIZE': '1'}), ('stdin', 'undeclared')]:
            changed = {**row, field: value}
            with self.assertRaises(ValueError):
                scripts.build([changed])
        row['command'] = ['python3', 'scripts/md5/unknown.py']
        self.assertEqual(scripts.build([row])['checks'], [])

    def test_new_oracles_keep_exact_populations_and_declared_harnesses(self):
        messages = set(range(321)) | {511, 512, 513, 1023, 1024, 1025, 4096}
        self.assertEqual(len(messages), 328)
        for script, harness, marker in [
            ('check-hmac-differential.py', 'differential', 'HMAC_ORACLE: 1100 cases'),
            ('check-hmac-bit-differential.py', 'bit_differential', 'HMAC_BIT_ORACLE: 1040 cases')]:
            check = next(c for c in self.doc['checks'] if c['command'][1].endswith('/' + script))
            paths = {p for k in check['inputs'] for p in self.doc['groups'][k].get('paths', [])}
            self.assertIn(f'crates/brynja-mac-hmac/tests/{harness}.rs', paths)
            self.assertEqual(check['success']['exact_tests'], 1)
            self.assertTrue(check['success']['unique_lines'][0].startswith(marker))
            self.assertNotIn('crates/brynja-crypto-cpu/src', paths)
            self.assertNotIn('crates/brynja-legacy-hmac/src', paths)

    def test_source_policy_markers_are_existing_exact_printed_lines(self):
        for check in self.doc['checks']:
            if 'RUSTUP_TOOLCHAIN' in check['environment'] or check['command'][1].endswith('test-md5-execution-asan.py'):
                continue
            tree = ast.parse((ROOT / check['command'][1]).read_text())
            printed = {a.value for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                       and n.func.id == 'print' for a in n.args if isinstance(a, ast.Constant) and isinstance(a.value, str)}
            self.assertIn(check['success']['contains'][0], printed, check['command'])

    def test_hash_populations_match_existing_bounded_selection_without_hashing(self):
        for seed, expected in [(1321, 1136), (0x1804, 1135)]:
            rng = random.Random(seed)
            self.assertEqual(len(set(range(1040)) | {rng.randrange(65537) for _ in range(96)}), expected)
        lengths = set(range(33))
        for boundary in (440, 448, 456, 504, 512, 520, 888, 896, 904, 1016, 1024, 1032):
            lengths.update(range(boundary - 7, boundary + 8))
        lengths.update((611, 710, 809, 1123, 1222, 1321, 2047, 2048, 2049, 4095, 4096))
        self.assertEqual(len(lengths) * 6, 1008)
        vectors = (ROOT / 'crates/brynja-hash-sha3/tests/vectors/nist-bit-selected.txt').read_text()
        self.assertEqual(len([s for s in vectors.splitlines() if s and not s.startswith('#')]), 76)
        for path in scripts.DIFFERENTIAL:
            tree = ast.parse((ROOT / path).read_text())
            self.assertTrue(any(isinstance(n, ast.JoinedStr) for n in ast.walk(tree)))

    def test_portable_comparisons_do_not_pull_optional_cpu_or_host_sources(self):
        for check in self.doc['checks']:
            if 'RUSTUP_TOOLCHAIN' not in check['environment']:
                continue
            groups = [self.doc['groups'][k] for k in check['inputs']]
            paths = {p for g in groups for p in g.get('paths', [])}
            self.assertFalse(any('brynja-crypto-cpu' in p for p in paths), check['command'])
            self.assertEqual(check['environment']['RUSTUP_TOOLCHAIN'], '1.99.1')
            self.assertEqual(check['environment']['CARGO_NET_OFFLINE'], 'true')
            self.assertTrue(any(t['program'] == 'cargo' for g in groups for t in g.get('tools', [])))
            if check['command'][1] in ('scripts/kmac/check-kmac-differential.py',
                'scripts/tuplehash/check-tuplehash-differential.py', 'scripts/parallelhash/check-parallelhash-differential.py'):
                self.assertTrue(set(scripts.CSHAKE) <= paths)

    def test_source_contracts_use_exact_modules_not_whole_core_crate(self):
        for check in self.doc['checks']:
            if not check['command'][1].startswith('scripts/foundations/'):
                continue
            groups = [self.doc['groups'][k] for k in check['inputs']]
            paths = {p for g in groups for p in g.get('paths', [])}
            self.assertNotIn('crates/brynja-core/src', paths)
            self.assertFalse(any(g.get('locks') or any(t['program'] == 'cargo' for t in g.get('tools', [])) for g in groups))
            self.assertTrue(any(p.endswith('_policy.py') for p in paths))

    def test_boundary_sources_match_policy_declarations_without_importing_them(self):
        for check in self.doc['checks']:
            if check['command'][1] not in scripts.boundary_definitions():
                continue
            groups = [self.doc['groups'][k] for k in check['inputs']]
            paths = {p for g in groups for p in g.get('paths', [])}
            helper = next(p for p in paths if p.endswith('_policy.py'))
            tree = ast.parse((ROOT / helper).read_text())
            constants = {n.targets[0].id: n.value for n in tree.body if isinstance(n, ast.Assign)
                         and isinstance(n.targets[0], ast.Name)}
            declared = constants['SOURCES']
            self.assertIsInstance(declared, ast.Tuple)
            for item in declared.elts:
                value = constants[item.id] if isinstance(item, ast.Name) else item
                self.assertIsInstance(value, ast.Call)
                self.assertEqual(value.func.id, 'Path')
                path = ast.literal_eval(value.args[0])
                if 'SOURCE_ROOT' in constants:
                    path = ast.literal_eval(constants['SOURCE_ROOT'].args[0]) + '/' + path
                self.assertIn(path, paths, check['command'])
            if 'TEST' in constants:
                self.assertIn(ast.literal_eval(constants['TEST'].args[0]), paths)
            self.assertFalse(any(g.get('locks') for g in groups))
            self.assertNotIn('crates/brynja-core/src', paths)

    def test_boundary_package_projection_and_literal_mutation_scopes_are_distinct(self):
        for check in self.doc['checks']:
            script = check['command'][1]
            if script not in scripts.boundary_definitions() or '/cpu/' in script:
                continue
            groups = [self.doc['groups'][k] for k in check['inputs']]
            paths = {p for g in groups for p in g.get('paths', [])}
            selected = {p: fields for g in groups for p, fields in g.get('toml', {}).items()}
            package = 'brynja-protocol' if '/protocols/' in script else 'brynja-pki'
            manifest = f'crates/{package}/Cargo.toml'
            if '/test-' in script:
                self.assertTrue({manifest, 'package-policy.toml'} <= paths)
            else:
                self.assertNotIn(manifest, paths)
                self.assertNotIn('package-policy.toml', paths)
                self.assertEqual(selected[manifest], ['dependencies', 'features'])
                self.assertIn('packages.' + package, selected['package-policy.toml'])
                self.assertFalse(any('version' in field for fields in selected.values() for field in fields))

    def test_pki_and_protocol_keep_original_command_id_with_actual_component_owner(self):
        for check in self.doc['checks']:
            script = check['command'][1]
            if script.startswith('scripts/pki/'):
                self.assertEqual(check['component'], 'pki')
            elif script.startswith('scripts/protocols/'):
                self.assertEqual(check['component'], 'protocol')
            else:
                continue
            row = next(r for r in self.rows if r['id'] == check['id'])
            self.assertEqual(check['command'], row['command'])
            self.assertTrue(row['history'], 'original observations must remain linked')


if __name__ == '__main__':
    unittest.main()
