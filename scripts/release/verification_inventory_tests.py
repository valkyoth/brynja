"""Binding-only regressions; never run linked HMAC assessments."""
import ast
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import verification_inventory_bindings as bindings
from verification_additional_tests import validate_inputs
from verification_legacy_policy_tests import policy

ROOT = Path(__file__).resolve().parents[2]


class InventoryBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = json.loads((ROOT / 'verification/catalog.json').read_text())['entries']
        cls.doc = bindings.build(cls.rows)

    def test_two_original_selectors_and_no_execution(self):
        with patch('subprocess.Popen', side_effect=AssertionError('no execution')):
            document = bindings.build(self.rows)
        self.assertEqual(len(document['checks']), 2)
        self.assertEqual({tuple(c['command']) for c in document['checks']}, set(bindings.definitions()))
        validate_inputs(document)
        for check in document['checks']:
            tools = [t for k in check['inputs'] for t in document['groups'][k].get('tools', [])]
            self.assertEqual(tools, [{'program': 'python3'}])
            self.assertIn('No linked campaign', check['establishes'])

    def test_no_write_flags_environment_or_stdin_expansion(self):
        ids = {c['id'] for c in self.doc['checks']}
        for row in (r for r in self.rows if r['id'] in ids):
            for key, value in [('command', row['command'] + ['--write']),
                               ('environment', {'PYTHONOPTIMIZE': '1'}), ('stdin', 'unreviewed')]:
                with self.assertRaises(ValueError):
                    bindings.build([{**row, key: value}])

    def test_explicit_paths_match_original_inventory_declarations(self):
        with patch('subprocess.Popen', side_effect=AssertionError('no execution')), \
                patch.object(sys, 'path', [*sys.path, str(ROOT / 'scripts/cryptography')]):
            inv = policy('binding_hmac_inventory', 'scripts/hmac/hmac_inventory.py')
        sources = {target.split('#')[0] for target in inv.OWNERS} | set(inv.VERIFY_DOCS)
        sources |= {inv.LEAF + name for name in (
            'lib.rs', 'bits.rs', 'algorithms.rs', 'scratch.rs', 'engine.rs', 'execution/retained.rs')}
        self.assertEqual(set(bindings.SOURCES), sources)
        self.assertEqual(set(bindings.LINKS), {name for _, name in inv.EVIDENCE})
        self.assertEqual(set(bindings.MANIFESTS),
                         {'crates/' + p + '/Cargo.toml' for _, p, _, _ in inv.PROFILES})
        self.assertEqual((len(inv.OWNERS), len(inv.PROFILES)), (14, 10))

    def test_only_check_reads_document_and_only_mutants_need_literal_manifests(self):
        for check in self.doc['checks']:
            group = self.doc['groups'][check['inputs'][-1]]
            paths = group['paths']
            mode = bindings.definitions()[tuple(check['command'])]
            self.assertEqual('docs/hmac-development-inventory.md' in paths, mode == 'check')
            self.assertFalse(any(p.startswith(('verification/', 'target/')) for p in paths))
            self.assertNotIn('Cargo.lock', paths)
            for manifest in bindings.MANIFESTS:
                self.assertEqual(manifest in paths, mode == 'test')
                if mode == 'check':
                    self.assertEqual(group['toml'][manifest], ['features'])
            self.assertTrue(set(bindings.HELPERS) <= set(paths))

    def test_completion_signals_match_original_driver(self):
        tree = ast.parse((ROOT / 'scripts/hmac/test-hmac-inventory.py').read_text())
        count = sum(isinstance(n, ast.FunctionDef) and n.name.startswith('test_') for n in ast.walk(tree))
        self.assertEqual(count, 11)
        for check in self.doc['checks']:
            if 'test-hmac' in check['command'][1]:
                self.assertEqual(check['success'], {'contains': ['\nRan 11 tests in '], 'unique_lines': ['OK']})
            else:
                self.assertEqual(check['success']['unique_lines'], [bindings.MARKER])
