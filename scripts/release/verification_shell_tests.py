"""Shell registration fixtures only; never run the bound campaigns."""
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import verification_shell_bindings as bindings
from verification_additional_tests import validate_inputs

ROOT = Path(__file__).resolve().parents[2]


class ShellBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = json.loads((ROOT / 'verification/catalog.json').read_text())['entries']
        cls.doc = bindings.build(cls.rows)

    def test_exact_commands_preserved_without_compilation(self):
        with patch('subprocess.Popen', side_effect=AssertionError('no execution')):
            doc = bindings.build(self.rows)
        self.assertEqual(len(doc['checks']), 17)
        self.assertEqual({tuple(c['command']) for c in doc['checks']}, set(bindings.definitions()))
        validate_inputs(doc)
        for check in doc['checks']:
            self.assertEqual(check['command'], next(r['command'] for r in self.rows if r['id'] == check['id']))
            self.assertEqual(check['environment']['CARGO_NET_OFFLINE'], 'true')
            self.assertEqual(check['environment']['PYTHONOPTIMIZE'], '0')
            self.assertEqual(check['environment']['RUSTUP_AUTO_INSTALL'], '0')

    def test_no_implicit_matrix_or_argument_change(self):
        ids = {c['id'] for c in self.doc['checks']}
        for row in (r for r in self.rows if r['id'] in ids):
            for field, value in [('command', row['command'] + ['--matrix']),
                                 ('environment', {'RUSTFLAGS': 'unreviewed'}), ('stdin', 'unexpected')]:
                with self.assertRaises(ValueError):
                    bindings.build([{**row, field: value}])

    def test_concrete_markers_and_nonzero_test_population(self):
        for check in self.doc['checks']:
            spec = bindings.definitions()[tuple(check['command'])]
            source = (ROOT / check['command'][0]).read_text()
            # Resolve only the explicitly reviewed shell interpolation forms.
            source = source.replace('${toolchain#+}', spec['versions'][0])
            source = source.replace('${toolchains[*]}', ' '.join(spec['versions']))
            source = source.replace('$target', bindings.TARGET)
            for marker in check['success']['unique_lines']:
                self.assertIn(marker, source)
            self.assertEqual(check['success'].get('minimum_tests', 0), int(spec['tests']))
            if not spec['markers']:
                self.assertEqual(check['command'], ['scripts/sanitization/check-sanitization-candidate.sh'])

    def test_scoped_tools_and_transitive_inputs(self):
        for check in self.doc['checks']:
            groups = [self.doc['groups'][k] for k in check['inputs']]
            paths = {p for g in groups for p in g.get('paths', [])}
            self.assertNotIn('Cargo.lock', paths)
            self.assertFalse(any(p.startswith(('verification/', 'docs/', 'target/')) for p in paths))
            tools = [t for g in groups for t in g.get('tools', [])]
            spec = bindings.definitions()[tuple(check['command'])]
            self.assertEqual({t['toolchain'] for t in tools if 'toolchain' in t}, set(spec['versions']))
            if check['component'] in ('md5', 'sha1'):
                self.assertNotIn('crates/brynja-mac-hmac/src', paths)
                self.assertNotIn('crates/brynja-crypto-cpu-std/src', paths)
        conformance = next(c for c in self.doc['checks'] if c['command'][0].endswith('conformance-gate.sh'))
        paths = {p for k in conformance['inputs'] for p in self.doc['groups'][k].get('paths', [])}
        self.assertIn('scripts/cryptography/rust_source_contract.py', paths)
        self.assertIn('crates/brynja-crypto-cpu/src', paths)
        candidate = next(c for c in self.doc['checks'] if c['command'][0].endswith('candidate.sh'))
        tools = [t for k in candidate['inputs'] for t in self.doc['groups'][k].get('tools', [])]
        self.assertIn({'program': 'rustfmt', 'toolchain': '1.99.1'}, tools)
        self.assertIn({'program': 'clippy-driver', 'toolchain': '1.99.1'}, tools)
