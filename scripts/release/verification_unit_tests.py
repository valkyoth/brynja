"""Static population must match actual unittest discovery, without setUpClass."""
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import verification_units as units
import verification_plan as plans
import verification_carry_forward as carry


class UnitTests(unittest.TestCase):
    def test_group_selectors_execute_each_test_once_with_normal_fixtures(self):
        script, name = next(iter(units.SUITES.items()))
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            path = root / script
            path.parent.mkdir(parents=True)
            source = ('import unittest\n' + f'class {name}(unittest.TestCase):\n'
                      '    @classmethod\n    def setUpClass(cls): print("SETUP")\n'
                      '    @classmethod\n    def tearDownClass(cls): print("TEARDOWN")\n')
            source += ''.join(f'    def test_{i}(self): print("CASE:{i}")\n' for i in range(9))
            path.write_text(source + 'if __name__ == "__main__": unittest.main()\n')
            entry = {'phase': 'repository', 'argv': ['python3', script],
                     'command': 'python3 ' + script, 'stdin': None, 'environment': {}}
            observed = []
            for unit in units.expand(entry, root):
                run = subprocess.run([sys.executable, *unit['argv'][1:]], cwd=root,
                                     text=True, capture_output=True, timeout=10, check=True)
                lines = run.stdout.splitlines()
                self.assertEqual(lines.count('SETUP'), 1)
                self.assertEqual(lines.count('TEARDOWN'), 1)
                self.assertIn(f"Ran {len(unit['argv']) - 2} test", run.stderr)
                observed.extend(line for line in lines if line.startswith('CASE:'))
            self.assertEqual(sorted(observed), [f'CASE:{i}' for i in range(9)])

    def test_exact_real_discovery_and_no_fixture_execution(self):
        for script, name in units.SUITES.items():
            with self.subTest(script=script), patch.object(sys, 'path', [str((plans.ROOT / script).parent), *sys.path]):
                spec = importlib.util.spec_from_file_location('unit_inventory', plans.ROOT / script)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                cls = getattr(module, name)
                with patch.object(cls, 'setUpClass', side_effect=AssertionError('no compilation')):
                    actual = unittest.defaultTestLoader.getTestCaseNames(cls)
                    grouped = units.groups(plans.ROOT, script)
                self.assertEqual(sorted(x for group in grouped for x in group), [name + '.' + x for x in actual])
                self.assertTrue(all(1 <= len(g) <= 4 for g in grouped))
                entry = {'phase': 'repository', 'argv': ['python3', script],
                         'command': 'python3 ' + script, 'stdin': None, 'environment': {}}
                expanded = units.expand(entry, plans.ROOT)
                self.assertTrue(carry.covered(entry, expanded))
                self.assertFalse(carry.covered(entry, expanded[:-1]))
                self.assertTrue(all(units.covers(entry, part, plans.ROOT, plans.ROOT) for part in expanded))

    def test_unknown_duplicate_or_cyclic_inventory_rejected(self):
        script = next(iter(units.SUITES))
        name = units.SUITES[script]
        variants = [f'class {name}(Unknown):\n    def test_one(self): pass\n',
                    f'class {name}(unittest.TestCase):\n    def test_one(self): pass\n    def test_one(self): pass\n',
                    f'class {name}(unittest.TestCase): pass\n',
                    f'class {name}(unittest.TestCase):\n    async def test_one(self): pass\n',
                    f'from mixin import Mix\nclass {name}(Mix): pass\n']
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            path = root / script
            path.parent.mkdir(parents=True)
            (path.parent / 'mixin.py').write_text('from mixin import Mix\nclass Mix(Mix): pass\n')
            for text in variants:
                path.write_text(text)
                with self.subTest(text=text), self.assertRaises(ValueError):
                    units.groups(root, script)
