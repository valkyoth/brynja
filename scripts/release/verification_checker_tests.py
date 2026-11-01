"""Test checker registration identity using syntax and synthetic outputs only."""
import ast
import io
import json
from pathlib import Path
import sys
import unittest
import tomllib
from unittest.mock import patch
import verification_checker_bindings as bindings
from verification_additional_tests import validate_inputs
from verification_legacy_policy_tests import policy

ROOT = Path(__file__).resolve().parents[2]


class CheckerBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = json.loads((ROOT / 'verification/catalog.json').read_text())['entries']
        cls.doc = bindings.build(cls.rows)

    def test_thirteen_exact_nonexecuting_bindings(self):
        with patch('subprocess.Popen', side_effect=AssertionError('no execution')):
            doc = bindings.build(self.rows)
        self.assertEqual(len(doc['checks']), 13)
        validate_inputs(doc)
        for check in doc['checks']:
            row = next(r for r in self.rows if r['id'] == check['id'])
            self.assertEqual(check['command'], row['command'])
            self.assertIn('synthetic/mock', check['establishes'])
            for field, value in [('command', row['command'] + ['--compiled']),
                                 ('environment', {'PYTHONOPTIMIZE': '1'}), ('stdin', 'unreviewed')]:
                with self.assertRaises(ValueError):
                    bindings.build([{**row, field: value}])

    def test_exact_unittest_population_and_literal_completion(self):
        for argv, spec in bindings.definitions().items():
            tree = ast.parse((ROOT / argv[1]).read_text())
            if spec['count']:
                methods = [n for cls in tree.body if isinstance(cls, ast.ClassDef)
                           for n in cls.body if isinstance(n, ast.FunctionDef) and n.name.startswith('test_')]
                for path in spec.get('test_modules', []):
                    extra = ast.parse((ROOT / path).read_text())
                    methods += [n for cls in extra.body if isinstance(cls, ast.ClassDef)
                                for n in cls.body if isinstance(n, ast.FunctionDef) and n.name.startswith('test_')]
                self.assertEqual(len(methods), spec['count'])
            else:
                strings = {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
                self.assertTrue(set(spec['success']['unique_lines']) <= strings)

    def test_helper_imports_bound_without_entire_crypto_tree(self):
        roots = [ROOT / 'scripts' / name for name in ('cryptography', 'legacy-hmac', 'hmac', 'sha2', 'sha3', 'repository', 'cpu')]
        for spec in bindings.definitions().values():
            paths = set(spec['paths'])
            for path in paths:
                if not path.endswith('.py'):
                    continue
                for node in ast.walk(ast.parse((ROOT / path).read_text())):
                    names = ([a.name for a in node.names] if isinstance(node, ast.Import)
                             else [node.module] if isinstance(node, ast.ImportFrom) and node.module else [])
                    for name in names:
                        if (path == 'scripts/legacy-hmac/test-legacy-hmac-timing.py'
                                and name == 'legacy_hmac_timing_fixture_tests'):
                            # Only the explicitly rejected --compiled selector imports this.
                            continue
                        for root in roots:
                            candidate = root / (name + '.py')
                            if candidate.exists():
                                self.assertIn(candidate.relative_to(ROOT).as_posix(), paths)
            self.assertNotIn('Cargo.toml', paths)  # Mocked digest contents are not a test premise.
            self.assertNotIn('Cargo.lock', paths)
            self.assertFalse(any((ROOT / p).is_dir() for p in paths))

    def test_hmac_acceptance_declares_copied_sources_without_native_execution(self):
        spec = bindings.definitions()[('python3', 'scripts/hmac/test-hmac-acceptance.py')]
        self.assertEqual(spec['count'], 12)  # Seven local tests plus five imported FaultTests.
        self.assertIn('crates/brynja-mac-hmac/src', spec['source_paths'])
        for module in ('execution/hmac.rs', 'strict_hmac/compiled.rs', 'macos_resident/hmac/compiled.rs'):
            self.assertIn('crates/brynja-crypto-cpu-std/src/' + module, spec['source_paths'])
        self.assertNotIn('Cargo.toml', spec['source_paths'])
        self.assertNotIn('Cargo.lock', spec['source_paths'])
        check = next(c for c in self.doc['checks'] if c['command'][1].endswith('test-hmac-acceptance.py'))
        tools = [t for key in check['inputs'] for t in self.doc['groups'][key].get('tools', [])]
        self.assertEqual(tools, [{'program': 'python3'}])
        self.assertNotIn('platform', check)

    def test_hmac_synthetic_acceptance_has_no_unmocked_process(self):
        with patch.object(sys, 'path', [str(ROOT / 'scripts/hmac'), *sys.path]), \
                patch('subprocess.Popen', side_effect=AssertionError('unexpected real command')):
            module = policy('binding_hmac_acceptance', 'scripts/hmac/test-hmac-acceptance.py')
            suite = unittest.defaultTestLoader.loadTestsFromModule(module)
            self.assertEqual(suite.countTestCases(), 12)
            stream = io.StringIO()
            result = unittest.TextTestRunner(stream=stream).run(suite)
        self.assertTrue(result.wasSuccessful(), stream.getvalue())
        self.assertFalse(result.skipped)

    def test_protected_checker_has_no_native_or_compiler_execution(self):
        with patch.object(sys, 'path', [str(ROOT / 'scripts/hmac'), *sys.path]), \
                patch('subprocess.Popen', side_effect=AssertionError('unexpected real command')):
            module = policy('binding_hmac_protected', 'scripts/hmac/test-hmac-protected.py')
            suite = unittest.defaultTestLoader.loadTestsFromModule(module)
            self.assertEqual(suite.countTestCases(), 10)
            stream = io.StringIO()
            result = unittest.TextTestRunner(stream=stream).run(suite)
        self.assertTrue(result.wasSuccessful(), stream.getvalue())
        self.assertFalse(result.skipped)

    def test_facade_and_strict_suites_never_launch_a_real_process(self):
        for script, count in [('test-hmac-facade.py', 5), ('test-hmac-strict.py', 9)]:
            with self.subTest(script=script), \
                    patch.object(sys, 'path', [str(ROOT / 'scripts/hmac'), *sys.path]), \
                    patch('subprocess.Popen', side_effect=AssertionError('unexpected real command')):
                module = policy('binding_' + script, 'scripts/hmac/' + script)
                suite = unittest.defaultTestLoader.loadTestsFromModule(module)
                self.assertEqual(suite.countTestCases(), count)
                stream = io.StringIO()
                result = unittest.TextTestRunner(stream=stream).run(suite)
                self.assertTrue(result.wasSuccessful(), stream.getvalue())
                self.assertFalse(result.skipped)
                declared = bindings.definitions()[('python3', 'scripts/hmac/' + script)]
                actual = module.checks.api.archives.specifications(module.checks.api.packaging)
                self.assertEqual({name for name, *_ in actual}, set(bindings.FACADE_PACKAGES))
                self.assertEqual(declared['toml'], {f'crates/{name}/Cargo.toml':
                    ['package.name', 'package.version'] for name, *_ in actual})
                self.assertNotIn('Cargo.lock', declared['paths'])
                self.assertNotIn('Cargo.toml', declared['paths'])
        strict = bindings.definitions()[('python3', 'scripts/hmac/test-hmac-strict.py')]
        self.assertEqual(strict['source_paths'], [
            'crates/brynja-strict/src/hmac_tests.rs', 'crates/brynja-strict/README.md'])

    def test_hmac_package_regressions_use_synthetic_archives_and_mocked_builds(self):
        with patch.object(sys, 'path', [str(ROOT / 'scripts/hmac'), *sys.path]), \
                patch('subprocess.Popen', side_effect=AssertionError('unexpected real command')):
            module = policy('binding_hmac_package', 'scripts/hmac/test-hmac-package.py')
            suite = unittest.defaultTestLoader.loadTestsFromModule(module)
            self.assertEqual(suite.countTestCases(), 12)
            stream = io.StringIO()
            result = unittest.TextTestRunner(stream=stream).run(suite)
        self.assertTrue(result.wasSuccessful(), stream.getvalue())
        self.assertFalse(result.skipped)
        spec = bindings.definitions()[('python3', 'scripts/hmac/test-hmac-package.py')]
        self.assertEqual(spec['source_paths'], [
            'crates/brynja-mac-hmac/tests/general.rs', 'crates/brynja-mac-hmac/README.md'])
        self.assertNotIn('toml', spec)

    def test_compiled_timing_import_remains_behind_explicit_option(self):
        script = 'scripts/legacy-hmac/test-legacy-hmac-timing.py'
        tree = ast.parse((ROOT / script).read_text())
        guards = [n for n in ast.walk(tree) if isinstance(n, ast.If)
                  and ast.unparse(n.test) == "'--compiled' in sys.argv"]
        self.assertEqual(len(guards), 1)
        self.assertTrue(any(isinstance(n, ast.ImportFrom) and n.module == 'legacy_hmac_timing_fixture_tests'
                            for n in ast.walk(guards[0])))
        spec = bindings.definitions()[('python3', script)]
        self.assertNotIn('scripts/legacy-hmac/legacy_hmac_timing_fixture_tests.py', spec['paths'])

    def test_resident_manifest_closure_is_projected_not_whole_workspace(self):
        script = ROOT / 'scripts/cryptography/check-macos-legacy-resident-package.py'
        tree = ast.parse(script.read_text())
        packages = ast.literal_eval(next(n.value for n in tree.body if isinstance(n, ast.Assign)
            and any(isinstance(v, ast.Name) and v.id == 'PACKAGES' for v in n.targets)))
        self.assertEqual(packages, bindings.RESIDENT_PACKAGES)
        inherited = set()
        for package in packages:
            manifest = tomllib.loads((ROOT / 'crates' / package / 'Cargo.toml').read_text())
            for table in [manifest, *manifest.get('target', {}).values()]:
                for kind in ('dependencies', 'dev-dependencies', 'build-dependencies'):
                    inherited.update(name for name, dep in table.get(kind, {}).items()
                                     if isinstance(dep, dict) and dep.get('workspace'))
        self.assertEqual(inherited, set(bindings.RESIDENT_DEPENDENCIES))
        spec = bindings.definitions()[('python3', 'scripts/cryptography/test-macos-legacy-resident-package.py')]
        self.assertEqual(set(spec['toml']['Cargo.toml']), {'workspace.dependencies.' + n for n in inherited})
        self.assertNotIn('Cargo.lock', spec['paths'])
