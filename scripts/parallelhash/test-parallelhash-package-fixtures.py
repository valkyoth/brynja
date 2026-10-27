#!/usr/bin/env python3
"""Regressions for pristine ParallelHash builds followed by external test targets."""
from pathlib import Path
import tempfile
import tomllib
import unittest

import parallelhash_package_fixtures as fixtures


class FixtureTests(unittest.TestCase):
    def tree(self, base):
        repository = base / 'repository'
        roots = {}
        for package, names in fixtures.TESTS.items():
            tests = repository / 'crates' / package / 'tests'
            tests.mkdir(parents=True)
            for name in names:
                (tests / (name + '.rs')).write_text('// repository test\n')
            root = base / 'archives' / package
            (root / 'src').mkdir(parents=True)
            (root / 'src/lib.rs').write_text('// extracted runtime\n')
            (root / 'Cargo.toml').write_text(f'[package]\nname="{package}"\nversion="0.1.0"\nautotests=false\n')
            roots[package] = root
        scoped = repository / 'assurance/parallelhash-differential/tests/scoped.rs'
        scoped.parent.mkdir(parents=True)
        scoped.write_text('// repository scoped test\n')
        return repository, roots

    def test_all_runtime_builds_precede_external_targets(self):
        with tempfile.TemporaryDirectory() as raw:
            repository, roots = self.tree(Path(raw))
            calls = []
            def build(command, cwd, env):
                self.assertEqual(command, ['cargo', 'build', '--offline', '--all-features', '--lib']
                                 + (['--release'] if '--release' in command else []))
                for root in roots.values():
                    self.assertNotIn('test', tomllib.loads((root / 'Cargo.toml').read_text()))
                    self.assertFalse((root / 'tests').exists())
                calls.append((cwd.name, '--release' in command))
            fixtures.prepare(roots, repository, build, {})
            self.assertEqual(calls, [(p, release) for p in fixtures.TESTS for release in (False, True)])
            for package, root in roots.items():
                targets = tomllib.loads((root / 'Cargo.toml').read_text())['test']
                expected = fixtures.test_paths(repository, package)
                self.assertEqual({t['name']: Path(t['path']) for t in targets}, expected)
                self.assertTrue(all(Path(t['path']).is_relative_to(repository) for t in targets))
                self.assertEqual((root / 'src/lib.rs').read_text(), '// extracted runtime\n')
                self.assertFalse((root / 'tests').exists())

    def test_missing_extra_and_archived_tests_fail_closed(self):
        for change in ('missing', 'extra', 'scoped', 'archived', 'declared'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as raw:
                repository, roots = self.tree(Path(raw))
                leaf = 'brynja-hash-parallel'
                path = repository / 'crates' / leaf / 'tests'
                if change == 'missing':
                    (path / 'api.rs').unlink()
                elif change == 'extra':
                    (path / 'unclassified.rs').write_text('')
                elif change == 'scoped':
                    (repository / 'assurance/parallelhash-differential/tests/scoped.rs').unlink()
                elif change == 'archived':
                    (roots[leaf] / 'tests').mkdir()
                else:
                    manifest = roots[leaf] / 'Cargo.toml'
                    manifest.write_text(manifest.read_text() + '\n[[test]]\nname="hidden"\npath="hidden.rs"\n')
                def no_build(*args):
                    self.fail('invalid fixture population reached a build')
                with self.assertRaises(ValueError):
                    fixtures.prepare(roots, repository, no_build, {})

    def test_failed_runtime_build_never_installs_fixtures(self):
        with tempfile.TemporaryDirectory() as raw:
            repository, roots = self.tree(Path(raw))
            def failed(*args):
                raise RuntimeError('synthetic missing runtime input')
            with self.assertRaisesRegex(RuntimeError, 'runtime input'):
                fixtures.prepare(roots, repository, failed, {})
            for root in roots.values():
                self.assertNotIn('test', tomllib.loads((root / 'Cargo.toml').read_text()))
                self.assertFalse((root / 'tests').exists())


if __name__ == '__main__':
    unittest.main()
