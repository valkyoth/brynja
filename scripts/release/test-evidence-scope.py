#!/usr/bin/env python3
"""Workspace consumer selection without launching any verification campaign."""
import tempfile
import unittest
from pathlib import Path

import verification_plan as plans
import native_review_tests as fixtures
import scope_workspace as workspace

OLD = '''[workspace]
members=["crates/*"]
resolver="3"
[workspace.dependencies]
external={version="=1.0.0",default-features=false}
'''


class WorkspaceScope(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='brynja-workspace-scope-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        fixtures.init_repository(self.root)
        fixtures.write(self.root, 'Cargo.toml', OLD)
        fixtures.write(self.root, 'Cargo.lock', 'version=4\npackage=[]\n')
        fixtures.write(self.root, 'crates/brynja-mac-kmac/Cargo.toml',
                       '[package]\nname="brynja-mac-kmac"\nversion="0.1.0"\n'
                       '[dependencies]\nexternal.workspace=true\n')
        fixtures.write(self.root, 'crates/brynja-mac-kmac/src/lib.rs', 'pub fn mac() {}\n')
        self.base = fixtures.commit(self.root)

    def selected(self, value):
        fixtures.write(self.root, 'Cargo.toml', value)
        return plans.scope.select_repository(self.base, self.root, verified_base=True)

    def test_dependency_change_selects_only_consumer(self):
        for value in (OLD.replace('1.0.0', '2.0.0'),
                      OLD.replace('default-features=false', 'default-features=true'),
                      OLD.replace('version="=1.0.0"', 'version="=1.0.0",features=["new"]')):
            with self.subTest(value=value):
                self.assertEqual(self.selected(value), (False, ('kmac',)))

    def test_unused_workspace_declaration_is_not_a_crypto_change(self):
        self.assertEqual(self.selected(OLD + 'unused={version="=1.0.0"}\n'), (False, ()))

    def test_removed_dependency_still_selects_original_consumer(self):
        self.assertEqual(self.selected(OLD.split('external=')[0]), (False, ('kmac',)))

    def test_untracked_and_deleted_consumers_do_not_disappear(self):
        path = 'crates/brynja-hash-sha2/Cargo.toml'
        fixtures.write(self.root, path, '[package]\nname="sha2"\nversion="1"\n'
                       '[target."cfg(windows)".build-dependencies]\nexternal.workspace=true\n')
        selected = workspace.consumer_paths(self.root, self.base, OLD.encode(),
                                            OLD.replace('1.0.0', '2.0.0').encode())
        self.assertIn(path, selected)
        original = self.root / 'crates/brynja-mac-kmac/Cargo.toml'
        original.unlink()
        self.assertIn('crates/brynja-mac-kmac/Cargo.toml', workspace.consumer_paths(
            self.root, self.base, OLD.encode(), OLD.replace('1.0.0', '2.0.0').encode()))

    def test_profile_resolver_patch_and_unknown_implementation_need_review(self):
        for value in (OLD.replace('resolver="3"', 'resolver="2"'),
                      OLD + '\n[profile.release]\nlto="fat"\n',
                      OLD + '\n[patch.crates-io]\nexternal={path="vendor/external"}\n'):
            with self.subTest(value=value):
                self.assertTrue(self.selected(value)[0])
        fixtures.write(self.root, 'crates/brynja-mac-hmac/Cargo.toml',
                       '[package]\nname="brynja-mac-hmac"\nversion="0.1.0"\n'
                       '[dependencies]\nexternal.workspace=true\n')
        self.assertTrue(self.selected(OLD)[0])
        # HMAC must register its own verifier commands when implemented. It
        # cannot borrow a KMAC or SHA-2 PASS by adding a workspace declaration.

    def test_workspace_table_change_cannot_hide_shared_source_change(self):
        fixtures.write(self.root, 'crates/brynja-hash-sha3/src/lib.rs', 'pub fn changed() {}\n')
        full, groups = self.selected(OLD + 'unused={version="=1.0.0"}\n')
        self.assertFalse(full)
        self.assertEqual(set(groups), {'sha3', 'kmac', 'tuplehash', 'parallelhash'})


if __name__ == '__main__':
    unittest.main()
