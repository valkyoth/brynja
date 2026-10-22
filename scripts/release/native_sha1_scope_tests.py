"""SHA-1 command-profile mutations; metadata only, never native qualification."""
import copy
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import native_dependency_scope as dependencies
import native_review_io as io
import native_review_tests as fixtures
import native_sha1_dependency_profile as profile
import native_md5_dependency_profile as md5
import native_unchanged as reuse


class Sha1DependencyProfileTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='brynja-sha1-native-profile-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        fixtures.init_repository(self.root)
        names = {'Cargo.toml', 'Cargo.lock', *profile.REVIEWED}
        names.update(n for n in io.names(io.ROOT, profile.REVIEW) if n.startswith('crates/')
                     and n.count('/') == 2 and n.endswith('/Cargo.toml'))
        for name in names:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(io.raw_blob(io.ROOT, profile.REVIEW, name))
        self.closure = {'Cargo.toml', 'Cargo.lock', *profile.REVIEWED}
        self.capture = fixtures.commit(self.root)
        self.captured = self.sources()
        patched = patch.object(profile, 'REVIEW', self.capture)
        patched.start()
        self.addCleanup(patched.stop)

    def sources(self):
        return {name: io.sha((self.root / name).read_bytes()) for name in self.closure}

    def equivalent(self, head):
        return dependencies.equivalent(self.root, self.capture, head, self.closure, profile.PROFILE)

    def test_optional_edge_only_and_default_projection_stays_conservative(self):
        self.assertTrue(self.equivalent(self.capture))
        with self.assertRaisesRegex(ValueError, 'absent from capture closure'):
            dependencies.projection(self.root, self.capture, self.closure)
        rows = dependencies.graph(io.raw_blob(self.root, self.capture, 'Cargo.lock'))
        old = copy.deepcopy(rows)
        projected = profile.reachability_rows(self.root, self.capture, self.closure, rows)
        self.assertEqual(rows, old)
        projected[profile.HOST]['dependencies'] = rows[profile.HOST]['dependencies']
        self.assertEqual(projected, rows)

    def test_hmac_archive_needs_separate_validation_approval(self):
        path = self.root / profile.PACKAGE
        old = path.read_bytes()
        self.assertEqual(old.count(md5.OLD_ARCHIVES), 1)
        new = old.replace(md5.OLD_ARCHIVES, md5.HMAC_ARCHIVES)
        path.write_bytes(new)
        head = fixtures.commit(self.root)
        self.assertTrue(self.equivalent(head))
        def check(changes):
            reuse.validate_inputs(self.root, self.capture, head, self.sources(), self.captured,
                lambda name, raw: io.sha(raw), changes, profile.PROFILE)
        with self.assertRaisesRegex(ValueError, 'native implementation/fixture/tool changed'):
            check({})
        check({profile.PACKAGE: {'before': io.sha(old), 'after': io.sha(new)}})
        with self.assertRaisesRegex(ValueError, 'reviewed validation bytes'):
            check({profile.PACKAGE: {'before': io.sha(old), 'after': '0' * 64}})

    def test_each_command_manifest_and_line_ending_remains_bound(self):
        for name in profile.REVIEWED:
            path = self.root / name
            original = path.read_bytes()
            for changed in (original + b'\n# drift\n', original.replace(b'\n', b'\r\n')):
                path.write_bytes(changed)
                with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'command/manifest review changed'):
                    self.equivalent(fixtures.commit(self.root))
            path.write_bytes(original)
            fixtures.commit(self.root)

    def test_feature_activation_and_other_roots_reject(self):
        for name, old, new in (
            ('crates/' + profile.HOST + '/Cargo.toml', b'default = []', b'default = ["strict-execution"]'),
            ('crates/' + profile.HOST + '/Cargo.toml', b'optional = true', b'optional = false'),
            ('scripts/sha1/hardened_native.py', b"'--features', 'runtime-hardened-execution'", b"'--all-features'"),
            (profile.PACKAGE, b'features=["runtime-hardened-execution"]', b'features=["strict-execution"]')):
            path = self.root / name
            original = path.read_bytes()
            self.assertIn(old, original)
            path.write_bytes(original.replace(old, new))
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'command/manifest review changed'):
                self.equivalent(fixtures.commit(self.root))
            path.write_bytes(original)
            fixtures.commit(self.root)
        for closure in (self.closure - {'crates/brynja-core/Cargo.toml'},
                        self.closure | {'crates/brynja-crypto-cpu/src/lib.rs'}):
            with self.assertRaisesRegex(ValueError, 'exact capture roots'):
                dependencies.projection(self.root, self.capture, closure, profile.PROFILE)

    def test_real_native_feature_union_has_no_shared_hosted_dependency(self):
        result = subprocess.run(['cargo', '+1.98.1', 'tree', '--locked', '--offline',
            '--color', 'never', '--target', 'all', '-p', 'brynja-legacy-sha1',
            '-p', profile.HOST, '--features',
            'brynja-legacy-sha1/hardened-execution,brynja-legacy-sha1-std/runtime-hardened-execution',
            '--prefix', 'none', '--format', '{p}|{f}'], cwd=io.ROOT, check=True,
            capture_output=True, text=True, timeout=60)
        names = set()
        for line in result.stdout.splitlines():
            if not line:
                continue
            identity, features = line.removesuffix(' (*)').split('|')
            name = identity.split()[0]
            names.add(name)
            self.assertIn(name, {path.split('/')[-1] for path in profile.ROOTS})
            self.assertNotIn('strict-execution', features)
            self.assertIn(f'({io.ROOT}/crates/{name})', identity)
        self.assertEqual(names, {path.split('/')[-1] for path in profile.ROOTS})
