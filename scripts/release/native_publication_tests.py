"""Pinned metadata projection cannot approve source or native observations."""
import copy
import tomllib
import unittest
from unittest.mock import patch

import native_publication_metadata as publication
import native_review_io as io
import native_review_tests as fixtures
import native_unchanged as reuse
from native_sha1_scope_tests import Sha1DependencyProfileTests
from native_md5_scope_tests import Md5DependencyProfileTests
import native_sha1_dependency_profile as sha1
import native_md5_dependency_profile as md5


class PublicationMetadataTests(unittest.TestCase):
    def pair(self, name):
        return tuple(io.raw_blob(io.ROOT, rev, name)
                     for rev in (publication.BASE, publication.REVIEW))

    def test_exact_pairs_are_raw_bound_and_only_legacy_profiles_apply(self):
        self.assertEqual(len(publication.PAIRS), 11)
        for name, digests in publication.PAIRS.items():
            before, after = self.pair(name)
            self.assertEqual(tuple(map(io.sha, (before, after))), digests)
            for profile in publication.PROFILES:
                self.assertEqual(publication.normalize(name, after, profile), before)
            for profile in (None, 'sha2-hardened', 'kmac-execution', 'hmac'):
                self.assertEqual(publication.normalize(name, after, profile), after)
            for changed in (after + b'\n', after.replace(b'\n', b'\r\n'),
                            after.replace(b'0.10.0', b'0.11.0') + b'# changed\n'):
                self.assertEqual(publication.normalize(name, changed, sha1.PROFILE), changed)
            for unknown in ('crates/brynja-core/src/lib.rs', 'README.md',
                            'assurance/register-cleanup/kmac-verify/src/lib.rs'):
                self.assertEqual(publication.normalize(unknown, after, sha1.PROFILE), after)

    def test_manifest_changes_only_packaging_and_core_version(self):
        include = ['Cargo.toml', 'LICENSE-APACHE', 'LICENSE-MIT', 'README.md', 'src/**/*.rs']
        for name in publication.PAIRS:
            if not name.startswith('crates/'):
                continue
            before, after = (tomllib.loads(raw.decode()) for raw in self.pair(name))
            self.assertEqual(after['package'].pop('include'), include)
            if name == 'crates/brynja-core/Cargo.toml':
                self.assertEqual(before['package']['version'], '0.9.0')
                self.assertEqual(after['package']['version'], '0.10.0')
                after['package']['version'] = '0.9.0'
            self.assertEqual(before, after)

    def test_locks_preserve_population_edges_and_third_party_identity(self):
        for name in publication.PAIRS:
            if not name.endswith('Cargo.lock'):
                continue
            before, after = (tomllib.loads(raw.decode()) for raw in self.pair(name))
            old = {row['name']: row for row in before['package']}
            new = {row['name']: row for row in after['package']}
            self.assertEqual(old.keys(), new.keys())
            for package in old:
                if old[package] == new[package]:
                    continue
                self.assertNotIn('source', old[package])
                self.assertNotIn('source', new[package])
                self.assertTrue(package.startswith('brynja'))
                for revision, row in ((publication.BASE, old[package]), (publication.REVIEW, new[package])):
                    manifest = tomllib.loads(io.raw_blob(io.ROOT, revision,
                        f'crates/{package}/Cargo.toml').decode())
                    self.assertEqual(row['version'], manifest['package']['version'])
                new[package]['version'] = old[package]['version']
            self.assertEqual(before, after)

    def test_workspace_only_exact_first_party_requirements(self):
        before, after = (tomllib.loads(raw.decode()) for raw in self.pair('Cargo.toml'))
        for name, old in before['workspace']['dependencies'].items():
            new = after['workspace']['dependencies'][name]
            if new == old:
                continue
            self.assertTrue(name.startswith('brynja-'))
            for revision, value in ((publication.BASE, old), (publication.REVIEW, new)):
                manifest = tomllib.loads(io.raw_blob(io.ROOT, revision,
                    value['path'] + '/Cargo.toml').decode())
                self.assertEqual(value['version'], '=' + manifest['package']['version'])
            new['version'] = old['version']
        self.assertEqual(before, after)

    def test_package_helpers_only_change_archive_version_literals(self):
        for family in ('md5', 'sha1'):
            before, after = self.pair(f'scripts/{family}/check-{family}-package.py')
            expected = before.replace(b"'brynja-core': '0.9.0'", b"'brynja-core': '0.10.0'")
            expected = expected.replace(b"'brynja-crypto-cpu': '0.1.1'", b"'brynja-crypto-cpu': '0.2.0'")
            expected = expected.replace(b"'brynja-crypto-cpu-std': '0.1.1'", b"'brynja-crypto-cpu-std': '0.2.0'")
            self.assertEqual(after, expected)

    def test_reference_tampering_rejects(self):
        _, after = self.pair('Cargo.toml')
        with patch.object(publication.io, 'raw_blob', return_value=b'forged reference'):
            with self.assertRaisesRegex(ValueError, 'reference drift'):
                publication.normalize('Cargo.toml', after, sha1.PROFILE)


class Sha1PublicationTests(unittest.TestCase):
    sources = Sha1DependencyProfileTests.sources
    equivalent = Sha1DependencyProfileTests.equivalent

    def setUp(self):
        Sha1DependencyProfileTests.setUp(self)
        name = 'crates/brynja-core/src/lib.rs'
        fixtures.write(self.root, name, 'pub fn implementation() {}\n')
        self.closure.add(name)
        self.capture = fixtures.commit(self.root)
        self.captured = self.sources()

    def publish_metadata(self):
        names = {'Cargo.toml', 'Cargo.lock', sha1.PACKAGE, 'crates/brynja/Cargo.toml'}
        names |= {name for name in publication.PAIRS if name in sha1.REVIEWED}
        for name in names:
            fixtures.write(self.root, name, io.raw_blob(io.ROOT, publication.REVIEW, name).decode())
        return fixtures.commit(self.root)

    def test_publication_still_requires_raw_validation_approval(self):
        head = self.publish_metadata()
        self.assertTrue(self.equivalent(head))
        def check(changes):
            reuse.validate_inputs(self.root, self.capture, head, self.sources(), self.captured,
                lambda name, raw: io.sha(raw), changes, sha1.PROFILE)
        with self.assertRaisesRegex(ValueError, 'native implementation/fixture/tool changed'):
            check({})
        changes = {sha1.PACKAGE: {
            'before': io.sha(io.raw_blob(self.root, self.capture, sha1.PACKAGE)),
            'after': io.sha(io.raw_blob(self.root, head, sha1.PACKAGE))}}
        check(changes)
        for key in ('before', 'after'):
            forged = copy.deepcopy(changes)
            forged[sha1.PACKAGE][key] = '0' * 64
            with self.assertRaisesRegex(ValueError, 'reviewed validation bytes'):
                check(forged)

    def test_publication_never_exempts_feature_dependency_or_source_changes(self):
        published = self.publish_metadata()
        changes = {sha1.PACKAGE: {
            'before': io.sha(io.raw_blob(self.root, self.capture, sha1.PACKAGE)),
            'after': io.sha(io.raw_blob(self.root, published, sha1.PACKAGE))}}
        for name, old, new in (
            ('Cargo.toml', b'default-features = false', b'default-features = true'),
            ('Cargo.lock', b'name = "sanitization"', b'name = "forged-sanitization"'),
            (sha1.MANIFEST, b'default = []', b'default = ["strict-execution"]'),
            ('crates/brynja-core/src/lib.rs', b'pub fn implementation()', b'pub fn changed()'),
        ):
            path = self.root / name
            original = path.read_bytes()
            self.assertIn(old, original)
            path.write_bytes(original.replace(old, new))
            head = fixtures.commit(self.root)
            with self.subTest(name=name), self.assertRaises(ValueError):
                reuse.validate_inputs(self.root, self.capture, head, self.sources(), self.captured,
                    lambda name, raw: io.sha(raw), changes, sha1.PROFILE)
            path.write_bytes(original)
            fixtures.commit(self.root)


class Md5PublicationTests(unittest.TestCase):
    setUp = Md5DependencyProfileTests.setUp
    sources = Md5DependencyProfileTests.sources

    def test_publication_and_inheritance_require_approval_and_preserve_code(self):
        names = {'Cargo.toml', 'Cargo.lock', 'crates/brynja/Cargo.toml'}
        names |= {name for name in publication.PAIRS if name in md5.REVIEWED}
        for name in names:
            fixtures.write(self.root, name, io.raw_blob(io.ROOT, publication.REVIEW, name).decode())
        head = fixtures.commit(self.root)
        pairs = {md5.PACKAGE: {
            'before': io.sha(io.raw_blob(self.root, self.capture, md5.PACKAGE)),
            'after': io.sha(io.raw_blob(self.root, head, md5.PACKAGE))}}
        def check(changes):
            reuse.validate_inputs(self.root, self.capture, head, self.sources(), self.captured,
                lambda name, raw: io.sha(raw), changes, md5.PROFILE)
        with self.assertRaisesRegex(ValueError, 'native implementation/fixture/tool changed'):
            check({})
        check(pairs)
        for name, old, new in (
            (md5.MANIFEST, b'default-features = true', b'default-features = false'),
            ('Cargo.toml', b'path = "crates/brynja-legacy-md5"', b'path = "crates/substituted"'),
            ('crates/brynja-core/src/lib.rs', b'implementation', b'changed'),
        ):
            path = self.root / name
            original = path.read_bytes()
            self.assertIn(old, original)
            path.write_bytes(original.replace(old, new))
            head = fixtures.commit(self.root)
            with self.subTest(name=name), self.assertRaises(ValueError):
                check(pairs)
            path.write_bytes(original)
            head = fixtures.commit(self.root)
