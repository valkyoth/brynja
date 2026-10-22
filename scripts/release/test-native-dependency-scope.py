#!/usr/bin/env python3
"""Real-Git mutations for dependency-scoped native reuse; no CPU qualification."""
import tempfile
import unittest
from pathlib import Path

import native_dependency_scope as dependencies
import native_review_io as io
import native_review_tests as fixtures
import native_unchanged as reuse
from native_md5_scope_tests import Md5DependencyProfileTests
from native_hmac_tests import InactiveHmacTests, HmacFeatureGraphTests
from native_sha1_scope_tests import Sha1DependencyProfileTests

WORKSPACE = '''[workspace]
members = ["crates/*"]
resolver = "3"
[workspace.dependencies]
core = { path = "crates/core", version = "=1.0.0", default-features = false }
[profile.release]
panic = "abort"
'''
LOCK = '''version = 4
[[package]]
name = "sha2"
version = "1.0.0"
dependencies = ["core"]
[[package]]
name = "core"
version = "1.0.0"
dependencies = ["external"]
[[package]]
name = "external"
version = "1.0.0"
source = "registry+https://example.invalid/index"
checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
'''
HMAC_ROW = '''
[[package]]
name = "hmac"
version = "0.1.0"
dependencies = ["sha2"]
'''


class NativeDependencies(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='brynja-native-dependencies-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        fixtures.init_repository(self.root)
        self.write('Cargo.toml', WORKSPACE)
        self.write('Cargo.lock', LOCK)
        self.write('rust-toolchain.toml', '[toolchain]\nchannel="1.99.1"\n')
        for package in ('core', 'sha2'):
            manifest = f'[package]\nname="{package}"\nversion="1.0.0"\n'
            manifest += ('[dependencies]\ncore.workspace=true\n' if package == 'sha2'
                         else '[dependencies]\nexternal="=1.0.0"\n')
            self.write(f'crates/{package}/Cargo.toml', manifest)
            self.write(f'crates/{package}/src/lib.rs', 'pub fn implementation() {}\n')
        self.write('scripts/capture.py', 'print("actual capture commands")\n')
        self.capture = fixtures.commit(self.root)
        self.closure = set(io.names(self.root, self.capture))
        self.captured = self.sources()

    def write(self, name, value):
        fixtures.write(self.root, name, value)

    def sources(self):
        return {name: io.sha(io.read(self.root, name)) for name in self.closure
                if (self.root / name).exists()}

    def check(self):
        head = fixtures.commit(self.root)
        reuse.validate_inputs(self.root, self.capture, head, self.sources(),
                              self.captured, lambda name, raw: io.sha(raw))

    def add_hmac(self):
        self.write('Cargo.lock', LOCK + HMAC_ROW)
        self.write('Cargo.toml', WORKSPACE.replace('[profile.release]',
                   'hmac = { path = "crates/hmac", version = "=0.1.0" }\n[profile.release]'))
        self.write('crates/hmac/Cargo.toml',
                   '[package]\nname="hmac"\nversion="0.1.0"\n'
                   '[dependencies]\nsha2={path="../sha2",version="=1.0.0"}\n')
        self.write('crates/hmac/src/lib.rs', 'pub fn new_mac() {}\n')

    def test_new_hmac_consumer_does_not_invalidate_existing_sha2(self):
        self.add_hmac()
        self.check()
        # Adding a consumer is not approval of that consumer: a new HMAC
        # capture must include HMAC sources, so an old SHA-2 record cannot fill it.
        with self.assertRaisesRegex(ValueError, 'population'):
            reuse.validate_inputs(self.root, self.capture,
                                  io.git(self.root, 'rev-parse', 'HEAD').decode().strip(),
                                  self.sources() | {'crates/hmac/src/lib.rs': '0' * 64},
                                  self.captured, lambda name, raw: io.sha(raw))

    def test_unrelated_lock_pin_does_not_invalidate_capture(self):
        self.write('Cargo.lock', LOCK + '''
[[package]]
name="unrelated"
version="9.0.0"
source="registry+https://example.invalid/index"
checksum="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
''')
        self.check()

    def test_implementation_fixture_toolchain_and_native_additions_reject(self):
        for name in ('crates/sha2/src/lib.rs', 'crates/core/src/lib.rs',
                     'crates/sha2/build.rs', 'crates/core/src/extra.rs',
                     'crates/sha2/kernel.S', 'crates/sha2/kernel.c',
                     'scripts/capture.py', '.cargo/config.toml', 'rust-toolchain.toml'):
            path = self.root / name
            original = path.read_bytes() if path.exists() else None
            self.write(name, 'changed implementation or build input\n')
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.check()
            if original is None:
                path.unlink()
            else:
                self.write(name, original.decode())
            fixtures.commit(self.root)

    def test_semantic_build_dependency_changes_reject(self):
        for name, value in (
            ('Cargo.toml', WORKSPACE.replace('abort', 'unwind')),
            ('Cargo.toml', WORKSPACE.replace('resolver = "3"', 'resolver = "2"')),
            ('Cargo.toml', WORKSPACE.replace('default-features = false', 'default-features = true')),
            ('Cargo.toml', WORKSPACE.replace('members = ["crates/*"]', 'members = ["crates/sha2"]')),
            ('Cargo.toml', WORKSPACE + '\n[patch.crates-io]\nexternal={path="vendor/external"}\n'),
            ('Cargo.lock', LOCK.replace('aaaaaaaa', 'bbbbbbbb')),
            ('Cargo.lock', LOCK.replace('registry+', 'git+')),
            ('Cargo.lock', LOCK.replace('dependencies = ["core"]', 'dependencies = []')),
            ('Cargo.lock', LOCK + HMAC_ROW + HMAC_ROW),
            ('Cargo.lock', LOCK.replace('["core"]', '["core 1.0.0"]')),
            ('Cargo.lock', LOCK.replace('["core"]', '["missing"]')),
            ('Cargo.lock', LOCK.replace('version = 4', 'version = 3')),
        ):
            path = self.root / name
            original = path.read_text()
            self.write(name, value)
            with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                self.check()
            self.write(name, original)
            fixtures.commit(self.root)

    def test_target_build_dev_and_alias_workspace_dependencies_count(self):
        manifest = {'target': {'cfg(windows)': {'dependencies': {
            'renamed': {'workspace': True, 'package': 'real-name'}}}},
            'build-dependencies': {'builder': {'workspace': True}},
            'dev-dependencies': {'test-tool': {'workspace': True}}}
        self.assertEqual(dependencies.inherited_dependencies(manifest),
                         {'renamed', 'builder', 'test-tool'})

    def test_deleted_input_and_forged_historical_hash_reject(self):
        altered = dict(self.captured)
        altered['scripts/capture.py'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'original native source'):
            reuse.validate_inputs(self.root, self.capture, self.capture, self.sources(),
                                  altered, lambda name, raw: io.sha(raw))
        (self.root / 'crates/core/src/lib.rs').unlink()
        with self.assertRaisesRegex(ValueError, 'population'):
            self.check()

    def test_missing_local_dependency_population_blocks_projection(self):
        with self.assertRaisesRegex(ValueError, 'absent from capture closure'):
            dependencies.projection(self.root, self.capture,
                                    {'crates/sha2/src/lib.rs'})

    def test_existing_custom_build_script_blocks_metadata_projection(self):
        self.write('crates/sha2/build.rs', 'fn main() {}\n')
        self.capture = fixtures.commit(self.root)
        self.closure.add('crates/sha2/build.rs')
        self.captured = self.sources()
        self.add_hmac()
        with self.assertRaisesRegex(ValueError, 'custom build script'):
            self.check()


if __name__ == '__main__':
    unittest.main()
