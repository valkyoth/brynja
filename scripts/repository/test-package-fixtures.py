#!/usr/bin/env python3
"""Repository fixtures must not require, modify, or repopulate runtime archives."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import tomllib
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import facade_sha2_execution as sha2
import facade_scoped_sha2 as scoped
import facade_sha3_execution as sha3
import facade_hardened_sha3 as hardened
import facade_kmac_acceptance as kmac
import facade_tuplehash_acceptance as tuplehash
import strict_consumer_sources as strict
import facade_parallelhash_execution as parallelhash
import legacy_execution_package as legacy
import legacy_hardened_package as legacy_hardened
import package_contents

ROOT = Path(__file__).resolve().parents[2]


class FixtureTests(unittest.TestCase):
    def test_lean_build_feature_profiles_are_explicit(self):
        spec = importlib.util.spec_from_file_location('lean_build_profiles',
            Path(__file__).with_name('check-lean-package-builds.py'))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            roots = {}
            for name in package_contents.MIGRATED:
                root = base / name
                root.mkdir()
                (root / 'Cargo.toml').write_text(f'[package]\nname="{name}"\nversion="0.1.0"\n'
                                               '[features]\ndefault=[]\naccelerated=[]\n')
                roots[name] = root
            consumer = base / 'consumer'
            (consumer / 'src').mkdir(parents=True)
            for hosted, all_features in ((True, True), (False, False), (False, True)):
                module.manifest(consumer, roots, hosted, all_features)
                data = tomllib.loads((consumer / 'Cargo.toml').read_text())
                expected = set(roots) - (set() if hosted else package_contents.HOSTED)
                self.assertEqual(set(data['dependencies']), expected)
                for declaration in data['dependencies'].values():
                    self.assertIs(declaration['default-features'], False)
                    self.assertEqual(declaration['features'], ['accelerated', 'default'] if all_features else [])
                self.assertEqual(set(data['patch']['crates-io']), set(roots))

    def test_facade_installers_work_without_archived_fixtures(self):
        cases = (
            (sha2, (False,), ('tests/execution.rs', 'src/vectors/nist-bit-selected.txt')),
            (sha2, (True,), ('tests/execution.rs', 'src/vectors/general-sha512-t-digest.txt')),
            (scoped, (), ('src/vectors/nist-bit-selected.txt',)),
            (sha3, (), ('tests/execution.rs', 'tests/cshake_execution.rs')),
            (hardened, (), ('tests/owned.rs', 'tests/corpus.rs', 'tests/scoped.rs')),
            (kmac, (), ('tests/execution.rs', 'tests/scoped.rs')),
            (tuplehash, (), ('tests/execution.rs', 'tests/scoped_accelerated.rs')),
            (parallelhash, (), ('tests/execution.rs', 'tests/threaded_scoped.rs', 'tests/scoped_accelerated.rs')),
        )
        for module, extra, expected in cases:
            for facade in ('brynja', 'brynja-crypto'):
                with self.subTest(module=module.__name__, extra=extra, facade=facade), \
                        tempfile.TemporaryDirectory() as directory:
                    base = Path(directory)
                    consumer = base / 'consumer'
                    (consumer / 'src').mkdir(parents=True)
                    (consumer / 'tests').mkdir()
                    # No archive files at all: requesting test inputs through
                    # this map is a regression. The real runtime manifest builder
                    # is tested separately; no compiler is mocked as succeeding.
                    roots = {}
                    def manifest(_consumer, actual, _package, *args, **kwargs):
                        self.assertIs(actual, roots)
                    api = SimpleNamespace(manifest=manifest, source=lambda *args: None)
                    module.install(api, consumer, roots, facade, *extra)
                    for name in expected:
                        self.assertTrue((consumer / name).read_bytes(), name)
                    self.assertEqual(set(base.iterdir()), {consumer})
                    for vector in (consumer / 'src/vectors').glob('*.txt'):
                        source = ROOT / 'crates/brynja-hash-sha2/tests/vectors' / vector.name
                        if module in (sha2, scoped):
                            self.assertEqual(vector.read_bytes(), source.read_bytes())

    def test_strict_consumer_vectors_are_repository_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            consumer = Path(directory)
            (consumer / 'src').mkdir()
            (consumer / 'tests').mkdir()
            strict.install(consumer, {})
            for name in ('nist-bit-selected.txt', 'general-sha512-t-digest.txt'):
                self.assertEqual((consumer / 'src/vectors' / name).read_bytes(),
                    (ROOT / 'crates/brynja-hash-sha2/tests/vectors' / name).read_bytes())

    def test_legacy_installers_work_without_archived_fixtures(self):
        for family in ('sha1', 'md5'):
            for module, filename in ((legacy, 'execution.rs'), (legacy_hardened, 'hardened_execution.rs')):
                with self.subTest(family=family, module=module.__name__), tempfile.TemporaryDirectory() as raw:
                    consumer = Path(raw) / 'consumer'
                    module.install(consumer, {}, family)
                    for output, suffix in (('execution.rs', ''), ('hosted.rs', '-std')):
                        source = ROOT / f'crates/brynja-legacy-{family}{suffix}/tests' / filename
                        self.assertEqual((consumer / 'tests' / output).read_bytes(), source.read_bytes())

    def test_leaf_packagers_keep_tests_outside_extracted_roots(self):
        cases = (
            ('kmac/check-kmac-execution-package.py', 'brynja-mac-kmac', 'shared', 'tests/execution.rs', 'execution.rs'),
            ('tuplehash/check-tuplehash-execution-package.py', 'brynja-hash-tuple', 'shared', 'tests/execution.rs', 'execution.rs'),
            ('sha3/check-keccak-hardened.py', 'brynja-hash-sha3', 'ordinary', 'tests/api.rs', 'hardened_execution.rs'),
        )
        for relative, crate, helper, output, source in cases:
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                spec = importlib.util.spec_from_file_location('lean_fixture_' + crate.replace('-', '_'),
                                                             ROOT / 'scripts' / relative)
                module = importlib.util.module_from_spec(spec)
                # The scripts ordinarily receive their directory through sys.path[0].
                with patch.object(sys, 'path', [str((ROOT / 'scripts' / relative).parent), *sys.path]):
                    spec.loader.exec_module(module)
                    roots = {name: base / 'pristine' / name for name in
                             (crate, 'brynja-crypto-cpu', 'brynja-crypto-cpu-std')}
                    with patch.object(getattr(module, helper), 'package', return_value=(None, roots)):
                        consumer, returned = module.package(base, {})
                self.assertIs(returned, roots)
                self.assertFalse((base / 'pristine').exists())
                self.assertEqual((consumer / output).read_bytes(),
                                 (ROOT / 'crates' / crate / 'tests' / source).read_bytes())


if __name__ == '__main__':
    unittest.main()
