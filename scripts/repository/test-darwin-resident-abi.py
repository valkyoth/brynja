#!/usr/bin/env python3
"""Focused regressions for the distinct resident profile's OS-only imports."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
import sys
import shutil

import darwin_resident_abi as abi
import first_party_rust_crypto as first
import unsafe_policy as boundary

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('unsafe_tests', Path(__file__).with_name('test-unsafe-policy.py'))
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)
sys.path.insert(0, str(ROOT / 'scripts/cpu'))
import cpu_boundary_policy as cpu
from cpu_boundary_backends import MACOS_RESIDENT_SOURCES, MACOS_RESIDENT_FEATURES
cpu_spec = importlib.util.spec_from_file_location('cpu_tests', ROOT / 'scripts/cpu/test-cpu-boundary.py')
cpu_support = importlib.util.module_from_spec(cpu_spec)
cpu_spec.loader.exec_module(cpu_support)


class DarwinBoundaryTests(unittest.TestCase):
    def test_legacy_private_adapters_match_reviewed_backend(self):
        abi.validate_private_copies(ROOT)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in set(abi.PRIVATE_COPIES) | set(abi.PRIVATE_COPIES.values()):
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, target)
            abi.validate_private_copies(root)
            for relative in abi.PRIVATE_COPIES:
                path = root / relative
                original = path.read_text()
                path.write_text(original + '\n// unreviewed divergence\n')
                with self.assertRaisesRegex(ValueError, 'private Darwin adapter diverged'):
                    abi.validate_private_copies(root)
                path.write_text(original)

    def test_feature_stays_opt_in_and_sources_stay_development_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cpu_support.fixture(root)
            cpu.validate(root)
            manifest = root / 'crates/brynja-crypto-cpu-std/Cargo.toml'
            original = manifest.read_text()
            manifest.write_text(original.replace('default = []', 'default = ["macos-resident"]'))
            with self.assertRaises(cpu.CpuBoundaryPolicyError):
                cpu.validate_packages(root)
            manifest.write_text(original)
            for feature in MACOS_RESIDENT_FEATURES:
                manifest.write_text(original.replace('default = []', f'default = ["{feature}"]'))
                with self.assertRaises(cpu.CpuBoundaryPolicyError):
                    cpu.validate_packages(root)
            for family, dependency in (('kmac', 'brynja-mac-kmac'), ('tuplehash', 'brynja-hash-tuple')):
                for changed in (
                    original.replace(f'"macos-resident-{family}", "{dependency}/hardened-execution"',
                                     f'"macos-resident-{family}"'),
                    original.replace(f'"macos-resident", "dep:{dependency}"',
                                     f'"strict-{family}", "dep:{dependency}"'),
                ):
                    self.assertNotEqual(changed, original)
                    manifest.write_text(changed)
                    with self.assertRaises(cpu.CpuBoundaryPolicyError):
                        cpu.validate_packages(root)
            manifest.write_text(original)
            self.assertEqual(len(MACOS_RESIDENT_SOURCES), 44)
            for relative in MACOS_RESIDENT_SOURCES:
                path = manifest.parent / relative
                original = path.read_text()
                path.write_text(original + '\n// unreviewed edit\n')
                with self.assertRaises(cpu.CpuBoundaryPolicyError):
                    cpu.validate(root)
                path.write_text(original)

    def test_exact_os_imports_reject_extra_import_duplicate_and_relocation(self):
        for relative, signatures in abi.OS_ABIS.items():
            with self.subTest(source=str(relative)), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path = root / relative
                path.parent.mkdir(parents=True)
                crate = relative.parts[1]
                (root / 'crates' / crate / 'Cargo.toml').write_text(
                    f'[package]\nname="{crate}"\nversion="0.1.1"\n')
                original = (ROOT / relative).read_text()
                path.write_text(original)
                first.validate(root)
                for changed in (
                    original + '\nunsafe extern "C" { fn foreign_crypto(); }\n',
                    original + '\n' + signatures[0],
                    original.replace(signatures[0], signatures[0].replace('fn ', 'fn changed_', 1)),
                ):
                    path.write_text(changed)
                    with self.assertRaises(first.FirstPartyRustCryptoError):
                        first.validate(root)
                path.write_text(original)
                path.with_name('unreviewed.rs').write_text(original)
                with self.assertRaises(first.FirstPartyRustCryptoError):
                    first.validate(root)

    def test_all_native_boundaries_are_source_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            support.fixture(root)
            boundary.validate(root)
            for relative in abi.UNSAFE_MODULES:
                path = root / relative
                original = path.read_text()
                path.write_text(original + '\n// unreviewed edit\n')
                with self.assertRaises(boundary.UnsafePolicyError):
                    boundary.validate(root)
                path.write_text(original)


if __name__ == '__main__':
    unittest.main()
