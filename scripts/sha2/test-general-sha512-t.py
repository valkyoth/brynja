#!/usr/bin/env python3
"""Review drift, gate, feature and real downstream compile regressions."""
import subprocess
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import general_sha512_t_policy as policy


class GeneralTests(unittest.TestCase):
    def test_compiled_algorithm_mutants_are_rejected(self):
        # Each mutant must compile, execute, and fail a real assertion. A
        # compiler/dependency failure is not accepted as mutation detection.
        with tempfile.TemporaryDirectory(prefix="brynja-general-mutants-") as directory:
            root = Path(directory)
            crate = policy.ROOT / "crates/brynja-hash-sha2"
            for folder in ("src", "tests"):
                shutil.copytree(crate / folder, root / folder)
            dependencies = "\n".join(
                name + ' = { path = "' + str(policy.ROOT / "crates" / name) + '" }'
                for name in ("brynja-core", "brynja-hash-core"))
            (root / "Cargo.toml").write_text(
                '[workspace]\n[package]\nname="brynja-hash-sha2"\nversion="0.1.0"\nedition="2024"\n'
                '[features]\ndefault=[]\ngeneral-sha512-t=[]\ncpu=[]\n[dependencies]\n' + dependencies + '\n', encoding="utf-8")
            command = ["cargo", "test", "--offline", "--manifest-path", str(root / "Cargo.toml"),
                       "--features", "general-sha512-t", "--lib", "--test", "general"]
            subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
            mutants = (
                ("parameter.rs", "bits == 0 || bits >= 512 || bits == 384", "bits == 0 || bits >= 512"),
                ("parameter.rs", "self.0.div_ceil(8) as usize", "(self.0 / 8) as usize"),
                ("iv.rs", 'b"SHA-512/"', 'b"SHA-511/"'),
                ("iv.rs", "0xa5a5_a5a5_a5a5_a5a5", "0x5a5a_5a5a_5a5a_5a5a"),
                ("iv.rs", "*marker = 0x80;", "*marker = 0;"),
                ("digest.rs", ".is_some_and(|last| last & !parameter.last_byte_mask() != 0)", ".is_some_and(|_| false)"),
                ("digest.rs", "let mut storage = [0_u8; 64];", "let mut storage = [1_u8; 64];"),
                ("digest.rs", "#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]", "#[derive(Clone, Copy, Debug, Eq, Hash)]"),
            )
            for name, before, after in mutants:
                path = root / "src/general" / name
                original = path.read_text()
                self.assertEqual(original.count(before), 1)
                try:
                    mutated = original.replace(before, after)
                    if before == "#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]":
                        mutated += '\nimpl PartialEq for Sha512TDigest { fn eq(&self, other: &Self) -> bool { self.storage == other.storage } }\n'
                    path.write_text(mutated, encoding="utf-8")
                    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
                    self.assertNotEqual(result.returncode, 0, name)
                    self.assertIn(b"test result: FAILED", result.stdout, result.stderr.decode())
                finally:
                    path.write_text(original, encoding="utf-8")

    def test_each_reviewed_file_is_bound(self):
        policy.validate()
        original = policy.contract.read
        for target in policy.BOUND:
            def changed(root, name, selected=target):
                value = original(root, name)
                return value + b"\n// changed\n" if name == selected else value
            with self.subTest(target=target), patch.object(policy.contract, "read", changed), self.assertRaises(ValueError):
                policy.validate()

    def test_feature_claim_and_coverage_mutations(self):
        original = policy.read
        cases = [
            ("crates/brynja-hash-sha2/Cargo.toml", "default = []", 'default = ["general-sha512-t"]'),
            ("crates/brynja-hash-sha2/Cargo.toml", "general-sha512-t = []", 'general-sha512-t = ["cpu"]'),
            ("crates/brynja-hash-sha2/src/lib.rs", '#[cfg(feature = "general-sha512-t")]', ""),
            ("crates/brynja-crypto/src/lib.rs", "#![no_std]", "#![no_std]\n// Sha512TBits"),
        ]
        for path in ("scripts/zeroization/check-zeroization-miri.sh", "scripts/zeroization/check-zeroization-sanitizer.sh"):
            cases.append((path, "--features general-sha512-t --test general", "--test sha256"))
        for script in ("check-general-sha512-t.py", "test-general-sha512-t.py"):
            cases.append(("scripts/checks.sh", f"python3 scripts/sha2/{script}", "# omitted"))
        for target, before, after in cases:
            def changed(root, name, selected=target, old=before, new=after):
                value = original(root, name)
                if name == selected:
                    self.assertIn(old, value)
                    return value.replace(old, new)
                return value
            with self.subTest(target=target), patch.object(policy, "read", changed), self.assertRaises(ValueError):
                policy.validate()

    def test_real_default_off_and_identity_compile_failures(self):
        with tempfile.TemporaryDirectory(prefix="brynja-general-compile-") as directory:
            root = Path(directory)
            (root / "src").mkdir()
            dep = policy.ROOT / "crates/brynja-hash-sha2"
            manifest = ('[workspace]\n[package]\nname="general-negative"\nversion="0.0.0"\nedition="2024"\n'
                        '[dependencies]\nbrynja-hash-sha2 = { path = "' + str(dep) + '", default-features = false FEATURES }\n')
            cases = (
                (False, "use brynja_hash_sha2::Sha512TBits;", "E0432"),
                (True, "const BAD: brynja_hash_sha2::Sha512TBits = brynja_hash_sha2::Sha512TBits(384);", "E0423"),
                (True, "fn convert(d: brynja_hash_sha2::Sha512TDigest) -> brynja_hash_sha2::Sha512_224Digest { d }", "E0308"),
            )
            # Known-valid control prevents accepting a broken compiler/dependency.
            (root / "Cargo.toml").write_text(manifest.replace(" FEATURES", ', features = ["general-sha512-t"]'), encoding="utf-8")
            (root / "src/lib.rs").write_text("pub use brynja_hash_sha2::Sha512TBits;", encoding="utf-8")
            base = ["cargo", "check", "--offline", "--manifest-path", str(root / "Cargo.toml")]
            subprocess.run(base, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
            for enabled, code, expected in cases:
                feature = ', features = ["general-sha512-t"]' if enabled else ""
                (root / "Cargo.toml").write_text(manifest.replace(" FEATURES", feature), encoding="utf-8")
                (root / "src/lib.rs").write_text(code, encoding="utf-8")
                result = subprocess.run(base, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected.encode(), result.stderr)


if __name__ == "__main__":
    unittest.main()
