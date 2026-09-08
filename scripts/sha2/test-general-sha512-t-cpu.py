#!/usr/bin/env python3
"""Cheap evidence/feature-boundary regressions; forced execution is local QEMU."""
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import general_sha512_t_cpu as cpu

spec = importlib.util.spec_from_file_location("capture_general", Path(__file__).with_name("capture-general-sha512-t-native.py"))
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)


class CpuTests(unittest.TestCase):
    def test_real_feature_and_consuming_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            prefix = '[workspace]\n[package]\nname="cpu-boundary"\nversion="0.0.0"\nedition="2024"\n[dependencies]\n'
            deps = 'brynja-hash-sha2={path="' + str(cpu.ROOT / "crates/brynja-hash-sha2") + '",features=FEATURES}\n'
            code = 'use brynja_hash_sha2::*;\n'
            valid = 'pub fn api(s: Sha512T, b: &Sha512BackendSession) { let _ = s.finalize_with_backend(b); }'
            command = ["cargo", "check", "--offline", "--manifest-path", str(root / "Cargo.toml")]
            cases = (
                ('["general-sha512-t","cpu"]', valid, None),
                ('["general-sha512-t"]', 'pub use brynja_hash_sha2::sha512_t_with_backend;', "E0432"),
                ('["cpu"]', 'pub use brynja_hash_sha2::sha512_t_with_backend;', "E0432"),
                ('["general-sha512-t","cpu"]', 'pub fn f(s: Sha512T, b: &Sha512BackendSession, i: BitString) { let _=s.finalize_bits_with_backend(i,b); let _=s.finalize_with_backend(b); }', "E0382"),
                ('["general-sha512-t","cpu"]', 'pub fn f(mut s: HardenedSha512T, b: &Sha512BackendSession) { let _=s.update_with_backend(b"secret",b); }', "E0599"),
            )
            for features, body, expected in cases:
                (root / "Cargo.toml").write_text(prefix + deps.replace("FEATURES", features))
                (root / "src/lib.rs").write_text(code + body)
                status, output = cpu.execute(command)
                if expected is None:
                    self.assertEqual(status, 0, output)
                else:
                    self.assertNotEqual(status, 0)
                    self.assertIn(expected, output)

    def test_transcript_requires_complete_exact_non_admitting_output(self):
        header = "General SHA-512/t CPU acceptance: PASS; parameters=510; cases=4590; backend=aarch64-sha512"
        rows = [f"t={t} bytes=16384 operations=32 accelerated_ns=42" for t in (1, 9, 224, 256, 511)]
        good = "\n".join([header, *rows, cpu.FOOTER])
        self.assertEqual(cpu.parse(good, "aarch64-sha512"), good)
        for bad in ("", good + "\n" + rows[0], good.replace(rows[1], rows[0]),
                    good.replace("4590", "4589"), good.replace("=42", "=0"),
                    good.replace("=42", "=1000000000000000"), good.replace("aarch64-sha512", "portable"),
                    good.replace("unadmitted", "admitted"), good.replace("false", "true"),
                    good.replace("hardened=portable-only", "hardened=accelerated")):
            with self.assertRaises(ValueError):
                cpu.parse(bad, "aarch64-sha512")

    def test_native_lane_fails_closed(self):
        with patch.object(capture.platform, "machine", return_value="x86_64"):
            for lane in capture.LANES:
                with self.assertRaises(ValueError):
                    capture.host(lane)
        with patch.object(capture.platform, "machine", return_value="arm64"), patch.object(capture.platform, "system", return_value="Darwin"):
            with patch.object(capture, "run", side_effect=lambda c: "Apple M2" if "machdep.cpu.brand_string" in c else "1"):
                self.assertEqual(capture.host("apple-m2-aarch64")[0], "aarch64-apple-darwin")
            with patch.object(capture, "run", side_effect=lambda c: "Apple M2" if "machdep.cpu.brand_string" in c else "0"):
                with self.assertRaises(ValueError):
                    capture.host("apple-m2-aarch64")

    def test_output_never_overwrites_or_follows_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "result.json"
            capture.destination(path)
            path.touch()
            with self.assertRaises(ValueError):
                capture.destination(path)
            link = root / "link"
            try:
                link.symlink_to(root, target_is_directory=True)
            except OSError:
                self.skipTest("symlink creation unavailable")
            with self.assertRaises(ValueError):
                capture.destination(link / "absent.json")

    def test_ordinary_build_and_arguments_reject(self):
        command = ["cargo", "run", "--locked", "--offline", "--manifest-path", cpu.FIXTURE]
        with tempfile.TemporaryDirectory() as directory:
            env = cpu.environment(directory, "", "x86_64-unknown-linux-gnu")
            code, output = cpu.execute(command, env=env)
            self.assertNotEqual(code, 0)
            self.assertIn("required SHA-512 CPU candidate unavailable; no fallback", output)
            code, output = cpu.execute(command + ["--", "--invalid"], env=env)
            self.assertNotEqual(code, 0)
            self.assertIn("expected no arguments or --quarantine", output)


if __name__ == "__main__":
    unittest.main()
