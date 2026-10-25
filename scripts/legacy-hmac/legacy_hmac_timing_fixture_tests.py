"""Compiled no-op/key/decision mutations: never use noisy timings as unit tests."""
from pathlib import Path
import shutil
import subprocess
import unittest

import legacy_hmac_timing_runner as runner


class FixtureTests(unittest.TestCase):
    def test_real_preflight_rejects_vacuous_measurements(self):
        with runner.cargo_environment.private_directory(runner.ROOT) as raw:
            root = Path(raw)
            fixture = root / "fixture"
            fixture.mkdir()
            shutil.copytree(runner.FIXTURE / "src", fixture / "src")
            shutil.copyfile(runner.FIXTURE / "Cargo.lock", fixture / "Cargo.lock")
            (fixture / "Cargo.toml").write_text((runner.FIXTURE / "Cargo.toml").read_text().replace(
                "../../crates/", str(runner.ROOT / "crates") + "/"))
            env = runner.environment(root)
            env["RUSTFLAGS"] = "-C target-cpu=generic"
            build = ["cargo", "+" + runner.TOOLCHAIN, "build", "--release", "--locked", "--offline",
                     "--manifest-path", str(fixture / "Cargo.toml")]
            binary = Path(env["CARGO_TARGET_DIR"]) / "release/brynja-legacy-hmac-timing"

            def run(route, family):
                return subprocess.run([str(binary), route, family, "--smoke"], cwd=fixture,
                                      env=env, capture_output=True, text=True, timeout=60)

            def baseline():
                for family in ("sha1", "md5"):
                    result = run("portable", family)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.splitlines(), [f"LEGACY_HMAC_TIMING_SMOKE portable {family} 1"])

            runner.run(build, env, fixture)
            baseline()
            # NEON is baseline on native AArch64, unlike AVX2 on x86-64.
            missing = ("sha1", "md5") if runner.architecture() == "x86_64" else ("sha1",)
            for route, family in (("unknown", "sha1"), ("portable", "unknown"),
                                  *((route, family) for route in ("static", "linux-compiled", "macos-compiled")
                                    for family in missing)):
                result = run(route, family)
                self.assertNotEqual(result.returncode, 0, "generic build must reject accelerated routes")
                self.assertNotIn("LEGACY_HMAC_TIMING_", result.stdout)
            path = fixture / "src/routes.rs"
            original = path.read_text()
            mutants = (
                ('return leaf_authentication(state.verify(black_box(&candidate[0][..bytes])));',
                 'let _ = (state, candidate); return Ok(false);'),
                ('return leaf_authentication(state.verify(black_box(&candidate[0][..bytes])));',
                 'let _ = (state, candidate); return Ok(true);'),
                ('black_box(checked(state.finalize_tag(&mut out[0][..bytes]))?.as_bytes());',
                 'let _ = state; out[0].fill(0);'),
                ('let key = black_box(key);', 'let key = black_box(&[0x55; 200][..key.len()]);'),
            )
            for before, after in mutants:
                self.assertIn(before, original)
                # Replace all occurrences so the portable path is definitely affected.
                path.write_text(original.replace(before, after))
                runner.run(build, env, fixture)  # Compiler errors are not runtime rejection evidence.
                for family in ("sha1", "md5"):
                    result = run("portable", family)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertRegex(result.stderr, "correctness preflight failed|invalid tag accepted")
                    self.assertNotIn("LEGACY_HMAC_TIMING_", result.stdout)
                path.write_text(original)
                runner.run(build, env, fixture)
                baseline()
            print("Legacy timing: both families reject four compiled no-op/key/decision mutations")
