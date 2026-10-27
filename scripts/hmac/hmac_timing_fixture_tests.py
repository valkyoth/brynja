"""Compiled correctness controls for the real timing fixture, not timings as tests."""
from pathlib import Path
import shutil
import subprocess

import hmac_verifiers as verifier


class FixtureTests:
    def test_real_compiled_preflight_rejects_vacuous_measurements(self):
        source = verifier.ROOT / "assurance/hmac-timing"
        with verifier.cargo_environment.private_directory(verifier.ROOT) as raw:
            root = Path(raw)
            fixture = root / "fixture"
            fixture.mkdir()
            shutil.copytree(source / "src", fixture / "src")
            shutil.copyfile(source / "Cargo.lock", fixture / "Cargo.lock")
            (fixture / "Cargo.toml").write_text((source / "Cargo.toml").read_text().replace(
                "../../crates/", str(verifier.ROOT / "crates") + "/"))
            env = verifier.environment(root)
            env["RUSTFLAGS"] = "-C target-cpu=generic"
            # No host instruction probes or target features are needed for these
            # portable controls; generic-build accelerated admission must fail.
            build = ["cargo", "+1.99.1", "build", "--release", "--locked", "--offline",
                     "--manifest-path", str(fixture / "Cargo.toml")]
            binary = root / "target/release/brynja-hmac-timing"

            def run(route="portable", family="all"):
                return subprocess.run([str(binary), route, family, "--smoke"], cwd=fixture,
                                      env=env, capture_output=True, text=True, timeout=60)

            verifier.run(build, env, fixture)
            baseline = run()
            self.assertEqual(baseline.returncode, 0, baseline.stderr)
            self.assertEqual(baseline.stdout.splitlines(), ["HMAC_TIMING_SMOKE 12 portable all"])
            for route, family in (("static", "all"), ("other", "all"), ("portable", "other")):
                rejected = run(route, family)
                self.assertNotEqual(rejected.returncode, 0)
                self.assertNotIn("HMAC_TIMING_", rejected.stdout)
            for route in ("static", "linux-compiled", "macos-compiled"):
                rejected = run(route, "sha256")
                self.assertNotEqual(rejected.returncode, 0, "generic build must not select acceleration")
                self.assertNotIn("HMAC_TIMING_", rejected.stdout)
            path = fixture / "src/routes.rs"
            original = path.read_text()
            mutants = (
                ("return leaf_decision(state.verify(black_box(candidate)));",
                 "let _ = (state, candidate); return Ok(false);"),
                ("return leaf_decision(state.verify(black_box(candidate)));",
                 "let _ = (state, candidate); return Ok(true);"),
                ("black_box(checked(state.finalize_tag(out))?.as_bytes());",
                 "let _ = state; out.fill(0);"),
                ("let key = black_box(key);", "let key = black_box(&[0x55; 200][..key.len()]);"),
            )
            for before, after in mutants:
                with self.subTest(mutation=after):
                    self.assertIn(before, original)
                    path.write_text(original.replace(before, after, 1))
                    # Compilation must succeed; a syntax/type error is no rejection proof.
                    verifier.run(build, env, fixture)
                    rejected = run()
                    self.assertNotEqual(rejected.returncode, 0)
                    self.assertRegex(rejected.stderr, "correctness preflight failed|invalid tag accepted")
                    self.assertNotIn("HMAC_TIMING_", rejected.stdout)
                    path.write_text(original)
                    verifier.run(build, env, fixture)
                    self.assertEqual(run().returncode, 0)
            print("HMAC timing fixture: 12 identities; four compiled no-op/key/decision mutants rejected")
