#!/usr/bin/env python3
"""Reject package evidence bloat without losing runtime/build inputs."""
import importlib.util
from pathlib import Path
import re
import subprocess
import tempfile
import tomllib
import unittest
from unittest.mock import patch

from hmac_package import REQUIRED, OPTIONAL, validate_members
from hmac_combined_tests import CombinedTests

spec = importlib.util.spec_from_file_location("hmac_packaged", Path(__file__).with_name("check-hmac-package.py"))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class PackageTests(unittest.TestCase):
    def test_fractional_oracle_has_only_an_extracted_test_dependency(self):
        roots = {name: Path("/private/extracted") / name for name in driver.NAMES}
        manifest = tomllib.loads(driver.consumer_manifest(roots))
        self.assertEqual(manifest["dependencies"], {
            "brynja-mac-hmac": {"version": "=0.1.0", "default-features": False}})
        self.assertEqual(manifest["dev-dependencies"], {
            "brynja-hash-sha2": {"version": "=0.1.0", "default-features": False}})
        self.assertEqual(manifest["patch"]["crates-io"],
                         {name: {"path": str(path)} for name, path in roots.items()})

    def test_general_population_includes_fractional_regression(self):
        source = (driver.ROOT / "crates/brynja-mac-hmac/tests/general.rs").read_text()
        self.assertEqual(set(re.findall(r"#\[test\]\s+fn (\w+)\(", source)), {
            "boundary_lifecycle", "parameter_and_truncation_policy", "named_identity_controls",
            "exact_inner_bit_answers", "fractional_profile_never_rounds_inner_digest_to_bytes",
            "canonical_verification_and_unwind"})
        populations = {"vectors": 7, "lifecycle": 11, "bounded": 13, "bits": 12, "general": 6, "tag_policy": 3}
        for bad in (None, "5 passed; 0 failed; 0 ignored;", "5 passed; 0 failed; 1 ignored;",
                    "6 passed; 1 failed; 0 ignored;", "0 passed; 0 failed; 0 ignored;"):
            calls = []
            def run(command, *_):
                calls.append(command)
                test = command[-1]
                if test == "general" and bad:
                    return "test result: ok. " + bad
                return f"test result: ok. {populations.get(test, 3)} passed; 0 failed; 0 ignored;"
            with patch.object(driver, "run", side_effect=run):
                if bad:
                    with self.assertRaisesRegex(ValueError, "population changed: general"):
                        driver.test_profiles(Path("/consumer"), {})
                else:
                    driver.test_profiles(Path("/consumer"), {})
                    self.assertEqual(len(calls), 14)
                    self.assertEqual(["--release" in c for c in calls if c[-1] == "general"], [False, True])

    def test_readme_population_requires_all_three_examples_in_both_profiles(self):
        readme = (driver.ROOT / "crates/brynja-mac-hmac/README.md").read_text()
        self.assertEqual(readme.count("```rust\n"), 3)
        populations = {"vectors": 7, "lifecycle": 11, "bounded": 13,
                       "bits": 12, "general": 6, "tag_policy": 3}
        rejected = ("", "0 passed; 0 failed; 0 ignored;",
                    "1 passed; 0 failed; 0 ignored;", "2 passed; 0 failed; 0 ignored;",
                    "4 passed; 0 failed; 0 ignored;", "2 passed; 0 failed; 1 ignored;",
                    "3 passed; 1 failed; 0 ignored;", "3 passed; 0 failed; 1 ignored;")
        for release in (False, True):
            for bad in (None, *rejected):
                calls = []
                def run(command, *_):
                    calls.append(command)
                    if command[-1] == "--doc":
                        if bad is not None and ("--release" in command) == release:
                            return "test result: ok. " + bad
                        return "test result: ok. 3 passed; 0 failed; 0 ignored;"
                    return f"test result: ok. {populations[command[-1]]} passed; 0 failed; 0 ignored;"
                with self.subTest(release=release, summary=bad), patch.object(driver, "run", side_effect=run):
                    if bad is not None:
                        with self.assertRaisesRegex(ValueError, "README example population changed"):
                            driver.test_profiles(Path("/consumer"), {})
                    else:
                        driver.test_profiles(Path("/consumer"), {})
                        self.assertEqual(["--release" in c for c in calls if c[-1] == "--doc"], [False, True])

    def test_failed_child_preserves_diagnostics_and_cannot_pass(self):
        for code in (101, 1, -9):
            result = subprocess.CompletedProcess([], code, "test result: ok. 6 passed;", "missing dependency E0432")
            with patch.object(driver.cargo_environment, "check"), \
                    patch.object(driver.subprocess, "run", return_value=result), \
                    self.assertRaisesRegex(RuntimeError, "missing dependency E0432"):
                driver.run(["cargo", "test"], Path("/consumer"), {})

    def test_runtime_archive(self):
        validate_members(REQUIRED)
        validate_members(REQUIRED | OPTIONAL)

    def test_declared_unit_source_is_required_without_repository_overlay(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            leaf = directory / "extracted"
            (leaf / "src/execution").mkdir(parents=True)
            (leaf / "Cargo.toml").write_text('[package]\nname="brynja-mac-hmac"\nversion="0.1.0"\n')
            roots = {"brynja-mac-hmac": leaf, "dependency": directory / "dependency"}
            with self.assertRaisesRegex(ValueError, "declared unit-test module"):
                driver.hmac_execution_acceptance.lifecycle_fixture(roots, directory)
            self.assertFalse((directory / "execution-faults").exists())
            payload = b"// Archive unit source, distinct from repository source.\r\n"
            (leaf / "src/execution/tests.rs").write_bytes(payload)
            with patch.object(driver.hmac_execution_acceptance.shutil, "copyfile",
                              wraps=driver.hmac_execution_acceptance.shutil.copyfile) as copy:
                fixture = driver.hmac_execution_acceptance.lifecycle_fixture(roots, directory)
                self.assertTrue(copy.call_args_list)
                self.assertTrue(all(Path(call.args[0]).is_relative_to(leaf) for call in copy.call_args_list))
            self.assertEqual((fixture / "src/execution/tests.rs").read_bytes(), payload)
            manifest = tomllib.loads((fixture / "Cargo.toml").read_text())
            self.assertEqual(manifest["patch"]["crates-io"], {"dependency": {"path": str(roots["dependency"])}})

    def test_required_inputs(self):
        for name in REQUIRED:
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate_members(REQUIRED - {name})

    def test_evidence_and_standalone_tests_stay_in_git(self):
        for name in ("evidence.json", "assurance/result.json", "native-capture.tar.gz",
                     "tests/vectors.rs", "src/adapter_tests.rs",
                     "src/execution/native_adapter_tests.rs", "assurance/hmac-timing/src/main.rs",
                     "scripts/check.py", "security/review.toml",
                     "src/tests/huge-fixture.json", "src/unreviewed.rs", "target/output",
                     "../outside", "/absolute", "src/../README.md", "src\\lib.rs"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate_members([*REQUIRED, name])

    def test_duplicate(self):
        with self.assertRaises(ValueError):
            validate_members([*REQUIRED, "src/lib.rs"])


if __name__ == "__main__":
    unittest.main()
