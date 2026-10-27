#!/usr/bin/env python3
"""Regressions for publication content, independent of crypto qualification."""
from pathlib import Path
import unittest

import package_contents as contents


class ContentsTests(unittest.TestCase):
    def setUp(self):
        self.package = {"name": "brynja-core", "include": contents.SOURCE_INCLUDE.copy()}
        self.members = sorted(contents.REQUIRED | {"Cargo.lock", "Cargo.toml.orig",
            ".cargo_vcs_info.json", "src/nested/module.rs", "src/unit_tests.rs"})

    def test_metadata_and_nested_source_are_retained(self):
        contents.validate(self.package, self.members, ["src/nested/module.rs", "src/unit_tests.rs"])

    def test_each_required_file_is_required(self):
        for name in contents.REQUIRED:
            with self.subTest(name=name), self.assertRaises(ValueError):
                contents.validate(self.package, [p for p in self.members if p != name])

    def test_repository_material_rejected_for_all_crates(self):
        for name in contents.REPOSITORY_ONLY:
            for package in (self.package, {"name": "not-yet-migrated"}):
                with self.subTest(name=name, package=package), self.assertRaises(ValueError):
                    contents.validate(package, [*self.members, f"{name}/capture.json"])

    def test_fixtures_and_build_inputs_cannot_sneak_into_lean_archives(self):
        for name in ("tests/vector.rs", "benches/bench.rs", "examples/demo.rs",
                     "PENTEST.md", "capture.json", "src/observations.json", "build.rs"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                contents.validate(self.package, [*self.members, name])

    def test_source_removal_rejected(self):
        with self.assertRaisesRegex(ValueError, "Rust source missing"):
            contents.validate(self.package, self.members, ["src/missing.rs"])

    def test_ambiguous_names_rejected(self):
        for name in ("../src/x.rs", "/src/x.rs", "src//x.rs", "src/./x.rs", "src\\x.rs", ""):
            with self.subTest(name=name), self.assertRaises(ValueError):
                contents.validate(self.package, [*self.members, name])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            contents.validate(self.package, [*self.members, self.members[0]])

    def test_manifest_restriction_cannot_be_removed(self):
        for change in ({"include": []}, {"include": ["**"]}, {"exclude": ["src/nested"]}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                contents.validate({**self.package, **change}, self.members)

    def test_real_migrated_manifests(self):
        root = Path(__file__).resolve().parents[2]
        for name in contents.MIGRATED:
            manifest = root / "crates" / name / "Cargo.toml"
            sources = [p.relative_to(manifest.parent).as_posix()
                       for p in (manifest.parent / "src").rglob("*.rs")]
            contents.check(manifest, sorted(contents.REQUIRED | set(sources)))

    def test_unpublished_fixture_support_is_not_trimmed(self):
        contents.validate({"name": "brynja-test-support", "publish": False}, [*self.members, "tests/helper.rs"])

    def test_new_publishable_packages_cannot_restore_test_payloads(self):
        for declaration in ({}, {"publish": ["crates-io"]}):
            with self.subTest(declaration=declaration), self.assertRaisesRegex(ValueError, "standalone tests"):
                contents.validate({"name": "future-crate", **declaration}, [*self.members, "tests/vector.txt"])


if __name__ == "__main__":
    unittest.main()
