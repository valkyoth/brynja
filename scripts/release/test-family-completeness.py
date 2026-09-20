#!/usr/bin/env python3
"""Fast synthetic review mutations; no crypto builds, network or gate execution."""

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import family_completeness as model


class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="brynja-family-review-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "docs").mkdir()
        (self.root / "docs/RELEASE_PLAN.md").write_text(
            "### v0.25.0 - HMAC\nImplementation\n"
            "### v0.25.1 - Compatibility\nLegacy\n"
            "### v0.25.2 - Acceptance\nClosure\n"
            "### v0.26.0 - Next family\nOther\n", encoding="utf-8")
        (self.root / "evidence.md").write_text("Synthetic test evidence, not a real review.", encoding="utf-8")
        self.plans = model.roadmap(self.root)
        self.expected = model.template("0.25.0", "0.25.2", {"sha256": "synthetic", "files": 1}, self.plans)
        self.record = copy.deepcopy(self.expected)
        self.record.update(reviewer="test fixture", scope="synthetic profiles only")
        for row in self.record["decisions"].values():
            row.update(status="reviewed", reason="Synthetic proof for validation tests only.",
                       evidence={"evidence.md": model.digest((self.root / "evidence.md").read_bytes())})

    def audit(self):
        # The review itself must never execute builds/tests/network operations.
        with patch.object(model.subprocess, "run", side_effect=AssertionError("unexpected execution")):
            return model.audit(self.root, self.record, self.expected, self.plans)

    def test_complete_record_is_not_security_claim(self):
        result = self.audit()
        self.assertEqual(result["result"], "REVIEW_RECORDED")
        self.assertIn("not security certification", result["limitations"])

    def test_no_review_cannot_be_green(self):
        self.record = copy.deepcopy(self.expected)
        self.assertEqual(len(self.audit()["issues"]), len(model.DIMENSIONS) + 1)

    def test_every_dimension_is_required(self):
        for key in model.DIMENSIONS:
            with self.subTest(key=key):
                old = self.record["decisions"].pop(key)
                with self.assertRaises(ValueError):
                    self.audit()
                self.record["decisions"][key] = old

    def test_no_status_can_hide_missing_evidence(self):
        for state in ("reviewed", "inherited", "not-applicable"):
            self.record["decisions"]["kernel-registers"].update(status=state, evidence={})
            self.assertEqual(self.audit()["result"], "FOLLOW_UP_REQUIRED")

    def test_each_binding_rejects_staleness(self):
        for key in ("version", "closing_version", "implementation", "roadmap"):
            with self.subTest(key=key):
                old = self.record[key]
                self.record[key] = None
                with self.assertRaises(ValueError):
                    self.audit()
                self.record[key] = old

    def test_evidence_tamper_missing_and_escape(self):
        row = self.record["decisions"]["kernel-registers"]
        for path, sha in (("evidence.md", "wrong"), ("absent", "a"), ("../escape", "a"), ("/tmp/escape", "a")):
            row["evidence"] = {path: sha}
            with self.assertRaises(ValueError):
                self.audit()

    def test_symlink_rejected(self):
        link = self.root / "link"
        try:
            link.symlink_to(self.root / "evidence.md")
        except OSError:
            self.skipTest("symlinks unavailable")
        self.record["decisions"]["kernel-registers"]["evidence"] = {"link": model.digest(link.read_bytes())}
        with self.assertRaises(ValueError):
            self.audit()

    def test_follow_up_does_not_claim_implementation(self):
        row = self.record["decisions"]["batch-simd"]
        row.update(status="planned", follow_up="0.25.1",
                   evidence={"docs/RELEASE_PLAN.md": model.digest((self.root / "docs/RELEASE_PLAN.md").read_bytes())})
        self.assertIn("PLANNED, NOT IMPLEMENTED", self.audit()["issues"][0])
        for version in ("0.25.0", "0.26.0", "0.25.99"):
            row["follow_up"] = version
            with self.assertRaises(ValueError):
                self.audit()

    def test_missing_milestone_is_actionable(self):
        self.record["decisions"]["batch-simd"].update(status="planned", follow_up=None)
        self.assertIn("ADD/SELECT A NUMBERED MILESTONE", self.audit()["issues"][0])

    def test_planned_milestone_needs_reviewed_plan(self):
        self.record["decisions"]["batch-simd"].update(status="planned", follow_up="0.25.1")
        with self.assertRaises(ValueError):
            self.audit()

    def test_unknown_fields_and_states_rejected(self):
        row = self.record["decisions"]["batch-simd"]
        row["status"] = "secure"
        with self.assertRaises(ValueError):
            self.audit()
        row["status"] = "reviewed"
        row["waiver"] = True
        with self.assertRaises(ValueError):
            self.audit()

    def test_blank_reason_and_reviewer_remain_open(self):
        self.record["decisions"]["batch-simd"]["reason"] = " "
        self.record["reviewer"] = ""
        self.assertEqual(len(self.audit()["issues"]), 2)

    def test_current_closure_cannot_defer_work(self):
        self.expected = model.template("0.25.2", "0.25.2", self.expected["implementation"], self.plans)
        self.record.update({key: self.expected[key] for key in ("version", "closing_version", "roadmap")})
        self.record["decisions"]["batch-simd"].update(status="planned", follow_up="0.26.0")
        with self.assertRaises(ValueError):
            self.audit()

    def test_unknown_dimension_and_disguised_deferral(self):
        self.record["decisions"]["new-unreviewed-area"] = {}
        with self.assertRaises(ValueError):
            self.audit()
        del self.record["decisions"]["new-unreviewed-area"]
        self.record["decisions"]["batch-simd"]["follow_up"] = "0.25.1"
        with self.assertRaises(ValueError):
            self.audit()

    def test_snapshot_tracks_dirty_untracked_deleted_shared_code_not_docs(self):
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        source = self.root / "crates/example/src"
        source.mkdir(parents=True)
        rust = source / "lib.rs"
        rust.write_text("pub fn example() {}", encoding="utf-8")
        (self.root / "Cargo.toml").write_text("[workspace]", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=self.root, check=True)
        before = model.implementation_snapshot(self.root)
        (self.root / "evidence.md").write_text("documentation only", encoding="utf-8")
        self.assertEqual(before, model.implementation_snapshot(self.root))
        rust.write_text("pub fn different() {}", encoding="utf-8")
        self.assertNotEqual(before, model.implementation_snapshot(self.root))
        rust.write_text("pub fn example() {}", encoding="utf-8")
        extra = source / "new.rs"
        extra.write_text("// untracked implementation", encoding="utf-8")
        self.assertNotEqual(before, model.implementation_snapshot(self.root))
        extra.unlink()
        shared = self.root / "crates/shared"
        shared.mkdir()
        (shared / "Cargo.toml").write_text('[package]\nname = "shared"', encoding="utf-8")
        with_shared = model.implementation_snapshot(self.root)
        self.assertNotEqual(before, with_shared)
        (shared / "Cargo.toml").write_text('[package]\nname = "changed"', encoding="utf-8")
        self.assertNotEqual(with_shared, model.implementation_snapshot(self.root))
        rust.unlink()
        # No Rust left is invalid rather than silently accepting an empty scope.
        with self.assertRaises(ValueError):
            model.implementation_snapshot(self.root)

    def test_invalid_closure_and_duplicate_plan(self):
        for version, closing in (("missing", "0.25.2"), ("0.25.2", "0.25.0"), ("0.25.0", "0.26.0")):
            with self.assertRaises(ValueError):
                model.template(version, closing, {}, self.plans)
        path = self.root / "docs/RELEASE_PLAN.md"
        path.write_text(path.read_text() + "### v0.25.0 - Duplicate\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            model.roadmap(self.root)

    def test_real_cli_template_report_and_invalid_version(self):
        script = Path(__file__).with_name("check-family-completeness.py")
        command = [sys.executable, str(script), "--version", "0.25.0", "--closing-version", "0.25.2"]
        result = subprocess.run(command + ["--template"], capture_output=True, text=True, check=True)
        generated = json.loads(result.stdout)
        self.assertTrue(all(row["status"] == "needs-review" for row in generated["decisions"].values()))
        result = subprocess.run(command + ["--json"], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 2, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(set(report["available_follow_ups"]), {"0.25.1", "0.25.2"})
        result = subprocess.run(command + ["--version", "0.25.999"], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 1, result.stderr)


if __name__ == "__main__":
    unittest.main()
