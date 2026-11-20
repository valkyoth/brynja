#!/usr/bin/env python3
"""Bookkeeping regressions, not fault-model or executable qualification."""
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "fault_sites", Path(__file__).with_name("check-aes-fault-sites.py"))
S = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(S)


class FaultSiteInventory(unittest.TestCase):
    def setUp(self):
        self.data = S.load(S.ROOT / S.INVENTORY)

    def reject(self, data):
        with self.assertRaises(ValueError):
            S.validate(data)

    def test_repository_candidates_are_open_not_qualified(self):
        count, bypasses = S.validate(self.data)
        self.assertEqual(count, len(self.data["sites"]))
        self.assertGreater(bypasses, 0)
        self.assertEqual(self.data["artifact_mappings"], [])

    def test_claims_cannot_be_promoted_by_changing_status(self):
        for name, value in [("status", "complete"), ("qualification", "qualified"),
                            ("artifact_mappings", [{"sha256": "0" * 64}]),
                            ("schema", True)]:
            with self.subTest(name=name):
                data = deepcopy(self.data)
                data[name] = value
                self.reject(data)
        for location in (self.data["sites"][0], self.data["dc1"]):
            location["status"] = "passed"
            self.reject(self.data)
            location["status"] = "open"

    def test_unknown_fields_and_classes_are_not_ignored(self):
        for location in (self.data, self.data["sites"][0], self.data["dc1"],
                         self.data["sites"][0]["source"]):
            location["qualified"] = True
            self.reject(self.data)
            del location["qualified"]
        self.data["sites"][0]["classes"].append("D99")
        self.reject(self.data)

    def test_duplicate_ids_and_duplicate_classes_are_rejected(self):
        self.data["sites"].append(deepcopy(self.data["sites"][0]))
        self.reject(self.data)
        self.data["sites"].pop()
        self.data["sites"][0]["classes"] *= 2
        self.reject(self.data)

    def test_scope_cannot_silently_lose_width_path_or_owner(self):
        for field in ("widths", "paths", "owners"):
            data = deepcopy(self.data)
            data["scope"][field].pop()
            self.reject(data)

    def test_model_class_and_dc1_coverage_cannot_disappear(self):
        for model in S.CLASSES:
            data = deepcopy(self.data)
            data["sites"] = [s for s in data["sites"] if model not in s["classes"]]
            self.reject(data)
        self.data["dc1"]["data_classes"].pop()
        self.reject(self.data)

    def test_dc1_bypasses_must_resolve_to_every_declared_c1_region(self):
        for replacement in ([], ["nonexistent"], [self.data["sites"][0]["id"]]):
            data = deepcopy(self.data)
            data["dc1"]["bypass_sites"] = replacement
            self.reject(data)
        self.data["dc1"]["bypass_sites"].pop()
        self.reject(self.data)

    def test_source_anchors_are_unique_and_present(self):
        for anchor in ("", "missing-fault-source-anchor", "\n"):
            self.data["sites"][0]["source"]["anchor"] = anchor
            self.reject(self.data)

    def test_mutations_outcomes_references_and_remaining_work_required(self):
        for name, value in [("mutation", "missing"), ("outcome", "missing"),
                            ("remaining", " "), ("evidence_runners", []),
                            ("evidence_runners", ["scripts/aes/missing-runner.py"])]:
            data = deepcopy(self.data)
            data["sites"][0][name] = value
            self.reject(data)

    def test_paths_cannot_escape_checkout_or_follow_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "real").write_text("fixture", encoding="utf-8")
            (root / "link").symlink_to(root / "real")
            (root / "parent").symlink_to(root, target_is_directory=True)
            self.assertEqual(S.file_at(root, "real"), root / "real")
            for name in ("../real", "/real", "./real", "a/../real", "a\\real",
                         "link", "parent/real", "missing", "real/"):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    S.file_at(root, name)

    def test_duplicate_json_fields_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "duplicate.json"
            source.write_text('{"status":"open", "status":"passed"}', encoding="utf-8")
            with self.assertRaises(ValueError):
                S.load(source)

    def test_source_case_populations_and_labels_are_stable_and_unique(self):
        cases = self.data["byte_case_sets"]
        self.assertEqual([c["id"] for c in cases], [
            "capture-copy-bytes", "capture-import-bytes", "capture-owner-paths"])
        self.assertEqual([S.byte_case_count(c) for c in cases], [147312, 147312, 1152])
        self.assertEqual([c["fixture_byte"] for c in cases], [0x42, 0x42, 0x24])
        for case in cases:
            labels = list(S.byte_case_ids(case))
            self.assertEqual(len(labels), case["expected_trials"])
            self.assertEqual(len(set(labels)), len(labels))
            self.assertEqual(labels, list(S.byte_case_ids(case)))
        self.assertEqual(next(S.byte_case_ids(cases[0])),
                         "capture-copy-bytes/aes128/capture-helper/copy/first/byte0/xor-1")
        self.assertEqual(list(S.byte_case_ids(cases[2]))[-1],
                         "capture-owner-paths/aes256/operation-local/decrypt-secret/second/byte15/replace-36")
        # The manifest records exactly the four families traversed by the Rust
        # source fixtures. Identical resulting bytes must not deduplicate cases.
        for case in cases[:2]:
            self.assertEqual(case["mutations"], [
                {"op": "xor", "first": 1, "last": 255},
                {"op": "replace", "first": 0, "last": 255},
                {"op": "and", "first": 0, "last": 255},
                {"op": "or", "first": 0, "last": 255}])

    def test_byte_cases_reject_duplicate_ids_and_unmapped_regions(self):
        self.data["byte_case_sets"].append(deepcopy(self.data["byte_case_sets"][0]))
        self.reject(self.data)
        self.data["byte_case_sets"].pop()
        for name, value in [("sites", ["missing"]), ("status", "qualified"),
                            ("expected_trials", 0), ("position_bound", True),
                            ("replicas", ["first"]), ("width_bytes", [16]),
                            ("owners", ["unknown"]), ("paths", ["encrypt/public"]),
                            ("fixture_byte", 256), ("fixture_byte", False)]:
            data = deepcopy(self.data)
            data["byte_case_sets"][0][name] = value
            self.reject(data)

    def test_byte_mutations_reject_invalid_ranges_and_duplicate_families(self):
        for op, first, last in [("xor", 0, 255), ("xor", -1, 255),
                                ("replace", 0, 256), ("and", 100, 99),
                                ("or", False, 255), ("or", 0, 1.0),
                                ("unknown", 0, 255)]:
            data = deepcopy(self.data)
            data["byte_case_sets"][0]["mutations"] = [{"op": op, "first": first, "last": last}]
            self.reject(data)
        self.data["byte_case_sets"][0]["mutations"] *= 2
        self.reject(self.data)

    def test_byte_case_definition_is_not_silently_shrunk_or_a_pass(self):
        data = deepcopy(self.data)
        data["byte_case_sets"][0]["mutations"][0]["last"] = 254
        self.reject(data)
        data = deepcopy(self.data)
        data["byte_case_sets"][0]["rust_test"]["anchor"] = "missing test"
        self.reject(data)
        data = deepcopy(self.data)
        data["byte_case_sets"][0]["passed"] = True
        self.reject(data)
        self.data["byte_case_sets"] = []
        self.reject(self.data)

    def test_cli_output_cannot_be_confused_with_qualification(self):
        output = io.StringIO()
        with patch("sys.argv", ["check"]), redirect_stdout(output):
            self.assertEqual(S.main(), 0)
        self.assertIn("OPEN", output.getvalue())
        self.assertIn("qualified configurations: 0", output.getvalue())
        self.assertIn("No experiments executed", output.getvalue())
        output, errors = io.StringIO(), io.StringIO()
        with patch("sys.argv", ["check"]), patch.object(S, "load", side_effect=ValueError("private detail")), \
                redirect_stdout(output), redirect_stderr(errors):
            self.assertEqual(S.main(), 2)
        self.assertEqual(output.getvalue(), "")
        self.assertNotIn("private detail", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
