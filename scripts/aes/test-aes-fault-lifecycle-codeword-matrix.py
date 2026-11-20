#!/usr/bin/env python3
"""Fail-closed bookkeeping for the pinned lifecycle codeword matrix."""
import importlib.util
import json
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "lifecycle_matrix", Path(__file__).with_name(
        "check-aes-fault-lifecycle-codeword-matrix.py"))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class LifecycleMatrixTests(unittest.TestCase):
    def test_pinned_artifacts_cover_both_toolchains(self):
        self.assertEqual(len(M.PINNED), 2)
        self.assertEqual(set(M.PINNED), set(M.L.DEST.SHAPES))
        self.assertEqual(set(M.PINNED), set(M.L.RESULT_MAP.SHAPES))
        self.assertEqual(set(M.PINNED), set(M.L.CALLER.SHAPES))

    def test_unknown_artifact_rejected_before_debugger(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "unreviewed.elf"
            path.write_bytes(b"\x7fELF\x02\x01" + b"\x00" * 12 + b"\x3e\x00")
            with patch.object(M.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "unreviewed lifecycle artifact"):
                    M.observe(path, [0], [0])
                run.assert_not_called()

    def test_empty_duplicate_or_out_of_range_dimensions_rejected(self):
        digest = next(iter(M.PINNED))
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "pinned.elf"
            path.write_bytes(b"\x7fELF\x02\x01" + b"\x00" * 12 + b"\x3e\x00")
            # Validate dimensions independently after the digest gate.
            with patch.object(M.hashlib, "sha256") as digest_function, \
                 patch.object(M.subprocess, "run") as run:
                digest_function.return_value.hexdigest.return_value = digest
                for positions, bits in (([], [0]), ([0], []), ([0, 0], [0]),
                                        ([16], [0]), ([0], [8]), ([0], [0, 0])):
                    with self.assertRaisesRegex(ValueError, "invalid byte/bit matrix"):
                        M.observe(path, positions, bits)
                run.assert_not_called()

    def test_record_has_complete_single_bit_cartesian_population(self):
        record = json.loads((Path(__file__).resolve().parents[2] /
                             "assurance/aes-fault-lifecycle-codeword-matrix-observations.json")
                            .read_text(encoding="utf-8"))
        scope = record["scope"]
        expected = (len(scope["widths"]) * len(scope["owners"]) *
                    len(scope["paths"]) * len(scope["byte_positions"]) *
                    len(scope["bit_positions"]))
        self.assertEqual(expected, 1536)
        self.assertEqual(scope["byte_positions"], list(range(16)))
        self.assertEqual(scope["bit_positions"], list(range(8)))
        self.assertEqual(record["qualification"], "none")
        self.assertEqual(record["source_stage"],
                         "lifecycle-handoff/completion-state-check")
        self.assertEqual({row["binary_sha256"] for row in record["artifacts"]},
                         M.PINNED)
        self.assertEqual([row["confirmed"] for row in record["artifacts"]],
                         [expected, expected])
        self.assertEqual([row["unconfirmed"] for row in record["artifacts"]],
                         [0, 0])

    def test_record_checker_rejects_missing_or_unconfirmed_case(self):
        record = json.loads(M.RECORD.read_text(encoding="utf-8"))
        positions, bits = list(range(16)), list(range(8))
        cases = M.expected_cases(positions, bits)
        reports = [{"toolchain": row["toolchain"],
                    "binary_sha256": row["binary_sha256"],
                    "cases": cases, "confirmed": len(cases), "unconfirmed": []}
                   for row in record["artifacts"]]
        M.check_record(reports, positions, bits)
        changed = copy.deepcopy(reports)
        changed[0]["cases"].pop()
        with self.assertRaises(ValueError):
            M.check_record(changed, positions, bits)
        changed = copy.deepcopy(reports)
        changed[1]["unconfirmed"] = [{"case": cases[0], "reason": "unconfirmed-markers"}]
        with self.assertRaises(ValueError):
            M.check_record(changed, positions, bits)
        changed = copy.deepcopy(reports)
        changed[1]["binary_sha256"] = changed[0]["binary_sha256"]
        with self.assertRaises(ValueError):
            M.check_record(changed, positions, bits)
        with self.assertRaises(ValueError):
            M.check_record(reports, positions, [0])


if __name__ == "__main__":
    unittest.main()
