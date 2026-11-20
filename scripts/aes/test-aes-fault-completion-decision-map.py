#!/usr/bin/env python3
"""Fail-closed tests for the candidate completion instruction map."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "completion_decision_map", Path(__file__).with_name(
        "check-aes-fault-completion-decision-map.py"))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class CompletionDecisionMapTests(unittest.TestCase):
    def test_points_are_exact_instruction_candidates(self):
        record = json.loads(M.RECORD.read_text(encoding="utf-8"))
        instruction_record = json.loads(M.INSTR.RECORD.read_text(encoding="utf-8"))
        M.check_record(record["artifacts"])
        for row in record["artifacts"]:
            digest = row["binary_sha256"]
            body = next(artifact["bodies"]["lifecycle-handoff"][0]
                        for artifact in instruction_record["artifacts"]
                        if artifact["binary_sha256"] == digest)
            self.assertEqual(row["body_address"], body["address"])
            self.assertEqual(row["body_decoded_sha256"], body["decoded_sha256"])
            points = list(row["completion_state_check"].values())
            points += list(row["shared_state_select_write"].values())
            points.append(row["result_return"])
            self.assertEqual(len(points), len(set(points)))
            self.assertTrue(set(points) <= set(body["instruction_offsets"]))
            self.assertEqual(len(row["completion_state_check"]), 7)

    def test_record_drift_rejected(self):
        rows = json.loads(M.RECORD.read_text(encoding="utf-8"))["artifacts"]
        changed = copy.deepcopy(rows)
        changed[0]["completion_state_check"]["copy-call"] += 1
        with self.assertRaises(ValueError):
            M.check_record(changed)

    def test_unknown_artifact_rejected_before_disassembly(self):
        with patch.object(M.INSTR, "observe", side_effect=ValueError("unreviewed")), \
             patch.object(M.subprocess, "run") as run:
            with self.assertRaises(ValueError):
                M.inspect(Path("/tmp/unreviewed.elf"))
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
