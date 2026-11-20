#!/usr/bin/env python3
"""Fail-closed tests for pinned decoded-instruction candidate bookkeeping."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest


SPEC = importlib.util.spec_from_file_location(
    "instruction_candidates",
    Path(__file__).with_name("check-aes-fault-instruction-candidates.py"))
S = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(S)


class InstructionCandidateTests(unittest.TestCase):
    def test_decoder_boundaries_and_syntactic_controls(self):
        dump = """0000000000001000 <example>:
 1000: mov %rax,%rbx
 1003: jne 1009 <example+0x9>
 1005: setne %al
 1009: ret
"""
        body = S.decode_body(dump, 0x1000, 0xa)
        self.assertEqual((body["instruction_count"], body["first_offset"],
                          body["last_offset"]), (4, 0, 9))
        self.assertEqual(body["instruction_offsets"], [0, 3, 5, 9])
        self.assertEqual(body["candidate_control_offsets"]["conditional-jump"], [3])
        self.assertEqual(body["candidate_control_offsets"]["setcc"], [5])
        self.assertEqual(body["candidate_control_offsets"]["return"], [9])

    def test_missing_duplicate_and_escaped_boundaries_rejected(self):
        for dump in (" 1001: ret\n",
                     " 1000: ret\n 1000: ret\n",
                     " 1000: ret\n 100a: ret\n",
                     " 1003: ret\n 1000: ret\n"):
            with self.assertRaises(ValueError):
                S.decode_body(dump, 0x1000, 0xa)

    def test_record_pins_both_artifacts_and_all_bodies(self):
        record = json.loads(S.RECORD.read_text(encoding="utf-8"))
        rows = record["artifacts"]
        S.check_record(rows)
        self.assertEqual({row["binary_sha256"] for row in rows},
                         set(S.SYMBOLS.PINNED))
        self.assertEqual(sum(body["instruction_count"] for row in rows
                             for spans in row["bodies"].values() for body in spans), 3435)
        self.assertTrue(all(set(row["bodies"]) == set(S.SYMBOLS.FAMILIES)
                            for row in rows))
        control_count = 0
        for row in rows:
            for spans in row["bodies"].values():
                for body in spans:
                    offsets = body["instruction_offsets"]
                    self.assertEqual((len(offsets), offsets[0], offsets[-1]),
                                     (body["instruction_count"], 0, body["last_offset"]))
                    self.assertEqual(offsets, sorted(set(offsets)))
                    for candidates in body["candidate_control_offsets"].values():
                        self.assertTrue(set(candidates) <= set(offsets))
                        control_count += len(candidates)
        self.assertEqual(control_count, 559)
        changed = copy.deepcopy(rows)
        changed[0]["bodies"]["lifecycle-handoff"][0]["instruction_count"] += 1
        with self.assertRaises(ValueError):
            S.check_record(changed)


if __name__ == "__main__":
    unittest.main()
