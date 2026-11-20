#!/usr/bin/env python3
"""Fail-closed bounds and result parsing for the actual secret destination grid."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "actual_secret_matrix",
    Path(__file__).with_name("check-aes-fault-actual-secret-byte-matrix.py"))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class ActualSecretByteMatrixTests(unittest.TestCase):
    def test_each_byte_targets_each_distinct_check(self):
        answer = bytes(range(16))
        owner = next(iter(M.S.SHAPES.values()))["owners"]["cached"]
        for check in M.CHECKS:
            for byte in range(16):
                commands = M.commands(owner, answer, byte, check)
                self.assertEqual(sum(command.startswith("set *($caller+")
                                     for command in commands), 1)
                self.assertIn(f"set *($caller+{byte}) = *($caller+{byte}) ^ 1",
                              commands)
                self.assertIn(f"+{M.OFFSETS[M.CHECKS.index(check)]})",
                              commands[7])
                pre = next(command for command in commands if "ACTUAL_PRE" in command)
                self.assertIn(f"$r8 == {M.CHECKS.index(check)}", pre)

    def test_unknown_artifact_rejected_before_debugger(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "unreviewed.elf"
            path.write_bytes(b"\x7fELF\x02\x01" + b"\x00" * 12 + b"\x3e\x00")
            with patch.object(M.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "unreviewed secret destination artifact"):
                    M.observe(path, [0], ["forward"])
                run.assert_not_called()

    def test_invalid_dimensions_rejected_before_debugger(self):
        digest = next(iter(M.S.SHAPES))
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "pinned.elf"
            path.write_bytes(b"\x7fELF\x02\x01" + b"\x00" * 12 + b"\x3e\x00")
            with patch.object(M.hashlib, "sha256") as digest_function, \
                 patch.object(M.subprocess, "run") as run:
                digest_function.return_value.hexdigest.return_value = digest
                for positions in ([], [0, 0], [-1], [16], [False]):
                    with self.assertRaisesRegex(ValueError, "invalid byte positions"):
                        M.observe(path, positions, ["forward"])
                for checks in ([], ["forward", "forward"], ["unknown"]):
                    with self.assertRaisesRegex(ValueError, "invalid readback checks"):
                        M.observe(path, [0], checks)
                run.assert_not_called()

    def test_result_parser_requires_all_outcomes(self):
        output = "\n".join((
            "ACTUAL_ENTRY 1", "ACTUAL_PRE 1", "ACTUAL_MUTATED 1",
            "BRYNJA_CACHED_EVIDENCE_CFG=false", "BRYNJA_CACHED_CASE=16:encrypt",
            "BRYNJA_CACHED_STORAGE_CLEARED", "BRYNJA_CACHED_REJECTED_RETIRED",
            "Hardware assisted breakpoint ", "Hardware assisted breakpoint ",
            "hit Breakpoint ", "hit Breakpoint ",
            M.S.RETAINED.identity(16, "cached", "encrypt"),
            "test result: ok. 1 passed; 0 failed; 0 ignored;", "exited normally",
        ))
        M.validate(output, 16, "cached", "encrypt")
        for marker in ("ACTUAL_PRE 1", "BRYNJA_CACHED_REJECTED_RETIRED",
                       "exited normally"):
            with self.assertRaises(ValueError):
                M.validate(output.replace(marker, ""), 16, "cached", "encrypt")

    def test_record_requires_complete_distinct_artifacts(self):
        record = json.loads(M.RECORD.read_text(encoding="utf-8"))
        positions, checks = list(range(16)), list(M.CHECKS)
        cases = M.expected_cases(positions, checks)
        reports = [{"toolchain": row["toolchain"],
                    "binary_sha256": row["binary_sha256"],
                    "cases": cases, "confirmed": len(cases), "unconfirmed": []}
                   for row in record["artifacts"]]
        M.check_record(reports, positions, checks)
        changed = copy.deepcopy(reports)
        changed[0]["cases"].pop()
        with self.assertRaises(ValueError):
            M.check_record(changed, positions, checks)
        changed = copy.deepcopy(reports)
        changed[1]["binary_sha256"] = changed[0]["binary_sha256"]
        with self.assertRaises(ValueError):
            M.check_record(changed, positions, checks)
        changed = copy.deepcopy(reports)
        changed[1]["unconfirmed"] = [{"case": cases[0], "reason": "timeout"}]
        with self.assertRaises(ValueError):
            M.check_record(changed, positions, checks)
        with self.assertRaises(ValueError):
            M.check_record(reports, [0], checks)
        with self.assertRaises(ValueError):
            M.check_record(reports, positions, ["forward"])


if __name__ == "__main__":
    unittest.main()
