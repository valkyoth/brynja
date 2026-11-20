#!/usr/bin/env python3
"""Guard the bounded exact-artifact regression sweep against coverage drift."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "native_sweep", Path(__file__).with_name("run-aes-fault-native-sweep.py"))
S = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(S)


class NativeSweepTests(unittest.TestCase):
    def test_profiles_are_finite_and_distinct(self):
        binary = Path("/tmp/pinned.elf")
        compact = list(S.jobs(binary, "compact"))
        complementary = list(S.jobs(binary, "complementary"))
        matrix = list(S.jobs(binary, "owner-path-matrix"))
        full = list(S.jobs(binary, "all-existing"))
        self.assertEqual(len(compact), 8)
        self.assertEqual(len(complementary), 6)
        self.assertEqual(len(matrix), 36)
        self.assertEqual(len(full), 40)
        self.assertEqual({name for name, _ in compact},
                         {name for name, _ in S.COMPACT_JOBS})
        self.assertTrue(all(args[:2] == ("--binary", str(binary))
                            for _, args in compact + complementary + matrix + full))
        with self.assertRaises(ValueError):
            list(S.jobs(binary, "unknown"))

    def test_unreviewed_artifact_is_rejected_before_execution(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "unreviewed.elf"
            path.write_bytes(b"\x7fELF\x02\x01" + b"\x00" * 12 + b"\x3e\x00")
            with patch.object(S.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "unreviewed test ELF"):
                    S.sweep([path, path])
                run.assert_not_called()

    def test_pinned_digests_and_dimensions(self):
        self.assertEqual(set(S.PINNED.values()), {"1.90.0", "1.100.0"})
        self.assertTrue(all(len(digest) == 64 for digest in S.PINNED))
        dimensions = [args for _, args in S.jobs(Path("/tmp/pinned.elf"), "compact")]
        self.assertTrue(any("--byte" in args for args in dimensions))
        self.assertTrue(any("secret" in args for args in dimensions))

    def test_one_probe_failure_remains_failed_without_retry(self):
        paths = [Path("/tmp/a.elf"), Path("/tmp/b.elf")]
        selected = [(paths[0], next(iter(S.PINNED))),
                    (paths[1], list(S.PINNED)[1])]
        calls = 0

        def fake_run(*_args, **_kwargs):
            nonlocal calls
            calls += 1
            return subprocess.CompletedProcess([], 2 if calls == 9 else 0)

        with patch.object(S, "inspect_binary", side_effect=selected), \
             patch.object(S.subprocess, "run", side_effect=fake_run):
            outcomes = S.sweep(paths)
        self.assertEqual((len(outcomes), calls), (16, 16))
        self.assertEqual([row[3] for row in outcomes].count(2), 1)

    def test_record_matches_exact_compact_roster(self):
        record = json.loads((S.ROOT / "assurance/aes-fault-native-sweep-observations.json")
                            .read_text(encoding="utf-8"))
        self.assertEqual((record["status"], record["qualification"], record["profile"]),
                         ("development-regression-inconsistent", "none", "compact"))
        self.assertEqual(record["secondary_profile"], "complementary")
        self.assertEqual({row["binary_sha256"] for row in record["artifacts"]},
                         set(S.PINNED))
        self.assertEqual([row["script_invocations_passed"] for row in record["artifacts"]],
                         [len(S.COMPACT_JOBS)] * 2)
        self.assertEqual(record["jobs_per_artifact"],
                         [S.job_label(script, dimensions)
                          for script, dimensions in S.COMPACT_JOBS])
        self.assertEqual(record["complementary_jobs_per_artifact"],
                         [S.job_label(script, dimensions)
                          for script, dimensions in S.COMPLEMENTARY_JOBS])
        self.assertTrue(any("15/16" in entry and "unconfirmed" in entry
                            for entry in record["observed"]))

    def test_owner_path_matrix_record_keeps_failure_open(self):
        record = json.loads((S.ROOT / "assurance/aes-fault-owner-path-matrix-observations.json")
                            .read_text(encoding="utf-8"))
        matrix = list(S.jobs(Path("/tmp/pinned.elf"), "owner-path-matrix"))
        self.assertEqual((record["status"], record["qualification"], record["profile"]),
                         ("incomplete-development-matrix", "none", "owner-path-matrix"))
        self.assertEqual(len(matrix), record["scope"]["script_invocations_per_artifact"])
        self.assertEqual(record["scope"]["script_families"],
                         [name.removeprefix("check-aes-fault-").removesuffix(".py")
                          for name in S.OWNER_PATH_SCRIPTS])
        self.assertEqual(record["scope"]["primary_output_byte_positions"], [0, 15])
        self.assertEqual({row["binary_sha256"] for row in record["artifacts"]},
                         set(S.PINNED))
        self.assertEqual([row["passed_invocations"] for row in record["artifacts"]],
                         [36, 35])
        self.assertTrue(record["unconfirmed"])


if __name__ == "__main__":
    unittest.main()
