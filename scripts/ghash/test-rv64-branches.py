"""Offline controls for native X60 perf reports; no perf access or remeasurement."""
import contextlib
import io
import json
from pathlib import Path
import runpy
import unittest

C = runpy.run_path(str(Path(__file__).with_name("check-rv64-branches.py")))


def report(branches, misses):
    return (f"{branches};;branches:u;12000;100.00;;\n"
            f"{misses};;branch-misses:u;12000;100.00;;\n")


class BranchRecords(unittest.TestCase):
    def test_exact_observations(self):
        directory = C["C"]["ROOT"] / "assurance/ghash-observations/branches-rv64-x60"
        pins = {"1.90.0": "3589d2625687f7834b4f7b653e9936851a6c227f7cb0e5674031d7567944b85a",
                "1.100.0": "6f6b2aa006271b4c5cfb70d5d661b944ba9073ee0beba7e8658dbc3141e12193"}
        for ver, pin in pins.items():
            self.assertEqual(C["C"]["digest"]((directory / f"{ver}.json").read_bytes()), pin)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(C["replay"](directory), [])

    def test_reject_absent_multiplexed_or_mislabeled_events(self):
        raw = report(100, 3)
        self.assertEqual(C["counts"](raw), [100, 3])
        for invalid in (raw.replace("100;", "<not counted>;"), raw.replace("100.00", "88.60"),
                        raw.replace("branches:u", "cache-misses:u"), raw + raw, report(1, 3)):
            with self.assertRaises(ValueError):
                C["counts"](invalid)

    def test_control_and_alarm_dispositions(self):
        rows = []
        for mode, pair, label in C["schedule"]():
            b = 1000 if mode != "empty" else 10
            if mode == "subkey":
                b -= label
            rows.append(dict(launch=[mode, pair, label], perf=report(b, 4)))
        def summarize(entries):
            return C["summary"]("\n".join(map(json.dumps, entries)).encode())
        result = summarize(rows)["campaigns"]
        self.assertTrue(result["subkey"]["branches:u"]["alarm"])
        self.assertFalse(result["identical"]["branches:u"]["alarm"])
        self.assertFalse(result["subkey"]["branch-misses:u"]["alarm"])
        for bad in (rows[:-1], list(reversed(rows)), [dict(rows[0], perf=report(1000, 4)), *rows[1:]]):
            with self.assertRaises(ValueError):
                summarize(bad)


if __name__ == "__main__":
    unittest.main()
