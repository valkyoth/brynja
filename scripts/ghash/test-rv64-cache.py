"""Replay retained native L1 records offline, including any first-run alarms."""
import contextlib
import io
import json
from pathlib import Path
import runpy
import unittest
from unittest.mock import patch

C = runpy.run_path(str(Path(__file__).with_name("check-rv64-branches.py")))
DEST = C["C"]["ROOT"] / "assurance/ghash-observations/cache-rv64-x60"
L1 = C["L1"]
PINS = {"1.90.0": "b9fd8bf16adf48f04edb0a33e132a21661cf9052a6c1048e475628f7e7b6a3f2",
        "1.100.0": "a9b10363b2b43a52fbab4a7cfc83cd7be4fedd38f1d7d76b7a8cd99181c6999c"}


def report(loads, misses):
    return f"{loads};;{L1[0]};12000;100.00;;\n{misses};;{L1[1]};12000;100.00;;\n"


class CacheRecords(unittest.TestCase):
    def test_saved_records(self):
        with patch("subprocess.Popen", side_effect=AssertionError("offline replay only")), \
                contextlib.redirect_stdout(io.StringIO()):
            alarms = C["replay"](DEST, l1=True)
        self.assertEqual(alarms, [])
        for version, pin in PINS.items():
            self.assertEqual(C["C"]["digest"]((DEST / f"{version}.json").read_bytes()), pin)

    def test_counter_controls(self):
        raw = report(112, 0)
        self.assertEqual(C["counts"](raw, L1), [112, 0])
        for bad in (raw.replace("112;", "<not counted>;"), raw.replace("100.00", "99.90"),
                    raw.replace("12000", "12001", 1), raw.replace(L1[0], "cache-references"),
                    raw + raw, report(1, 2)):
            with self.assertRaises(ValueError):
                C["counts"](bad, L1)
        control = (DEST / "positive.txt").read_text()
        C["l1_control"](control)
        for field in ("exclude_hv", "exclude_kernel", "0x10000", "perf_event_attr:"):
            with self.assertRaises(ValueError):
                C["l1_control"](control.replace(field, "missing", 1))
        attrs = "\n".join(line for line in control.splitlines() if ";" not in line)
        with self.assertRaises(ValueError):
            C["l1_control"](attrs + "\n" + raw)

    def test_miss_overlap_keeps_alarm(self):
        rows = []
        for mode, pair, label in C["schedule"]():
            loads, misses = (20, 10) if mode == "empty" else (200, 3)
            rows.append(dict(launch=[mode, pair, label], perf=report(loads, misses + label)))

        def summarize(entries):
            return C["summary"]("\n".join(map(json.dumps, entries)),
                                lambda raw: C["counts"](raw, L1), L1, envelope=True)

        result = summarize(rows)["campaigns"]["identical"][L1[1]]
        self.assertFalse(result["all_active_above_empty"])
        self.assertTrue(result["alarm"])
        self.assertIsNone(result["paired_t"])
        for bad in (rows[:-1], list(reversed(rows)), [dict(rows[0], perf=report(200, 10)), *rows[1:]]):
            with self.assertRaises(ValueError):
                summarize(bad)


if __name__ == "__main__":
    unittest.main()
