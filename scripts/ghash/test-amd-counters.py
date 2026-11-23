"""Offline replay and rejection controls. Does not open performance counters."""
import json
from pathlib import Path
import runpy
import unittest

A = runpy.run_path(str(Path(__file__).with_name("check-amd-counters.py")))


class CounterRecords(unittest.TestCase):
    def test_first_observation(self):
        dest = A["C"]["ROOT"] / "assurance/ghash-observations/counters-amd-9950x3d"
        for ver, pin in {
            "1.90.0": "6367512e157b806af5599c55fd2db739e4bd5bdce1360ad08eb659f4b125cd70",
            "1.100.0": "eba6fccf531ce3da3b22a1bd4ae0d4a25e8baa17fe8af2cea72e2b8ecbf8908a",
        }.items():
            self.assertEqual(A["digest"](dest / f"{ver}.json"), pin)
        self.assertEqual(A["replay"](dest), [])

    def test_unavailable_is_not_zero(self):
        for bad in ("", "1 1 1 0 2", "10 9 1 0 2 0", "0 0 1 0 2 0", "1 1 1 2 1 1", "1 1 1 0 -1 0"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                A["counts"](bad)
        self.assertEqual(A["counts"]("9 9 4 0 0 5\n"), [4, 0, 0, 5])
        with self.assertRaises(ValueError):
            A["probe"]("9 9 4 1 0 5\n")

    def test_alarm_envelope_and_order(self):
        rows = []
        for mode, pair, label in A["R"]["schedule"]():
            b = 10 if mode == "empty" else 100
            refs = label if mode == "block" else 0
            rows.append(json.dumps(dict(launch=[mode, pair, label], perf=f"7 7 {b} 1 {refs} 0")))
        campaigns = A["summary"]("\n".join(rows))["campaigns"]
        self.assertTrue(campaigns["block"]["cache-references:u"]["alarm"])
        self.assertFalse(campaigns["block"]["cache-references:u"]["all_active_above_empty"])
        self.assertFalse(campaigns["identical"]["branches:u"]["alarm"])
        self.assertTrue(campaigns["identical"]["branches:u"]["all_active_above_empty"])
        for bad in (rows[:-1], list(reversed(rows))):
            with self.assertRaises(ValueError):
                A["summary"]("\n".join(bad))


if __name__ == "__main__":
    unittest.main()
