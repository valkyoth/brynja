"""Offline replay and negative controls; never launches the timing executable."""
import gzip
from pathlib import Path
import runpy
import unittest

C = runpy.run_path(str(Path(__file__).with_name("check-paired-timing.py")))
PINS = {"build.json": "6cbda10680b8235359de34393c9ed71ebc2e6fd2ffc0d5cf221bdde12486a9bc",
        "1.90.0.json": "4f71ca0aaf00e920422222de5a233f63b6cdf90733c761ddaf2b5d3892db72e3",
        "1.100.0.json": "921c07c09003f3ab18819889d2ff31ad0747c71e3f1986fda740bacc76988bbc"}


class PairedTimingTests(unittest.TestCase):
    def test_pinned_host_build_and_both_full_populations(self):
        for name, sha in PINS.items():
            self.assertEqual(C["digest"]((C["RUN"] / name).read_bytes()), sha)
        # The pinned summaries contain the hashes of the uncompressed rows.
        self.assertFalse(C["replay"](C["RUN"]))

    def test_incomplete_unbalanced_or_malformed_population_is_rejected(self):
        raw = gzip.decompress((C["RUN"] / "1.90.0.txt.gz").read_bytes())
        first, second, rest = raw.split(b"\n", 2)
        cells = second.split()
        cells[2] = first.split()[2]
        for bad in (raw[:-1].rsplit(b"\n", 1)[0], b"\n".join([first, b" ".join(cells), rest]),
                    first.replace(b"identical", b"values")+b"\n"+second+b"\n"+rest):
            with self.assertRaises(ValueError):
                C["analyse"](bad)

    def test_an_alarm_and_a_failed_sensitivity_control_cannot_cancel(self):
        bad_case = "128-seal-values"
        raw = b"".join(f"{case} {i} {i%2} 100 {200 if case == bad_case else 100}\n".encode()
                       for case in C["CAMPAIGNS"] for i in range(C["N"]))
        summary = C["analyse"](raw)
        self.assertEqual([k for k, v in summary.items() if v["status"] == "flagged"],
                         [bad_case, "sensitivity"])


if __name__ == "__main__":
    unittest.main()
