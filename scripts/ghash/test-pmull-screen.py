"""Offline replay, including the retained Neoverse identical-input control alarm."""
import contextlib
import io
import json
from pathlib import Path
import runpy
import shutil
import tempfile
import unittest

C = runpy.run_path(str(Path(__file__).with_name("check-pclmul-screen.py")))
OBS = C["ROOT"] / "assurance/ghash-observations"
PINS = {
    "aws": ("4f70cc0f8a5c3b6351b1c1af18ac4bee4b6688b052dc3ee32a12d2fa93f632fc",
            "0b5edd2a3fd09fcbba43ca09c0bde8c3b63b87ecbb3ac40d7a2251d1491152ed"),
    "apple": ("2792c18fa0da1de1e217943977183fd26479011c3e25ca332382426a9bbda983",
              "28eaadb2d8fe086918c0c073052c3478bf69975c5caa5ddc8bf2bea5a7444eaf"),
}


def replay(host, directory):
    with contextlib.redirect_stdout(io.StringIO()):
        return C["replay"](host, directory)


class PmullScreen(unittest.TestCase):
    def test_independent_order_followup(self):
        order = runpy.run_path(str(Path(__file__).with_name("check-pmull-order.py")))
        directory = OBS / "order-pmull-aws"
        for ver, pin in zip(C["VERSIONS"], (
                "e63661f4bd9800fa1591b6810eeb2c3a060dbe53fe906ae2d39b83e747274125",
                "3f7caa29b93f97f5a1b5d43a7b3bbc0c2f84412e696f982173356ef55523ddbf"), strict=True):
            self.assertEqual(C["digest"]((directory / f"{ver}.json").read_bytes()), pin)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(order["replay"](directory), [])

    def test_order_parser_rejects_old_confounded_schedule_and_keeps_alarms(self):
        order = runpy.run_path(str(Path(__file__).with_name("check-pmull-order.py")))
        def rows(schedule):
            return b"".join(f"{mode} {first} 11 10\n".encode()
                            for mode in ("identical", "subkey", "block")
                            for _ in range(512) for first in schedule)
        with self.assertRaisesRegex(ValueError, "confounded"):
            order["analyze"](rows((0, 1, 0, 1)))
        good = rows((0, 0, 1, 1))
        with self.assertRaisesRegex(ValueError, "population"):
            order["analyze"](good.split(b"\n", 1)[1])
        a = order["analyze"](good)
        self.assertTrue(all(m["alarm"] for m in a["label"].values()))
        self.assertEqual(a["first_minus_second_ns"]["identical"], [0, 0])

    def test_exact_records_and_control_alarm(self):
        for host, pins in PINS.items():
            directory = OBS / ("timing-pmull-" + host)
            for ver, pin in zip(C["VERSIONS"], pins, strict=True):
                self.assertEqual(C["digest"]((directory / f"{ver}.json").read_bytes()), pin)
            self.assertEqual(replay(host, directory), [("1.100.0", "identical")] if host == "aws" else [])

    def test_control_alarm_cannot_be_relabelled(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "result"
            shutil.copytree(OBS / "timing-pmull-aws", directory)
            path = directory / "1.100.0.json"
            record = json.loads(path.read_text())
            record["results"]["identical"]["alarm"] = False
            path.write_text(json.dumps(record))
            with self.assertRaisesRegex(ValueError, "alarm mismatch"):
                replay("aws", directory)

    def test_retained_aws_identical_control_by_execution_order(self):
        # Post-hoc description, not another qualification test or a new threshold.
        # timed() printed class 0 then class 1, regardless of execution order.
        # Its 64 warm-up pairs leave class 0 first on the first measured pair.
        directory = OBS / "timing-pmull-aws"
        raw = (directory / "1.100.0.txt").read_bytes()
        overall = C["summarize"](raw)["identical"]  # checks all rows and their order
        self.assertTrue(overall["alarm"])
        differences = [int(a) - int(b) for mode, a, b in
                       (line.split() for line in raw.splitlines()) if mode == b"identical"]
        totals = []
        for offset, expected in enumerate(((-53161, -7643, 5999), (10, -31, 25))):
            group = differences[offset::2]
            self.assertEqual(len(group), 1024)
            self.assertEqual((sum(group), min(group), max(group)), expected)
            totals.append(sum(group))
        self.assertEqual(sum(totals) / len(differences), overall["mean_difference_ns"])

    def test_host_target_and_placement_must_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "result"
            shutil.copytree(OBS / "timing-pmull-apple", directory)
            with self.assertRaisesRegex(ValueError, "build configuration"):
                replay("aws", directory)
            path = directory / "1.90.0.json"
            record = json.loads(path.read_text())
            path.write_text(json.dumps(record | {"cpu": 0}))
            with self.assertRaisesRegex(ValueError, "identity mismatch"):
                replay("apple", directory)


if __name__ == "__main__":
    unittest.main()
