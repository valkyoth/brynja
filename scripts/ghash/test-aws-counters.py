"""Offline AWS perf record controls. Never open perf events or invoke sudo."""
import json
from pathlib import Path
import runpy
import unittest
from unittest.mock import patch

A = runpy.run_path(str(Path(__file__).with_name("check-aws-counters.py")))
BASE = A["C"]["ROOT"] / "assurance/ghash-observations/aws-attached"
RECORDS = (
    ("aws", "branches", "arm-branches",
     "1909897877a4f9d69297947e9e2067b3065baa6491676dda2a30471aa30c8cf1",
     "615cf048c6765506e8ef6abce7b5c06c89d4dae80d8f3bd4deb6420043143a6c"),
    ("aws", "arm-l1-only", "arm-l1",
     "43bfe759e1c9f2e5f67f2c6654945fa1dbffefdd7fbc0e550c8e7efe4fe2e19c",
     "907ec6a69b717f2b6e6d3aa2d08c7b3a1c675fd81ff939f91fa3e53ebf68cf3a"),
    ("intel", "intel-l1", "intel-l1",
     "a015ccecb0ba7aba62155a13f79818a23ec71aac2bd1ef23fb011dce2142b16d",
     "82aecd03dab52de91bf771d56fdfab403a48780441a0b535ebf5072cd41ce98d"),
)


class AwsCounters(unittest.TestCase):
    def test_exact_first_records(self):
        with patch("subprocess.Popen", side_effect=AssertionError("replay cannot launch a process")):
            for host, profile, directory, msrv, latest in RECORDS:
                dest = BASE / directory
                for ver, pin in zip(A["R"]["VERSIONS"], (msrv, latest), strict=True):
                    self.assertEqual(A["C"]["digest"]((dest / f"{ver}.json").read_bytes()), pin)
                    for line in (dest / f"{ver}.jsonl").read_text().splitlines():
                        raw = json.loads(line)["perf"].splitlines()
                        self.assertEqual(raw[:3], ["Events disabled", "Events enabled", "Events disabled"])
                        self.assertEqual(len({r.split(";")[3] for r in raw[3:]}), 1)
                self.assertEqual(A["replay"](host, profile, dest), [])

    def test_collect_only_the_declared_group_on_one_task(self):
        flags = A["collector"](12345, A["BRANCH"])
        self.assertEqual(flags[:6], ["/usr/bin/sudo", "-n", "-H", "--", "/usr/bin/perf", "stat"])
        self.assertEqual(flags[flags.index("-p")+1], "12345")
        self.assertEqual(flags[flags.index("-e")+1], "{branches:u,branch-misses:u}")
        self.assertIn("--no-inherit", flags)
        self.assertNotIn("-a", flags)
        for pid, events in ((0, A["BRANCH"]), (-1, A["BRANCH"]), ("12345", A["BRANCH"]), (12345, ("cycles:k",))):
            with self.assertRaises(ValueError):
                A["collector"](pid, events)
        with self.assertRaises(ValueError):
            A["selected"]("aws", "intel-l1")

    def test_unsupported_multiplexed_or_wrong_event_is_not_zero(self):
        events = A["BRANCH"]
        good = "8;;branches:u;32;100.00;;\n0;;branch-misses:u;32;100.00;;\n"
        self.assertEqual(A["counts"](good, events), [8, 0])
        for bad in (good.replace("0;;branch-", "<not supported>;;branch-"),
                    good.replace("100.00", "99.00"), good.replace("branches:u", "cycles:k"),
                    good.replace("0;;branch-", "9;;branch-"), good + good):
            with self.assertRaises(ValueError):
                A["counts"](bad, events)


if __name__ == "__main__":
    unittest.main()
