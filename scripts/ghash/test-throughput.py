"""Replay historical measurements; no timed executions or CPU feature requirements."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("throughput", Path(__file__).with_name("check-throughput.py"))
BENCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BENCH)
OBS = BENCH.ROOT / "assurance/ghash-observations/throughput-amd-9950x3d"


class ThroughputReplay(unittest.TestCase):
    def test_units_and_route_order(self):
        lines = []
        for pair in range(12):
            for route in (("candidate", "portable") if pair % 2 else ("portable", "candidate")):
                for size, chunk, count in BENCH.CASES:
                    ns = count * (300 if route == "portable" else 200)
                    lines.append(f"{pair} {route} {size} {chunk} {count} {ns}")
        result = BENCH.summarize("\n".join(lines).encode())
        self.assertEqual(len(result), 4)
        for summary in result.values():
            self.assertEqual(summary, dict(portable_ns=300, candidate_ns=200, speedup=1.5))
        for changed in (lines[:-1], [*lines, lines[0]], [lines[4], *lines[1:]],
                        [lines[0].replace("4096 ", "4095 "), *lines[1:]],
                        [lines[0].rsplit(" ", 1)[0] + " 0", *lines[1:]]):
            with self.assertRaises(ValueError):
                BENCH.summarize("\n".join(changed).encode())

    def test_retained_records(self):
        with contextlib.redirect_stdout(io.StringIO()):
            BENCH.replay(OBS)

    def test_mismatched_record_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "observation"
            shutil.copytree(OBS, dest)
            path = dest / "1.90.0.json"
            original = json.loads(path.read_text())
            for change in ({"raw_sha256": "0" * 64}, {"results": {}},
                           {"binary_sha256": dict.fromkeys(BENCH.ROUTES, "0" * 64)}):
                path.write_text(json.dumps(original | change))
                with self.assertRaises(ValueError):
                    BENCH.replay(dest)


if __name__ == "__main__":
    unittest.main()
