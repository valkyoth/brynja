"""Replay the native M2 Pro samples without running a benchmark."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("arm", Path(__file__).with_name("check-arm-throughput.py"))
ARM = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ARM)
OBS = ARM.B.ROOT / "assurance/ghash-observations/throughput-apple-m2-pro"


class AppleThroughput(unittest.TestCase):
    def test_retained_native_builds(self):
        with contextlib.redirect_stdout(io.StringIO()):
            ARM.replay(OBS, ARM.APPLE)
        for version in ARM.B.VERSIONS:
            self.assertEqual(json.loads((OBS / f"{version}.json").read_text())["model"], "Apple M2 Pro")

    def test_linux_replay_rejects_apple_builds(self):
        with self.assertRaisesRegex(ValueError, "ARM build provenance"):
            ARM.replay(OBS)

    def test_false_affinity_and_non_native_metadata_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "results"
            shutil.copytree(OBS, dest)
            path = dest / "1.90.0.json"
            record = json.loads(path.read_text())
            for change in ({"cpu": 0}, {"host": "Linux-arm64"}, {"compiler": "rustc 1.90.0 cross"}):
                path.write_text(json.dumps(record | change))
                with self.assertRaisesRegex(ValueError, "Apple compiler, host or CPU placement"):
                    ARM.replay(dest, ARM.APPLE)


if __name__ == "__main__":
    unittest.main()
