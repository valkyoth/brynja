"""Replay ARM measurements without a native CPU, Cargo, or a timed rerun."""
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
OBS = ARM.B.ROOT / "assurance/ghash-observations/throughput-aws-neoverse-v2"


class ArmThroughput(unittest.TestCase):
    def test_recorded_neoverse_v2_measurements(self):
        with contextlib.redirect_stdout(io.StringIO()):
            ARM.replay(OBS)
        for version in ARM.B.VERSIONS:
            record = json.loads((OBS / f"{version}.json").read_text())
            self.assertEqual(record["model"], "Neoverse-V2")
            self.assertIn("aarch64", record["host"])

    def test_mislabelled_build_or_changed_sample_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "observation"
            shutil.copytree(OBS, dest)
            path = dest / "build.json"
            original = path.read_bytes()
            path.write_text(json.dumps(json.loads(original) | {"target": "x86_64-unknown-linux-musl"}))
            with self.assertRaisesRegex(ValueError, "ARM build provenance"):
                ARM.replay(dest)
            path.write_bytes(original)
            raw = dest / "1.90.0.txt"
            raw.write_bytes(raw.read_bytes().replace(b"portable", b"candidate", 1))
            with self.assertRaises(ValueError):
                ARM.replay(dest)

    def test_all_binaries_checked_before_measurement(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp)
            manifest = json.loads((OBS / "build.json").read_text())
            for version in ARM.B.VERSIONS:
                for route in ARM.B.ROUTES:
                    data = f"{version}-{route}".encode()
                    (bundle / data.decode()).write_bytes(data)
                    manifest["builds"][version]["binary_sha256"][route] = ARM.B.digest(data)
            self.assertEqual(set(ARM.checked_builds(bundle, manifest)), set(ARM.B.VERSIONS))
            (bundle / "1.100.0-candidate").write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "binary or compiler mismatch"):
                ARM.checked_builds(bundle, manifest)


if __name__ == "__main__":
    unittest.main()
