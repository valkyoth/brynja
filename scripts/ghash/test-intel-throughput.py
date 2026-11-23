"""Replay the Intel measurements without requiring Intel hardware."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("collector", Path(__file__).with_name("check-arm-throughput.py"))
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)
OBS = C.B.ROOT / "assurance/ghash-observations/throughput-intel-6975p-c"


class IntelThroughput(unittest.TestCase):
    def test_retained_xeon_records(self):
        with contextlib.redirect_stdout(io.StringIO()):
            C.replay(OBS, C.INTEL)
        for version in C.B.VERSIONS:
            self.assertEqual(json.loads((OBS / f"{version}.json").read_text())["model"], "Intel(R) Xeon(R) 6975P-C")

    def test_vendor_and_exact_cpu_flag_required(self):
        block = "vendor_id : GenuineIntel\nflags : sse2 pclmulqdq\nmodel name : Xeon"
        self.assertEqual(C.intel_cpu(block), ("Xeon", dict(vendor="GenuineIntel", pclmulqdq=True)))
        for changed in (block.replace("GenuineIntel", "AuthenticAMD"), block.replace("pclmulqdq", "vpclmulqdq")):
            with self.assertRaisesRegex(ValueError, "Intel with PCLMULQDQ"):
                C.intel_cpu(changed)

    def test_out_of_scope_records_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "result"
            shutil.copytree(OBS, dest)
            build = dest / "build.json"
            original = build.read_bytes()
            for change in ({"target": C.APPLE}, {"portable_rustflags": "-C target-cpu=native"},
                           {"candidate_rustflags": "--cfg brynja_ghash_pmull_evidence"}):
                build.write_text(json.dumps(json.loads(original) | change))
                with self.assertRaisesRegex(ValueError, "Intel build provenance"):
                    C.replay(dest, C.INTEL)
            build.write_bytes(original)
            path = dest / "1.90.0.json"
            record = json.loads(path.read_text())
            for change in ({"vendor": "AuthenticAMD"}, {"cpu": False}, {"pclmulqdq": False}, {"host": "Linux-arm64"}):
                path.write_text(json.dumps(record | change))
                with self.assertRaisesRegex(ValueError, "unexpected Intel host"):
                    C.replay(dest, C.INTEL)


if __name__ == "__main__":
    unittest.main()
