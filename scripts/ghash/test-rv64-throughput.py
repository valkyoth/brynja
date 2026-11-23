"""Validate the archived X60 scalar measurements without RISC-V hardware."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("collector", Path(__file__).with_name("check-arm-throughput.py"))
BENCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BENCH)
OBS = BENCH.B.ROOT / "assurance/ghash-observations/throughput-spacemit-x60"


class X60Throughput(unittest.TestCase):
    def test_replay_native_records(self):
        with contextlib.redirect_stdout(io.StringIO()):
            BENCH.replay(OBS, BENCH.RV64)
        for version in BENCH.B.VERSIONS:
            record = json.loads((OBS / f"{version}.json").read_text())
            self.assertEqual(record["model"], "spacemit,x60")
            self.assertEqual(record["scalar_extensions"], ["zbc"])

    def test_only_exact_scalar_isa_tokens_qualify(self):
        for ext in ("zbc", "zbkc"):
            self.assertEqual(BENCH.scalar_extensions("rv64imafdc_" + ext), [ext])
        for isa in ("rv64imafdcv_zvbc_zvkg", "rv64gc_zkne_zknd", "rv64gc_zbcx"):
            with self.assertRaisesRegex(ValueError, "lacks scalar"):
                BENCH.scalar_extensions(isa)

    def test_out_of_scope_records_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "result"
            shutil.copytree(OBS, dest)
            build = dest / "build.json"
            raw = build.read_bytes()
            meta = json.loads(raw)
            for change in ({"target": BENCH.TARGET}, {"portable_rustflags": ""},
                           {"candidate_rustflags": meta["candidate_rustflags"] + " -C target-feature=+zbc"}):
                build.write_text(json.dumps(meta | change))
                with self.assertRaisesRegex(ValueError, "RV64 build provenance"):
                    BENCH.replay(dest, BENCH.RV64)
            build.write_bytes(raw)
            path = dest / "1.90.0.json"
            record = json.loads(path.read_text())
            for change in ({"cpu": None}, {"cpu": -1}, {"scalar_extensions": ["zbkc"]}, {"host": "Linux-arm64"}):
                path.write_text(json.dumps(record | change))
                with self.assertRaisesRegex(ValueError, "unexpected RV64 host"):
                    BENCH.replay(dest, BENCH.RV64)


if __name__ == "__main__":
    unittest.main()
