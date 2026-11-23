"""Offline identity, capability and record controls for the native X60 timing screen."""
import contextlib
import io
import json
from pathlib import Path
import runpy
import shutil
import tempfile
import unittest

C = runpy.run_path(str(Path(__file__).with_name("check-pclmul-screen.py")))
OBS = C["ROOT"] / "assurance/ghash-observations/timing-rv64-x60"


def replay(directory):
    with contextlib.redirect_stdout(io.StringIO()):
        return C["replay"]("x60", directory)


class X60Screen(unittest.TestCase):
    def test_exact_retained_records(self):
        pins = {"1.90.0": "8505ce7e716dc351b209387f483e30d3fa1c8c769bced88e654ea684524cacc6",
                "1.100.0": "63ea576f3fdaedafebdcad0c20266fd39c2c0552410057c7351b2af2910da8e9"}
        for version, pin in pins.items():
            self.assertEqual(C["digest"]((OBS / f"{version}.json").read_bytes()), pin)
        self.assertEqual(replay(OBS), [])

    def test_scalar_capability_on_named_host(self):
        validate = C["require_x60"]
        validate(dict(uarch="spacemit,x60", isa="rv64imafdcv_zbc_zbs"))
        for fields in (dict(uarch="other", isa="rv64imafdc_zbc"),
                       dict(uarch="spacemit,x60", isa="rv64imafdcv_zvbc_zvkg"),
                       dict(uarch="spacemit,x60", isa="rv64imafdc_zbcx"), {}):
            with self.assertRaisesRegex(ValueError, "scalar Zbc"):
                validate(fields)

    def test_wrong_build_or_execution_identity_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "record"
            shutil.copytree(OBS, dest)
            manifest = dest / "build.json"
            raw = manifest.read_bytes()
            meta = json.loads(raw)
            for change in ({"target": C["TARGET"]}, {"rustflags": meta["rustflags"] + " -C target-feature=+zbc"}):
                manifest.write_text(json.dumps(meta | change))
                with self.assertRaisesRegex(ValueError, "build configuration"):
                    replay(dest)
            manifest.write_bytes(raw)
            path = dest / "1.90.0.json"
            record = json.loads(path.read_text())
            for change in ({"os": "Linux-x86_64"}, {"required_scalar_extension": "zvbc"}):
                path.write_text(json.dumps(record | change))
                with self.assertRaisesRegex(ValueError, "X60 execution record"):
                    replay(dest)


if __name__ == "__main__":
    unittest.main()
