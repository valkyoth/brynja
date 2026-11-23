"""Offline integrity and alarm-reporting controls for the x86 candidate screen."""
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
    "amd": ("9f85c9c6b0f5081957346cee2443b26d9670ecd9e3d47824a8ed5ef0936bc112",
            "75e5d552599818ba0a38ec01acf77cadff8d7dd0edcdc1d78d902be9801b78a3"),
    "intel": ("211650f49a423cdde0e3f8733c1d18ed29055ee801b20c18597c7472dcb0fb73",
              "73fe77767c53f5e7244ce4cc103b31f05adb2f2f12d1cf851bc36680f995c744"),
}


def replay(host, directory):
    with contextlib.redirect_stdout(io.StringIO()):
        return C["replay"](host, directory)


class PclmulScreen(unittest.TestCase):
    def test_retained_records_same_binaries(self):
        manifests = []
        for host, pins in PINS.items():
            directory = OBS / ("timing-pclmul-" + host)
            for version, expected in zip(C["VERSIONS"], pins, strict=True):
                self.assertEqual(C["digest"]((directory / f"{version}.json").read_bytes()), expected)
            replay(host, directory)
            manifests.append((directory / "build.json").read_bytes())
        self.assertEqual(*manifests)

    def test_changed_population_or_wrong_host_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "result"
            shutil.copytree(OBS / "timing-pclmul-amd", dest)
            with self.assertRaisesRegex(ValueError, "identity mismatch"):
                replay("intel", dest)
            with (dest / "1.90.0.txt").open("ab") as f:
                f.write(b"block 1 1\n")
            with self.assertRaisesRegex(ValueError, "identity mismatch"):
                replay("amd", dest)

    def test_alarm_is_reported_and_cannot_be_suppressed(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "result"
            shutil.copytree(OBS / "timing-pclmul-amd", dest)
            raw = b"".join(f"{mode} 10 {11 if mode == 'block' else 10}\n".encode() * 2048
                           for mode in ("identical", "subkey", "block"))
            (dest / "1.90.0.txt").write_bytes(raw)
            path = dest / "1.90.0.json"
            record = json.loads(path.read_text())
            record.update(raw_sha256=C["digest"](raw), results=C["summarize"](raw))
            path.write_text(json.dumps(record))
            self.assertIn(("1.90.0", "block"), replay("amd", dest))
            record["results"]["block"]["alarm"] = False
            path.write_text(json.dumps(record))
            with self.assertRaisesRegex(ValueError, "alarm mismatch"):
                replay("amd", dest)


if __name__ == "__main__":
    unittest.main()
