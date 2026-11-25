"""Regression controls for the retained native observation checker."""
from pathlib import Path
import runpy
import shutil
import tempfile
import unittest

m = runpy.run_path(str(Path(__file__).with_name("check-native-pair-records.py")))


class Records(unittest.TestCase):
    def test_complete(self):
        m["check"]()

    def test_rejects_substitution(self):
        host, version = "windows-x64", "1.90.0"
        for field, value in (("host", "linux-arm64"), ("inputs_sha256", "0"*64),
                             ("replay", {}), ("images", {}), ("tests", {}), ("compiler", "")):
            with self.subTest(field=field):
                record = m["json"].loads((m["ROOT"] / host / (version+".json")).read_bytes())
                record[field] = value
                with self.assertRaises(ValueError):
                    m["validate"](record, host, version)

    def test_missing_or_altered_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "records"
            shutil.copytree(m["ROOT"], root)
            path = root / "macos-arm64/1.100.0.json"
            path.write_bytes(path.read_bytes()+b" ")
            with self.assertRaisesRegex(ValueError, "digest"):
                m["check"](root)
            path.unlink()
            with self.assertRaises(FileNotFoundError):
                m["check"](root)


if __name__ == "__main__":
    unittest.main()
