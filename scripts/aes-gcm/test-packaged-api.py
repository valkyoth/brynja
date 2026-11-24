"""Negative controls for archive evidence (no Cargo processes needed)."""
import importlib.util
from pathlib import Path
import shutil
import tempfile
import tomllib
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("gcm_archives", Path(__file__).with_name("check-packaged-api.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class ArchiveTests(unittest.TestCase):
    def test_fixture_change_fails_even_if_the_number_of_examples_is_unchanged(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fixture = root / "fixture"
            for directory in ("src", "tests"):
                shutil.copytree(runner.FIXTURE / directory, fixture / directory)
            data = fixture / "tests/nist-worked.txt"
            data.write_bytes(data.read_bytes().replace(b"3247184b", b"3247184a", 1))
            with patch.object(runner, "FIXTURE", fixture), self.assertRaisesRegex(ValueError, "NIST fixture"):
                runner.prepare(root, "brynja-crypto", {"brynja-crypto": "0.2.0"})

    def test_archive_registration_covers_every_packaged_crate_and_helper(self):
        registry = tomllib.loads((runner.ROOT / "verification/checks.toml").read_text())
        check, = (c for c in registry["checks"] if
                  (c["component"], c["id"]) == ("aes_gcm", "packaged-public-api"))
        self.assertEqual(check["command"], ["python3", "scripts/aes-gcm/check-packaged-api.py"])
        paths = {p for group in check["inputs"] for p in registry["groups"][group].get("paths", [])}
        required = {f"crates/{name}" for name in runner.pkg.MODERN}
        self.assertTrue(required | {check["command"][1], "scripts/ghash/check-packaged-api.py",
                        "scripts/hkdf/check-hkdf-public-api.py", "scripts/repository/facade_cargo_environment.py",
                        "assurance/aes-gcm-consumer/tests", "assurance/aes-gcm-consumer/src"} <= paths)
        self.assertEqual(check["success"]["contains"], ["AES_GCM_ARCHIVE_COMPLETE"])


if __name__ == "__main__":
    unittest.main()
