"""Runner regressions; these do not require a copy of the NIST archive."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("gcmvs", Path(__file__).with_name("check-gcmvs.py"))
gcmvs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gcmvs)


class GcmvsTests(unittest.TestCase):
    def test_wrong_bytes_are_rejected_before_opening_zip(self):
        with tempfile.TemporaryDirectory() as root, patch.object(gcmvs, "SIZE", 4):
            path = Path(root) / "fixture.zip"
            path.write_bytes(b"test")
            with patch.object(gcmvs.zipfile, "ZipFile") as reader, self.assertRaisesRegex(ValueError, "wrong GCMVS"):
                gcmvs.corpus(path)
            reader.assert_not_called()

    def test_counts_lengths_and_rejection_labels_are_checked_even_for_exclusions(self):
        group = (8, 0, 0, 32)
        heading = "[Keylen = 128]\n[IVlen = 8]\n[PTlen = 0]\n[AADlen = 0]\n[Taglen = 32]"
        body = "\n\n".join(f"Count = {n}\nKey = {'00'*16}\nIV = 00\nAAD = \nCT = \nTag = 00000000\nFAIL"
                           for n in range(15))
        sample = "# synthetic parser test\n\n" + heading + "\n\n" + body
        with patch.object(gcmvs, "GRID", {group}):
            def replay(source, mode="Decrypt"):
                return list(gcmvs.rows(source.encode("ascii"), mode, 128))
            self.assertEqual([k for k, _ in replay(sample)], ["excluded"] * 15)
            for bad in (sample.replace("Count = 1\n", "Count = 0\n"),
                        sample.replace("IV = 00\n", "IV = 0000\n"),
                        sample.replace("CT = \n", ""),
                        sample.replace("AAD = \n", "AAD = \nAAD = \n")):
                with self.assertRaises(ValueError):
                    replay(bad)
            with self.assertRaises(ValueError):
                replay(sample, "EncryptExtIV")


if __name__ == "__main__":
    unittest.main()
