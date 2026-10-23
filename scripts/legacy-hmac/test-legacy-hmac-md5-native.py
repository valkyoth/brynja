#!/usr/bin/env python3
"""MD5 native driver rejects forged/missing population and incomplete CPU flags."""
import hashlib
import hmac
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import legacy_hmac_md5_native as native


def valid_output():
    rows = ["test result: ok. 3 passed; 0 failed; 0 ignored;", *native.MARKERS]
    for key in (0, 1, 63, 64, 65, 80, 1024):
        for size in (0, 1, 55, 56, 63, 64, 65, 127, 128, 4096):
            digest = hmac.new(bytes([0xa7]) * key, bytes([0x39]) * size, hashlib.md5).hexdigest()
            rows.append(f"LEGACY_MD5_BATCH_BYTE:{key}:{size}:{digest}")
    rows.extend("LEGACY_MD5_BATCH_BITS:" + key.removeprefix("md5:") + ":" + value
                for key, value in native.legacy_hmac_bits.expected().items() if key.startswith("md5:"))
    return "\n".join(rows)


class Native(unittest.TestCase):
    def test_output_population(self):
        original = valid_output()
        native.validate_output(original)
        rows = original.splitlines()
        mutants = ["", original.replace("3 passed", "2 passed"), original.replace("0 ignored", "1 ignored"),
                   "\n".join(rows[:-1]), original + "\n" + rows[-1],
                   original.replace("LEGACY_MD5_BATCH_BYTE:0:0:", "LEGACY_MD5_BATCH_BYTE:0:1:"),
                   "\n".join(rows[:-1]) + "\nLEGACY_MD5_BATCH_BITS:129:1025:00"]
        for marker in native.MARKERS:
            mutants.extend((original.replace(marker, ""), original + "\n" + marker))
        for index, mutant in enumerate(mutants):
            with self.subTest(index=index), self.assertRaises(ValueError):
                native.validate_output(mutant)

    def test_linux_all_processors(self):
        for machine, flag, expected in (("x86_64", "avx2", "+avx2"), ("aarch64", "asimd", "+neon")):
            with patch.object(native.platform, "machine", return_value=machine), patch.object(native.platform, "system", return_value="Linux"):
                field = "flags" if machine == "x86_64" else "Features"
                with patch.object(Path, "read_text", return_value=f"{field}: {flag}\n{field}: {flag}\n"):
                    self.assertEqual(native.features(), expected)
                for bad in ("", f"{field}: none", f"{field}: {flag}\n{field}: missing", f"{field}spoof: {flag}"):
                    with patch.object(Path, "read_text", return_value=bad), self.assertRaises(ValueError):
                        native.features()

    def test_apple_and_unsupported(self):
        with patch.object(native.platform, "machine", return_value="arm64"), patch.object(native.platform, "system", return_value="Darwin"):
            with patch.object(native.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout="1\n")) as probe:
                self.assertEqual(native.features(), "+neon")
                probe.assert_called_once()
            for bad in (SimpleNamespace(returncode=1, stdout="1\n"), SimpleNamespace(returncode=0, stdout="0\n")):
                with patch.object(native.subprocess, "run", return_value=bad), self.assertRaises(ValueError):
                    native.features()
        with patch.object(native.platform, "machine", return_value="unknown"), self.assertRaises(ValueError):
            native.features()


if __name__ == "__main__":
    unittest.main()
