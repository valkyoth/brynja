#!/usr/bin/env python3
"""Native evidence population and host preflight fail-closed regressions."""
import hashlib
import hmac
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import legacy_hmac_native as native


def valid_output():
    rows = ["test result: ok. 2 passed; 0 failed; 0 ignored;",
            "LEGACY_SHA1_EXECUTION: 70 byte cases, 88 bit cases; no fallback",
            "LEGACY_SHA1_LIFECYCLE: malformed outputs preserve executor; revocation is terminal"]
    for key in (0, 1, 63, 64, 65, 80, 1024):
        for length in (0, 1, 55, 56, 63, 64, 65, 127, 128, 4096):
            digest = hmac.new(bytes([0xa7]) * key, bytes([0x39]) * length, hashlib.sha1).hexdigest()
            rows.append(f"LEGACY_SHA1_BYTE:{key}:{length}:{digest}")
    rows.extend("LEGACY_SHA1_BITS:" + identity.removeprefix("sha1:") + ":" + digest
                for identity, digest in native.legacy_hmac_bits.expected().items() if identity.startswith("sha1:"))
    return "\n".join(rows)


class Native(unittest.TestCase):
    def test_population_and_differentials(self):
        output = valid_output()
        native.validate_output(output)
        rows = output.splitlines()
        mutations = ["", output.replace("2 passed", "0 passed"), output.replace("0 ignored", "2 ignored"),
                     "\n".join(rows[1:]), "\n".join(rows[:1] + rows[2:]),
                     "\n".join(rows[:2] + rows[3:]), "\n".join(rows[:-1]),
                     output + "\n" + rows[-1], output.replace("LEGACY_SHA1_BYTE:0:0:", "LEGACY_SHA1_BYTE:0:1:"),
                     "\n".join(rows[:-1]) + "\nLEGACY_SHA1_BITS:129:1025:00"]
        for index, changed in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(ValueError):
                native.validate_output(changed)

    def test_linux_requires_complete_per_cpu_features(self):
        for machine, flags, expected in (("x86_64", "sha_ni sse2", "+sha,+sse2"),
                                         ("aarch64", "asimd sha1 sha2", "+neon,+sha2")):
            with patch.object(native.platform, "machine", return_value=machine), patch.object(native.platform, "system", return_value="Linux"):
                field = "flags" if machine == "x86_64" else "Features"
                with patch.object(Path, "read_text", return_value=f"{field}: {flags}\n{field}: {flags}\n"):
                    self.assertEqual(native.features(), expected)
                for partial in ("", f"{field}:\n", f"{field}: {flags}\n{field}: missing\n", f"{field}spoof: {flags}\n"):
                    with patch.object(Path, "read_text", return_value=partial), self.assertRaises(ValueError):
                        native.features()

    def test_apple_requires_each_feature_probe(self):
        good = SimpleNamespace(returncode=0, stdout="1\n")
        with patch.object(native.platform, "machine", return_value="arm64"), patch.object(native.platform, "system", return_value="Darwin"):
            with patch.object(native.subprocess, "run", return_value=good) as probe:
                self.assertEqual(native.features(), "+neon,+sha2")
                self.assertEqual(probe.call_count, 3)
            for bad in (SimpleNamespace(returncode=1, stdout="1\n"), SimpleNamespace(returncode=0, stdout="0\n")):
                for index in range(3):
                    responses = [good, good, good]
                    responses[index] = bad
                    with patch.object(native.subprocess, "run", side_effect=responses), self.assertRaises(ValueError):
                        native.features()

    def test_unsupported_host_rejects(self):
        with patch.object(native.platform, "machine", return_value="unknown"), patch.object(native.platform, "system", return_value="unknown"), self.assertRaises(ValueError):
            native.features()


if __name__ == "__main__":
    unittest.main()
