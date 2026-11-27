"""Negative controls for interpreting installed ChaCha20 results."""
from pathlib import Path
import subprocess
import struct
import tempfile
import unittest
from unittest.mock import Mock, patch

from chacha20_installed import ciphertext_controls, installed, signatures


def record(counter, size):
    return struct.pack("<IH", counter, size) + bytes(44 + size * 2)


class Installed(unittest.TestCase):
    def exercise(self, *, selected="sse2", linked=("sse2",), report="PASS 302 sse2",
                 rejection=(2, "", "ciphertext differs"), suffix="", second=None, stripped=False):
        corpus = record(0xfffffffc, 256) + record(0xffffffff, 64)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pkg = Mock()
            def execute(cmd, cwd, env):
                if cmd[0] == "llvm-nm":
                    rows = ["00aa T main", *(f"00ff t brynja_crypto_cpu::chacha20_{isa}::packed_rounds{suffix}" for isa in linked)]
                    return Mock(stdout="" if stripped else "\n".join(rows))
                return Mock(stdout=report)
            pkg.run.side_effect = execute
            changes = []
            def rerun(cmd, **kwargs):
                actual = Path(cmd[-1]).read_bytes()
                changes.append([i for i, (a, b) in enumerate(zip(actual, corpus, strict=True)) if a != b])
                return subprocess.CompletedProcess(cmd, *(second if second and len(changes) == 2 else rejection))
            with patch("chacha20_installed.subprocess.run", side_effect=rerun):
                installed(pkg, ["cargo"], root, {}, [], [], selected, corpus)
            self.assertEqual(changes, [[50 + 256], [len(corpus) - 1]])

    def test_accepts_only_matching_observations(self):
        self.exercise()
        self.exercise(suffix="::h0123456789abcdef")
        self.exercise(selected=None, linked=(), report="PASS 302 scalar")
        for change in ({"linked": ()}, {"linked": ("neon",)}, {"linked": ("sse2", "neon")},
                       {"selected": None}, {"report": "PASS 302 scalar"}, {"report": "PASS 301 sse2"},
                       {"suffix": "_tail"}, {"suffix": "::h123"}, {"second": (0, "", "")},
                       {"selected": None, "linked": (), "report": "PASS 302 scalar", "stripped": True},
                       {"rejection": (0, "PASS 302 sse2", "")}, {"rejection": (2, "", "parse error")}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.exercise(**change)

    def test_controls_require_complete_admitted_records_of_both_shapes(self):
        for bad in (b"", b"x", record(0, 256), record(0xffffffff, 64),
                    record(0, 256) + record(0xffffffff, 64)[:-1],
                    record(0xffffffff, 256) + record(0xffffffff, 64)):
            with self.assertRaises(ValueError):
                ciphertext_controls(bad)

    def test_signature_probes_removed_after_success_and_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            pkg = Mock()
            for matches in (True, False):
                pkg.diagnostic_matches.return_value = matches
                if matches:
                    signatures(pkg, [], root, {}, [], [], "Owner")
                else:
                    with self.assertRaises(ValueError):
                        signatures(pkg, [], root, {}, [], [], "Owner")
                self.assertFalse((root / "src/bin/contract.rs").exists())


if __name__ == "__main__":
    unittest.main()
