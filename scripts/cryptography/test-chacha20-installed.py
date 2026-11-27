"""Negative controls for interpreting installed ChaCha20 results."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from chacha20_installed import installed


class Installed(unittest.TestCase):
    def exercise(self, *, selected="sse2", linked=("sse2",), report="PASS 302 sse2",
                 rejection=(2, "", "ciphertext differs")):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pkg = Mock()
            def execute(cmd, cwd, env):
                if cmd[0] == "llvm-nm":
                    return Mock(stdout="\n".join(f"chacha20_{isa}::packed_rounds" for isa in linked))
                return Mock(stdout=report)
            pkg.run.side_effect = execute
            def rerun(cmd, **kwargs):
                self.assertEqual(Path(cmd[-1]).read_bytes(), b"ac")
                return subprocess.CompletedProcess(cmd, *rejection)
            with patch("chacha20_installed.subprocess.run", side_effect=rerun):
                installed(pkg, ["cargo"], root, {}, [], [], selected, b"ab")

    def test_accepts_only_matching_observations(self):
        self.exercise()
        self.exercise(selected=None, linked=(), report="PASS 302 scalar")
        for change in ({"linked": ()}, {"linked": ("neon",)}, {"linked": ("sse2", "neon")},
                       {"selected": None}, {"report": "PASS 302 scalar"}, {"report": "PASS 301 sse2"},
                       {"rejection": (0, "PASS 302 sse2", "")}, {"rejection": (2, "", "parse error")}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.exercise(**change)


if __name__ == "__main__":
    unittest.main()
