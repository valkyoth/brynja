"""Replay pinned LLVM listings and exercise linked-code review rejection paths."""
import runpy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

C = runpy.run_path(str(Path(__file__).with_name("check-linked-screen.py")))
RECORDS = C["OBS"] / "linked-timing"


class LinkedReview(unittest.TestCase):
    def test_recorded_endpoints(self):
        metadata = [RECORDS / arch / (v + ".json") for arch in C["CONFIG"] for v in C["VERSIONS"]]
        self.assertEqual(C["digest"](b"".join(p.read_bytes() for p in sorted(metadata))),
                         "f9418bee00f60f840f8e4c7f28c353306eed3704c0de44d42091e60fda7b3acb")
        for arch in C["CONFIG"]:
            with self.subTest(arch=arch):
                C["replay"](arch, RECORDS / arch)

    def test_reject_wrong_executable_before_decoder(self):
        with tempfile.TemporaryDirectory() as tmp, patch("subprocess.check_output") as decoder:
            root = Path(tmp)
            (root / "1.90.0").write_bytes(b"not the timing binary")
            with self.assertRaisesRegex(ValueError, "executable"):
                C["collect"]("x86", root, root / "review")
            decoder.assert_not_called()
            self.assertFalse((root / "review").exists())

    def test_startup_or_unrelated_instructions_do_not_cover_the_batch(self):
        text = (RECORDS / "arm-mac/1.90.0.asm").read_text()
        before, update = text.split("\n000000010000389c ", 1)
        self.assertIn("pmull.1q", before)  # Startup still has working instructions.
        for broken in (before + "\n000000010000389c " + update.replace("pmull.1q", "nop"),
                       text.replace("Ghash::update", "Ghash::new", 1),
                       text.replace("Timespec::now", "example::now", 1)):
            with self.assertRaises(ValueError):
                C["review"]("arm-mac", broken)

    def test_branch_inside_product_span_rejected(self):
        text = (RECORDS / "rv64/1.100.0.asm").read_text()
        marker = "\tclmulh\t"
        index = text.index("\n", text.index(marker))
        changed = text[:index] + "\n   1284e:       blt a0, a1, 0x12860" + text[index:]
        with self.assertRaisesRegex(ValueError, "branch or call"):
            C["review"]("rv64", changed)


if __name__ == "__main__":
    unittest.main()
