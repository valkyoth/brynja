#!/usr/bin/env python3
"""Fail-closed tests for the finite lifecycle-completion debugger probe."""
import importlib.util
from pathlib import Path
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "lifecycle_complete_probe", Path(__file__).with_name(
        "check-aes-fault-lifecycle-complete.py"))
S = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(S)


def good_output(width, owner, path):
    prefix = "BRYNJA_" + owner.upper()
    return "\n".join([
        *[f"Hardware assisted breakpoint {i} at 0x{i}" for i in range(1, 4)],
        prefix + "_EVIDENCE_CFG=false", f"{prefix}_CASE={width}:{path}",
        "hit Breakpoint 1", "LIFECYCLE_PRE 1",
        "hit Breakpoint 2", "LIFECYCLE_MUTATED 1", "LIFECYCLE_REJECTED 1",
        "hit Breakpoint 3", "LIFECYCLE_CALLER 1",
        prefix + "_STORAGE_CLEARED", prefix + "_REJECTED_RETIRED",
        S.RETAINED.identity(width, owner, path),
        "test result: ok. 1 passed; 0 failed; 0 ignored;", "exited normally",
    ])


class LifecycleCompletionTests(unittest.TestCase):
    def test_rejection_markers_and_retirement_are_mandatory(self):
        for width in S.RETAINED.WIDTHS:
            for owner in S.RETAINED.OWNERS:
                for path in ("encrypt", "decrypt"):
                    good = good_output(width, owner, path)
                    S.validate_output(good, width, owner, path)
                    for marker in ("LIFECYCLE_PRE 1", "LIFECYCLE_MUTATED 1",
                                   "LIFECYCLE_REJECTED 1", "LIFECYCLE_CALLER 1"):
                        with self.assertRaises(ValueError):
                            S.validate_output(good.replace(marker, marker[:-1] + "0"),
                                              width, owner, path)
                    with self.assertRaises(ValueError):
                        S.validate_output(good.replace("_REJECTED_RETIRED", "_ACCEPTED"),
                                          width, owner, path)

    def test_one_declared_byte_mutation_only(self):
        for digest, owner_shape in S.DEST.SHAPES.items():
            result_shape = S.RESULT_MAP.SHAPES[digest]
            caller_shape = S.CALLER.SHAPES[digest]
            for owner in S.RETAINED.OWNERS:
                commands = S.commands(owner_shape["owners"][owner],
                                      result_shape["owners"][owner],
                                      caller_shape["callers"][owner],
                                      S.RESULT.CIPHERS[16])
                self.assertEqual(sum(command.startswith("set {unsigned char}")
                                     for command in commands), 1)
                self.assertIn("set {unsigned char}$state = 0x3d", commands)
                self.assertIn("LIFECYCLE_CALLER", "\n".join(commands))
                self.assertNotIn("set $al = 0", commands)

    def test_each_codeword_byte_and_bit_has_one_exact_mutation(self):
        digest = next(iter(S.DEST.SHAPES))
        owner = "cached"
        owner_shape = S.DEST.SHAPES[digest]["owners"][owner]
        local = S.RESULT_MAP.SHAPES[digest]["owners"][owner]
        caller = S.CALLER.SHAPES[digest]["callers"][owner]
        for byte in range(16):
            for bit in range(8):
                commands = S.commands(owner_shape, local, caller,
                                      S.RESULT.CIPHERS[16], byte, bit)
                writes = [command for command in commands
                          if command.startswith("set {unsigned char}")]
                self.assertEqual(len(writes), 1)
                self.assertIn(f"0x{0x3c ^ (1 << bit):02x}", writes[0])
                self.assertIn("$state" if byte == 0 else f"$state+{byte}", writes[0])
                self.assertIn("LIFECYCLE_MUTATED", "\n".join(commands))
        for byte, bit in ((-1, 0), (16, 0), (0, -1), (0, 8)):
            with self.assertRaises(ValueError):
                S.commands(owner_shape, local, caller, S.RESULT.CIPHERS[16], byte, bit)

    def test_static_boundaries_are_the_existing_pinned_shapes(self):
        self.assertEqual(set(S.DEST.SHAPES), set(S.RESULT_MAP.SHAPES))
        self.assertEqual(set(S.DEST.SHAPES), set(S.CALLER.SHAPES))
        for digest, owner_shape in S.DEST.SHAPES.items():
            for owner in S.RETAINED.OWNERS:
                self.assertLess(owner_shape["owners"][owner]["permit"],
                                S.RESULT_MAP.SHAPES[digest]["owners"][owner]["complete"])

    def test_unknown_artifact_rejected_before_debugger(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "unreviewed.elf"
            path.write_bytes(b"\x7fELF\x02\x01" + b"\x00" * 12 + b"\x3e\x00")
            with self.assertRaises(ValueError):
                S.observe(path)


if __name__ == "__main__":
    unittest.main()
