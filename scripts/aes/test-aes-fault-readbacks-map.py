#!/usr/bin/env python3
"""Fail-closed tests for read-only paired guarded-write checks."""
import importlib.util
from pathlib import Path
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "readbacks_map", Path(__file__).with_name("check-aes-fault-readbacks-map.py"))
R = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(R)


def fake_dump(shape):
    base = shape["guarded_address"]
    return "\n".join([
        f"{base:x} <{R.GUARDED}>:",
        f'  {base + shape["flag_offsets"][0]:x}: xor %r8d,%r8d',
        f'  {base + shape["call_offsets"][0]:x}: '
        f'call {shape["check_address"]:x} <{R.CHECK}>',
        f'  {base + shape["flag_offsets"][1]:x}: mov $0x1,%r8d',
        f'  {base + shape["call_offsets"][1]:x}: '
        f'call {shape["check_address"]:x} <{R.CHECK}>',
    ])


def good_output(width, owner, path):
    prefix = "BRYNJA_" + owner.upper()
    return "\n".join([
        "Hardware assisted breakpoint 1 at 0x1",
        "Hardware assisted breakpoint 2 at 0x2",
        prefix + "_EVIDENCE_CFG=false", f"{prefix}_CASE={width}:{path}",
        "hit Breakpoint 1", "READBACK_FORWARD 1", "READBACK_FORWARD_DONE 1",
        "hit Breakpoint 2", "READBACK_REVERSE 1", "READBACK_REVERSE_DONE 1",
        prefix + "_STORAGE_CLEARED", prefix + "_ACCEPTED",
        R.RETAINED.identity(width, owner, path),
        "test result: ok. 1 passed; 0 failed; 0 ignored;", "exited normally",
    ])


class ReadbacksMapTests(unittest.TestCase):
    def test_pinned_distinct_calls_and_selectors(self):
        for shape in R.SHAPES.values():
            with self.subTest(toolchain=shape["toolchain"]):
                dump = fake_dump(shape)
                R.inspect(dump, shape)
                for bad in (
                    dump.replace("xor %r8d,%r8d", "mov $0x1,%r8d"),
                    dump.replace("mov $0x1,%r8d", "xor %r8d,%r8d"),
                    dump.replace(R.CHECK, "other::check", 1),
                    dump + f'\n  {shape["guarded_address"] + 0x300:x}: '
                    f'call {shape["check_address"]:x} <{R.CHECK}>',
                    dump + "\n" + dump,
                ):
                    with self.assertRaises(ValueError):
                        R.inspect(bad, shape)

    def test_all_fixture_markers_required(self):
        for width in R.RETAINED.WIDTHS:
            for owner in R.RETAINED.OWNERS:
                for path in R.RETAINED.PATHS:
                    good = good_output(width, owner, path)
                    R.validate_output(good, width, owner, path)
                    for bad in (
                        good.replace("READBACK_FORWARD 1", "READBACK_FORWARD 0"),
                        good.replace("READBACK_FORWARD_DONE 1", "READBACK_FORWARD_DONE 0"),
                        good.replace("READBACK_REVERSE 1", "READBACK_REVERSE 0"),
                        good.replace("READBACK_REVERSE_DONE 1", "READBACK_REVERSE_DONE 0"),
                        good.replace("_ACCEPTED", "_REJECTED_RETIRED"),
                        good.replace("hit Breakpoint 2", "not hit"),
                    ):
                        with self.assertRaises(ValueError):
                            R.validate_output(bad, width, owner, path)

    def test_commands_are_read_only_and_cover_full_answer(self):
        for shape in R.SHAPES.values():
            commands = "\n".join(R.commands(shape, R.RESULT.CIPHERS[16]))
            self.assertIn("READBACK_FORWARD_DONE", commands)
            self.assertIn("READBACK_REVERSE_DONE", commands)
            self.assertEqual(commands.count(
                R.RESULT.equal_words('$checked', R.RESULT.CIPHERS[16])), 2)
            self.assertNotIn("set *", commands)
            self.assertNotIn("dump ", commands)

    def test_unknown_artifact_rejected_before_debugger(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "fake-elf"
            binary.write_bytes(b"\x7fELF\x02\x01" + bytes(12) + b"\x3e\x00" + bytes(100))
            with self.assertRaisesRegex(ValueError, "unreviewed readback artifact"):
                R.observe(binary, objdump="missing-objdump", gdb="missing-gdb")


if __name__ == "__main__":
    unittest.main()
