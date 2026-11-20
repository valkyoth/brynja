#!/usr/bin/env python3
"""Fail-closed tests for read-only primary/secondary result mapping."""
import importlib.util
from pathlib import Path
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "result_map", Path(__file__).with_name("check-aes-fault-result-map.py"))
R = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(R)


def fake_dump(shape):
    base = shape["compute_address"]
    lines = [f'{base:x} <{shape["compute"]}>:',
             f"  {base + 0x12:x}: mov %rcx,%r15",
             f"  {base + 0x15:x}: mov %rdx,%r12"]
    for width, offset in R.PRIMARY_CALLS.items():
        lines.append(f"  {base + offset - 3:x}: mov %r12,%rdi")
        lines.append(f"  {base + offset:x}: call abc <brynja_crypto::aes::portable::"
                     f"transform_{width}>")
    lines += [
        f"  {base + R.PRIMARY_RETURN:x}: test %al,%al",
        f"  {base + R.SECONDARY_CALL - 3:x}: mov %r15,%rdx",
        f"  {base + R.SECONDARY_CALL:x}: call def <brynja_crypto::aes::"
        "fault_integrity::schedule::Schedule::transform>",
        f"  {base + R.SECONDARY_RETURN:x}: test %al,%al",
        f'  {base + 0xe9:x}: call 123 <{shape["validate"]}>',
    ]
    return "\n".join(lines)


def good_output(width, owner, path):
    prefix = "BRYNJA_" + owner.upper()
    return "\n".join([
        "Hardware assisted breakpoint 1 at 0x1",
        "Hardware assisted breakpoint 2 at 0x2",
        prefix + "_EVIDENCE_CFG=false", f"{prefix}_CASE={width}:{path}",
        "hit Breakpoint 1", "RESULT_PRIMARY 1",
        "hit Breakpoint 2", "RESULT_SECONDARY 1",
        prefix + "_STORAGE_CLEARED", prefix + "_ACCEPTED",
        R.RETAINED.identity(width, owner, path),
        "test result: ok. 1 passed; 0 failed; 0 ignored;", "exited normally",
    ])


class ResultMapTests(unittest.TestCase):
    def test_reviewed_shapes_and_order(self):
        for shape in R.RETAINED.SHAPES.values():
            with self.subTest(toolchain=shape["toolchain"]):
                dump = fake_dump(shape)
                R.inspect(dump, shape)
                for bad in (
                    dump.replace("portable::transform_16", "other::transform_16"),
                    dump.replace("Schedule::transform", "Schedule::other"),
                    dump.replace("mov %rdx,%r12", "mov %rax,%r12"),
                    dump.replace("mov %r15,%rdx", "mov %r14,%rdx"),
                    dump.replace("test %al,%al", "test %cl,%cl", 1),
                    dump.replace(shape["validate"], "other::validate"),
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
                        good.replace("RESULT_PRIMARY 1", "RESULT_PRIMARY 0"),
                        good.replace("RESULT_SECONDARY 1", "RESULT_SECONDARY 0"),
                        good.replace("_ACCEPTED", "_REJECTED_RETIRED"),
                        good.replace("hit Breakpoint 2", "not hit"),
                    ):
                        with self.assertRaises(ValueError):
                            R.validate_output(bad, width, owner, path)

    def test_expected_words_and_read_only_commands(self):
        self.assertEqual(R.equal_words("p", R.PLAIN).count("=="), 4)
        for width in R.RETAINED.WIDTHS:
            self.assertNotEqual(R.equal_words("p", R.PLAIN),
                                R.equal_words("p", R.CIPHERS[width]))
        for shape in R.RETAINED.SHAPES.values():
            commands = "\n".join(R.commands(shape, R.CIPHERS[16]))
            self.assertIn("RESULT_PRIMARY", commands)
            self.assertIn("RESULT_SECONDARY", commands)
            self.assertNotIn("set *", commands)
            self.assertNotIn("dump ", commands)

    def test_unknown_artifact_rejected_before_debugger(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "fake-elf"
            binary.write_bytes(b"\x7fELF\x02\x01" + bytes(12) + b"\x3e\x00" + bytes(100))
            with self.assertRaisesRegex(ValueError, "unreviewed result artifact"):
                R.observe(binary, objdump="missing-objdump", gdb="missing-gdb")


if __name__ == "__main__":
    unittest.main()
