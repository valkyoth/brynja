#!/usr/bin/env python3
"""Fail-closed tests for read-only retained-validation call mapping."""
import importlib.util
from pathlib import Path
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "retained_validation", Path(__file__).with_name(
        "check-aes-fault-retained-validation-map.py"))
R = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(R)


def fake_dump(shape):
    base = shape["compute_address"]
    lines = [f'{base:x} <{shape["compute"]}>:']
    for offset in shape["call_offsets"]:
        call = base + offset
        ops = [
            (call - 3, "mov %r14,%rdi"),
            (call, f'call {shape["validate_address"]:x} <{shape["validate"]}>'),
            (call + 5, "test %al,%al"),
            (call + 7, f'jne {base + 0x120:x} <{shape["compute"]}+0x120>'),
        ]
        lines += [f"  {address:x}: {op}" for address, op in ops]
        if offset == shape["call_offsets"][0]:
            lines.append(f"  {call + 20:x}: call 123456 <brynja_crypto::aes::fault_integrity::schedule::Schedule::transform>")
    return "\n".join(lines)


def good_output(width, owner, path):
    prefix = "BRYNJA_" + owner.upper()
    return "\n".join([
        "Hardware assisted breakpoint 1 at 0x1",
        "Hardware assisted breakpoint 2 at 0x2",
        prefix + "_EVIDENCE_CFG=false", f"{prefix}_CASE={width}:{path}",
        "hit Breakpoint 1", "VALIDATE_PRE 1", "VALIDATE_PRE_DONE 1",
        "hit Breakpoint 2", "VALIDATE_POST 1", "VALIDATE_POST_DONE 1",
        prefix + "_STORAGE_CLEARED", prefix + "_ACCEPTED",
        R.identity(width, owner, path),
        "test result: ok. 1 passed; 0 failed; 0 ignored;", "exited normally",
    ])


class RetainedValidationMapTests(unittest.TestCase):
    def test_reviewed_shapes_and_distinct_calls(self):
        for shape in R.SHAPES.values():
            with self.subTest(toolchain=shape["toolchain"]):
                R.inspect(fake_dump(shape), shape)
                dump = fake_dump(shape)
                for bad in (
                    dump.replace(shape["validate"], "other::validate", 1),
                    dump.replace("mov %r14,%rdi", "mov %rax,%rdi", 1),
                    dump.replace("test %al,%al", "test %cl,%cl", 1),
                    dump.replace("jne ", "je ", 1),
                    dump.replace("schedule::Schedule::transform", "other::transform"),
                    dump + "\n" + dump,
                ):
                    with self.assertRaises(ValueError):
                        R.inspect(bad, shape)

    def test_all_fixture_markers_required(self):
        for width in R.WIDTHS:
            for owner in R.OWNERS:
                for path in R.PATHS:
                    good = good_output(width, owner, path)
                    R.validate(good, width, owner, path)
                    for bad in (
                        good.replace("VALIDATE_PRE_DONE 1", "VALIDATE_PRE_DONE 0"),
                        good.replace("VALIDATE_POST 1", "VALIDATE_POST 0"),
                        good.replace("_ACCEPTED", "_REJECTED_RETIRED"),
                        good.replace("hit Breakpoint 2", "not hit"),
                    ):
                        with self.assertRaises(ValueError):
                            R.validate(bad, width, owner, path)

    def test_commands_do_not_mutate_or_dump(self):
        for shape in R.SHAPES.values():
            commands = "\n".join(R.commands(shape))
            self.assertIn("VALIDATE_PRE_DONE", commands)
            self.assertIn("VALIDATE_POST_DONE", commands)
            self.assertNotIn("set *", commands)
            self.assertNotIn("dump ", commands)

    def test_unknown_artifact_rejected_before_debugger(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "fake-elf"
            binary.write_bytes(b"\x7fELF\x02\x01" + bytes(12) + b"\x3e\x00" + bytes(100))
            with self.assertRaisesRegex(ValueError, "unreviewed retained artifact"):
                R.observe(binary, objdump="missing-objdump", gdb="missing-gdb")

    def test_fixture_identity_is_bounded(self):
        for args in ((8, "cached", "public"), (16, "other", "public"),
                     (16, "cached", "other")):
            with self.assertRaises(ValueError):
                R.identity(*args)


if __name__ == "__main__":
    unittest.main()
