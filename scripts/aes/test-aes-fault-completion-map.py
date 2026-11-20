#!/usr/bin/env python3
"""Fail-closed tests for the read-only inner completion store mapper."""
import importlib.util
from pathlib import Path
import tempfile
import unittest


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


C = module("completion_map", "check-aes-fault-completion-map.py")
R_TEST = module("result_map_tests", "test-aes-fault-result-map.py")


def fake_dump(shape):
    base = shape["compute_address"]
    lines = [R_TEST.fake_dump(shape)]
    for offset, op in (
        (0x0c, "mov %r9,%rbx"),
        (0xee, "test %al,%al"),
        (0xf0, f'jne {base + 0x120:x} <{shape["compute"]}+0x120>'),
        (0xf2, "movdqa 0x10(%rsp),%xmm0"),
        (0xf8, "pcmpeqb (%rsp),%xmm0"),
        (0xfd, "pmovmskb %xmm0,%eax"),
        (0x101, "cmp $0xffff,%eax"),
        (0x106, f'jne {base + 0x120:x} <{shape["compute"]}+0x120>'),
        (0x108, "movdqa 0x123(%rip),%xmm0"),
        (C.STORE_OFFSET, "movdqu %xmm0,(%rbx)"),
    ):
        lines.append(f"  {base + offset:x}: {op}")
    return "\n".join(lines)


def good_output(width, owner, path):
    prefix = "BRYNJA_" + owner.upper()
    return "\n".join([
        "Hardware assisted breakpoint 1 at 0x1",
        prefix + "_EVIDENCE_CFG=false", f"{prefix}_CASE={width}:{path}",
        "hit Breakpoint 1", "COMPLETION_BEFORE 1", "COMPLETION_AFTER 1",
        prefix + "_STORAGE_CLEARED", prefix + "_ACCEPTED",
        C.RETAINED.identity(width, owner, path),
        "test result: ok. 1 passed; 0 failed; 0 ignored;", "exited normally",
    ])


class CompletionMapTests(unittest.TestCase):
    def test_store_shape_and_preceding_guards(self):
        for shape in C.RETAINED.SHAPES.values():
            with self.subTest(toolchain=shape["toolchain"]):
                dump = fake_dump(shape)
                C.inspect(dump, shape)
                for bad in (
                    dump.replace("mov %r9,%rbx", "mov %r8,%rbx"),
                    dump.replace("pmovmskb %xmm0,%eax", "pmovmskb %xmm1,%eax"),
                    dump.replace("movdqu %xmm0,(%rbx)", "movdqu %xmm0,(%rax)"),
                    dump.replace("jne ", "je ", 1),
                    dump + "\n" + dump,
                ):
                    with self.assertRaises(ValueError):
                        C.inspect(bad, shape)

    def test_all_fixture_markers_required(self):
        for width in C.RETAINED.WIDTHS:
            for owner in C.RETAINED.OWNERS:
                for path in C.RETAINED.PATHS:
                    good = good_output(width, owner, path)
                    C.validate_output(good, width, owner, path)
                    for bad in (
                        good.replace("COMPLETION_BEFORE 1", "COMPLETION_BEFORE 0"),
                        good.replace("COMPLETION_AFTER 1", "COMPLETION_AFTER 0"),
                        good.replace("_ACCEPTED", "_REJECTED_RETIRED"),
                        good.replace("hit Breakpoint 1", "not hit"),
                    ):
                        with self.assertRaises(ValueError):
                            C.validate_output(bad, width, owner, path)

    def test_commands_are_read_only(self):
        for shape in C.RETAINED.SHAPES.values():
            commands = "\n".join(C.commands(shape))
            self.assertIn("COMPLETION_BEFORE", commands)
            self.assertIn("COMPLETION_AFTER", commands)
            self.assertNotIn("set *", commands)
            self.assertNotIn("dump ", commands)

    def test_unknown_artifact_rejected_before_debugger(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "fake-elf"
            binary.write_bytes(b"\x7fELF\x02\x01" + bytes(12) + b"\x3e\x00" + bytes(100))
            with self.assertRaisesRegex(ValueError, "unreviewed completion artifact"):
                C.observe(binary, objdump="missing-objdump", gdb="missing-gdb")


if __name__ == "__main__":
    unittest.main()
