#!/usr/bin/env python3
"""Fail-closed tests for read-only inner-to-outer completion mapping."""
import importlib.util
from pathlib import Path
import tempfile
import unittest


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


O = module("outer_completion_map", "check-aes-fault-outer-completion-map.py")
I_TEST = module("completion_map_tests", "test-aes-fault-completion-map.py")


def fake_dump(retained, outer):
    base = outer["address"]
    return "\n".join([
        I_TEST.fake_dump(retained),
        f'{base:x} <{outer["symbol"]}>:',
        f'  {base + outer["inner_call"]:x}: call 123 <{retained["compute"]}>',
        f'  {base + outer["inner_call"] + 5:x}: test %al,%al',
        f'  {base + outer["inner_call"] + 7:x}: jne 456 <{outer["symbol"]}+0x999>',
        f'  {base + outer["outer_load"]:x}: movdqa 0x123(%rip),%xmm0',
        f'  {base + outer["outer_store"]:x}: movdqu %xmm0,(%rax)',
    ])


def good_output(width, path):
    return "\n".join([
        "Hardware assisted breakpoint 1 at 0x1",
        "Hardware assisted breakpoint 2 at 0x2",
        "Hardware assisted breakpoint 3 at 0x3",
        "BRYNJA_EPHEMERAL_EVIDENCE_CFG=false",
        f"BRYNJA_EPHEMERAL_CASE={width}:{path}",
        "hit Breakpoint 1", "OUTER_ENTRY 1",
        "hit Breakpoint 2", "OUTER_INNER 1", "OUTER_INNER_DONE 1",
        "hit Breakpoint 3", "OUTER_STORE 1", "OUTER_STORE_DONE 1",
        "BRYNJA_EPHEMERAL_STORAGE_CLEARED", "BRYNJA_EPHEMERAL_ACCEPTED",
        O.identity(width, path),
        "test result: ok. 1 passed; 0 failed; 0 ignored;", "exited normally",
    ])


class OuterCompletionMapTests(unittest.TestCase):
    def test_pinned_inner_call_and_outer_store(self):
        for digest, outer in O.SHAPES.items():
            with self.subTest(toolchain=outer["toolchain"]):
                retained = O.RETAINED.SHAPES[digest]
                dump = fake_dump(retained, outer)
                O.inspect(dump, retained, outer)
                for bad in (
                    dump.replace("movdqu %xmm0,(%rax)", "movdqu %xmm0,(%rbx)"),
                    dump.replace(retained["compute"], "other::compute"),
                    dump.replace("test %al,%al", "test %cl,%cl", 1),
                    dump + "\n" + dump,
                ):
                    with self.assertRaises(ValueError):
                        O.inspect(bad, retained, outer)

    def test_all_fixture_markers_required(self):
        for width in O.RETAINED.WIDTHS:
            for path in O.RETAINED.PATHS:
                good = good_output(width, path)
                O.validate_output(good, width, path)
                for bad in (
                    good.replace("OUTER_ENTRY 1", "OUTER_ENTRY 0"),
                    good.replace("OUTER_INNER_DONE 1", "OUTER_INNER_DONE 0"),
                    good.replace("OUTER_STORE_DONE 1", "OUTER_STORE_DONE 0"),
                    good.replace("_ACCEPTED", "_REJECTED_RETIRED"),
                    good.replace("hit Breakpoint 3", "not hit"),
                ):
                    with self.assertRaises(ValueError):
                        O.validate_output(bad, width, path)

    def test_commands_are_read_only_and_identity_is_bounded(self):
        for digest, outer in O.SHAPES.items():
            commands = "\n".join(O.commands(O.RETAINED.SHAPES[digest], outer))
            self.assertIn("OUTER_INNER_DONE", commands)
            self.assertIn("OUTER_STORE_DONE", commands)
            self.assertNotIn("set *", commands)
            self.assertNotIn("dump ", commands)
        for width, path in ((8, "public"), (16, "unknown")):
            with self.assertRaises(ValueError):
                O.identity(width, path)

    def test_unknown_artifact_rejected_before_debugger(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "fake-elf"
            binary.write_bytes(b"\x7fELF\x02\x01" + bytes(12) + b"\x3e\x00" + bytes(100))
            with self.assertRaisesRegex(ValueError, "unreviewed outer completion artifact"):
                O.observe(binary, objdump="missing-objdump", gdb="missing-gdb")


if __name__ == "__main__":
    unittest.main()
