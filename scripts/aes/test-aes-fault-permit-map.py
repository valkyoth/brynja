#!/usr/bin/env python3
"""Fail-closed tests for read-only final-permit boundary mapping."""
import importlib.util
from pathlib import Path
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "permit_map", Path(__file__).with_name("check-aes-fault-permit-map.py"))
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)


def fake_dump(shape):
    base = shape["address"]
    return "\n".join([
        f"{base:x} <{P.SYMBOL}>:",
        f'  {base + shape["deny_load"]:x}: movdqu (%r9),%xmm0',
        f'  {base + shape["deny_store"]:x}: movdqu %xmm0,(%r8)',
        f'  {base + shape["observe_call"]:x}: call 123 <Candidate::observe>',
        f'  {base + shape["guarded_call"]:x}: call 456 <guarded_copy::tentative_copy_16>',
        f'  {base + shape["return_offset"]:x}: ret',
    ])


def good_output(width, owner, path):
    prefix = "BRYNJA_" + owner.upper()
    return "\n".join([
        "Hardware assisted breakpoint 1 at 0x1",
        "Hardware assisted breakpoint 2 at 0x2",
        "Hardware assisted breakpoint 3 at 0x3",
        prefix + "_EVIDENCE_CFG=false", f"{prefix}_CASE={width}:{path}",
        "hit Breakpoint 1", "PERMIT_ENTRY 1",
        "hit Breakpoint 2", "PERMIT_DENIED 1",
        "hit Breakpoint 3", "PERMIT_RETURN 1",
        prefix + "_STORAGE_CLEARED", prefix + "_ACCEPTED",
        P.RETAINED.identity(width, owner, path),
        "test result: ok. 1 passed; 0 failed; 0 ignored;", "exited normally",
    ])


class PermitMapTests(unittest.TestCase):
    def test_reviewed_deny_first_shape(self):
        for shape in P.SHAPES.values():
            with self.subTest(toolchain=shape["toolchain"]):
                dump = fake_dump(shape)
                P.inspect(dump, shape)
                for bad in (
                    dump.replace("(%r9),%xmm0", "(%r8),%xmm0"),
                    dump.replace("%xmm0,(%r8)", "%xmm0,(%r9)"),
                    dump.replace("Candidate::observe", "Candidate::other"),
                    dump.replace("guarded_copy::tentative_copy_16", "other::copy"),
                    dump + "\n  0: ret",
                    dump + "\n" + dump,
                ):
                    with self.assertRaises(ValueError):
                        P.inspect(bad, shape)

    def test_all_fixture_markers_required(self):
        for width in P.RETAINED.WIDTHS:
            for owner in P.RETAINED.OWNERS:
                for path in P.RETAINED.PATHS:
                    good = good_output(width, owner, path)
                    P.validate_output(good, width, owner, path)
                    for bad in (
                        good.replace("PERMIT_ENTRY 1", "PERMIT_ENTRY 0"),
                        good.replace("PERMIT_DENIED 1", "PERMIT_DENIED 0"),
                        good.replace("PERMIT_RETURN 1", "PERMIT_RETURN 0"),
                        good.replace("_ACCEPTED", "_REJECTED_RETIRED"),
                        good.replace("hit Breakpoint 3", "not hit"),
                    ):
                        with self.assertRaises(ValueError):
                            P.validate_output(bad, width, owner, path)

    def test_commands_are_read_only_and_cover_full_answer(self):
        for shape in P.SHAPES.values():
            commands = "\n".join(P.commands(shape, P.RESULT.CIPHERS[16]))
            self.assertIn("PERMIT_DENIED", commands)
            self.assertIn("PERMIT_RETURN", commands)
            self.assertEqual(commands.count(
                P.RESULT.equal_words('$destination', P.RESULT.CIPHERS[16])), 3)
            self.assertNotIn("set *", commands)
            self.assertNotIn("dump ", commands)

    def test_unknown_artifact_rejected_before_debugger(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "fake-elf"
            binary.write_bytes(b"\x7fELF\x02\x01" + bytes(12) + b"\x3e\x00" + bytes(100))
            with self.assertRaisesRegex(ValueError, "unreviewed permit artifact"):
                P.observe(binary, objdump="missing-objdump", gdb="missing-gdb")


if __name__ == "__main__":
    unittest.main()
