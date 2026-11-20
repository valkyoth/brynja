#!/usr/bin/env python3
"""Fail-closed tests for read-only actual secret-destination mapping."""
import importlib.util
from pathlib import Path
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "secret_destination_map", Path(__file__).with_name(
        "check-aes-fault-secret-destination-map.py"))
S = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(S)


def fake_dump(shape):
    lines = [f'{shape["validate_address"]:x} <{S.VALIDATE}>:',
             f'  {shape["validate_address"] + 0x14:x}: xor %r8d,%r8d',
             f'  {shape["validate_address"] + 0x17:x}: '
             f'call {shape["check_address"]:x} <{S.CHECK}>',
             f'  {shape["validate_address"] + 0x2a:x}: mov $0x1,%r8d',
             f'  {shape["validate_address"] + 0x30:x}: '
             f'call {shape["check_address"]:x} <{S.CHECK}>']
    for owner in shape["owners"].values():
        lines.append(f'{owner["address"]:x} <{owner["symbol"]}>:')
        for label, target in (("guarded", S.GUARDED),
                              ("validate", S.VALIDATE), ("permit", S.PERMIT)):
            lines.append(f'  {owner["address"] + owner[label]:x}: call 123 <{target}>')
    return "\n".join(lines)


def good_output(width, owner, path):
    prefix = "BRYNJA_" + owner.upper()
    return "\n".join([
        *[f"Hardware assisted breakpoint {i} at 0x{i}" for i in range(1, 5)],
        prefix + "_EVIDENCE_CFG=false", f"{prefix}_CASE={width}:{path}",
        "hit Breakpoint 1", "SECRET_ENTRY 1",
        "hit Breakpoint 2", "SECRET_STAGE 1", "SECRET_STAGE_DONE 1",
        "hit Breakpoint 3", "SECRET_DESTINATION 1", "SECRET_DESTINATION_DONE 1",
        "hit Breakpoint 4", "SECRET_PERMIT_NEXT 1",
        prefix + "_STORAGE_CLEARED", prefix + "_ACCEPTED",
        S.RETAINED.identity(width, owner, path),
        "test result: ok. 1 passed; 0 failed; 0 ignored;", "exited normally",
    ])


class SecretDestinationMapTests(unittest.TestCase):
    def test_owner_order_and_two_validator_calls_are_pinned(self):
        for shape in S.SHAPES.values():
            with self.subTest(toolchain=shape["toolchain"]):
                dump = fake_dump(shape)
                S.inspect(dump, shape)
                for bad in (
                    dump.replace("xor %r8d,%r8d", "mov $0x1,%r8d"),
                    dump.replace(S.CHECK, "other::check", 1),
                    dump.replace(S.VALIDATE, "other::validate", 1),
                    dump.replace(S.PERMIT, "other::permit", 1),
                    dump + "\n" + dump,
                ):
                    with self.assertRaises(ValueError):
                        S.inspect(bad, shape)

    def test_all_secret_fixture_markers_required(self):
        for width in S.RETAINED.WIDTHS:
            for owner in S.RETAINED.OWNERS:
                for path in ("encrypt", "decrypt"):
                    good = good_output(width, owner, path)
                    S.validate_output(good, width, owner, path)
                    for bad in (
                        good.replace("SECRET_ENTRY 1", "SECRET_ENTRY 0"),
                        good.replace("SECRET_STAGE 1", "SECRET_STAGE 0"),
                        good.replace("SECRET_DESTINATION 1", "SECRET_DESTINATION 0"),
                        good.replace("SECRET_DESTINATION_DONE 1", "SECRET_DESTINATION_DONE 0"),
                        good.replace("SECRET_PERMIT_NEXT 1", "SECRET_PERMIT_NEXT 0"),
                        good.replace("_ACCEPTED", "_REJECTED_RETIRED"),
                    ):
                        with self.assertRaises(ValueError):
                            S.validate_output(bad, width, owner, path)

    def test_commands_are_read_only_and_distinguish_staging(self):
        for shape in S.SHAPES.values():
            for owner in shape["owners"].values():
                commands = "\n".join(S.commands(owner, S.RESULT.CIPHERS[16]))
                self.assertIn("$stage != $caller", commands)
                self.assertIn("SECRET_DESTINATION_DONE", commands)
                self.assertIn("SECRET_PERMIT_NEXT", commands)
                self.assertEqual(commands.count(
                    S.RESULT.equal_words('$caller', S.RESULT.CIPHERS[16])), 2)
                self.assertNotIn("set *", commands)
                self.assertNotIn("dump ", commands)

    def test_unknown_artifact_rejected_before_debugger(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "fake-elf"
            binary.write_bytes(b"\x7fELF\x02\x01" + bytes(12) + b"\x3e\x00" + bytes(100))
            with self.assertRaisesRegex(ValueError, "unreviewed secret-destination artifact"):
                S.observe(binary, objdump="missing-objdump", gdb="missing-gdb")


if __name__ == "__main__":
    unittest.main()
