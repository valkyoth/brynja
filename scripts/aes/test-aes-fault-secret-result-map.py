#!/usr/bin/env python3
"""Fail-closed tests for read-only secret-result construction mapping."""
import importlib.util
from pathlib import Path
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "secret_result_map", Path(__file__).with_name(
        "check-aes-fault-secret-result-map.py"))
S = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(S)


def fake_dump(shape, destination):
    lines = []
    for name, owner in destination["owners"].items():
        local = shape["owners"][name]
        register = local["result_register"]
        lines.extend([
            f'{owner["address"]:x} <{owner["symbol"]}>:',
            f'  {owner["address"] + local["complete"]:x}: '
            f'call {shape["complete_address"]:x} <{shape["complete_symbol"]}>',
            f'  {owner["address"] + local["pointer_store"]:x}: '
            f'mov %rax,0x8(%{register})',
            f'  {owner["address"] + local["length_store"]:x}: '
            f'movq $0x10,0x10(%{register})',
        ])
    return "\n".join(lines)


def good_output(width, owner, path):
    prefix = "BRYNJA_" + owner.upper()
    return "\n".join([
        *[f"Hardware assisted breakpoint {i} at 0x{i}" for i in range(1, 4)],
        prefix + "_EVIDENCE_CFG=false", f"{prefix}_CASE={width}:{path}",
        "hit Breakpoint 1", "SECRET_RESULT_ENTRY 1",
        "hit Breakpoint 2", "SECRET_RESULT_COMPLETE 1", "SECRET_RESULT_COMPLETED 1",
        "hit Breakpoint 3", "SECRET_RESULT_POINTER 1",
        "SECRET_RESULT_POINTER_STORED 1", "SECRET_RESULT_LENGTH 1",
        "SECRET_RESULT_LENGTH_STORED 1",
        prefix + "_STORAGE_CLEARED", prefix + "_ACCEPTED",
        S.RETAINED.identity(width, owner, path),
        "test result: ok. 1 passed; 0 failed; 0 ignored;", "exited normally",
    ])


class SecretResultMapTests(unittest.TestCase):
    def test_completion_and_descriptor_stores_are_pinned(self):
        for digest, shape in S.SHAPES.items():
            with self.subTest(toolchain=shape["toolchain"]):
                destination = S.DEST.SHAPES[digest]
                dump = fake_dump(shape, destination)
                S.inspect(dump, shape, destination)
                for bad in (
                    dump.replace(shape["complete_symbol"], "other::complete", 1),
                    dump.replace("mov %rax,0x8(", "mov %rdx,0x8(", 1),
                    dump.replace("movq $0x10,0x10(", "movq $0x8,0x10(", 1),
                    dump + "\n" + dump,
                ):
                    with self.assertRaises(ValueError):
                        S.inspect(bad, shape, destination)

    def test_markers_require_all_stages_and_accepted_fixture(self):
        for width in S.RETAINED.WIDTHS:
            for owner in S.RETAINED.OWNERS:
                for path in ("encrypt", "decrypt"):
                    good = good_output(width, owner, path)
                    S.validate_output(good, width, owner, path)
                    for marker in ("SECRET_RESULT_ENTRY 1",
                                   "SECRET_RESULT_COMPLETE 1",
                                   "SECRET_RESULT_COMPLETED 1",
                                   "SECRET_RESULT_POINTER 1",
                                   "SECRET_RESULT_POINTER_STORED 1",
                                   "SECRET_RESULT_LENGTH 1",
                                   "SECRET_RESULT_LENGTH_STORED 1"):
                        with self.assertRaises(ValueError):
                            S.validate_output(good.replace(marker, marker[:-1] + "0"),
                                              width, owner, path)
                    with self.assertRaises(ValueError):
                        S.validate_output(good.replace("_ACCEPTED", "_REJECTED_RETIRED"),
                                          width, owner, path)

    def test_debugger_commands_only_observe_public_fixture(self):
        for digest, shape in S.SHAPES.items():
            for name, owner in S.DEST.SHAPES[digest]["owners"].items():
                commands = "\n".join(S.commands(owner, shape["owners"][name],
                                                    S.RESULT.CIPHERS[16]))
                self.assertIn("SECRET_RESULT_LENGTH_STORED", commands)
                self.assertIn("$result=(unsigned char*)$rdi", commands)
                self.assertNotIn("set *(unsigned", commands)
                self.assertNotIn("call (", commands)

    def test_unknown_artifact_rejected_before_debugger(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "unreviewed.elf"
            path.write_bytes(b"\x7fELF\x02\x01" + b"\x00" * 12 + b"\x3e\x00")
            with self.assertRaises(ValueError):
                S.observe(path)


if __name__ == "__main__":
    unittest.main()
