#!/usr/bin/env python3
"""Fail-closed tests for read-only secret fixture-caller return mapping."""
import importlib.util
from pathlib import Path
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "secret_caller_map", Path(__file__).with_name("check-aes-fault-secret-caller-map.py"))
S = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(S)


def fake_dump(shape, owner_shape):
    lines = []
    for name, caller in shape["callers"].items():
        owner = owner_shape["owners"][name]
        lines.extend([
            f'{caller["address"]:x} <{caller["symbol"]}>:',
            f'  {caller["address"] + caller["call"]:x}: '
            f'call {owner["address"]:x} <{owner["symbol"]}>',
            f'  {caller["address"] + caller["status"]:x}: '
            f'{caller["status_instruction"]}',
        ])
    return "\n".join(lines)


def good_output(width, owner, path):
    prefix = "BRYNJA_" + owner.upper()
    return "\n".join([
        "Hardware assisted breakpoint 1 at 0x1",
        prefix + "_EVIDENCE_CFG=false", f"{prefix}_CASE={width}:{path}",
        "hit Breakpoint 1", "SECRET_CALLER_ENTRY 1", "SECRET_CALLER_RETURN 1",
        prefix + "_STORAGE_CLEARED", prefix + "_ACCEPTED",
        S.RETAINED.identity(width, owner, path),
        "test result: ok. 1 passed; 0 failed; 0 ignored;", "exited normally",
    ])


class SecretCallerMapTests(unittest.TestCase):
    def test_exact_caller_call_and_status_check_are_pinned(self):
        for digest, shape in S.SHAPES.items():
            with self.subTest(toolchain=shape["toolchain"]):
                owner_shape = S.DEST.SHAPES[digest]
                dump = fake_dump(shape, owner_shape)
                S.inspect(dump, shape, owner_shape)
                for bad in (
                    dump.replace(owner_shape["owners"]["cached"]["symbol"],
                                 "other::secret", 1),
                    dump.replace(shape["callers"]["cached"]["status_instruction"],
                                 "cmpb $0x7,0x40(%rsp)", 1),
                    dump + "\n" + dump,
                ):
                    with self.assertRaises(ValueError):
                        S.inspect(bad, shape, owner_shape)

    def test_markers_and_acceptance_are_required(self):
        for width in S.RETAINED.WIDTHS:
            for owner in S.RETAINED.OWNERS:
                for path in ("encrypt", "decrypt"):
                    good = good_output(width, owner, path)
                    S.validate_output(good, width, owner, path)
                    for bad in (
                        good.replace("SECRET_CALLER_ENTRY 1", "SECRET_CALLER_ENTRY 0"),
                        good.replace("SECRET_CALLER_RETURN 1", "SECRET_CALLER_RETURN 0"),
                        good.replace("_ACCEPTED", "_REJECTED_RETIRED"),
                    ):
                        with self.assertRaises(ValueError):
                            S.validate_output(bad, width, owner, path)

    def test_debugger_commands_do_not_mutate_fixture(self):
        for shape in S.SHAPES.values():
            for caller in shape["callers"].values():
                commands = "\n".join(S.commands(caller, S.RESULT.CIPHERS[16]))
                self.assertIn("SECRET_CALLER_RETURN", commands)
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
