#!/usr/bin/env python3
"""Fail-closed tests for the private local-recapture observation runner."""
import importlib.util
from pathlib import Path
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "local_recapture", Path(__file__).with_name("check-aes-fault-local-recapture-map.py"))
R = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(R)
LEAF = {"symbol": "brynja_core::secret_memory_transfer::copy_bytes",
        "events": {"entry": 0, "word_load": 14, "word_store": 18,
                   "return": 62}}


def fake_dump(shape):
    dst1, dst2, length, src1, src2 = shape["registers"]
    lines = [f'{shape["base"]:x} <{shape["symbol"]}>:']
    for offset, dst, src, stack in zip(shape["offsets"], (dst1, dst2), (src1, src2), shape["stack"]):
        start = shape["base"] + offset - 5
        ops = [
            f"lea {stack}(%rsp),{dst}", f"mov {dst},%rdi", f"mov {length},%rsi",
            f"mov {src},%rdx", f"mov {length},%rcx",
            f"call {shape['copy']:x} <{R.COPY}>", f"cmp ${shape['result']},%al",
            f"jne {shape['base'] + 4096:x} <{shape['symbol']}+0x1000>",
        ]
        for n, op in enumerate(ops):
            address = shape["base"] + offset if n == 5 else start + n
            if n > 5:
                address = shape["base"] + offset + n - 5
            lines.append(f"  {address:x}: {op}")
    return "\n".join(lines)


def good_output(width, path):
    test = R.TEST_PREFIX + f"{width * 8}_{path}"
    lines = [
        'Hardware assisted breakpoint 1 at 0x1',
        'Hardware assisted breakpoint 2 at 0x2',
        'Hardware assisted breakpoint 3 at 0x3',
        'Hardware assisted breakpoint 4 at 0x4',
        'Hardware assisted breakpoint 5 at 0x5',
        'BRYNJA_IMPORT_USE_EVIDENCE_CFG=false',
        f'BRYNJA_IMPORT_USE_CASE={width}:{path}',
        'BRYNJA_IMPORT_USE_OWNER_RETURNED',
        'hit Breakpoint 1', 'LOCAL_FIRST 1',
        'hit Breakpoint 3', 'LEAF_FIRST_ENTRY 1',
    ]
    for replica in ('FIRST', 'SECOND'):
        if replica == 'SECOND':
            lines += ['hit Breakpoint 2', 'LOCAL_SECOND 1',
                      'hit Breakpoint 3', 'LEAF_SECOND_ENTRY 1']
        for index in range(width // 8):
            lines += ['hit Breakpoint 5', f'WORD_{replica}_LOAD_{index} 1',
                      f'WORD_{replica}_AT_STORE_{index} 1',
                      f'WORD_{replica}_STORED_{index} 1']
        lines += ['hit Breakpoint 4', f'LEAF_{replica}_DONE 1']
    lines += [
        'BRYNJA_IMPORT_USE_SOURCE_AND_GUARDS_INTACT',
        'BRYNJA_IMPORT_USE_STORAGE_CLEARED', 'BRYNJA_IMPORT_USE_ACCEPTED',
        test, 'test result: ok. 1 passed; 0 failed; 0 ignored;',
        'exited normally',
    ]
    return '\n'.join(lines)


class LocalRecaptureMapTests(unittest.TestCase):
    def test_reviewed_static_shapes(self):
        for shape in R.SHAPES.values():
            with self.subTest(toolchain=shape["toolchain"]):
                R.inspect(fake_dump(shape), shape)

    def test_missing_duplicate_and_changed_calls_fail(self):
        for shape in R.SHAPES.values():
            dump = fake_dump(shape)
            with self.subTest(toolchain=shape["toolchain"]):
                for bad in (
                    dump.replace(R.COPY, "other::copy", 1),
                    dump.replace(f"mov {shape['registers'][4]},%rdx", "mov %rax,%rdx"),
                    dump.replace(f"cmp ${shape['result']},%al", "cmp $0x7,%al", 1),
                    dump.replace("jne ", "je ", 1),
                    dump + "\n" + dump,
                ):
                    with self.assertRaises(ValueError):
                        R.inspect(bad, shape)

    def test_runtime_output_requires_all_checkpoints_and_fixture(self):
        for width in R.SIZES:
            for path in R.PATHS:
                test = R.TEST_PREFIX + f"{width * 8}_{path}"
                good = good_output(width, path)
                R.validate(good, width, path, test)
                for bad in (
                    good.replace("LOCAL_SECOND 1", "LOCAL_SECOND 0"),
                    good.replace("LEAF_FIRST_DONE 1", "LEAF_FIRST_DONE 0"),
                    good.replace("LEAF_SECOND_ENTRY 1", "LEAF_SECOND_ENTRY 0"),
                    good.replace("WORD_FIRST_STORED_0 1", "WORD_FIRST_STORED_0 0"),
                    good.replace("WORD_SECOND_LOAD_0 1", "WORD_SECOND_LOAD_0 0"),
                    good.replace("BRYNJA_IMPORT_USE_ACCEPTED", "BRYNJA_IMPORT_USE_USE_REJECTED_RETIRED"),
                    good.replace("hit Breakpoint 2", "not hit"),
                    good.replace("EVIDENCE_CFG=false", "EVIDENCE_CFG=true"),
                ):
                    with self.assertRaises(ValueError):
                        R.validate(bad, width, path, test)

    def test_commands_do_not_mutate_or_dump(self):
        for shape in R.SHAPES.values():
            for width in R.SIZES:
                command = "\n".join(R.commands(shape, LEAF, width))
                self.assertIn("LOCAL_FIRST", command)
                self.assertIn("LOCAL_SECOND", command)
                self.assertIn("LEAF_FIRST_DONE", command)
                self.assertIn("LEAF_SECOND_DONE", command)
                self.assertIn("WORD_FIRST_AT_STORE_0", command)
                self.assertIn(f"WORD_SECOND_STORED_{width // 8 - 1}", command)
                self.assertNotIn("set *", command)
                self.assertNotIn("dump ", command)

    def test_unknown_artifact_rejected_before_debugger(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "fake-elf"
            binary.write_bytes(b"\x7fELF\x02\x01" + bytes(12) + b"\x3e\x00" + bytes(100))
            with self.assertRaisesRegex(ValueError, "unreviewed recapture artifact"):
                R.observe(binary, objdump="missing-objdump", gdb="missing-gdb")


if __name__ == "__main__":
    unittest.main()
