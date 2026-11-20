#!/usr/bin/env python3
"""Synthetic mapping/runner regressions; no native fault evidence."""
from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import aes_fault_capture_map as M

SPEC = importlib.util.spec_from_file_location(
    "capture_map_runner", Path(__file__).with_name("check-aes-fault-capture-map.py"))
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)


def disassembly(shape="source-r14-result-ff", hashed=False):
    starts = {"capture": 0x1000, "wrapper": 0x2000, "copy": 0x3000}
    names = {role: symbol + ("::h0123456789abcdef" if hashed else "") for role, symbol in M.SYMBOLS.items()}
    output = []
    for role, ops in M.PATTERNS[shape].items():
        start = starts[role]
        output.append(f"{start:x} <{names[role]}>:")
        for index, op in enumerate(ops):
            if op.startswith("call @"):
                target = op.removeprefix("call @")
                op = f"call {starts[target]:x} <{names[target]}>"
            elif " @" in op:
                mnemonic, offset = op.split(" @")
                address = start + 4 * int(offset)
                op = f"{mnemonic} {address:x} <{names[role]}+0x{4 * int(offset):x}>"
            output.append(f" {start + 4 * index:x}: {op}")
        output.append(f" {start + 4 * len(ops):x}: int3")
    return "\n".join(output)


def transcript(width, owner, path):
    prefix = "BRYNJA_" + owner.upper()
    return "\n".join([
        C.R.C.identity(width, path, "baseline", owner),
        *[f"Hardware assisted breakpoint {index} at 0x1" for index in range(1, 5)],
        *[f"hit Breakpoint {index}, 0x1" for index in (1, 2, 3, 2, 3, 4)],
        *[marker + " 1" for marker in C.MARKERS],
        prefix + "_EVIDENCE_CFG=false", f"{prefix}_CASE={width}:{path}",
        prefix + "_STORAGE_CLEARED", prefix + "_ACCEPTED",
        "test result: ok. 1 passed; 0 failed; 0 ignored;", "exited normally"])


def runs():
    yield subprocess.CompletedProcess(["objdump"], 0, disassembly(), "")
    for width in C.R.C.ANSWERS:
        for owner in C.R.C.OWNERS:
            for path in C.R.C.PATHS:
                for _scope in C.SCOPES:
                    yield subprocess.CompletedProcess(["gdb"], 0, transcript(width, owner, path), "")


ELF = b"\x7fELF\x02\x01" + bytes(12) + b"\x3e\x00" + bytes(44)


class CaptureMapping(unittest.TestCase):
    def test_both_paired_shapes_and_hashed_symbols_map_exact_events(self):
        for shape in M.PATTERNS:
            for hashed in (False, True):
                result = M.inspect(disassembly(shape, hashed))
                self.assertEqual(set(result), set(M.SYMBOLS))
                for role, function in result.items():
                    self.assertEqual(function["shape"], shape)
                    self.assertEqual(function["events"], {k: v * 4 for k, v in M.EVENTS[role].items()})
                    self.assertEqual(len(function["normalized_sha256"]), 64)

    def test_missing_duplicate_alias_or_malformed_symbols_fail(self):
        good = disassembly()
        for bad in ("", good + "\n" + good,
                    good.replace("2000 <" + M.SYMBOLS["wrapper"], "1000 <" + M.SYMBOLS["wrapper"]),
                    good.replace(M.SYMBOLS["copy"], "unknown::copy"),
                    good.replace(" 1000: push %rbp", "unparsed instruction")):
            with self.subTest(), self.assertRaises(ValueError):
                M.inspect(bad)

    def test_unrecognized_instruction_or_missing_instruction_never_maps(self):
        for shape in M.PATTERNS:
            good = disassembly(shape)
            for line in good.splitlines():
                if ": " not in line or line.endswith(": int3"):
                    continue
                for altered in (line.split(": ")[0] + ": nop", ""):
                    with self.subTest(shape=shape, line=line), self.assertRaises(ValueError):
                        M.inspect(good.replace(line, altered, 1))

    def test_no_fused_second_capture_or_wrong_source_pointer(self):
        good = disassembly()
        for bad in (good.replace("mov %r14,%rdx", "mov %rdi,%rdx"),
                    good.replace("mov %r15,%rdi", "mov %rdx,%rdi"),
                    good.replace("call 2000", "jmp 2000"),
                    good.replace("mov (%rsi,%rcx,1),%rax", "mov (%rdi,%rcx,1),%rax")):
            with self.assertRaises(ValueError):
                M.inspect(bad)

    def test_branch_targets_and_call_addresses_are_not_guessed(self):
        good = disassembly()
        for bad in (good.replace("jne 1068", "jne 1064"),
                    good.replace("jne 1068", "jne 1069"),
                    good.replace("call 2000", "call 2001"),
                    good.replace("call 3000", "call *%rax")):
            with self.assertRaises(ValueError):
                M.inspect(bad)

    def test_result_encodings_must_match_across_caller_and_wrapper(self):
        for shape in M.PATTERNS:
            good = disassembly(shape)
            old, new = ("$0xff", "$0x4") if shape.endswith("ff") else ("$0x4", "$0xff")
            with self.assertRaises(ValueError):
                M.inspect(good.replace(f"mov {old},%al", f"mov {new},%al"))

    def test_every_runtime_marker_and_fixture_outcome_is_required(self):
        for width in C.R.C.ANSWERS:
            for owner in C.R.C.OWNERS:
                for path in C.R.C.PATHS:
                    good = transcript(width, owner, path)
                    for scope in C.SCOPES:
                        C.validate(good, width, owner, path, scope)
                        for line in good.splitlines():
                            if line.startswith(("MAP_", "BRYNJA_")):
                                for replacement in ("", line + "\n" + line):
                                    with self.assertRaises(ValueError):
                                        C.validate(good.replace(line, replacement), width, owner, path, scope)
                            if line.startswith("MAP_"):
                                with self.assertRaises(ValueError):
                                    C.validate(good.replace(line, line.replace(" 1", " 0")), width, owner, path, scope)

    def test_wrong_execution_population_or_evidence_hooks_never_pass(self):
        good = transcript(16, "cached", "public")
        for before, after in [("EVIDENCE_CFG=false", "EVIDENCE_CFG=true"),
                              ("_ACCEPTED", "_REJECTED_RETIRED"),
                              ("Hardware assisted breakpoint", "Breakpoint"),
                              ("hit Breakpoint", "missed Breakpoint"),
                              ("test result: ok. 1 passed", "test result: ok. 0 passed"),
                              ("exited normally", "exited abnormally")]:
            with self.assertRaises(ValueError):
                C.validate(good.replace(before, after), 16, "cached", "public", "key")

    def test_commands_only_observe_full_copies_and_mapped_return_addresses(self):
        for shape in M.PATTERNS:
            mapping = M.inspect(disassembly(shape))
            for width in C.R.C.ANSWERS:
                for scope in C.SCOPES:
                    commands, _ = C.commands(mapping, width, "cached", "public", scope)
                    self.assertEqual(sum(c.startswith("hbreak ") for c in commands), 4)
                    self.assertEqual(sum(c == "continue" for c in commands), 7)
                    self.assertEqual("ignore 1 1" in commands, scope == "input")
                    self.assertFalse(any(c.startswith("set *") for c in commands))
                    self.assertEqual([c.split("=")[0] for c in commands if c.startswith("set $")],
                                     ["set $source", "set $first", "set $second"])
                    checks = "\n".join(c for c in commands if c.startswith("printf"))
                    self.assertEqual(checks.count("*(unsigned long long*)$rsp =="), 4)
                    self.assertEqual(checks.count("(unsigned long long)&'"), 4)
                    self.assertIn("$source+", checks)
                    self.assertIn("set print thread-events off", commands)

    def test_invalid_selection_rejected_before_commands(self):
        mapping = M.inspect(disassembly())
        for width, owner, path, scope in [(17, "cached", "public", "key"),
                (16, "invalid", "public", "key"), (16, "cached", "invalid", "key"),
                (16, "cached", "public", "invalid")]:
            with self.assertRaises(ValueError):
                C.commands(mapping, width, owner, path, scope)

    def test_runner_checks_all_cases_and_artifact_immutability(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "fixture"
            binary.write_bytes(ELF)
            with patch.object(C.subprocess, "run", side_effect=list(runs())) as run:
                report = C.observe(binary)
            self.assertEqual(run.call_count, 37)
            self.assertEqual(len(set(report["baseline_cases"])), 36)
            self.assertEqual(report["qualification"], "none")
            with patch.object(C.subprocess, "run", side_effect=list(runs())), \
                    patch.object(Path, "read_bytes", side_effect=[ELF, ELF + b"changed"]):
                with self.assertRaises(ValueError):
                    C.observe(binary)

    def test_invalid_elf_and_disassembly_never_run_debugger(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "fixture"
            binary.write_bytes(b"invalid")
            with patch.object(C.subprocess, "run") as run, self.assertRaises(ValueError):
                C.observe(binary)
            run.assert_not_called()
            binary.write_bytes(ELF)
            with patch.object(C.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")) as run, \
                    self.assertRaises(ValueError):
                C.observe(binary)
            self.assertEqual(run.call_count, 1)

    def test_cli_failure_does_not_print_debugger_or_subprocess_details(self):
        sentinel = "PRIVATE_DEBUGGER_DETAIL"
        for error in (subprocess.CalledProcessError(1, [sentinel], output=sentinel),
                      subprocess.TimeoutExpired([sentinel], 60, output=sentinel), OSError(sentinel)):
            output, errors = io.StringIO(), io.StringIO()
            with patch("sys.argv", ["map", "--binary", "fixture", "--json"]), \
                    patch.object(C, "observe", side_effect=error), redirect_stdout(output), redirect_stderr(errors):
                self.assertEqual(C.main(), 2)
            self.assertEqual(output.getvalue(), "")
            self.assertNotIn(sentinel, errors.getvalue())


if __name__ == "__main__":
    unittest.main()
