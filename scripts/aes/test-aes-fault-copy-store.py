#!/usr/bin/env python3
"""Synthetic copy-store runner contracts; mock transcripts are not evidence."""
from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


C = module("copy_store", "check-aes-fault-copy-store.py")
F = module("capture_map_tests", "test-aes-fault-capture-map.py")


def dump(shape="source-r14-result-ff"):
    return F.disassembly(shape) + f"\n4000 <{C.COMPUTE}>:\n 4000: nop\n 4001: ret\n"


def transcript(width, owner, path, case):
    prefix = "BRYNJA_" + owner.upper()
    events = ["ENTRY", "CAPTURE", "BEFORE", "VALUE", "AFTER", "PAIR_RETURN", "COMPUTE_RETURN"]
    if case == "combined":
        events += ["FORGED"]
    return "\n".join([
        C.R.C.identity(width, path, "baseline", owner),
        *[f"Hardware assisted breakpoint {i} at 0x1" for i in range(1, 6)],
        *[f"hit Breakpoint {i}, 0x1" for i in (1, 2, 3, 5, 4)],
        *["STORE_" + event + " 1" for event in events],
        prefix + "_EVIDENCE_CFG=false", f"{prefix}_CASE={width}:{path}", prefix + "_STORAGE_CLEARED",
        prefix + ("_ACCEPTED" if case == "baseline" else "_REJECTED_RETIRED"),
        "test result: ok. 1 passed; 0 failed; 0 ignored;", "exited normally"])


def runs():
    yield subprocess.CompletedProcess(["objdump"], 0, dump(), "")
    for width in C.R.C.ANSWERS:
        for owner in C.R.C.OWNERS:
            for path in C.R.C.PATHS:
                for _replica in C.REPLICAS:
                    for case in C.CASES:
                        for _byte in ([0] if case == "baseline" else range(16)):
                            yield subprocess.CompletedProcess(["gdb"], 0, transcript(width, owner, path, case), "")


class CopyStoreRunner(unittest.TestCase):
    def test_exact_store_successor_and_single_return_required(self):
        for shape in F.M.PATTERNS:
            mapping, compute = C.map_sites(dump(shape))
            self.assertEqual(mapping["copy"]["events"]["after_word_store"], 28)
            self.assertEqual(compute["ret"], 1)
        for bad in (dump().replace("4001: ret", "4001: nop"),
                    dump().replace("4001: ret", "4001: ret\n4002: ret"),
                    dump().replace("add $0x8,%rcx", "add $0x9,%rcx")):
            with self.assertRaises(ValueError):
                C.map_sites(bad)

    def test_every_byte_selects_correct_replica_word_and_register_lane(self):
        mapping, compute = C.map_sites(dump())
        for replica in C.REPLICAS:
            for byte in range(16):
                for case in ("data", "combined"):
                    commands, _ = C.commands(mapping, compute, 16, "cached", "public", replica, byte, case)
                    skip = (2 if replica == "second" else 0) + byte // 8
                    self.assertEqual([c for c in commands if c.startswith("ignore 3")],
                                     [f"ignore 3 {skip}"] if skip else [])
                    self.assertIn(f"set $rax = $rax ^ {1 << (byte % 8 * 8)}ULL", commands)
                    self.assertFalse(any(c.startswith("set *") for c in commands))
                    self.assertEqual(commands.count("stepi"), 1)
                    self.assertEqual("set $al = 0" in commands, case == "combined")
                    self.assertLess(commands.index("delete 1"), next(i for i,c in enumerate(commands) if "hbreak" in c and "+128)" in c))
                    before = next(c for c in commands if c.startswith('printf "STORE_BEFORE'))
                    self.assertIn(f"$rcx == {byte // 8 * 8}", before)
                    self.assertIn(f"(unsigned char*)$rdi == ${replica}", before)

    def test_baseline_never_mutates_and_combined_requires_failed_compute(self):
        mapping, compute = C.map_sites(dump())
        for case in C.CASES:
            commands, _ = C.commands(mapping, compute, 32, "ephemeral", "decrypt", "second", 0, case)
            writes = [c for c in commands if c.startswith(("set $rax", "set $al"))]
            self.assertEqual(len(writes), {"baseline": 0, "data": 1, "combined": 2}[case])
            ret = next(c for c in commands if c.startswith('printf "STORE_COMPUTE_RETURN'))
            self.assertIn(f"$al == {int(case != 'baseline')}", ret)
            if case == "combined":
                self.assertLess(commands.index(ret), commands.index("set $al = 0"))

    def test_all_markers_and_exact_outcomes_required(self):
        for width in C.R.C.ANSWERS:
            for owner in C.R.C.OWNERS:
                for path in C.R.C.PATHS:
                    for case in C.CASES:
                        good = transcript(width, owner, path, case)
                        C.validate(good, width, owner, path, "first", 0, case)
                        for line in good.splitlines():
                            if line.startswith(("STORE_", "BRYNJA_")):
                                for replacement in ("", line + "\n" + line):
                                    with self.assertRaises(ValueError):
                                        C.validate(good.replace(line, replacement), width, owner, path, "first", 0, case)
                            if line.startswith("STORE_"):
                                with self.assertRaises(ValueError):
                                    C.validate(good.replace(line, line.replace(" 1", " 0")), width, owner, path, "first", 0, case)

    def test_bad_execution_and_source_hooks_do_not_pass(self):
        good = transcript(16, "cached", "public", "combined")
        for old, new in [("EVIDENCE_CFG=false", "EVIDENCE_CFG=true"),
                         ("_REJECTED_RETIRED", "_ACCEPTED"), ("hit Breakpoint", "missed Breakpoint"),
                         ("Hardware assisted breakpoint", "Breakpoint"),
                         ("test result: ok. 1 passed", "test result: ok. 0 passed"),
                         ("exited normally", "exited abnormally")]:
            with self.assertRaises(ValueError):
                C.validate(good.replace(old,new), 16, "cached", "public", "first", 0, "combined")

    def test_invalid_selections_reject_before_debugging(self):
        for replica, byte, case in [("other",0,"data"), ("first",-1,"data"), ("first",16,"data"),
                                    ("first",True,"data"), ("first",1,"baseline"), ("first",0,"unknown")]:
            with self.assertRaises(ValueError):
                C.selection(16,"cached","public",replica,byte,case)

    def test_full_declared_population_and_unchanged_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "fixture"
            binary.write_bytes(F.ELF)
            with patch.object(C.subprocess, "run", side_effect=runs()) as run:
                report = C.observe(binary)
            self.assertEqual(run.call_count, 1189)
            self.assertEqual(len(report["groups"]), 36)
            self.assertTrue(all(g["counts"] == {"baseline":1,"data":16,"combined":16} for g in report["groups"]))
            self.assertEqual(report["qualification"], "none")
            with patch.object(C.subprocess, "run", side_effect=runs()), \
                    patch.object(Path, "read_bytes", side_effect=[F.ELF, F.ELF+b"changed"]):
                with self.assertRaises(ValueError):
                    C.observe(binary)

    def test_no_retry_and_failure_diagnostics_never_print_subprocess_data(self):
        sentinel = "PRIVATE_DEBUGGER_DETAIL"
        for error in (subprocess.CalledProcessError(1,[sentinel],output=sentinel),
                      subprocess.TimeoutExpired([sentinel],60,output=sentinel)):
            with tempfile.TemporaryDirectory() as directory:
                binary = Path(directory) / "fixture"
                binary.write_bytes(F.ELF)
                output, errors = io.StringIO(), io.StringIO()
                with patch("sys.argv", ["store","--binary",str(binary),"--json"]), \
                        patch.object(C.subprocess,"run",side_effect=[next(runs()),error]) as run, \
                        redirect_stdout(output), redirect_stderr(errors):
                    self.assertEqual(C.main(),2)
                self.assertEqual(run.call_count,2)
                self.assertEqual(output.getvalue(),"")
                self.assertNotIn(sentinel,errors.getvalue())

    def test_invalid_elf_or_unmapped_code_never_runs_debugger(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "fixture"
            binary.write_bytes(b"invalid")
            with patch.object(C.subprocess, "run") as run, self.assertRaises(ValueError):
                C.observe(binary)
            run.assert_not_called()
            binary.write_bytes(F.ELF)
            with patch.object(C.subprocess, "run", return_value=subprocess.CompletedProcess([],0,"", "")) as run, \
                    self.assertRaises(ValueError):
                C.observe(binary)
            self.assertEqual(run.call_count,1)


if __name__ == "__main__":
    unittest.main()
