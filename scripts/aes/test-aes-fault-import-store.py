#!/usr/bin/env python3
"""Import-store tooling regressions; synthetic transcripts are not evidence."""
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


I = module("import_store", "check-aes-fault-import-store.py")
F = module("copy_store_tests", "test-aes-fault-copy-store.py")


def transcript(width, owner, case):
    prefix = "BRYNJA_IMPORT_" + owner.upper()
    return "\n".join([
        I.identity(width, owner, "first", 0, case),
        *[f"Hardware assisted breakpoint {i} at 0x1" for i in range(1,4)],
        *[f"hit Breakpoint {i}, 0x1" for i in (1,2,3)],
        *["IMPORT_" + event + " 1" for event in ("ENTRY","BEFORE","VALUE","AFTER","PAIR_RETURN")],
        prefix + "_EVIDENCE_CFG=false", f"{prefix}_WIDTH={width}",
        prefix + "_SOURCE_AND_GUARDS_INTACT", prefix + "_STORAGE_CLEARED",
        prefix + ("_ACCEPTED" if case == "baseline" else "_REJECTED"),
        "test result: ok. 1 passed; 0 failed; 0 ignored;", "exited normally"])


def runs():
    yield subprocess.CompletedProcess(["objdump"],0,F.dump(),"")
    for width in I.WIDTHS:
        for owner in I.OWNERS:
            for _replica in I.C.REPLICAS:
                for case in I.CASES:
                    for _byte in ([0] if case == "baseline" else range(width)):
                        yield subprocess.CompletedProcess(["gdb"],0,transcript(width,owner,case),"")


class ImportStoreRunner(unittest.TestCase):
    def test_each_key_byte_maps_to_the_correct_store_visit_and_lane(self):
        mapping, _ = I.C.map_sites(F.dump())
        for width in I.WIDTHS:
            for replica in I.C.REPLICAS:
                for byte in range(width):
                    commands, _ = I.commands(mapping,width,"cached",replica,byte,"data")
                    skip = (width // 8 if replica == "second" else 0) + byte // 8
                    self.assertEqual([c for c in commands if c.startswith("ignore 2")],
                                     [f"ignore 2 {skip}"] if skip else [])
                    self.assertEqual([c for c in commands if c.startswith(("set $rax","set $al","set *"))],
                                     [f"set $rax = $rax ^ {1 << (byte % 8 * 8)}ULL"])
                    self.assertEqual(commands.count("stepi"),1)
                    before = next(c for c in commands if c.startswith('printf "IMPORT_BEFORE'))
                    self.assertIn(f"$rdx == {width-byte//8*8}",before)
                    self.assertIn(f"$rcx == {byte//8*8}",before)
                    self.assertIn(f"(unsigned char*)$rdi == ${replica}",before)

    def test_baselines_do_not_mutate_and_guards_are_observed(self):
        mapping, _ = I.C.map_sites(F.dump())
        for width in I.WIDTHS:
            for replica in I.C.REPLICAS:
                commands, _ = I.commands(mapping,width,"ephemeral",replica,0,"baseline")
                self.assertFalse(any(c.startswith(("set $rax","set $al","set *")) for c in commands))
                for stage in ("ENTRY","BEFORE","AFTER","PAIR_RETURN"):
                    check = next(c for c in commands if c.startswith(f'printf "IMPORT_{stage}'))
                    self.assertIn("*($first-1) == 0x91",check)
                    self.assertIn(f"*($second+{width}) == 0x92",check)

    def test_every_event_cleanup_guard_and_outcome_marker_is_required(self):
        for width in I.WIDTHS:
            for owner in I.OWNERS:
                for case in I.CASES:
                    good = transcript(width,owner,case)
                    I.validate(good,width,owner,"first",0,case)
                    for line in good.splitlines():
                        if line.startswith(("IMPORT_","BRYNJA_")):
                            for replacement in ("", line+"\n"+line):
                                with self.assertRaises(ValueError):
                                    I.validate(good.replace(line,replacement),width,owner,"first",0,case)
                        if line.startswith("IMPORT_"):
                            with self.assertRaises(ValueError):
                                I.validate(good.replace(line,line.replace(" 1"," 0")),width,owner,"first",0,case)

    def test_wrong_execution_or_source_hooks_are_rejected(self):
        good = transcript(16,"cached","data")
        for old,new in [("EVIDENCE_CFG=false","EVIDENCE_CFG=true"), ("_REJECTED","_ACCEPTED"),
                        ("_REJECTED","_REJECTED_RETIRED"), ("hit Breakpoint","missed Breakpoint"),
                        ("Hardware assisted breakpoint","Breakpoint"),
                        ("test result: ok. 1 passed","test result: ok. 0 passed"),
                        ("exited normally","exited abnormally")]:
            with self.assertRaises(ValueError):
                I.validate(good.replace(old,new),16,"cached","first",0,"data")

    def test_invalid_selection_never_constructs_commands(self):
        for width,owner,replica,byte,case in [(16,"invalid","first",0,"data"),
                (16,"cached","other",0,"data"), (17,"cached","first",0,"data"),
                (True,"cached","first",0,"data"), (16,"cached","first",True,"data"),
                (16,"cached","first",16,"data"), (24,"cached","first",-1,"data"),
                (32,"cached","first",1,"baseline"), (32,"cached","first",0,"combined")]:
            with self.assertRaises(ValueError):
                I.identity(width,owner,replica,byte,case)

    def test_population_is_all_key_bytes_not_just_block_length(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory)/"fixture"
            binary.write_bytes(F.F.ELF)
            with patch.object(I.subprocess,"run",side_effect=runs()) as run:
                report = I.observe(binary)
            self.assertEqual(run.call_count,301)
            self.assertEqual(len(report["groups"]),12)
            self.assertTrue(all(g["counts"]=={"baseline":1,"data":g["width_bits"]//8} for g in report["groups"]))
            self.assertEqual(report["qualification"],"none")

    def test_changed_artifacts_and_invalid_objects_cannot_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory)/"fixture"
            binary.write_bytes(b"invalid")
            with patch.object(I.subprocess,"run") as run, self.assertRaises(ValueError):
                I.observe(binary)
            run.assert_not_called()
            binary.write_bytes(F.F.ELF)
            with patch.object(I.subprocess,"run",side_effect=runs()), \
                    patch.object(Path,"read_bytes",side_effect=[F.F.ELF,F.F.ELF+b"changed"]), self.assertRaises(ValueError):
                I.observe(binary)

    def test_unknown_shape_stops_before_debugger(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory)/"fixture"
            binary.write_bytes(F.F.ELF)
            with patch.object(I.subprocess,"run",return_value=subprocess.CompletedProcess([],0,"", "")) as run, \
                    self.assertRaises(ValueError):
                I.observe(binary)
            self.assertEqual(run.call_count,1)

    def test_failure_is_not_retried_or_dumped(self):
        sentinel="PRIVATE_DEBUGGER_DETAIL"
        for error in (subprocess.CalledProcessError(1,[sentinel],output=sentinel),
                      subprocess.TimeoutExpired([sentinel],60,output=sentinel)):
            with tempfile.TemporaryDirectory() as directory:
                binary=Path(directory)/"fixture"
                binary.write_bytes(F.F.ELF)
                output, errors = io.StringIO(), io.StringIO()
                with patch("sys.argv",["import","--binary",str(binary),"--json"]), \
                        patch.object(I.subprocess,"run",side_effect=[next(runs()),error]) as run, \
                        redirect_stdout(output), redirect_stderr(errors):
                    self.assertEqual(I.main(),2)
                self.assertEqual(run.call_count,2)
                self.assertEqual(output.getvalue(),"")
                self.assertNotIn(sentinel,errors.getvalue())


if __name__ == "__main__":
    unittest.main()
