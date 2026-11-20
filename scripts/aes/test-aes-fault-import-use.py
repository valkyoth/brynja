#!/usr/bin/env python3
"""Synthetic import/use runner contracts; no native evidence from mocks."""
from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


U = module("import_use", "check-aes-fault-import-use.py")
F = module("bypass_tests", "test-aes-fault-import-bypass.py")


def transcript(width, path, case):
    prefix = "BRYNJA_IMPORT_USE_"
    lines = [U.identity(width,path,"first",0,case),
             *[f"Hardware assisted breakpoint {i} at 0x1" for i in range(1,5)],
             *[f"hit Breakpoint {i}, 0x1" for i in range(1,5)],
             *[f"IMPORT_{event} 1" for event in ("ENTRY","BEFORE","VALUE","AFTER","PAIR_RETURN")],
             "BYPASS_DECISION 1"]
    if case in ("bypass","combined"):
        lines += ["BYPASS_FORGED 1"]
    lines += [prefix+"EVIDENCE_CFG=false",prefix+f"CASE={width}:{path}"]
    if case != "data":
        lines += [prefix+"OWNER_RETURNED"]
    lines += [prefix+"SOURCE_AND_GUARDS_INTACT",prefix+"STORAGE_CLEARED",
              prefix+{"baseline":"ACCEPTED","bypass":"ACCEPTED","data":"IMPORT_REJECTED","combined":"USE_REJECTED_RETIRED"}[case],
              "test result: ok. 1 passed; 0 failed; 0 ignored;", "exited normally"]
    return "\n".join(lines)


def runs():
    yield subprocess.CompletedProcess([],0,F.dump(),"")
    for width in U.B.I.WIDTHS:
        for path in U.PATHS:
            for _replica in U.B.I.C.REPLICAS:
                for case in U.B.CASES:
                    for _byte in ([0] if case in ("baseline","bypass") else range(width)):
                        yield subprocess.CompletedProcess([],0,transcript(width,path,case),"")


class ImportUse(unittest.TestCase):
    def test_each_path_reuses_the_exact_import_mutation_protocol(self):
        mapping, site = U.B.map_sites(F.dump())
        for width in U.B.I.WIDTHS:
            for path in U.PATHS:
                for replica in U.B.I.C.REPLICAS:
                    for case in U.B.CASES:
                        for byte in ([0] if case in ("baseline","bypass") else range(width)):
                            cmds,test = U.commands(mapping,site,width,path,replica,byte,case)
                            reference,_ = U.B.commands(mapping,site,width,replica,byte,case)
                            self.assertEqual(cmds,reference)
                            self.assertEqual(test,U.identity(width,path,replica,byte,case))
                            self.assertIn("import_use_tests::",test)

    def test_every_checkpoint_cleanup_and_outcome_is_required(self):
        for width in U.B.I.WIDTHS:
            for path in U.PATHS:
                for case in U.B.CASES:
                    good=transcript(width,path,case)
                    U.validate(good,width,path,"first",0,case)
                    for line in good.splitlines():
                        if line.startswith(("IMPORT_","BYPASS_","BRYNJA_")):
                            for replacement in ("",line+"\n"+line):
                                with self.assertRaises(ValueError):
                                    U.validate(good.replace(line,replacement),width,path,"first",0,case)
                        if line.startswith(("IMPORT_","BYPASS_")):
                            with self.assertRaises(ValueError):
                                U.validate(good.replace(line,line.replace(" 1"," 0")),width,path,"first",0,case)

    def test_import_rejection_is_not_use_rejection_or_retirement(self):
        data=transcript(16,"public","data")
        combined=transcript(16,"public","combined")
        for text,case in [(data+"\nBRYNJA_IMPORT_USE_OWNER_RETURNED","data"),
                          (data.replace("_IMPORT_REJECTED","_USE_REJECTED_RETIRED"),"data"),
                          (combined.replace("_USE_REJECTED_RETIRED","_IMPORT_REJECTED"),"combined"),
                          (combined.replace("_USE_REJECTED_RETIRED","_ACCEPTED"),"combined")]:
            with self.assertRaises(ValueError):U.validate(text,16,"public","first",0,case)

    def test_wrong_path_hooks_or_execution_rejected(self):
        good=transcript(24,"decrypt","combined")
        for old,new in [("EVIDENCE_CFG=false","EVIDENCE_CFG=true"),("CASE=24:decrypt","CASE=24:encrypt"),
                        ("import_use_tests","import_tests"),("exited normally","crashed"),
                        ("hit Breakpoint 4","no stop 4"),("Hardware assisted breakpoint 4","software breakpoint 4"),
                        ("test result: ok. 1 passed","test result: ok. 0 passed")]:
            with self.assertRaises(ValueError):U.validate(good.replace(old,new),24,"decrypt","first",0,"combined")

    def test_invalid_selections(self):
        for args in [(16,"other","first",0,"data"),(True,"public","first",0,"data"),
                     (16,"public","third",0,"data"),(16,"public","first",16,"data"),
                     (16,"public","first",1,"bypass"),(16,"public","first",0,"unknown")]:
            with self.assertRaises(ValueError):U.identity(*args)

    def test_complete_population_and_no_mutated_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            binary=Path(directory)/"fixture"
            binary.write_bytes(F.F.F.F.ELF)
            with patch.object(U.subprocess,"run",side_effect=runs()) as execute:
                report=U.observe(binary)
            self.assertEqual(execute.call_count,901)
            self.assertEqual(len(report["groups"]),18)
            self.assertEqual(report["qualification"],"none")
            for group in report["groups"]:
                self.assertEqual(group["counts"],dict(baseline=1,bypass=1,data=group["width_bits"]//8,combined=group["width_bits"]//8))
            sequence=iter(runs())
            def mutate(*args,**kwargs):
                binary.write_bytes(F.F.F.F.ELF+b"changed")
                return next(sequence)
            with patch.object(U.subprocess,"run",side_effect=mutate):
                with self.assertRaisesRegex(ValueError,"artifact changed"):U.observe(binary)

    def test_no_retry_and_quiet_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            binary=Path(directory)/"fixture"
            binary.write_bytes(F.F.F.F.ELF)
            results=[subprocess.CompletedProcess([],0,F.dump(),""),subprocess.TimeoutExpired(["PRIVATE_DEBUG_PAYLOAD"],60)]
            with patch.object(U.subprocess,"run",side_effect=results) as execute:
                with self.assertRaisesRegex(ValueError,"unconfirmed AES-128 operation-local public first byte-0 baseline"):U.observe(binary)
                self.assertEqual(execute.call_count,2)
            output=io.StringIO()
            with patch.object(U.sys,"argv",["runner","--binary",str(binary)]), patch.object(U,"observe",side_effect=subprocess.TimeoutExpired(["PRIVATE_DEBUG_PAYLOAD"],60)), redirect_stderr(output), redirect_stdout(output):
                self.assertEqual(U.main(),2)
            self.assertNotIn("PRIVATE_DEBUG_PAYLOAD",output.getvalue())

    def test_unknown_artifact_or_shape_never_reaches_debugger(self):
        with tempfile.TemporaryDirectory() as directory:
            binary=Path(directory)/"fixture"
            binary.write_bytes(b"invalid")
            with patch.object(U.subprocess,"run") as execute:
                with self.assertRaises(ValueError):U.observe(binary)
                execute.assert_not_called()
            binary.write_bytes(F.F.F.F.ELF)
            with patch.object(U.subprocess,"run",return_value=subprocess.CompletedProcess([],0,"unknown shape","")) as execute:
                with self.assertRaises(ValueError):U.observe(binary)
                self.assertEqual(execute.call_count,1)


if __name__ == "__main__":
    unittest.main()
