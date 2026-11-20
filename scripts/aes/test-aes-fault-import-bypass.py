#!/usr/bin/env python3
"""Mock runner contracts, not native fault evidence."""
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


B = module("import_bypass", "check-aes-fault-import-bypass.py")
F = module("import_store_tests", "test-aes-fault-import-store.py")


def dump(symbol=B.SYMBOLS[0]):
    ops = ["nop", "mov %bpl,0x7(%rsp)", "lea 0x7(%rsp),%rdi", "mov $0x1,%esi",
           "call 7000 <brynja_core::secret_memory_volatile::zeroize_region_volatile>",
           "cmpb $0x0,0x7(%rsp)", f"jne 500e <{symbol}+0xe>",
           "test %bpl,%bpl", f"je 500d <{symbol}+0xd>",
           "movb $0x1,0x8(%rbx)", "movq $0x0,(%rbx)", "lea 0x8(%rsp),%rdi",
           "nop", "nop", "ret"]
    return F.F.dump()+f"\n0000000000005000 <{symbol}>:\n"+"\n".join(
        f" {0x5000+i:x}: {op}" for i, op in enumerate(ops))+"\n"


def transcript(width, case):
    data = case in ("data", "combined")
    text = F.transcript(width, "cached", "data" if data else "baseline")
    text += "\nHardware assisted breakpoint 4 at 0x1\nhit Breakpoint 4, 0x1\nBYPASS_DECISION 1"
    if case in ("bypass", "combined"):
        text += "\nBYPASS_FORGED 1"
    return text


def runs():
    yield subprocess.CompletedProcess([], 0, dump(), "")
    for width in B.I.WIDTHS:
        for _replica in B.I.C.REPLICAS:
            for case in B.CASES:
                for _byte in ([0] if case in ("baseline", "bypass") else range(width)):
                    yield subprocess.CompletedProcess([], 0, transcript(width, case), "")


class ImportBypass(unittest.TestCase):
    def test_maps_only_the_inlined_decision_and_unique_constructor(self):
        for symbol in B.SYMBOLS:
            _, site = B.map_sites(dump(symbol))
            self.assertEqual(site["decision"], 7)
            self.assertEqual(site["decision_register"], "bpl")
        for bad in (dump().replace("test %bpl,%bpl", "test %al,%al"),
                    dump().replace("cmpb $0x0,0x7(%rsp)", "nop"),
                    dump().replace("movb $0x1,0x8(%rbx)", "nop"),
                    dump().replace("zeroize_region_volatile", "other_function"),
                    dump()+dump(), dump().replace("500e: ret", "500e: nop")):
            with self.assertRaises(ValueError):
                B.map_sites(bad)

    def test_register_mutations_and_expected_decision_for_every_case(self):
        mapping, site = B.map_sites(dump())
        for width in B.I.WIDTHS:
            for replica in B.I.C.REPLICAS:
                for case in B.CASES:
                    for byte in ([0] if case in ("baseline", "bypass") else range(width)):
                        cmds, _ = B.commands(mapping, site, width, replica, byte, case)
                        writes = [c for c in cmds if c.startswith(("set $rax", "set $bpl", "set *"))]
                        expected = []
                        if case in ("data", "combined"):
                            expected += [f"set $rax = $rax ^ {1 << (byte % 8 * 8)}ULL"]
                        if case in ("bypass", "combined"):
                            expected += ["set $bpl = 0"]
                        self.assertEqual(writes, expected)
                        decision = next(c for c in cmds if c.startswith('printf "BYPASS_DECISION'))
                        self.assertIn(f"$bpl == {int(case in ('data','combined'))}", decision)
                        self.assertIn("*(unsigned char*)($rsp+7) == 0", decision)
                        self.assertLess(cmds.index("delete 3"), next(i for i,c in enumerate(cmds) if "+7)" in c and c.startswith("hbreak")))
                        if "set $bpl = 0" in cmds:
                            self.assertLess(cmds.index(decision), cmds.index("set $bpl = 0"))

    def test_every_checkpoint_and_outcome_required(self):
        for width in B.I.WIDTHS:
            for case in B.CASES:
                good = transcript(width, case)
                B.validate(good, width, "first", 0, case)
                for line in good.splitlines():
                    if line.startswith(("IMPORT_", "BYPASS_", "BRYNJA_")):
                        for replacement in ("", line+"\n"+line):
                            with self.assertRaises(ValueError):
                                B.validate(good.replace(line,replacement),width,"first",0,case)
                    if line.startswith(("IMPORT_", "BYPASS_")):
                        with self.assertRaises(ValueError):
                            B.validate(good.replace(line,line.replace(" 1"," 0")),width,"first",0,case)

    def test_bad_execution_source_hooks_and_wrong_outcomes_rejected(self):
        good = transcript(16,"combined")
        for old,new in [("EVIDENCE_CFG=false","EVIDENCE_CFG=true"),
                        ("_REJECTED","_ACCEPTED"), ("hit Breakpoint 4","missed stop 4"),
                        ("exited normally","crashed"), ("Hardware assisted breakpoint 4","software breakpoint 4")]:
            with self.assertRaises(ValueError):
                B.validate(good.replace(old,new),16,"first",0,"combined")

    def test_invalid_selectors(self):
        mapping, site = B.map_sites(dump())
        for width,replica,byte,case in [(True,"first",0,"data"),(16,"third",0,"data"),
                                     (16,"first",16,"data"),(16,"first",1,"bypass"),
                                     (16,"first",0,"unknown")]:
            with self.assertRaises(ValueError):
                B.commands(mapping,site,width,replica,byte,case)

    def test_complete_population_and_unchanged_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory)/"fixture"
            binary.write_bytes(F.F.F.ELF)
            with patch.object(B.subprocess,"run",side_effect=runs()) as execute:
                report = B.observe(binary)
            self.assertEqual(execute.call_count,301)
            self.assertEqual(len(report["groups"]),6)
            self.assertEqual(report["qualification"],"none")
            for group in report["groups"]:
                self.assertEqual(group["counts"],dict(baseline=1,bypass=1,data=group["width_bits"]//8,combined=group["width_bits"]//8))
            sequence = iter(runs())
            def change(*args, **kwargs):
                result = next(sequence)
                binary.write_bytes(F.F.F.ELF+b"changed")
                return result
            with patch.object(B.subprocess,"run",side_effect=change):
                with self.assertRaisesRegex(ValueError,"artifact changed"):
                    B.observe(binary)

    def test_no_retry_or_raw_failure_output(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory)/"fixture"
            binary.write_bytes(F.F.F.ELF)
            results = [subprocess.CompletedProcess([],0,dump(),""),
                       subprocess.CalledProcessError(1,["gdb"],output="PRIVATE_DEBUG_PAYLOAD")]
            with patch.object(B.subprocess,"run",side_effect=results) as execute:
                with self.assertRaisesRegex(ValueError,"unconfirmed AES-128 cached first byte-0 baseline"):
                    B.observe(binary)
                self.assertEqual(execute.call_count,2)
            capture = io.StringIO()
            with patch.object(B.sys,"argv",["runner","--binary",str(binary)]), patch.object(B,"observe",side_effect=subprocess.CalledProcessError(1,["PRIVATE_DEBUG_PAYLOAD"])), redirect_stderr(capture), redirect_stdout(capture):
                self.assertEqual(B.main(),2)
            self.assertNotIn("PRIVATE_DEBUG_PAYLOAD",capture.getvalue())

    def test_unknown_artifact_and_mapping_stop_before_debugger(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory)/"fixture"
            binary.write_bytes(b"invalid")
            with patch.object(B.subprocess,"run") as execute:
                with self.assertRaises(ValueError):B.observe(binary)
                execute.assert_not_called()
            binary.write_bytes(F.F.F.ELF)
            with patch.object(B.subprocess,"run",return_value=subprocess.CompletedProcess([],0,"unknown shape","")) as execute:
                with self.assertRaises(ValueError):B.observe(binary)
                self.assertEqual(execute.call_count,1)


if __name__ == "__main__":
    unittest.main()
