#!/usr/bin/env python3
"""Mutate real MD5 error paths and exercise conservative reachability rules."""
import importlib.util
from pathlib import Path
import re
import unittest

spec = importlib.util.spec_from_file_location("md5_driver", Path(__file__).with_name("check-legacy-hmac-md5-cleanup.py"))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
results, errors = driver.results, driver.results.errors
phases, flow, syntax = errors.phases, errors.flow, errors.syntax


class Results(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = driver.runner.cargo_environment.private_directory(driver.ROOT)
        cls.addClassCleanup(cls.directory.cleanup)
        cls.compilers = []
        for compiler in ("1.90.0", "1.99.1"):
            artifacts = driver.emit(Path(cls.directory.name) / compiler, compiler,
                                    "x86_64-unknown-linux-gnu", "unwind", True)
            driver.validate(artifacts, "unwind")
            cls.compilers.append((artifacts[0][1], artifacts[1][1]))

    def callers(self):
        for fixture, llvm in self.compilers:
            definitions, aliases = flow.definitions_and_aliases(llvm)
            for operation in ("authenticate", "authenticate_secret", "verify"):
                yield fixture, llvm, phases.rows.method(definitions, aliases, operation)[1][1]

    def rejects(self, fixture, llvm, body, before, after):
        self.assertIn(before, body)
        self.assertNotEqual(before, after)
        with self.subTest(before=before, after=after), self.assertRaises(ValueError):
            results.validate(fixture, llvm.replace(body, body.replace(before, after, 1), 1), "unwind")

    def test_ready_result_authority_and_success_guard(self):
        for fixture, llvm, body in self.callers():
            ready, inner, outer = results.sites(body)
            graph = flow.blocks(body)
            call = graph[ready[0]][ready[1]]
            self.rejects(fixture, llvm, body, call, call.replace(ready[2], ready[2] + "_fake"))
            self.rejects(fixture, llvm, body, call,
                         call.replace(syntax.operand(ready[3][0]), "%workspace.i.i"))
            normal, _ = results.continuation(graph, ready)
            check = graph[normal[0]]
            comparison = next(line for line in check if "icmp eq i8" in line)
            self.rejects(fixture, llvm, body, comparison, comparison.replace("icmp eq", "icmp ne"))
            extract = next(line for line in check if "extractvalue { i8, i8 }" in line)
            self.rejects(fixture, llvm, body, extract, extract[:-1] + "1")
            branch = next(line for line in check if line.startswith("br i1"))
            self.rejects(fixture, llvm, body, branch, "br label %" + inner[0])
            self.rejects(fixture, llvm, body, branch, "br label %" + outer[0])

    def test_inner_error_load_phi_and_switch_are_load_bearing(self):
        for fixture, llvm, body in self.callers():
            _, inner, _ = results.sites(body)
            result = syntax.operand(inner[3][0])
            pointers = syntax.pointers(body, (result,))
            load = next(line for line in body.splitlines() if (match := re.search(
                r"load i8, ptr (%[-\w.]+),", line)) and pointers.get(match[1]) == (result, 48))
            self.rejects(fixture, llvm, body, load, re.sub(r"load i8, ptr %[-\w.]+,", f"load i8, ptr {result},", load))
            loaded = load.strip().split(" = ")[0]
            phi = next(line for line in body.splitlines() if "phi i8" in line and loaded + "," in line)
            self.rejects(fixture, llvm, body, phi, phi.replace(loaded + ",", "0,"))
            discriminator = phi.strip().split(" = ")[0]
            switch = next(line for line in body.splitlines() if "switch i8 " + discriminator + "," in line)
            default = re.search("label %" + flow.LABEL, switch)[1]
            graph = flow.blocks(body)
            block = next(lines for lines in graph.values() if switch.strip() in lines)
            for case in block[block.index(switch.strip()) + 1:-1]:
                self.rejects(fixture, llvm, body, case, re.sub("label %" + flow.LABEL, "label %" + default, case))

    def test_unwind_cannot_enter_outer(self):
        for fixture, llvm, body in self.callers():
            ready, inner, outer = results.sites(body)
            graph = flow.blocks(body)
            for site in (ready, inner):
                edge = graph[site[0]][site[1] + 1]
                self.rejects(fixture, llvm, body, edge,
                             re.sub("unwind label %" + flow.LABEL, "unwind label %" + outer[0], edge))

    def test_success_cannot_bypass_inner_dispatch(self):
        for fixture, llvm, body in self.callers():
            _, inner, outer = results.sites(body)
            anchor = inner[0] + ":"
            bypass = anchor + "\n  br i1 %unknown, label %retained_inner, label %" + outer[0] + "\nretained_inner:"
            self.rejects(fixture, llvm, body, anchor, bypass)

    def test_unknown_aliasing_effects_cannot_preserve_result_knowledge(self):
        for fixture, llvm, body in self.callers():
            _, inner, _ = results.sites(body)
            result = syntax.operand(inner[3][0])
            pointers = syntax.pointers(body, (result,))
            load = next(line for line in body.splitlines() if (match := re.search(
                r"load i8, ptr (%[-\w.]+),", line)) and pointers.get(match[1]) == (result, 48))
            for effect in ("call void @unknown_callback()", f"store i8 0, ptr {result}, align 1",
                           "store i8 0, ptr %unbound_pointer, align 1"):
                self.rejects(fixture, llvm, body, load, effect + "\n" + load)

    def test_compiled_probe_cannot_be_missing_or_rebound(self):
        for fixture, llvm in self.compilers:
            definitions, aliases = flow.definitions_and_aliases(fixture)
            body = results.fence.admission.probe(definitions, aliases, "digest_rejection")
            for before, after in (("i64 48", "i64 47"), ("ptr %_0,", "ptr %wrong,"),
                                  ("%error.0,", "%error.1,"), ("ret void", "call void @extra()\nret void")):
                self.assertIn(before, body)
                with self.subTest(before=before), self.assertRaises(ValueError):
                    results.validate(fixture.replace(body, body.replace(before, after, 1), 1), llvm, "unwind")


class Reachability(unittest.TestCase):
    BODY = """entry:
  %result = alloca [56 x i8], align 8
  %tag = getelementptr inbounds i8, ptr %result, i64 48
  %d = load i8, ptr %tag, align 8
  br label %join
join:
  %joined = phi i8 [ %d, %entry ]
  %failed = icmp eq i8 %joined, -1
  br i1 %failed, label %exit, label %outer
outer:
  ret void
exit:
  ret void
"""

    def reaches(self, body, **kwargs):
        return errors.reaches(body, ("entry", 0), None, {}, "%result", 255, {("outer", 0)}, **kwargs)

    def test_unknown_values_and_mutations_never_prove_exclusion(self):
        self.assertFalse(self.reaches(self.BODY))
        allowed = self.BODY.replace("%joined, -1", "%joined, 0")
        self.assertTrue(self.reaches(allowed))
        self.assertFalse(self.reaches(allowed, barriers={("join", 0)}))
        for before, after in (("icmp eq", "icmp ne"), ("load i8, ptr %tag", "load i8, ptr %unknown"),
                              ("%joined, -1", "%unknown, -1"), ("[ %d,", "[ 0,"),
                              ("br label %join", "br label %outer")):
            with self.subTest(before=before):
                self.assertTrue(self.reaches(self.BODY.replace(before, after)))
        for line in ("call void @unknown()", "store i8 0, ptr %tag, align 1",
                     "store i64 0, ptr %unknown, align 8",
                     "%old = atomicrmw xchg ptr %tag, i8 0 seq_cst",
                     "%pair = cmpxchg ptr %tag, i8 -1, i8 0 seq_cst seq_cst",
                     "%alias = getelementptr i8, ptr %result, i64 0\n  call void @llvm.lifetime.end.p0(ptr %alias)",
                     "call void @llvm.lifetime.end.p0(ptr %unknown)",
                     "%other = alloca [16 x i8], align 8\n  %far = getelementptr i8, ptr %other, i64 17\n"
                     "  store i8 0, ptr %far, align 1"):
            self.assertTrue(self.reaches(self.BODY.replace("  %d =", "  " + line + "\n  %d =")))

    def test_phi_predecessors_unknowns_and_cycles(self):
        graph = """entry:
  br i1 %unknown, label %left, label %right
left:
  br label %join
right:
  br label %join
join:
  %d = phi i8 [ 255, %left ], [ 0, %right ]
  %fail = icmp eq i8 %d, -1
  br i1 %fail, label %exit, label %outer
outer:
  ret void
exit:
  br label %exit
"""
        self.assertTrue(self.reaches(graph))
        self.assertFalse(self.reaches(graph.replace("[ 0, %right ]", "[ 255, %right ]")))
        self.assertTrue(self.reaches(graph.replace("[ 0, %right ]", "[ undef, %right ]")))

    def test_width_normalization_and_parallel_phi_values(self):
        self.assertEqual(errors.evaluate("phi i8 [ -1, %from ]", {}, "from", {}, {}), 255)
        self.assertEqual(errors.evaluate("icmp eq i8 %a, -1", {"%a": 255}, None, {}, {}), 1)
        self.assertIsNone(errors.evaluate("freeze i8 %a", {"%a": 255}, None, {}, {}))
        self.assertIsNone(errors.evaluate("and i8 %a, 0", {}, None, {}, {}))
        body = """entry:
  br label %loop
loop:
  %a = phi i8 [ 0, %entry ], [ %b, %loop ]
  %b = phi i8 [ 255, %entry ], [ %a, %loop ]
  %done = icmp eq i8 %a, 255
  br i1 %done, label %outer, label %loop
outer:
  ret void
"""
        self.assertTrue(self.reaches(body))

    def test_unparsed_control_flow_fails_closed(self):
        for before, after in (("br label %join", "indirectbr ptr %target, [label %join]"),
                              ("br label %join", "br label %missing"),
                              ("[ %d, %entry ]", "[ %d, %wrong ]")):
            with self.subTest(before=before), self.assertRaises(ValueError):
                self.reaches(self.BODY.replace(before, after))


if __name__ == "__main__":
    unittest.main()
