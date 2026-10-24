#!/usr/bin/env python3
"""Mutate actual normalization setup, readiness and report transport artifacts."""
import importlib.util
from pathlib import Path
import re
import unittest

spec = importlib.util.spec_from_file_location("driver", Path(__file__).with_name("check-legacy-hmac-md5-cleanup.py"))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
setup, reports = driver.setup, driver.reports
n, syntax, flow = reports.n, reports.syntax, reports.flow


class SetupReports(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = driver.runner.cargo_environment.private_directory(driver.ROOT)
        cls.addClassCleanup(cls.directory.cleanup)
        cls.cases = []
        for compiler in ("1.90.0", "1.99.1"):
            artifacts = driver.emit(Path(cls.directory.name) / compiler, compiler,
                                    "x86_64-unknown-linux-gnu", "unwind", True)
            fixture, llvm = artifacts[0][1], artifacts[1][1]
            check, ready, visited = setup.validate(fixture, llvm, "unwind")
            report = reports.validate(fixture, llvm)
            cls.cases.append((fixture, llvm, check, ready, visited, report))

    def rejects(self, case, before, after, *, mode="setup", shape=(65,) * 8, backend=0):
        fixture, llvm = case[:2]
        self.assertIn(before, llvm)
        self.assertNotEqual(before, after)
        body = case[2].body
        mutant = llvm.replace(body, body.replace(before, after, 1), 1) if before in body else llvm.replace(before, after, 1)
        with self.subTest(before=before, mode=mode), self.assertRaises(ValueError):
            if mode == "setup":
                setup.validate(fixture, mutant, "unwind")
            elif mode == "owner":
                n.validate(fixture, mutant)
            elif mode == "guards":
                check = reports.Check(fixture, mutant)
                for selected in (0, 1):
                    for width in (0, 4, 8, 9):
                        check.run(shape, selected, width=width)
                    for active in (0, 4, 8, 9):
                        check.run(shape, selected, active=active)
                    for vector in (0, 3, 4, 7, 8, 9):
                        check.run(shape, selected, vector=vector)
                    for other in (0, 1, 2):
                        check.run(shape, selected, reported_backend=other)
            else:
                reports.Check(fixture, mutant).run(shape, backend)

    def test_all_scenarios_nonvacuous(self):
        for case in self.cases:
            self.assertEqual(case[-1].scenarios, 662)
            self.assertEqual(case[-1].keys.routes, {"scalar", "simd", "none"})

    def test_arm_scalar_report_form_and_field_substitution(self):
        artifacts = driver.emit(Path(self.directory.name) / "arm", "1.99.1",
                                "aarch64-unknown-linux-gnu", "unwind", True)
        fixture, llvm = artifacts[0][1], artifacts[1][1]
        check, ready, visited = setup.validate(fixture, llvm, "unwind")
        report = reports.validate(fixture, llvm)
        self.assertEqual(report.scenarios, 662)
        self.assertEqual(set(report.fields), {8, 16, 24})
        case = (fixture, llvm, check, ready, visited, report)
        for offset, (dtype, name) in report.fields.items():
            self.assertEqual(dtype, "i64")
            line = next(line for line in report.owner.graph[report.success] if line.startswith("store i64 " + name + ","))
            other = report.fields[16 if offset != 16 else 24][1]
            for shape in ((65,) * 8, (65,) + (64,) * 7):
                self.rejects(case, line, line.replace("i64 " + name + ",", "i64 " + other + ","),
                             mode="report", shape=shape)

    def test_iv_bytes_offsets_extent_and_population(self):
        for case in self.cases:
            check, visited = case[2], case[4]
            lines = [check.graph[label][index] for label, index in sorted(visited)]
            offsets = [line for line in lines if "getelementptr" in line and check.workspace in line]
            copies = [line for line in lines if "llvm.memcpy" in line]
            self.assertEqual((len(offsets), len(copies)), (8, 8))
            for line in offsets:
                self.rejects(case, line, re.sub(r"i64 \d+$", "i64 0", line))
            for line in copies:
                self.rejects(case, line, line.replace("i64 16", "i64 15"))
            self.rejects(case, copies[0], copies[0] + "\n" + copies[0])
            constant = next(line for line in case[1].splitlines() if 'constant [16 x i8] c"\\01#Eg' in line)
            self.rejects(case, constant, constant.replace(r"\01", r"\00", 1))

    def test_authority_and_setup_effects(self):
        for case in self.cases:
            check, ready, visited = case[2:5]
            line = check.graph[ready[0]][ready[1]]
            arg = syntax.operand(ready[3][0])
            self.rejects(case, line, line.replace(arg, check.scope))
            load = next(check.graph[label][index] for label, index in visited
                        if " = load ptr, ptr " + check.workspace in check.graph[label][index])
            self.rejects(case, load, load.replace("ptr " + check.workspace, "ptr " + check.scope))
            for effect in ("call void @unexpected()", "fence seq_cst", "store i8 0, ptr " + check.workspace + ", align 8"):
                self.rejects(case, line, effect + "\n" + line)

    def test_readiness_results_cannot_bypass_or_reverse_guard(self):
        for case in self.cases:
            check, ready = case[2:4]
            start, _ = setup.results.continuation(check.graph, ready)
            lines = check.graph[start[0]][start[1]:]
            comparison = next(line for line in lines if "icmp eq i8" in line)
            self.rejects(case, comparison, comparison.replace("icmp eq", "icmp ne"))
            branch = next(line for line in lines if line.startswith("br i1"))
            for destination in (check.calls["scalar"][0], check.calls["simd"][0], check.stop):
                self.rejects(case, branch, "br label %" + destination)
            extract = next(line for line in lines if "extractvalue" in line)
            self.rejects(case, extract, re.sub(r", 0$", ", 1", extract))

    def test_setup_unwinds_cannot_dispatch(self):
        for case in self.cases:
            check, ready = case[2:4]
            clear = setup.phases.one(check.body, lambda name, args: setup.results.fence.identity(name, "clear"), "clear")
            scalar = next(site for site, kind in case[-1].keys.frontiers.items() if kind == "scalar")
            for site in (clear, ready, scalar):
                line = check.graph[site[0]][site[1] + 1]
                for destination in (check.calls["scalar"][0], check.calls["simd"][0], check.stop):
                    self.rejects(case, line, re.sub(r"unwind label %[-\w.]+", "unwind label %" + destination, line))

    def test_scalar_setup_has_no_intervening_effect(self):
        for case in self.cases:
            check = case[2]
            call = check.graph[check.calls["scalar"][0]][check.calls["scalar"][1]]
            self.rejects(case, call, "call void @unexpected()\n" + call)

    def test_scope_completion_required_before_destructor(self):
        for case in self.cases:
            check = n.validate(case[0], case[1])
            lines = [check.graph[label][index] for label, index in check.visited]
            pointer_map = syntax.pointers(check.body, (check.scope,))
            stores = [line for line in lines if (m := re.fullmatch(r"store i8 1, ptr (%[-\w.]+), align 8(?:, !.*)?", line))
                      and pointer_map.get(m[1]) == (check.scope, 8)]
            self.assertEqual(len(stores), 1)
            self.rejects(case, stores[0], stores[0].replace("store i8 1", "store i8 0"), mode="owner")

    def test_report_abi_probes(self):
        for case in self.cases:
            fixture, llvm = case[:2]
            definitions, aliases = flow.definitions_and_aliases(fixture)
            for name, before, after in (("work_report", "i64 %active", "i64 %scalar"),
                                        ("work_report", "i64 16", "i64 8"),
                                        ("execution_report", "i64 32", "i64 31"),
                                        ("execution_report", "i64 24", "i64 23")):
                body = n.pads.descriptors.admission.probe(definitions, aliases, name)
                self.assertIn(before, body)
                with self.subTest(name=name, before=before), self.assertRaises(ValueError):
                    reports.Check(fixture.replace(body, body.replace(before, after, 1), 1), llvm)

    def test_report_stores_constants_swaps_and_later_overwrites(self):
        for case in self.cases:
            report = case[-1]
            lines = report.owner.graph[report.success]
            for offset, (dtype, name) in report.fields.items():
                line = next(line for line in lines if line.startswith("store " + dtype + " " + name + ","))
                for shape in ((65,) * 8, (65,) + (64,) * 7, (64,) * 8):
                    replacement = "zeroinitializer" if dtype.startswith("<") else "0"
                    self.rejects(case, line, line.replace(dtype + " " + name + ",", dtype + " " + replacement + ","),
                                 mode="report", shape=shape)
                self.rejects(case, line, line + "\n" + line, mode="report")
                self.rejects(case, line, line + "\ncall void @escape(ptr %_0)", mode="report")
                self.rejects(case, line, line + "\n%leaked = ptrtoint ptr %_0 to i64", mode="report")

    def test_report_loads_phis_and_guard_comparisons(self):
        for case in self.cases:
            report, owner = case[-1], case[-1].owner
            lines = [owner.graph[label][index] for label, index in sorted(owner.visited)]
            guards = [line for line in lines if re.search(r"icmp(?: samesign)? (eq|ne|ugt|uge|ult|ule) i(?:8|64) ", line)]
            self.assertGreaterEqual(len(guards), 5)
            for line in guards:
                changed = re.sub(r"icmp( samesign)? (eq|ne|ugt|uge|ult|ule)",
                                 lambda m: "icmp" + (m[1] or "") + " " +
                                 {"eq": "ne", "ne": "eq", "ugt": "ule", "uge": "ult", "ult": "uge", "ule": "ugt"}[m[2]], line)
                self.rejects(case, line, changed, mode="guards")
            for line in (line for line in lines if " = and i1 " in line or " = or i1 " in line):
                changed = line.replace(" = and i1 ", " = or i1 ") if " = and i1 " in line else line.replace(" = or i1 ", " = and i1 ")
                self.rejects(case, line, changed, mode="guards")
            for kind in ("scalar", "simd"):
                result = syntax.operand(owner.calls[kind][3][0])
                pointers = syntax.pointers(owner.body, (result,))
                load = next(line for line in lines if (m := re.search(r"load <2 x i64>, ptr (%[-\w.]+),", line))
                            and pointers.get(m[1]) == (result, 32))
                address = re.search(r"ptr (%[-\w.]+),", load)[1]
                shape = (65,) * 8 if kind == "simd" else (65,) + (64,) * 7
                self.rejects(case, load, load.replace(address, result), mode="report", shape=shape)
            dtype, name = report.fields[8]
            phi = owner.defs[name][1]
            self.assertIn("phi i64", phi)
            self.rejects(case, phi, re.sub(r"\[ (%[-\w.]+),", "[ 0,", phi), mode="report")
            self.assertIn("[ 0,", phi)
            self.rejects(case, phi, phi.replace("[ 0,", "[ 1,", 1), mode="report", shape=(64,) * 8)


if __name__ == "__main__":
    unittest.main()
