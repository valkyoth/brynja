#!/usr/bin/env python3
"""Actual emitted inner report guards reject field, shape and ABI mutations."""
import importlib.util
from pathlib import Path
import re
import unittest

spec = importlib.util.spec_from_file_location("driver", Path(__file__).with_name("check-legacy-hmac-md5-cleanup.py"))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
report = driver.inner_report
flow, syntax = report.flow, report.syntax


class InnerReport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = driver.runner.cargo_environment.private_directory(driver.ROOT)
        cls.addClassCleanup(cls.directory.cleanup)
        cls.cases = []
        for compiler, target in (("1.90.0", "x86_64-unknown-linux-gnu"),
                                 ("1.99.1", "x86_64-unknown-linux-gnu"),
                                 ("1.99.1", "aarch64-unknown-linux-gnu")):
            artifacts = driver.emit(Path(cls.directory.name) / (compiler + target), compiler, target, "unwind", True)
            fixture, llvm = artifacts[0][1], artifacts[1][1]
            report.reports.probes(fixture)
            definitions, aliases = flow.definitions_and_aliases(llvm)
            for operation in ("authenticate", "authenticate_secret", "verify"):
                signature, body = report.phases.rows.method(definitions, aliases, operation)[1]
                check = report.Check(signature, body, llvm)
                check.run_report(255, 0)
                check.run_report(15, 1)
                cls.cases.append((signature, body, llvm, fixture, check))

    def rejects(self, case, before, after):
        signature, body, llvm, _, _ = case
        self.assertIn(before, body)
        self.assertNotEqual(before, after)
        changed = body.replace(before, after, 1)
        with self.subTest(before=before, after=after), self.assertRaises(ValueError):
            check = report.Check(signature, changed, llvm.replace(body, changed, 1))
            for mask in (0, 1, 2, 15, 240, 255):
                for backend in (0, 1):
                    check.run_report(mask, backend)
                    check.run_report(mask, backend, reported_backend=1 - backend)
                    check.run_report(mask, backend, active=9)
                    check.run_report(mask, backend, width=0)
                    check.run_report(mask, backend, vector=0)

    def lines(self, case, predecessors=False):
        check = case[-1]
        sites = check.predecessors if predecessors else check.visited
        return [check.graph[label][index] for label, index in sorted(sites)]

    def test_each_report_comparison_and_branch(self):
        for case in self.cases:
            count = 0
            for line in self.lines(case):
                if " = icmp " in line:
                    self.rejects(case, line, re.sub(r"icmp (eq|ne|uge)", lambda m:
                                 "icmp " + {"eq": "ne", "ne": "eq", "uge": "ugt"}[m[1]], line))
                    count += 1
            self.assertIn(count, (5, 6))  # Older LLVM keeps a separate Result tag comparison.
            branch = next(line for line in self.lines(case) if "label %" + case[-1].stop in line)
            self.rejects(case, branch, "br label %" + case[-1].stop)

    def test_input_activity_pointer_stride_and_sum(self):
        for case in self.cases:
            check, lines = case[-1], self.lines(case, True)
            loads = [line for line in lines if " = load ptr," in line]
            self.assertEqual(len(loads), 8)
            for line in loads:
                pointer = re.search(r"ptr (%[-\w.]+),", line)[1]
                # Reading descriptor payload instead of the presence niche must fail.
                self.rejects(case, line, f"%wrong = getelementptr inbounds i8, ptr {check.inputs}, i64 8\n"
                             + line.replace("ptr " + pointer + ",", "ptr %wrong,"))
            adds = [line for line in lines if " = add " in line]
            self.assertEqual(len(adds), 7)
            for line in adds:
                self.rejects(case, line, re.sub(r", %[-\w.]+$", ", 0", line))

    def test_selection_width_and_backend_load(self):
        for case in self.cases:
            check, lines = case[-1], self.lines(case, True)
            # LLVM 1.90 branches and merges constants; newer LLVM uses select.
            widths = [line for line in lines + self.lines(case) if " = select i1 " in line
                      and "i64 4" in line and "i64 8" in line]
            if widths:
                self.assertEqual(len(widths), 1)
                self.rejects(case, widths[0], widths[0].replace("i64 4", "i64 5"))
            else:
                width = next(line for line in self.lines(case) if " = phi i64 " in line
                             and "[ 4," in line and "[ 8," in line)
                self.rejects(case, width, width.replace("[ 4,", "[ 5,"))
            load = next(line for line in lines if " = load i8," in line)
            pointer = re.search(r"ptr (%[-\w.]+),", load)[1]
            self.rejects(case, load, load.replace("ptr " + pointer + ",", "ptr " + check.inputs + ","))

    def test_result_report_offsets(self):
        for case in self.cases:
            check, lines = case[-1], self.lines(case)
            pointers = syntax.pointers(check.body, (check.result,))
            count = 0
            for line in lines:
                load = re.search(r"load (i64|<2 x i64>), ptr (%[-\w.]+),", line)
                if load and pointers.get(load[2], (None, -1))[0] == check.result and pointers[load[2]][1] >= 16:
                    if pointers[load[2]][1] == 32 and load[1] == 'i64':
                        continue  # Scalar work is transported later, not an admission predicate.
                    self.rejects(case, line, line.replace("ptr " + load[2] + ",", "ptr " + check.result + ","))
                    count += 1
            self.assertGreaterEqual(count, 3)

    def test_constructor_backend_binding(self):
        for case in self.cases:
            llvm = case[2]
            definitions, aliases = flow.definitions_and_aliases(llvm)
            _, body = report.phases.rows.method(definitions, aliases, "with_tag_length")[1]
            pointers = syntax.pointers(body, ("%_0",))
            line = next(line for line in body.splitlines() if (m := re.search(r"store i8 (%[-\w.]+), ptr (%[-\w.]+),", line))
                        and pointers.get(m[2]) == ("%_0", 16))
            changed = re.sub(r"store i8 %[-\w.]+,", "store i8 0,", line)
            with self.assertRaises(ValueError):
                report.selection_layout(llvm.replace(body, body.replace(line, changed, 1), 1))
            destination = re.search(r", ptr (%[-\w.]+),", line)[1]
            for extra in (changed, f"  store i64 0, ptr {destination}, align 8",
                          f"  call void @unreviewed(ptr {destination})"):
                with self.assertRaises(ValueError):
                    report.selection_layout(llvm.replace(body, body.replace(line, line + "\n" + extra, 1), 1))

    def test_predecessor_effects_cycles_overflow_and_mutable_borrows(self):
        for case in self.cases:
            line = next(line for line in self.lines(case, True) if " = add " in line)
            name = line.split(" = ", 1)[0]
            for expression in ("call i64 @unreviewed()", "add i64 %missing, 0",
                               f"add i64 {name}, 0", "add i64 18446744073709551615, 1"):
                self.rejects(case, line, name + " = " + expression)
            signature, body, llvm = case[:3]
            for attribute in ("readonly", "noalias"):
                self.assertIn(attribute, signature)
                with self.assertRaises(ValueError):
                    report.Check(signature.replace(attribute, ""), body, llvm)

    def test_independent_report_layout_probes(self):
        for case in self.cases:
            fixture = case[3]
            definitions, aliases = flow.definitions_and_aliases(fixture)
            for name, before, after in (("work_report", "i64 %active", "i64 %scalar"),
                                        ("execution_report", "i64 %width", "i64 8"),
                                        ("normalized_simd_success", "i64 16", "i64 24")):
                body = report.n.pads.descriptors.admission.probe(definitions, aliases, name)
                self.assertIn(before, body)
                with self.assertRaises(ValueError):
                    report.reports.probes(fixture.replace(body, body.replace(before, after, 1), 1))


if __name__ == "__main__":
    unittest.main()
