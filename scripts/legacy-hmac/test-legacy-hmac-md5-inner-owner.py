#!/usr/bin/env python3
"""Mutation checks on real emitted inner-result owner handoffs."""
import importlib.util
from pathlib import Path
import re
import unittest

spec = importlib.util.spec_from_file_location("driver", Path(__file__).with_name("check-legacy-hmac-md5-cleanup.py"))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
owner = driver.inner_owner
flow, syntax = owner.flow, owner.syntax


class InnerOwner(unittest.TestCase):
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
            checks = owner.validate(fixture, llvm)
            definitions, aliases = flow.definitions_and_aliases(llvm)
            for operation, check in zip(("authenticate", "authenticate_secret", "verify"), checks):
                signature, body = owner.phases.rows.method(definitions, aliases, operation)[1]
                cls.cases.append((signature, body, llvm, fixture, check))

    def rejects(self, case, before, after):
        signature, body, llvm, _, _ = case
        self.assertIn(before, body)
        self.assertNotEqual(before, after)
        changed = body.replace(before, after, 1)
        with self.subTest(before=before, after=after), self.assertRaises(ValueError):
            owner.Check(signature, changed, llvm.replace(body, changed, 1)).run()

    def lines(self, case):
        check = case[-1]
        return [check.graph[label][index] for label, index in sorted(check.visited)]

    def test_owner_pointer_and_length_cannot_be_replaced(self):
        for case in self.cases:
            check = case[-1]
            pointers = syntax.pointers(check.body, (check.owner,))
            count = 0
            for line in self.lines(case):
                store = re.fullmatch(r"store (ptr|i64) (%[-\w.]+), ptr (%[-\w.]+), align 8(?:, !.*)?", line)
                if store and pointers.get(store[3], (None,))[0] == check.owner:
                    replacement = "null" if store[1] == "ptr" else "128"
                    self.rejects(case, line, line.replace(store[1] + " " + store[2] + ",", store[1] + " " + replacement + ",", 1))
                    count += 1
            self.assertEqual(count, 2)

    def test_split_pointer_loads_and_casts_are_bound(self):
        for case in self.cases:
            lines = self.lines(case)
            load = next(line for line in lines if " = load i48," in line)
            address = re.search(r"ptr (%[-\w.]+),", load)[1]
            self.rejects(case, load, load.replace(address, case[-1].output))
            cast = next(line for line in lines if " = inttoptr i64 " in line)
            self.rejects(case, cast, re.sub(r"inttoptr i64 %[-\w.]+", "inttoptr i64 128", cast))
            merges = [line for line in lines if " = or disjoint i64 " in line]
            self.assertEqual(len(merges), 2)
            for line in merges:
                self.rejects(case, line, re.sub(r", %[-\w.]+$", ", 0", line))

    def test_length_phi_cannot_be_rebound(self):
        for case in self.cases:
            check, lines = case[-1], self.lines(case)
            pointers = syntax.pointers(check.body, (check.result,))
            load = next(line for line in lines if (match := re.search(r"load i64, ptr (%[-\w.]+),", line))
                        and pointers.get(match[1]) == (check.result, 8))
            value = load.split(" = ")[0]
            phi = next(line for line in lines if "phi i64" in line and "[ " + value + "," in line)
            self.rejects(case, phi, phi.replace("[ " + value + ",", "[ 128,"))

    def test_scope_completion_and_identity(self):
        for case in self.cases:
            check = case[-1]
            completed = next(line for line in self.lines(case) if line.startswith("store i8 1,"))
            self.rejects(case, completed, completed.replace("i8 1", "i8 0"))
            drop = next(line for line in self.lines(case) if (call := syntax.call(line))
                        and owner.n.results.fence.identity(call[0], "drop"))
            label = next(label for label, index in check.visited if check.graph[label][index] == drop)
            begin = check.body.index(label + ":")
            anchor = check.body[begin:check.body.index(drop, begin) + len(drop)]
            self.rejects(case, anchor, anchor.replace(drop, drop.replace(check.scope, check.owner)))

    def test_expiry_clobbers_unknown_effects_and_cycles(self):
        for case in self.cases:
            check = case[-1]
            branch = next(line for line in self.lines(case) if "label %" + check.stop in line)
            for extra in (f"store ptr null, ptr {check.owner}, align 8",
                          f"call void @llvm.lifetime.end.p0(ptr {check.output})",
                          f"call void @llvm.lifetime.start.p0(ptr {check.output})",
                          f"call void @llvm.lifetime.end.p0(ptr {check.owner})",
                          "call void @unreviewed_effect()", "fence seq_cst"):
                self.rejects(case, branch, extra + "\n" + branch)
            self.rejects(case, branch, "br label %" + check.start[0])

    def test_error_and_unwind_bypasses(self):
        for case in self.cases:
            signature, body, llvm, fixture, check = case
            tag = owner.n.layouts(fixture)
            for error in (*range(4), None):
                self.assertEqual(check.run(error_tag=tag, error=error), 0)
            self.assertEqual(check.run(backend=2), 0)
            edge = check.graph[check.site[0]][check.site[1] + 1]
            changed = body.replace(edge, re.sub(r"unwind label %[-\w.]+", "unwind label %" + check.stop, edge), 1)
            with self.assertRaises(ValueError):
                owner.Check(signature, changed, llvm.replace(body, changed, 1)).run()


if __name__ == "__main__":
    unittest.main()
