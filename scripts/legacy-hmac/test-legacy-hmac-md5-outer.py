#!/usr/bin/env python3
"""Real emitted outer prefix, descriptor, failure and lifetime mutations."""
import importlib.util
from pathlib import Path
import re
import unittest

spec = importlib.util.spec_from_file_location("driver", Path(__file__).with_name("check-legacy-hmac-md5-cleanup.py"))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
outer = driver.outer
syntax, flow = outer.syntax, outer.flow


class Outer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = driver.runner.cargo_environment.private_directory(driver.ROOT)
        cls.addClassCleanup(cls.directory.cleanup)
        cls.cases = []
        for compiler, target in (("1.90.0", "x86_64-unknown-linux-gnu"), ("1.99.1", "x86_64-unknown-linux-gnu"),
                                 ("1.99.1", "aarch64-unknown-linux-gnu")):
            artifacts = driver.emit(Path(cls.directory.name) / (compiler + target), compiler, target, "unwind", True)
            fixture, llvm = artifacts[0][1], artifacts[1][1]
            definitions, aliases = flow.definitions_and_aliases(llvm)
            for operation in ("authenticate", "authenticate_secret", "verify"):
                signature, body = outer.phases.rows.method(definitions, aliases, operation)[1]
                check = outer.Check(signature, body, llvm)
                check.run(255)
                check.run(0)
                cls.cases.append((signature, body, llvm, check))

    def rejects(self, case, before, after, mask=255, failure=None):
        signature, body, llvm, _ = case
        self.assertIn(before, body)
        self.assertNotEqual(before, after)
        mutated = body.replace(before, after, 1)
        with self.subTest(before=before, after=after), self.assertRaises(ValueError):
            outer.Check(signature, mutated, llvm.replace(body, mutated, 1)).run(mask, failure)

    def lines(self, case):
        check = case[-1]
        return [check.graph[label][index] for label, index in sorted(check.visited)]

    def test_xor_mask_extent_lane_and_bit_geometry(self):
        for case in self.cases:
            lines = self.lines(case)
            mask = next(line for line in lines if line.startswith("store i8 106,"))
            for byte in (0, 54, 92, 107):
                self.rejects(case, mask, mask.replace("i8 106", "i8 " + str(byte)))
            extent = next(line for line in lines if re.search(r"icmp eq i64 .*?, 64$", line))
            for length in (63, 65):
                self.rejects(case, extent, extent.replace(", 64", ", " + str(length)))
            call = next(line for line in lines if (c := syntax.call(line)) and outer.model.pad.primitive(c[0], "xor_secret_byte_bits"))
            self.rejects(case, call, call.replace("i8 noundef 8", "i8 noundef 7"))
            name, args = syntax.call(call)
            self.rejects(case, call, call.replace(syntax.operand(args[0]), case[-1].pad))
            self.rejects(case, call, call.replace(name, name + "_fake"))

    def test_constructor_pointer_width_and_lane_offsets(self):
        for case in self.cases:
            lines, check = self.lines(case), case[-1]
            call = next(line for line in lines if (c := syntax.call(line)) and check.constructor(c[0]))
            for before, after in (("i64 noundef 16", "i64 noundef 15"), ("i8 noundef 8", "i8 noundef 7")):
                self.rejects(case, call, call.replace(before, after))
            args = syntax.call(call)[1]
            self.rejects(case, call, call.replace(syntax.operand(args[1]), check.pad))
            digest = next(line for line in lines if "getelementptr" in line and "[16 x i8]" in line)
            for width in (8, 32):
                self.rejects(case, digest, digest.replace("[16 x i8]", f"[{width} x i8]"))
            self.rejects(case, digest, re.sub(r"i64 %[-\w.]+$", "i64 0", digest))

    def test_descriptor_population_payload_and_activity(self):
        for case in self.cases:
            check, lines = case[-1], self.lines(case)
            null = next(line for line in lines if line.startswith("store ptr null, ptr " + check.outer))
            self.rejects(case, null, null.replace("ptr null", "ptr " + check.pad), mask=0)
            copies = [line for line in lines if "llvm.memcpy" in line]
            self.assertEqual(len(copies), 2)
            for line in copies:
                self.rejects(case, line, re.sub(r"i64 (23|24)", lambda m: "i64 " + str(int(m[1]) - 1), line))
            lane = next(line for line in lines if "getelementptr" in line and
                        ", ptr " + check.outer + ", i64 %" in line)
            self.rejects(case, lane, re.sub(r"i64 %[-\w.]+$", "i64 0", lane))
            niches = [line for line in lines if "icmp eq ptr" in line and ", null" in line]
            self.assertEqual(len(niches), 2)
            for line in niches:
                self.rejects(case, line, line.replace("icmp eq", "icmp ne"))

    def test_owner_exposure_and_iteration_limit(self):
        for case in self.cases:
            lines = self.lines(case)
            limit = next(line for line in lines if "@llvm.umin.i64" in line)
            self.rejects(case, limit, limit.replace("i64 8)", "i64 7)"))
            shift = next(line for line in lines if "lshr i64" in line)
            self.rejects(case, shift, shift.replace(", 4", ", 5"))
            # Replacing the owner's pointer with a different root must not make
            # the loop's old pointer magically acquire the seeded provenance.
            pointer = next(line for line in case[1].splitlines() if "store ptr" in line and
                           "ptr " + case[-1].owner + "," in line)
            self.rejects(case, pointer, re.sub(r"store ptr %[-\w.]+,", "store ptr " + case[-1].pad + ",", pointer))

    def test_output_zeroing_and_capture(self):
        for case in self.cases:
            check, lines = case[-1], self.lines(case)
            clear = next(line for line in lines if "llvm.memset" in line)
            for changed in (clear.replace("i64 128", "i64 127"), clear.replace("i8 0", "i8 1"),
                            clear.replace(check.final, check.pad)):
                self.rejects(case, clear, changed)
            for name in (check.pad, check.outer, check.final, check.control):
                line = next(line for line in lines if line.startswith("store ptr " + name + ","))
                self.rejects(case, line, line.replace("store ptr " + name + ",", "store ptr null,"))

    def test_failures_and_unwinds_cannot_reenter_dispatch(self):
        for case in self.cases:
            check = case[-1]
            for failure in (("xor", 0), ("xor", 511), ("constructor", 0), ("constructor", 7)):
                check.run(255, failure)
            unwinds = 0
            for label, index in sorted(check.visited):
                line = check.graph[label][index]
                call = syntax.call(line)
                if call and (check.constructor(call[0]) or outer.model.pad.primitive(call[0], "xor_secret_byte_bits")):
                    unwinds += 1
                    edge = check.graph[label][index + 1]
                    # Use the exact block text because calls share cleanup edge strings.
                    begin = check.body.index(label + ":")
                    end = check.body.index(edge, begin) + len(edge)
                    anchor = check.body[begin:end]
                    self.rejects(case, anchor, anchor.replace(edge, re.sub(r"unwind label %[-\w.]+", "unwind label %" + check.stop[0], edge)))
            self.assertEqual(unwinds, 2)
            lines = self.lines(case)
            bypasses = 0
            for label, block in check.graph.items():
                if label not in {site[0] for site in check.visited}:
                    continue
                for line in block:
                    if line.startswith("br i1"):
                        condition = re.match(r"br i1 (%[-\w.]+)", line)
                        if condition and any(condition[1] + " = invoke" in value for value in lines):
                            bypasses += 1
                            targets = re.findall(r"label (%[-\w.]+)", line)
                            self.rejects(case, line, "br label " + targets[-1], failure=("xor", 0))
            self.assertEqual(bypasses, 1)
            constructor = next((label, index, syntax.call(check.graph[label][index])) for label, index in check.visited
                               if (call := syntax.call(check.graph[label][index])) and check.constructor(call[0]))
            normal, _ = check.results.continuation(check.graph, constructor[:2])
            branch = next(line for line in check.graph[normal[0]] if line.startswith("br i1"))
            target = re.findall(r"label (%[-\w.]+)", branch)[-1]
            self.rejects(case, branch, "br label " + target, failure=("constructor", 0))

    def test_lifetimes_unknown_effects_and_escaping_copies(self):
        for case in self.cases:
            check = case[-1]
            line = next(line for line in self.lines(case) if "llvm.memset" in line)
            for effect in ("call void @unknown()", f"call void @llvm.lifetime.end.p0(ptr {check.outer})",
                           f"call void @llvm.lifetime.end.p0(ptr {check.owner})", f"call void @llvm.lifetime.end.p0(ptr {check.pad})"):
                self.rejects(case, line, line + "\n" + effect)
            copy = next(line for line in self.lines(case) if "llvm.memcpy" in line)
            dest = syntax.operand(syntax.call(copy)[1][0])
            self.rejects(case, copy, copy.replace(dest, check.owner))
            self.rejects(case, copy, copy.replace(dest, check.pad))


if __name__ == "__main__":
    unittest.main()
