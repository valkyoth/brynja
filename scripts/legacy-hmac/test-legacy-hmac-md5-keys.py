#!/usr/bin/env python3
"""Real emitted input/routing mutations, including constructor failure paths."""
import importlib.util
from pathlib import Path
import re
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("driver", Path(__file__).with_name("check-legacy-hmac-md5-cleanup.py"))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
keys, model = driver.keys, driver.keys.model
flow, syntax, VALUE = keys.flow, keys.syntax, keys.VALUE


class Keys(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = driver.runner.cargo_environment.private_directory(driver.ROOT)
        cls.addClassCleanup(cls.directory.cleanup)
        cls.cases = []
        for compiler, target in (("1.90.0", "x86_64-unknown-linux-gnu"),
                                 ("1.99.1", "x86_64-unknown-linux-gnu"),
                                 ("1.99.1", "aarch64-unknown-linux-gnu")):
            artifacts = driver.emit(Path(cls.directory.name) / (compiler + target), compiler,
                                    target, "unwind", True)
            fixture, llvm = artifacts[0][1], artifacts[1][1]
            cls.cases.append((fixture, llvm, keys.validate(fixture, llvm)))

    def run_shapes(self, check):
        for backend in (0, 1):
            check.run((129,) * 8, backend=backend)
            for mask in (0, 1, 128, 15, 240, 255, 85, 170):
                check.run(tuple(65 + lane * 17 if mask & (1 << lane) else 64 for lane in range(8)), backend=backend)
                check.run(tuple(65 + lane * 17 for lane in range(8)), mask, backend)
            for lane in range(8):
                check.run((65,) * 8, backend=backend, failure=lane)

    def rejects(self, case, before, after, full=False):
        fixture, llvm, check = case
        self.assertIn(before, check.body)
        self.assertNotEqual(before, after)
        mutated = llvm.replace(check.body, check.body.replace(before, after, 1), 1)
        with self.subTest(before=before, after=after), self.assertRaises(ValueError):
            if full:
                keys.validate(fixture, mutated)
            else:
                self.run_shapes(keys.Check(fixture, mutated))

    def lines(self, check):
        return [line for label, lines in check.graph.items() for index, line in enumerate(lines)
                if (label, index) in check.visited]

    def test_every_constructor_has_original_lane_length_and_bit_width(self):
        for case in self.cases:
            lines = [line for line in self.lines(case[-1]) if (call := syntax.call(line)) and keys.constructor(call[0])]
            self.assertEqual(len(lines), 8)
            for line in lines:
                self.rejects(case, line, line.replace("i8 noundef 8", "i8 noundef 7"))
                self.rejects(case, line, re.sub(r"i64 noundef %[-\w.]+", "i64 noundef 65", line))
            symbol, args = syntax.call(lines[0])
            self.rejects(case, lines[0], lines[0].replace(symbol, symbol + "_fake"))
            self.rejects(case, lines[0], lines[0].replace(syntax.operand(args[1]), "null"))

    def test_length_threshold_and_inactive_niches(self):
        for case in self.cases:
            lines = self.lines(case[-1])
            comparisons = [line for line in lines if re.fullmatch(rf"{VALUE} = icmp ugt i64 {VALUE}, 64", line)]
            self.assertEqual(len(comparisons), 8)
            for line in comparisons:
                self.rejects(case, line, line.replace(", 64", ", 63"))
                # 65 is the first valid long key in run_shapes.
                self.rejects(case, line, line.replace(", 64", ", 65"))
            absent = next(line for line in lines if re.fullmatch(rf"{VALUE} = icmp eq ptr {VALUE}, null", line))
            self.rejects(case, absent, absent.replace("icmp eq", "icmp ne"))

    def test_descriptor_payload_copy_length_and_lane_offset(self):
        for case in self.cases:
            check = case[-1]
            lines = self.lines(check)
            copy = next(line for line in lines if "llvm.memcpy" in line and "i64 23" in line)
            self.rejects(case, copy, copy.replace("i64 23", "i64 22"))
            self.rejects(case, copy, copy.replace("i64 23", "i64 24"))
            offset = next(line for line in lines if re.fullmatch(rf"{VALUE} = getelementptr inbounds(?: nuw)? i8, ptr {re.escape(check.keys)}, i64 41", line))
            self.rejects(case, offset, offset.replace("i64 41", "i64 73"))
            load = next(line for line in lines if "load i8" in line)
            self.rejects(case, load, re.sub(r"load i8, ptr %[-\w.]+", "load i8, ptr " + check.keys, load))

    def test_constructor_error_guard_and_error_reentry(self):
        for case in self.cases:
            check = case[-1]
            constructor = next((label, i) for label, i in check.visited if (call := syntax.call(check.graph[label][i]))
                               and keys.constructor(call[0]))
            lines = check.graph[constructor[0]]
            guard = next(line for line in lines[constructor[1]:] if "icmp eq ptr" in line)
            self.rejects(case, guard, guard.replace("icmp eq", "icmp ne"))
            self.assertEqual(len(check.error_sites), 1)
            label, index = next(iter(check.error_sites))
            tag = check.graph[label][index]
            self.rejects(case, tag, tag.replace("i8 1", "i8 0"))
            # Anchor the branch to this error block; identical cleanup edges
            # elsewhere must not accidentally be the mutation target.
            tail = check.graph[label][-1]
            start = check.body.index(label + ":")
            fragment = check.body[start:check.body.index(tail, start) + len(tail)]
            target = next(site[0] for site, kind in check.frontiers.items() if kind == "simd")
            self.rejects(case, fragment, fragment.replace(tail, "br label %" + target))

    def test_route_width_and_dynamic_descriptor_stride(self):
        for case in self.cases:
            lines = self.lines(case[-1])
            selection = next(line for line in lines if re.fullmatch(rf"{VALUE} = select i1 {VALUE}, i64 4, i64 8", line))
            self.rejects(case, selection, selection.replace("i64 4", "i64 8"))
            self.rejects(case, selection, selection.replace("i64 8", "i64 4"))
            step = next(line for line in lines if "getelementptr" in line and re.search(r"ptr %[-\w.]+, i64 32$", line)
                        and ", ptr " + case[-1].keys not in line)
            self.rejects(case, step, step.replace("i64 32", "i64 31"))

    def test_activity_vector_and_empty_owner(self):
        for case in self.cases:
            lines = self.lines(case[-1])
            inserts = [line for line in lines if "insertelement <8 x ptr>" in line and line.endswith("i64 7")]
            if inserts:
                self.rejects(case, inserts[0], inserts[0].replace("i64 7", "i64 6"))
            else:
                additions = [line for line in lines if " = add nuw nsw i64 " in line and ".i.i.i.i.7" in line]
                self.assertEqual(len(additions), 1)
                self.rejects(case, additions[0], re.sub(r", %[-\w.]+$", ", 0", additions[0]))
            empty = f"store i64 0, ptr {case[-1].owner}, align 8"
            self.rejects(case, empty, empty.replace("i64 0", "i64 1"))
            zero = next(line for line in lines if "llvm.memset" in line and "i64 128" in line)
            self.rejects(case, zero, zero.replace("i64 128", "i64 127"))

    def test_lifetime_bounds_unknown_effects_and_nontermination(self):
        for case in self.cases:
            check = case[-1]
            load = next(line for line in self.lines(check) if "load ptr, ptr " + check.keys + "," in line)
            for effect in (f"call void @llvm.lifetime.end.p0(ptr {check.keys})", "call void @unknown()",
                           "br label %start", "fence seq_cst"):
                self.rejects(case, load, effect + "\n" + load)
            absent = next(line for line in self.lines(check) if f"load ptr, ptr {check.inputs}," in line)
            self.rejects(case, absent, absent + f"\n  %bad_key_len = getelementptr inbounds i8, ptr {check.inputs}, i64 8\n"
                         "  %bad_key_read = load i64, ptr %bad_key_len, align 8")

    def test_late_key_array_escape_after_route_frontier(self):
        for case in self.cases:
            check = case[-1]
            site = next(site for site, kind in check.frontiers.items() if kind == "scalar")
            call = check.graph[site[0]][site[1]]
            # A call argument creates an escape in the unexecuted setup suffix.
            # The other argument/identity checks also still apply.
            edge = check.graph[site[0]][site[1] + 1]
            target = re.search(r"to label %([-\w.]+)", edge)[1]
            marker = target + ":"
            self.rejects(case, marker, marker + f"\n  call void @escape(ptr {check.keys})", full=True)

    def test_unvisited_remainder_prologue_cannot_hide_effects(self):
        case = self.cases[-1]
        check = case[-1]
        cold = [(label, line) for label, lines in check.graph.items() for i, line in enumerate(lines)
                if " = load ptr, ptr " in line and ".prol" in line and (label, i) not in check.visited]
        self.assertTrue(cold)
        for label, line in cold:
            for effect in (f"call void @escape(ptr {check.keys})", f"store ptr null, ptr {check.keys}, align 8"):
                self.rejects(case, line, effect + "\n" + line, full=True)

    def test_probes_and_source_bound_constructor_contract(self):
        for fixture, llvm, _ in self.cases:
            defs, aliases = flow.definitions_and_aliases(fixture)
            for name, before, after in (("key_descriptor_success", "i64 32", "i64 31"),
                                        ("key_descriptor_failure", "ptr null", "ptr %wrong"),
                                        ("key_length_rejection", "store i8 0", "store i8 2")):
                body = driver.admission.probe(defs, aliases, name)
                self.assertIn(before, body)
                with self.subTest(name=name), self.assertRaises(ValueError):
                    keys.probes(fixture.replace(body, body.replace(before, after, 1), 1))
        original = Path.read_bytes
        source = driver.ROOT / keys.SOURCE
        with patch.object(Path, "read_bytes", lambda path: original(path) + (b"\n" if path == source else b"")), self.assertRaises(ValueError):
            keys.validate(self.cases[0][0], self.cases[0][1])


class Arithmetic(unittest.TestCase):
    def test_modular_unsigned_signed_and_exact_instructions(self):
        state = model.State.__new__(model.State)
        state.values = {}
        self.assertEqual(state.expression("add nsw i64 128, -32").number(), 96)
        self.assertEqual(state.expression("add i64 -1, 1").number(), 0)
        self.assertEqual(state.expression("lshr exact i64 96, 5").number(), 3)
        for expression in ("add nuw i64 -1, 1", "sub nuw i64 0, 1",
                           "add nsw i64 9223372036854775807, 1", "lshr exact i64 95, 5", "shl i64 1, 64"):
            with self.subTest(expression=expression), self.assertRaises(ValueError):
                state.expression(expression)


if __name__ == "__main__":
    unittest.main()
