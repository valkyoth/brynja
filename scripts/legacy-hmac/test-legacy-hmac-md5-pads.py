#!/usr/bin/env python3
"""Real emitted pad-loop mutations and every copy/XOR failure boundary."""
import importlib.util
from pathlib import Path
import re
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("driver", Path(__file__).with_name("check-legacy-hmac-md5-cleanup.py"))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
pads, model = driver.pads, driver.pads.model


class Pads(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = driver.runner.cargo_environment.private_directory(driver.ROOT)
        cls.addClassCleanup(cls.directory.cleanup)
        cls.cases = []
        for compiler in ("1.90.0", "1.99.1"):
            artifacts = driver.emit(Path(cls.directory.name) / compiler, compiler,
                                    "x86_64-unknown-linux-gnu", "unwind", True)
            fixture, llvm = artifacts[0][1], artifacts[1][1]
            check = pads.validate(fixture, llvm)
            definitions, _ = pads.flow.definitions_and_aliases(llvm)
            signature, body = next(value for name, value in definitions.items() if pads.phases.identity(name, "pads"))
            cls.cases.append((fixture, llvm, signature, body, check))

    def rejects(self, case, before, after):
        fixture, llvm, signature, body, check = case
        self.assertIn(before, body)
        self.assertNotEqual(before, after)
        with self.subTest(before=before, after=after), self.assertRaises(ValueError):
            mutated = pads.Check(signature, body.replace(before, after, 1), llvm, check.copy_ok)
            for lengths in ((64,) * 8, (65,) * 8, (0,) * 8, tuple(range(8))):
                mutated.run(lengths)
            for lane in range(8):
                mutated.run((65,) * 8, 1 << lane, (True, True, lane * 16 + 15))
            mutated.unwind()
            mutated.uses()

    def lines(self, case):
        check = case[-1]
        return [line for label, lines in check.graph.items() for index, line in enumerate(lines)
                if (label, index) in check.visited]

    def test_lane_geometry_iteration_and_short_key_boundary(self):
        for case in self.cases:
            check = case[-1]
            lines = self.lines(case)
            row = next(line for line in lines if "[64 x i8], ptr " + check.pads in line)
            self.rejects(case, row, row.replace("[64 x i8]", "[63 x i8]"))
            threshold = next(line for line in lines if re.fullmatch(r"%[-\w.]+ = icmp ugt i64 %[-\w.]+, 64", line))
            self.rejects(case, threshold, threshold.replace(", 64", ", 63"))
            self.rejects(case, threshold, threshold.replace(", 64", ", 65"))
            end = next(line for line in lines if re.fullmatch(r"%[-\w.]+ = icmp eq i64 %[-\w.]+, 8", line))
            self.rejects(case, end, end.replace(", 8", ", 7"))
            cursor = next(line for line in check.graph[check.start] if " = add nuw nsw i64 " in line)
            self.rejects(case, cursor, cursor.replace(", 1", ", 2"))

    def test_normalized_owner_bounds_and_lane_selection(self):
        for case in self.cases:
            lines = self.lines(case)
            row = next(line for line in lines if "getelementptr" in line and "[16 x i8]" in line)
            self.rejects(case, row, row.replace("[16 x i8]", "[15 x i8]"))
            self.rejects(case, row, re.sub(r"i64 %[-\w.]+$", "i64 0", row))
            chunks = next(line for line in lines if " = lshr i64 " in line)
            self.rejects(case, chunks, chunks.replace(", 4", ", 3"))
            copy_length = next(line for line in lines if " = phi i64 " in line and "[ 16," in line)
            self.rejects(case, copy_length, copy_length.replace("[ 16,", "[ 15,"))
            for lane in range(8):
                for owner in ((False, False, 0), (True, False, 128), (True, True, 0)):
                    case[-1].run((65,) * 8, 1 << lane, owner)

    def test_mask_byte_bit_geometry_and_full_block(self):
        for case in self.cases:
            lines = self.lines(case)
            mask = next(line for line in lines if line.startswith("store i8 54,"))
            self.rejects(case, mask, mask.replace("i8 54", "i8 55"))
            xor = next(line for line in lines if "20xor_secret_byte_bits" in line)
            self.rejects(case, xor, xor.replace("i8 noundef 8", "i8 noundef 7"))
            self.rejects(case, xor, xor.replace("20xor_secret_byte_bits", "20xor_secret_byte_bits_fake"))
            end = next(line for line in lines if re.fullmatch(r"%[-\w.]+ = icmp eq i64 %[-\w.]+, 64", line))
            self.rejects(case, end, end.replace(", 64", ", 63"))
            self.rejects(case, end, end.replace(", 64", ", 65"))

    def test_every_primitive_failure_boundary(self):
        for case in self.cases:
            check = case[-1]
            for lane in range(8):
                check.run((1,) * 8, 1 << lane, failure=("copy", lane * 64))
                for byte in range(64):
                    check.run((1,) * 8, 1 << lane, failure=("xor", lane * 64 + byte))
            check.unwind()

    def test_success_and_error_guards_are_not_decorative(self):
        for case in self.cases:
            lines = self.lines(case)
            copy = next(line for line in lines if "18copy_secret_region" in line)
            result = copy.split(" = ")[0]
            guard = next(line for line in lines if "icmp eq i8 " + result + "," in line)
            self.rejects(case, guard, guard.replace("icmp eq", "icmp ne"))
            success = next(label for label, flag in case[-1].stops.items() if flag)
            block = case[-1].graph[success]
            row = next(line.split(" = ")[0] for line in lines if "[64 x i8], ptr " + case[-1].pads in line)
            self.rejects(case, block[0], f"store i8 42, ptr {row}, align 1\n" + block[0])

    def test_unwind_cannot_resume_construction_or_success(self):
        for case in self.cases:
            check = case[-1]
            success = next(label for label, value in check.stops.items() if value)
            edges = {check.graph[label][index + 1] for label, index in check.visited
                     if "invoke " in check.graph[label][index]}
            self.assertEqual(len(edges), 2)
            for edge in edges:
                self.rejects(case, edge, re.sub(r"unwind label %[-\w.]+", "unwind label %" + success, edge))
                self.rejects(case, edge, re.sub(r"unwind label %[-\w.]+", "unwind label %" + check.start, edge))

    def test_zero_prefix_caller_binding(self):
        for fixture, llvm, *_ in self.cases:
            definitions, aliases = pads.flow.definitions_and_aliases(llvm)
            for op in ("authenticate", "authenticate_secret", "verify"):
                _, body = pads.phases.rows.method(definitions, aliases, op)[1]
                pad = pads.phases.owner(pads.phases.allocations(body), "pad", 512)
                zero = next(line for line in body.splitlines() if "llvm.memset" in line and pad + "," in line)
                call = next(line for line in body.splitlines() if (parsed := pads.syntax.call(line)) and pads.phases.identity(parsed[0], "pads"))
                for before, after in ((zero, zero.replace("i64 512", "i64 511")),
                                      (zero, zero.replace("i8 0", "i8 1")),
                                      (call, f"store i8 1, ptr {pad}, align 1\n" + call),
                                      (call, f"call void @escape(ptr {pad})\n" + call)):
                    with self.subTest(op=op, after=after), self.assertRaises(ValueError):
                        pads.zero_prefixes(llvm.replace(body, body.replace(before, after, 1), 1))

    def test_independent_abi_probes(self):
        for fixture, *_ in self.cases:
            definitions, aliases = pads.flow.definitions_and_aliases(fixture)
            for name, before, after in (("copy_success", "ret i8", "ret i64"),
                                        ("xor_success", "false", "true"),
                                        ("normalized_present", "i64 16", "i64 15"),
                                        ("normalized_absent", "i64 0", "i64 1"),
                                        ("pad_rejection", "store i8 2", "store i8 3"),
                                        ("pad_success", "i64 24", "i64 23")):
                body = pads.descriptors.admission.probe(definitions, aliases, name)
                self.assertIn(before, body)
                with self.subTest(name=name), self.assertRaises(ValueError):
                    pads.probes(fixture.replace(body, body.replace(before, after, 1), 1))

    def test_unknown_effects_expired_masks_and_nontermination(self):
        for case in self.cases:
            check = case[-1]
            lines = self.lines(case)
            xor = next(line for line in lines if "20xor_secret_byte_bits" in line)
            local = next(iter(check.locals))
            for extra in ("call void @unknown()", f"call void @llvm.lifetime.end.p0(ptr {local})",
                          "br label %" + check.start, "fence seq_cst"):
                self.rejects(case, xor, extra + "\n" + xor)
            store = next(line for line in lines if line.startswith("store i8 54,"))
            self.rejects(case, store, store.replace(local, check.inputs))

    def test_primitive_semantic_pins_are_load_bearing(self):
        fixture, llvm, *_ = self.cases[0]
        original = Path.read_bytes
        for name in pads.PINS:
            changed = pads.phases.rows.contracts.ROOT / name
            def read(path):
                return original(path) + b"\n" if path == changed else original(path)
            with self.subTest(name=name), patch.object(Path, "read_bytes", read), self.assertRaises(ValueError):
                pads.validate(fixture, llvm)


if __name__ == "__main__":
    unittest.main()
