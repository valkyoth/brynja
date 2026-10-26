#!/usr/bin/env python3
"""Mutate real emitted normalization handoffs and split-pointer bit origins."""
import importlib.util
from pathlib import Path
import re
import unittest

spec = importlib.util.spec_from_file_location("driver", Path(__file__).with_name("check-legacy-hmac-md5-cleanup.py"))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
normalization = driver.normalization
bits, flow, syntax = normalization.bits, normalization.flow, normalization.syntax
Bits, Pointer = bits.Bits, bits.Pointer


def mutate_probe(fixture, name, before, after):
    """Mutate the named definition, never the first identical function body."""
    definitions, aliases = flow.definitions_and_aliases(fixture)
    body = normalization.pads.descriptors.admission.probe(definitions, aliases, name)
    matches = [symbol for symbol in (*definitions, *aliases)
               if re.search("30brynja_legacy_hmac_md5_cleanup" + str(len(name)) + name
                            + r"(?:17h[0-9a-f]+E)?$", symbol)]
    flow.require(len(matches) == 1, "mutation probe identity missing/ambiguous")
    symbol = matches[0]
    while symbol in aliases:  # probe() already rejects alias cycles.
        symbol = aliases[symbol]
    pattern = (r'^define [^\n]*@(?:"' + re.escape(symbol) + r'"|' + re.escape(symbol)
               + r')\([^\n]*\)[^{]*\{\n(.*?)^\}')
    sites = list(re.finditer(pattern, fixture, re.M | re.S))
    flow.require(len(sites) == 1 and sites[0][1] == body,
                 "mutation definition body missing/ambiguous")
    flow.require(before != after and body.count(before) == 1,
                 "mutation anchor missing/ambiguous/unchanged")
    changed = body.replace(before, after, 1)
    start, end = sites[0].span(1)
    mutant = fixture[:start] + changed + fixture[end:]
    mutated_definitions, mutated_aliases = flow.definitions_and_aliases(mutant)
    flow.require(normalization.pads.descriptors.admission.probe(
        mutated_definitions, mutated_aliases, name) == changed, "requested probe was not mutated")
    return mutant


class Normalization(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = driver.runner.cargo_environment.private_directory(driver.ROOT)
        cls.addClassCleanup(cls.directory.cleanup)
        cls.cases = []
        for compiler in ("1.90.0", "1.99.1"):
            artifacts = driver.emit(Path(cls.directory.name) / compiler, compiler,
                                    "x86_64-unknown-linux-gnu", "unwind", True)
            fixture, llvm = artifacts[0][1], artifacts[1][1]
            cls.cases.append((fixture, llvm, normalization.validate(fixture, llvm)))

    def rejects(self, case, before, after):
        fixture, llvm, check = case
        self.assertIn(before, check.body)
        self.assertNotEqual(before, after)
        with self.subTest(before=before, after=after), self.assertRaises(ValueError):
            normalization.validate(fixture, llvm.replace(check.body, check.body.replace(before, after, 1), 1))

    def lines(self, check):
        return [line for label, lines in check.graph.items() for index, line in enumerate(lines)
                if (label, index) in check.visited]

    def test_call_identities_and_distinct_buffers(self):
        for case in self.cases:
            check = case[-1]
            for site in check.calls.values():
                line = check.graph[site[0]][site[1]]
                self.rejects(case, line, line.replace(site[2], site[2] + "_fake"))
                for original, wrong in ((check.output, check.workspace), (check.keys, check.output),
                                         (check.control, check.workspace)):
                    self.rejects(case, line, line.replace(original, wrong))

    def test_pointer_fragments_shifts_and_integer_reassembly(self):
        for case in self.cases:
            lines = self.lines(case[-1])
            shifts = [line for line in lines if " = shl " in line]
            self.assertEqual(len(shifts), 2)
            for line in shifts:
                self.rejects(case, line, re.sub(r", (8|16)$", ", 7", line))
            load = next(line for line in lines if " = load i48," in line)
            address = re.search(r"ptr (%[-\w.]+),", load)[1]
            self.rejects(case, load, load.replace(address, case[-1].output))
            convert = next(line for line in lines if " = inttoptr " in line)
            self.rejects(case, convert, re.sub(r"inttoptr i64 %[-\w.]+", "inttoptr i64 128", convert))
            for line in (item for item in lines if " = or disjoint i64 " in item):
                self.rejects(case, line, re.sub(r", %[-\w.]+$", ", 0", line))

    def test_scalar_and_simd_owner_pointer_length_and_presence(self):
        for case in self.cases:
            check = case[-1]
            pointers = syntax.pointers(check.body, (check.owner,))
            changed = 0
            for line in self.lines(check):
                store = re.fullmatch(r"store (ptr|i64) (%[-\w.]+|1), ptr (%[-\w.]+), align 8", line)
                if store and pointers.get(store[3], (None,))[0] == check.owner:
                    value = "null" if store[1] == "ptr" else "0" if store[2] == "1" else "128"
                    self.rejects(case, line, line.replace(store[1] + " " + store[2] + ",", store[1] + " " + value + ",", 1))
                    changed += 1
            self.assertEqual(changed, 6)

    def test_scalar_failure_and_simd_backend_guards(self):
        for case in self.cases:
            check = case[-1]
            scalar = check.calls["scalar"]
            start, _ = normalization.results.continuation(check.graph, scalar)
            branch = next(line for line in check.graph[start[0]][start[1]:] if line.startswith("br i1"))
            targets = re.findall(r"label (%[-\w.]+)", branch)
            self.rejects(case, branch, "br label " + targets[1])
            lines = self.lines(check)
            match = next(line for line in lines if "icmp eq i8" in line and check.selection in line)
            self.rejects(case, match, match.replace("icmp eq", "icmp ne"))
            absent = next(line for line in lines if re.search(r"icmp ne i8 .*?, 2$", line))
            self.rejects(case, absent, absent.replace(", 2", ", 3"))

    def test_phi_returned_length_cannot_be_replaced(self):
        for case in self.cases:
            check = case[-1]
            result = syntax.operand(check.calls["simd"][3][0])
            pointers = syntax.pointers(check.body, (result,))
            load = next(line for line in self.lines(check) if (match := re.search(r"load i64, ptr (%[-\w.]+),", line))
                        and pointers.get(match[1]) == (result, 8))
            value = load.split(" = ")[0]
            phi = next(line for line in self.lines(check) if "phi i64" in line and "[ " + value + "," in line)
            self.rejects(case, phi, phi.replace("[ " + value + ",", "[ 128,"))

    def test_preheader_overwrites_expiry_unknown_effects_and_cycles(self):
        for case in self.cases:
            check = case[-1]
            jump = "br label %" + check.stop
            self.assertIn(jump, self.lines(check))
            for extra in (f"store i64 0, ptr {check.owner}, align 8", "call void @unreviewed()",
                          f"call void @llvm.lifetime.end.p0(ptr {check.output})",
                          f"call void @llvm.lifetime.start.p0(ptr {check.output})",
                          f"call void @llvm.lifetime.end.p0(ptr {check.owner})", "fence seq_cst"):
                self.rejects(case, jump, extra + "\n" + jump)
            label = next(label for label, lines in check.graph.items() if jump in lines)
            self.rejects(case, jump, f"br i1 undef, label %{label}, label %{check.stop}")

    def test_expired_owner_cannot_be_repopulated_without_restart(self):
        for case in self.cases:
            check = case[-1]
            stores = [line for line in self.lines(check) if line.startswith("store ptr ") and check.secret not in line]
            self.assertEqual(len(stores), 2)
            for line in stores:
                self.rejects(case, line, f"call void @llvm.lifetime.end.p0(ptr {check.owner})\n" + line)

    def test_scope_drop_cannot_be_rebound_or_refill_output(self):
        for case in self.cases:
            check = case[-1]
            label, index = next((label, index) for label, index in check.visited
                                if (call := syntax.call(check.graph[label][index]))
                                and normalization.results.fence.identity(call[0], "drop"))
            line = check.graph[label][index]
            # The unwind cleanup uses identical call text. Anchor this mutation
            # to the normal-return block, not the first textual occurrence.
            start = check.body.index(label + ":")
            drop = check.body[start:check.body.index(line, start) + len(line)]
            self.rejects(case, drop, drop.replace(check.scope, check.secret))
            self.rejects(case, drop, drop.replace(line, f"store ptr {check.output}, ptr {check.scope}, align 8\n" + line))
            self.rejects(case, drop, drop.replace(line, f"store i8 0, ptr {check.output}, align 1\n" + line))

    def test_scope_setup_does_not_assume_later_binding(self):
        for case in self.cases:
            check = case[-1]
            site = check.calls["simd"]
            call = check.graph[site[0]][site[1]]
            for effect in (f"store ptr {check.output}, ptr {check.scope}, align 8",
                           f"call void @escape(ptr {check.scope})",
                           f"call void @llvm.lifetime.end.p0(ptr {check.scope})"):
                self.rejects(case, call, effect + "\n" + call)

    def test_digest_and_scope_unwinds_cannot_enter_pad_loop(self):
        for case in self.cases:
            check = case[-1]
            sites = list(check.calls.values()) + [(label, index) for label, index in check.visited
                                                 if "invoke " in check.graph[label][index]]
            self.assertEqual(len(sites), 3)
            for site in sites:
                edge = check.graph[site[0]][site[1] + 1]
                self.rejects(case, edge, re.sub(r"unwind label %[-\w.]+", "unwind label %" + check.stop, edge))

    def test_independent_result_layout_probes(self):
        for fixture, llvm, _ in self.cases:
            for name, before, after, rejection in (
                ("normalized_scalar_success", "i64 8", "i64 0", "normalization probe store aliases/escapes"),
                ("normalized_scalar_error", "store i8 1", "store i8 0", "normalization Result layout changed"),
                ("normalized_simd_success", "i64 40", "i64 39", "normalization report probe changed"),
            ):
                mutant = mutate_probe(fixture, name, before, after)
                with self.subTest(name=name), self.assertRaisesRegex(ValueError, rejection):
                    normalization.validate(mutant, llvm)


class BitProvenance(unittest.TestCase):
    def test_split_and_reassemble_arbitrary_pointer(self):
        memory = bits.Memory({"result": 16})
        pointer, length = Pointer("owner"), Bits.token("length")
        memory.store(Pointer("result"), pointer)
        memory.store(Pointer("result", 8), length)
        parts = [memory.load(Pointer("result", offset), dtype).resize(64).binary("shl", Bits.integer(offset * 8, 64))
                 for offset, dtype in ((0, "i8"), (1, "i8"), (2, "i48"))]
        combined = parts[0].binary("or", parts[1]).binary("or", parts[2])
        self.assertEqual(bits.unpack(combined, "ptr"), pointer)
        self.assertEqual(memory.load(Pointer("result", 8), "i64"), length)
        for bit in range(64):
            corrupted = Bits(combined.data[:bit] + (0,) + combined.data[bit + 1:])
            self.assertNotEqual(bits.unpack(corrupted, "ptr"), pointer)

    def test_unknowns_masks_comparisons_and_lifetimes(self):
        unknown = Bits.unknown(64)
        self.assertIsNone(unknown.compare("eq", unknown).number())
        self.assertEqual(unknown.binary("and", Bits.integer(0, 64)), Bits.integer(0, 64))
        self.assertEqual(unknown.binary("or", Bits.integer(-1, 64)), Bits.integer(-1, 64))
        memory = bits.Memory({"a": 8})
        memory.store(Pointer("a"), Pointer("x"))
        memory.invalidate("a")
        self.assertEqual(memory.load(Pointer("a"), "ptr"), unknown)
        for pointer in (Pointer("other"), Pointer("a", 1), Pointer("a", -1)):
            with self.assertRaises(ValueError):
                memory.load(pointer, "ptr")
        for shift in (Bits.unknown(64), Bits.integer(64, 64)):
            with self.assertRaises(ValueError):
                unknown.binary("shl", shift)


if __name__ == "__main__":
    unittest.main()
