#!/usr/bin/env python3
"""Mutation checks for the actual eight-lane input descriptor transport."""
import importlib.util
from pathlib import Path
import re
import unittest

spec = importlib.util.spec_from_file_location("driver", Path(__file__).with_name("check-legacy-hmac-md5-cleanup.py"))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
descriptors = driver.descriptors
flow, syntax = descriptors.flow, descriptors.syntax


class Descriptors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = driver.runner.cargo_environment.private_directory(driver.ROOT)
        cls.addClassCleanup(cls.directory.cleanup)
        cls.artifacts = []
        for compiler in ("1.90.0", "1.99.1"):
            artifacts = driver.emit(Path(cls.directory.name) / compiler, compiler,
                                    "x86_64-unknown-linux-gnu", "unwind", True)
            driver.validate(artifacts, "unwind")
            cls.artifacts.append((artifacts[0][1], artifacts[1][1]))

    def callers(self):
        for fixture, llvm in self.artifacts:
            definitions, aliases = flow.definitions_and_aliases(llvm)
            for operation in ("authenticate", "authenticate_secret", "verify"):
                signature, body = descriptors.phases.rows.method(definitions, aliases, operation)[1]
                self.current_signature = signature
                trace = descriptors.Trace(signature, body)
                trace.run(0)
                trace.run(255)
                yield fixture, llvm, body, trace

    def constructed(self, trace):
        return [line for label, lines in trace.graph.items() for index, line in enumerate(lines)
                if (label, index) in trace.executed]

    def rejects(self, fixture, llvm, body, before, after):
        self.assertIn(before, body)
        self.assertNotEqual(before, after)
        with self.subTest(before=before, after=after), self.assertRaises(ValueError):
            trace = descriptors.Trace(self.current_signature, body.replace(before, after, 1))
            for mask in (255, *range(255)):
                trace.run(mask)
            trace.preservation()

    def test_lane_pointer_and_tail_offsets(self):
        for fixture, llvm, body, trace in self.callers():
            for offset in (16, 24, 64, 72, 352, 360):
                line = next(line for line in body.splitlines() if re.fullmatch(
                    descriptors.GEP, line.strip()) and trace.pointers.get(line.strip().split(" = ")[0])
                    == (trace.inputs, offset))
                self.rejects(fixture, llvm, body, line,
                             line.replace("i64 " + str(offset), "i64 " + str(offset - 1)))

    def test_activity_predicates_and_phi_sources(self):
        for fixture, llvm, body, trace in self.callers():
            branch = trace.graph[trace.start[0]][-1]
            condition = re.search(r"br i1 (%[-\w.]+),", branch)[1]
            comparison = trace.defs[condition][1]
            opposite = comparison.replace("icmp eq", "icmp ne") if "icmp eq" in comparison else comparison.replace("icmp ne", "icmp eq")
            self.rejects(fixture, llvm, body, comparison, opposite)
            phi = next(line for line in self.constructed(trace) if " = phi ptr " in line)
            value = re.search(r"\[ (%[-\w.]+),", phi)[1]
            self.rejects(fixture, llvm, body, phi, phi.replace(value + ",", "null,"))
            self.rejects(fixture, llvm, body, phi, phi.replace("[ null,", "[ %not_defined,"))

    def test_copy_extents_sources_overlap_and_lifetime(self):
        for fixture, llvm, body, trace in self.callers():
            line = next(line for line in self.constructed(trace) if "llvm.memcpy" in line)
            args = syntax.call(line)[1]
            dest, source = [syntax.operand(arg) for arg in args[:2]]
            self.rejects(fixture, llvm, body, line, line.replace("i64 24,", "i64 23,"))
            self.rejects(fixture, llvm, body, line, line.replace(source + ",", dest + ","))
            self.rejects(fixture, llvm, body, line,
                         f"call void @llvm.lifetime.end.p0(ptr {dest})\n" + line)
            self.rejects(fixture, llvm, body, line,
                         "call void @unknown_callback()\n" + line)

    def test_final_pointer_stores_and_absent_lanes(self):
        for fixture, llvm, body, trace in self.callers():
            stores = [line for line in body.splitlines() if (match := re.search(
                r"store ptr (%[-\w.]+), ptr (%[-\w.]+),", line)) and
                trace.pointers.get(match[2], (None,))[0] == trace.messages]
            self.assertEqual(len(stores), 8)
            for line in (stores[0], stores[3], stores[7]):
                value = re.search(r"store ptr (%[-\w.]+),", line)[1]
                self.rejects(fixture, llvm, body, line, line.replace(value + ",", "null,"))
            first = re.search(r"store ptr (%[-\w.]+),", stores[0])[1]
            last = re.search(r"store ptr (%[-\w.]+),", stores[-1])[1]
            self.rejects(fixture, llvm, body, stores[-1], stores[-1].replace(last + ",", first + ","))

    def test_descriptor_preservation_to_dispatch(self):
        for fixture, llvm, body, trace in self.callers():
            inner = trace.graph[trace.inner[0]][trace.inner[1]]
            for extra in (f"store ptr null, ptr {trace.messages}, align 8",
                          f"call void @escape(ptr {trace.messages})",
                          f"call void @llvm.lifetime.end.p0(ptr {trace.messages})",
                          f"%alias_escape = ptrtoint ptr {trace.messages} to i64"):
                self.rejects(fixture, llvm, body, inner, extra + "\n" + inner)
            self.rejects(fixture, llvm, body, inner, inner.replace(trace.messages + ",", "%wrong_messages,"))

    def test_layout_probes_are_independent_and_required(self):
        for fixture, llvm in self.artifacts:
            definitions, aliases = flow.definitions_and_aliases(fixture)
            for name, before, after in (("input_descriptor", "i64 16", "i64 8"),
                                         ("message_descriptor", "i64 32", "i64 24"),
                                         ("absent_input", "store ptr null", "store ptr %unknown"),
                                         ("absent_message", "store ptr null", "store ptr %unknown")):
                body = descriptors.admission.probe(definitions, aliases, name)
                self.assertIn(before, body)
                with self.subTest(name=name), self.assertRaises(ValueError):
                    descriptors.validate(fixture.replace(body, body.replace(before, after, 1), 1), llvm)

    def test_cycles_unsupported_control_and_input_immutability(self):
        for fixture, llvm, body, trace in self.callers():
            start = trace.graph[trace.start[0]][trace.start[1]]
            for extra in ("br label %" + trace.start[0], "unreachable", "fence seq_cst"):
                self.rejects(fixture, llvm, body, start, start + "\n" + extra)
            self.rejects(fixture, llvm, body, start,
                         start + f"\nstore ptr null, ptr {trace.inputs}, align 8")
            signature = descriptors.phases.rows.method(*flow.definitions_and_aliases(llvm), "authenticate")[1][0]
            with self.assertRaises(ValueError):
                descriptors.Trace(signature.replace("readonly", ""), body)

    def test_predecessor_sensitive_phi_and_address_definition(self):
        for fixture, llvm, body, trace in self.callers():
            phi = next(line for line in self.constructed(trace) if " = phi ptr " in line)
            predecessor = re.search(r", (%[-\w.]+) \]", phi)[1]
            self.rejects(fixture, llvm, body, phi, phi.replace(predecessor + " ]", "%wrong_predecessor ]"))
            source = next(line for line in body.splitlines() if re.fullmatch(descriptors.GEP, line.strip())
                          and trace.pointers.get(line.strip().split(" = ")[0]) == (trace.inputs, 16))
            self.rejects(fixture, llvm, body, source, source.replace("i64 16", "i64 400"))


if __name__ == "__main__":
    unittest.main()
