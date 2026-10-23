#!/usr/bin/env python3
"""Reject misrouted phase pointers in actual emitted MD5 HMAC callers."""
import importlib.util
from pathlib import Path
import re
import unittest

spec = importlib.util.spec_from_file_location("md5_driver", Path(__file__).with_name("check-legacy-hmac-md5-cleanup.py"))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
phases = driver.phases


class Phases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = driver.runner.cargo_environment.private_directory(driver.ROOT)
        cls.addClassCleanup(cls.directory.cleanup)
        artifacts = driver.emit(Path(cls.directory.name), "1.99.1", "x86_64-unknown-linux-gnu", "unwind", True)
        cls.llvm = artifacts[1][1]
        cls.definitions, cls.aliases = phases.flow.definitions_and_aliases(cls.llvm)
        driver.validate(artifacts, "unwind")

    def callers(self):
        for operation in ("authenticate", "authenticate_secret", "verify"):
            yield phases.rows.method(self.definitions, self.aliases, operation)[1]

    def rejects(self, body, before, after):
        self.assertIn(before, body)
        self.assertNotEqual(before, after)
        with self.subTest(before=before, after=after), self.assertRaises(ValueError):
            phases.validate(self.llvm.replace(body, body.replace(before, after, 1), 1))

    def site(self, body, role):
        return phases.one(body, lambda symbol, args: phases.identity(symbol, role)
                          and (role != "outer" or len(args) == 3), role)

    def test_each_phase_argument_and_callee(self):
        for _, body in self.callers():
            graph = phases.flow.blocks(body)
            for role in ("new", "pads", "digest", "outer"):
                label, index, symbol, args = self.site(body, role)
                line = graph[label][index]
                self.rejects(body, line, line.replace(symbol, symbol + "_fake"))
                for i, arg in enumerate(args):
                    if role == "pads" and i == 0:
                        continue  # Normalization return provenance is separate.
                    changed = arg.rsplit(" ", 1)[0] + " %wrong"
                    self.rejects(body, line, line.replace(arg, changed, 1))

    def test_selection_field_origins_and_allocation_extents(self):
        for _, body in self.callers():
            new = self.site(body, "new")
            value = phases.syntax.operand(new[3][1])
            load = next(line for line in body.splitlines() if value + " = load ptr," in line)
            self.rejects(body, load, load.replace("ptr %self,", "ptr %control,"))
            backend = self.site(body, "pads")[3][1].split()[-1]
            load = next(line for line in body.splitlines() if backend + " = load i8," in line)
            pointer = re.search(r"ptr (%[-\w.]+),", load)[1]
            gep = next(line for line in body.splitlines() if pointer + " = getelementptr" in line)
            self.rejects(body, gep, gep.replace("i64 16", "i64 8"))
            for name in ("workspace", "pad", "messages", "inner", "outer_inputs", "final_tags"):
                line = next(line for line in body.splitlines() if re.search("%" + name + r"\.[^ ]+ = alloca", line))
                self.rejects(body, line, re.sub(r"\[(\d+) x i8\]", lambda m: f"[{int(m[1]) + 1} x i8]", line))

    def test_capture_fields_offsets_and_partial_writes(self):
        for _, body in self.callers():
            outer = self.site(body, "outer")
            record = phases.syntax.operand(outer[3][2])
            pointers = {name: origin for name, origin in phases.syntax.pointers(body, (record,)).items()
                        if origin[0] == record}
            seen = 0
            for line in body.splitlines():
                store = re.search(r"store ptr (%[-\w.]+), ptr (%[-\w.]+),", line)
                if store and store[2] in pointers:
                    seen += 1
                    self.rejects(body, line, line.replace("store ptr " + store[1], "store ptr %wrong"))
                    self.rejects(body, line, line.replace("store ptr " + store[1], "store i8 0"))
                    self.rejects(body, line, "")
                    self.rejects(body, line, line + "\n" + line)
                if "getelementptr" in line and "ptr " + record + "," in line:
                    self.rejects(body, line, re.sub(r"i64 \d+", "i64 32", line))
            self.assertEqual(seen, 4)

    def test_capture_cannot_escape_alias_or_gain_late_effects(self):
        for _, body in self.callers():
            outer = self.site(body, "outer")
            record = phases.syntax.operand(outer[3][2])
            line = phases.flow.blocks(body)[outer[0]][outer[1]]
            for extra in (f"call void @capture_escape(ptr {record})",
                          f"%alias = select i1 true, ptr {record}, ptr %control",
                          f"%address = ptrtoint ptr {record} to i64",
                          f"store ptr {record}, ptr %control, align 8",
                          f"store i8 0, ptr {record}, align 1",
                          "call void @late_callback()"):
                self.rejects(body, line, extra + "\n" + line)

    def test_capture_lifetime_is_live_at_dispatch(self):
        for _, body in self.callers():
            outer = self.site(body, "outer")
            record = phases.syntax.operand(outer[3][2])
            line = next(line for line in body.splitlines() if "llvm.lifetime.start.p0" in line and record + ")" in line)
            self.rejects(body, line, "")
            self.rejects(body, line, line + "\n" + line)
            self.rejects(body, line, line.replace("lifetime.start", "lifetime.end"))
            first = next(line for line in body.splitlines() if "store ptr" in line and "ptr " + record + "," in line)
            self.rejects(body, first, "call void @llvm.lifetime.end.p0(ptr " + record + ")\n" + first)

    def test_actual_outer_helper_loads_and_forwarding(self):
        helpers = [(signature, body) for name, (signature, body) in self.definitions.items()
                   if phases.identity(name, "outer") and len(phases.syntax.parameters(signature)) == 3]
        self.assertEqual(len(helpers), 1)
        signature, body = helpers[0]
        params = phases.syntax.parameters(signature)
        record = phases.syntax.operand(params[2])
        site = self.site(body, "digest")
        line = phases.flow.blocks(body)[site[0]][site[1]]
        for arg in site[3]:
            self.rejects(body, line, line.replace(arg, arg.rsplit(" ", 1)[0] + " %wrong", 1))
        for offset in (8, 16, 24):
            gep = next(line for line in body.splitlines() if f"ptr {record}, i64 {offset}" in line)
            self.rejects(body, gep, gep.replace(f"i64 {offset}", "i64 0"))
        first = next(line for line in body.splitlines() if f"load ptr, ptr {record}," in line)
        self.rejects(body, first, first.replace(f"ptr {record},", "ptr %self,"))
        self.rejects(body, first, "call void @capture_escape(ptr " + record + ")\n" + first)

    def test_real_cfg_bypass_and_disconnected_phase(self):
        for _, body in self.callers():
            graph = phases.flow.blocks(body)
            pads = self.site(body, "pads")
            outer = self.site(body, "outer")
            # Introduce an edge from normalization directly to the final fence.
            final = phases.one(body, lambda symbol, args: driver.handoff.fence.helper(symbol)
                               and len(args) == 1, "final")
            label = pads[0]
            line = graph[label][pads[1]]
            self.rejects(body, line, "br label %" + final[0] + "\ndisconnected:\n" + line)
            self.rejects(body, outer[0] + ":", outer[0] + ":\n  br label %" + final[0] + "\nunused_outer:")

    def test_dominance_handles_branches_unwind_cycles_and_same_block(self):
        graph = {"entry": ["br label %init"], "init": ["invoke void @f()", "to label %loop unwind label %fail"],
                 "loop": ["br i1 %again, label %loop, label %end"], "end": ["ret void"], "fail": ["ret void"]}
        phases.dominates(graph, ("init", 0), ("end", 0))
        phases.dominates(graph, ("init", 0), ("init", 1))
        for before, after in ((("init", 1), ("init", 0)), (("loop", 0), ("fail", 0))):
            with self.assertRaises(ValueError):
                phases.dominates(graph, before, after)
        for replacement in ("br i1 %bypass, label %init, label %end",
                            "invoke void @f()\nto label %init unwind label %end"):
            with self.assertRaises(ValueError):
                phases.dominates(dict(graph, entry=[replacement]), ("init", 0), ("end", 0))


if __name__ == "__main__":
    unittest.main()
