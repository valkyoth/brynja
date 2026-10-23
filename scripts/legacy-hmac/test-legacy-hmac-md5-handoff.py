#!/usr/bin/env python3
"""Mutate the actual final readiness helper and each caller handoff."""
import importlib.util
from pathlib import Path
import re
import unittest

spec = importlib.util.spec_from_file_location("md5_driver", Path(__file__).with_name("check-legacy-hmac-md5-cleanup.py"))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
handoff, fence = driver.handoff, driver.handoff.fence


class Handoff(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = driver.runner.cargo_environment.private_directory(driver.ROOT)
        cls.addClassCleanup(cls.directory.cleanup)
        cls.root = Path(cls.directory.name)
        cls.artifacts = driver.emit(cls.root, "1.99.1", "x86_64-unknown-linux-gnu", "unwind", True)
        cls.fixture, cls.llvm = cls.artifacts[0][1], cls.artifacts[1][1]
        cls.definitions, cls.aliases = fence.flow.definitions_and_aliases(cls.llvm)
        cls.helpers = [(signature, body) for name, (signature, body) in cls.definitions.items()
                       if fence.helper(name) and len(fence.syntax.parameters(signature)) == 1]
        driver.validate(cls.artifacts, "unwind")

    def rejects(self, body, before, after):
        self.assertIn(before, body)
        self.assertNotEqual(before, after)
        with self.subTest(before=before), self.assertRaises(ValueError):
            handoff.validate(self.fixture, self.llvm.replace(body, body.replace(before, after, 1), 1), "unwind")

    def test_helper_authority_completion_and_result(self):
        self.assertEqual(len(self.helpers), 1)
        _, body = self.helpers[0]
        for line in body.splitlines():
            call = fence.syntax.call(line)
            if not call:
                continue
            symbol, args = call
            if fence.identity(symbol, "ready"):
                self.rejects(body, line, line.replace(fence.syntax.operand(args[0]), "%self"))
                self.rejects(body, line, line.replace(symbol, symbol + "_fake"))
            elif fence.identity(symbol, "drop"):
                self.rejects(body, line, line.replace("%scope", "%self"))
        for before, after in (("store i8 1", "store i8 0"), ("store i8 0", "store i8 1"),
                              ("icmp eq i8", "icmp ne i8"), ("i64 185", "i64 184"),
                              ("i64 16, i1 false)", "i64 15, i1 false)")):
            self.rejects(body, before, after)
        result = next(line for line in body.splitlines() if "insertvalue { i8, i8 }" in line)
        self.rejects(body, result, result.replace(", 1", ", 0"))
        phi = next(line for line in body.splitlines() if "phi i8" in line)
        self.rejects(body, phi, re.sub(r"\[ %[-\w.]+,", "[ 0,", phi, count=1))

    def test_helper_missing_cleanup_and_swallowed_unwind(self):
        _, body = self.helpers[0]
        for label, lines in fence.flow.blocks(body).items():
            for index, line in enumerate(lines):
                call = fence.syntax.call(line)
                if call and fence.identity(call[0], "drop"):
                    if "invoke " in line:
                        normal = re.search("to label %" + fence.flow.LABEL, lines[index + 1])[1]
                        before = body[body.index(line):].splitlines()[:2]
                        self.rejects(body, "\n".join(before), "br label %" + normal)
                    else:
                        self.rejects(body, line, "")
            for line in lines:
                if line.startswith("resume "):
                    self.rejects(body, line, "ret { i8, i8 } zeroinitializer")

    def test_each_caller_success_error_and_unwind_edges(self):
        for operation in ("authenticate", "authenticate_secret", "verify"):
            _, body = fence.rows.method(self.definitions, self.aliases, operation)[1]
            graph = fence.flow.blocks(body)
            found = 0
            for label, lines in graph.items():
                for index, line in enumerate(lines):
                    call = fence.syntax.call(line)
                    if not call or not fence.helper(call[0]) or len(call[1]) != 1:
                        continue
                    found += 1
                    following = lines[index + 1]
                    normal = re.search("to label %" + fence.flow.LABEL, following)[1]
                    accepted = re.search("i8 -1, label %" + fence.flow.LABEL, "\n".join(graph[normal]))[1]
                    check = next(item for item in graph[normal] if item.startswith("switch i8 "))
                    default = re.search("label %" + fence.flow.LABEL, check)[1]
                    self.rejects(body, check, check.replace("%" + default, "%" + accepted))
                    case = "i8 -1, label %" + accepted
                    self.rejects(body, case, case.replace("i8 -1", "i8 0"))
                    edge = re.search("unwind label %" + fence.flow.LABEL, following)[1]
                    self.rejects(body, following, following.replace("%" + edge, "%" + accepted))
                    self.rejects(body, line, line.replace(fence.syntax.operand(call[1][0]), "%pad.i.i"))
            self.assertEqual(found, 1)

    def test_no_extra_effects_and_exact_row_input(self):
        for operation in ("authenticate", "authenticate_secret", "verify"):
            _, body = fence.rows.method(self.definitions, self.aliases, operation)[1]
            for label, lines in fence.flow.blocks(body).items():
                for line in lines:
                    call = fence.syntax.call(line)
                    selected = call and (handoff.closure(call[0], operation) or
                               operation == "authenticate" and handoff.copy_region(call[0])
                               and "%output" in call[1][0])
                    if not selected:
                        continue
                    source = fence.syntax.operand(call[1][2])
                    self.rejects(body, line, line.replace(source, "%final_tags.i.i"))
                    self.rejects(body, label + ":", label + ":\n  call void @late_callback()")
                    if operation == "authenticate":
                        self.rejects(body, line, line.replace("i64 noundef 128", "i64 noundef 127", 1))

    def test_source_premise_and_abi_probe_are_required(self):
        for name in fence.PINS:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((driver.ROOT / name).read_bytes())
        fence.validate_source(self.root)
        for name in fence.PINS:
            path = self.root / name
            original = path.read_bytes()
            path.write_bytes(original + b"\n// changed\n")
            with self.subTest(name=name), self.assertRaises(ValueError):
                fence.validate_source(self.root)
            path.write_bytes(original)
        definitions, aliases = fence.flow.definitions_and_aliases(self.fixture)
        body = fence.admission.probe(definitions, aliases, "readiness_ok")
        self.assertIn("i8 -1", body)
        with self.assertRaises(ValueError):
            handoff.validate(self.fixture.replace(body, body.replace("i8 -1", "i8 0"), 1), self.llvm, "unwind")


if __name__ == "__main__":
    unittest.main()
