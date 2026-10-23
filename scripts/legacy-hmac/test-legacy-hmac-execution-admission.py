#!/usr/bin/env python3
"""Non-vacuous constructor admission, scratch and iterator-helper regressions."""
import importlib.util
from pathlib import Path
import re
import shutil
import tomllib
import unittest

spec = importlib.util.spec_from_file_location("admission_driver", Path(__file__).with_name(
    "check-legacy-hmac-execution-cleanup.py"))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
admission, iterator = driver.admission, driver.iterator


class AdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = driver.runner.cargo_environment.private_directory(driver.ROOT)
        cls.addClassCleanup(cls.directory.cleanup)
        cls.root = Path(cls.directory.name)
        cls.artifacts = driver.collect(cls.root / "baseline", "1.99.1", "x86_64-unknown-linux-gnu", "unwind")
        cls.llvm, cls.fixture = cls.artifacts[1][1], cls.artifacts[0][1]
        cls.definitions, cls.aliases = driver.graph.flow.definitions_and_aliases(cls.llvm)
        cls.symbol, (cls.signature, cls.body) = driver.final.method(cls.definitions, cls.aliases, "with_tag_length")
        cls.cache = admission.contracts.validate(cls.fixture, cls.symbol)

    def rejects(self, before, after, *, body=None, stage="admission"):
        original = self.body if body is None else body
        self.assertIn(before, original)
        self.assertNotEqual(before, after)
        changed = original.replace(before, after, 1)
        with self.subTest(stage=stage, before=before, after=after), self.assertRaises(ValueError):
            if stage == "admission":
                admission.validate(self.llvm.replace(original, changed, 1), self.fixture, "unwind")
            elif stage == "fixture":
                admission.contracts.validate(changed, self.symbol)
            else:
                llvm = self.llvm.replace(original, changed, 1)
                definitions, aliases = driver.graph.flow.definitions_and_aliases(llvm)
                body = driver.final.method(definitions, aliases, "with_tag_length")[1][1]
                iterator.check(body, llvm, definitions, aliases, "unwind", self.cache)

    def test_independent_abi_probes_and_forwarding(self):
        definitions, aliases = driver.graph.flow.definitions_and_aliases(self.fixture)
        for name in ("stream_size", "start_rejection", "constructor_tag_rejection",
                     "constructor_authority_rejection", "portable_report", "empty_iterator_cache"):
            body = admission.contracts.consumer(definitions, aliases, name)
            self.rejects(body, body.replace("ret ", "ret i8 19\n; ", 1), body=self.fixture, stage="fixture")
        body = admission.contracts.consumer(definitions, aliases, "construct")
        for name in ("%_0", "%executor", "%key.0", "%key.1", "%bytes"):
            self.rejects(body, body.replace(name, "%wrong_argument"), body=self.fixture, stage="fixture")
        default = driver.final.method(self.definitions, self.aliases, "new")[1][1]
        for before, after in (("i64 noundef 20", "i64 noundef 9"), ("%executor", "%wrong_executor"),
                              ("%key.0", "%wrong_key"), ("start:", "start:\n  ret void\nunused:")):
            self.rejects(before, after, body=default)

    def test_invalid_tag_portable_and_long_key_predicates(self):
        for before, after in (("add i64 %0, -10", "add i64 %0, -9"),
                              ("icmp ult i64 %1, 11", "icmp ult i64 %1, 12"),
                              ("icmp eq i8 %_10.1, 2", "icmp eq i8 %_10.1, 3"),
                              ("ugt i64 %key.1, 64", "ugt i64 %key.1, 65")):
            self.rejects(before, after)
        self.rejects("start:", "start:\n  %key_leak = load i8, ptr %key.0, align 1")
        self.rejects("start:", "start:\n  store ptr %executor, ptr %_0, align 8")
        self.rejects("start:", "start:\n  %unbounded = load i64, ptr %outside, align 8")

    def test_start_identity_binding_and_failure_rejection(self):
        lines = [line for line in self.body.splitlines() if (item := admission.syntax.call(line))
                 and admission.executor_method(item[0], "start")]
        self.assertEqual(len(lines), 3)
        for line in lines:
            symbol, _ = admission.syntax.call(line)
            self.rejects(line, line.replace("%executor", "%unapproved_executor"))
            self.rejects(line, line.replace(symbol, "wrong_start"))
        self.rejects("%6 = icmp eq i8 %5, 2", "%6 = icmp eq i8 %5, 3")
        self.rejects("%first = alloca [448 x i8]", "%first = alloca [447 x i8]")

    def test_partial_admission_cleanup_and_unwind(self):
        # Identify pre-key destruction by actual pointer provenance, not label
        # spelling: post-key drops are outside this admission model.
        pointers = admission.syntax.pointers(self.body, ("%first", "%second"))
        lines = [line for line in self.body.splitlines() if (item := admission.syntax.call(line))
                 and admission.shared.owner_drop(item[0], "sha1")
                 and pointers.get(admission.syntax.operand(item[1][0]), (None,))[0] in ("%first", "%second")]
        self.assertGreaterEqual(len(lines), 4)
        for line in lines:
            _, args = admission.syntax.call(line)
            self.rejects(line, line.replace(admission.syntax.operand(args[0]), "%lost_owner"))
        second = next(line for line in self.body.splitlines() if "invoke void" in line
                      and (item := admission.syntax.call(line)) and admission.executor_method(item[0], "start"))
        offset = self.body.index(second) + len(second)
        edge = self.body[offset:].splitlines()[1]
        changed = self.body.replace(edge, re.sub(r"unwind label %[-\w.]+", "unwind label %escape", edge), 1)
        with self.assertRaises(ValueError):
            admission.validate(self.llvm.replace(self.body, changed + "\nescape:\n  resume { ptr, i32 } zeroinitializer\n"),
                               self.fixture, "unwind")

    def test_admitted_pool_byte_provenance_and_metadata(self):
        for before, after in (("i64 440, i1 false", "i64 439, i1 false"),
                              ("i64 896, i1 false", "i64 895, i1 false"),
                              ("ptr %streams, i64 24", "ptr %streams, i64 25"),
                              ("store i64 1, ptr %streams", "store i64 0, ptr %streams"),
                              ("store i64 3, ptr %_98.sroa.0.sroa.5.0.streams.sroa_idx",
                               "store i64 2, ptr %_98.sroa.0.sroa.5.0.streams.sroa_idx"),
                              ("store i8 -1, ptr %_98.sroa.5.0.streams.sroa_idx",
                               "store i8 0, ptr %_98.sroa.5.0.streams.sroa_idx")):
            self.rejects(before, after)
        line = next(line for line in self.body.splitlines() if "store i8 %5," in line)
        self.rejects(line, "")
        initialization = "store i64 1, ptr %streams, align 8"
        self.rejects(initialization, initialization +
                     "\n  call void @llvm.memcpy.p0.p0.i64(ptr %streams, ptr %first, i64 8, i1 false)")
        # Apple emits adjacent iterator metadata as one vector store. Exercise
        # that supported form on the same real graph and reject changed lanes.
        first = "store i64 1, ptr %streams, align 8"
        second = next(line for line in self.body.splitlines()
                      if "store i64 0," in line and "streams.sroa_idx" in line)
        vector = "store <2 x i64> <i64 1, i64 0>, ptr %streams, align 16"
        body = self.body.replace(first, vector, 1).replace(second, "", 1)
        admission.validate(self.llvm.replace(self.body, body), self.fixture, "unwind")
        with self.assertRaises(ValueError):
            admission.validate(self.llvm.replace(self.body, body.replace(vector, vector.replace("i64 0>", "i64 1>"))),
                               self.fixture, "unwind")

    def test_no_successful_exit_or_missing_frontier(self):
        self.rejects("start:", "start:\n  ret void\nunused:")
        self.rejects("store i8 2, ptr %2, align 8", "store i8 0, ptr %2, align 8")
        self.rejects("call void @llvm.lifetime.start.p0(ptr nonnull %pad.i)", "")

    def test_real_iterator_helper_cursor_niche_and_cleanup(self):
        _, (_, body) = iterator.selected(self.body, self.definitions, self.aliases)
        for before, after in (("start:", "start:\n  ret void\nunused:"),
                              ("i64 24", "i64 25"), ("i64 441", "i64 440"),
                              ("i64 8", "i64 9")):
            self.rejects(before, after, body=body, stage="iterator")
        calls = [line for line in body.splitlines() if (item := admission.syntax.call(line))
                 and admission.shared.owner_drop(item[0], "sha1")]
        self.assertTrue(calls)
        for line in calls:
            _, args = admission.syntax.call(line)
            pointer = admission.syntax.operand(args[0])
            self.rejects(line, line.replace(pointer, "%wrong_owner"), body=body, stage="iterator")

    def test_constructor_scratch_and_separate_iterator_binding(self):
        for owner, width in (("%pad.i", 64), ("%digest.i", 20)):
            lines = [line for line in self.body.splitlines()
                     if "18clear_owned_region" in line and re.search(re.escape(owner) + r",", line)]
            self.assertTrue(lines)
            changed = self.body
            for line in lines:
                changed = changed.replace(line, re.sub(r"i64 noundef " + str(width) + r"\)",
                                                       "i64 noundef " + str(width - 1) + ")", line))
            self.rejects(self.body, changed, stage="iterator")
        line = next(line for line in self.body.splitlines() if (item := admission.syntax.call(line)) and "Flatten" in item[0])
        for before, after in (("%streams", "%pad.i"), ("dereferenceable(2264)", "dereferenceable(2263)")):
            self.rejects(line, line.replace(before, after), stage="iterator")

    def test_compiled_constructor_admission_mutants(self):
        work, leaf = self.root / "fixture", self.root / "leaf"
        source = driver.ROOT / "crates/brynja-legacy-hmac"
        shutil.copytree(source / "src", leaf / "src")
        shutil.copyfile(source / "README.md", leaf / "README.md")
        manifest = (source / "Cargo.toml").read_text()
        workspace = tomllib.loads((driver.ROOT / "Cargo.toml").read_text())["workspace"]
        for field in ("edition", "rust-version", "license", "repository"):
            manifest = manifest.replace(field + ".workspace = true", field + ' = "' + workspace["package"][field] + '"')
        manifest = manifest.replace("brynja-core.workspace = true", 'brynja-core = { path = "'
                                    + str(driver.ROOT / "crates/brynja-core") + '", default-features = false }')
        manifest = manifest.replace('path = "../', 'path = "' + str(driver.ROOT / "crates") + "/")
        (leaf / "Cargo.toml").write_text(manifest.replace("[lints]\nworkspace = true", "") + "\n[workspace]\n")
        fixture = driver.FIXTURE.parent
        shutil.copytree(fixture / "src", work / "src")
        manifest = (fixture / "Cargo.toml").read_text().replace("../../crates/brynja-legacy-hmac", str(leaf))
        (work / "Cargo.toml").write_text(manifest.replace("../../crates/", str(driver.ROOT / "crates") + "/"))
        shutil.copyfile(fixture / "Cargo.lock", work / "Cargo.lock")
        path = leaf / "src/execution/mod.rs"
        original = path.read_text()
        baseline = driver.emit(work, "1.99.1", "x86_64-unknown-linux-gnu", "unwind", work / "Cargo.toml")
        admission.validate(baseline[1][1], baseline[0][1], "unwind")
        for before, after in (("key.len() > 64", "key.len() > 65"),
                              ("(10..=20)", "(9..=20)"),
                              (".ok_or(Error::ExecutionUnavailable)?", ".unwrap_or(Sha1Backend::X86Sha)"),
                              ("let first = executor.start()", "core::hint::black_box(key); let first = executor.start()")):
            self.assertIn(before, original)
            path.write_text(original.replace(before, after, 1))
            artifacts = driver.emit(work, "1.99.1", "x86_64-unknown-linux-gnu", "unwind", work / "Cargo.toml")
            with self.assertRaises(ValueError):
                admission.validate(artifacts[1][1], artifacts[0][1], "unwind")


if __name__ == "__main__":
    unittest.main()
