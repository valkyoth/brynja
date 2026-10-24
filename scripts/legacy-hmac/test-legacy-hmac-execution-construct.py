#!/usr/bin/env python3
"""Compiled and emitted-graph regressions for post-admission stream ownership."""
import importlib.util
from pathlib import Path
import re
import shutil
import tomllib
import unittest

import legacy_hmac_execution_construct as construct

spec = importlib.util.spec_from_file_location("construct_driver", Path(__file__).with_name(
    "check-legacy-hmac-execution-cleanup.py"))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class ConstructTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = driver.runner.cargo_environment.private_directory(driver.ROOT)
        cls.addClassCleanup(cls.directory.cleanup)
        cls.root = Path(cls.directory.name)
        cls.artifacts = driver.emit(cls.root / "baseline", "1.99.1", "x86_64-unknown-linux-gnu", "unwind")
        cls.llvm, cls.fixture = cls.artifacts[1][1], cls.artifacts[0][1]
        definitions, aliases = construct.flow.definitions_and_aliases(cls.llvm)
        _, (_, cls.body) = construct.admission.final.method(definitions, aliases, "with_tag_length")
        construct.validate(cls.llvm, cls.fixture, "unwind")

    def rejects(self, before, after, *, long_key=False):
        self.assertIn(before, self.body)
        self.assertNotEqual(before, after)
        llvm = self.llvm.replace(self.body, self.body.replace(before, after, 1), 1)
        definitions, aliases = construct.flow.definitions_and_aliases(llvm)
        symbol, (signature, body) = construct.admission.final.method(definitions, aliases, "with_tag_length")
        cache = construct.admission.contracts.validate(self.fixture, symbol)
        with self.subTest(before=before, after=after), self.assertRaises(ValueError):
            construct.check(signature, body, definitions, aliases, llvm, "unwind", 0, long_key, 0, cache)

    def calls(self, predicate):
        return [(line, item) for line in self.body.splitlines()
                if (item := construct.syntax.call(line)) and predicate(item[0])]

    def test_each_update_owner_input_extent_and_identity(self):
        calls = self.calls(construct.admission.final.model.stream_update)
        self.assertEqual(len(calls), 3)
        for line, (symbol, args) in calls:
            normalizing = construct.syntax.operand(args[0]) == "%state.i"
            for before, after in ((symbol, "unknown_update"),
                                  (construct.syntax.operand(args[0]), "%wrong_owner"),
                                  (construct.syntax.operand(args[1]), "%wrong_input"),
                                  (args[2], "i64 noundef 63")):
                self.rejects(line, line.replace(before, after), long_key=normalizing)

    def test_normalizer_consumption_and_destination(self):
        calls = self.calls(lambda symbol: construct.admission.final.stream_finalizer(symbol, "sha1"))
        self.assertEqual(len(calls), 1)
        line, (symbol, args) = calls[0]
        for before, after in ((symbol, "unknown_finalizer"),
                              (construct.syntax.operand(args[1]), "%inner.i"),
                              ("%digest.i,", "%pad.i,"), ("i64 noundef 20", "i64 noundef 19")):
            self.rejects(line, line.replace(before, after), long_key=True)

    def test_unwind_leak_and_unrecognized_callback(self):
        line, _ = self.calls(construct.admission.final.model.stream_update)[0]
        edge = self.body[self.body.index(line) + len(line):].splitlines()[1]
        changed = re.sub(r"unwind label %[-\w.]+", "unwind label %leak", edge)
        body = self.body.replace(edge, changed, 1) + "\nleak:\n  resume { ptr, i32 } zeroinitializer\n"
        llvm = self.llvm.replace(self.body, body, 1)
        with self.assertRaises(ValueError):
            construct.validate(llvm, self.fixture, "unwind")
        frontier = next(line for line in self.body.splitlines()
                        if "@llvm.lifetime.start.p0(ptr nonnull %pad.i)" in line)
        self.rejects(frontier, frontier + "\n  call void %unexpected_callback()")
        self.rejects(frontier, frontier + "\n  %a = atomicrmw add ptr %unexpected, i64 1 seq_cst")

    def test_split_returned_stream_and_tag_policy(self):
        lines = self.body.splitlines()
        copies = [line for line in lines if "@llvm.memcpy" in line and "_0.sroa_idx" in line]
        self.assertEqual(len(copies), 3)
        for line in copies:
            extent = re.search(r"i64 (\d+), i1 false", line)
            self.rejects(line, line.replace(extent[0], f"i64 {int(extent[1]) - 1}, i1 false"))
        tag = next(line for line in lines if "store i8 %_41.sroa.0.sroa.0.0.extract.trunc, ptr %_0" in line)
        self.rejects(tag, tag.replace("%_41.sroa.0.sroa.0.0.extract.trunc", "10"))
        padding = next(line for line in lines if "store i56 0," in line)
        self.rejects(padding, padding.replace("i56 0", "i56 1"))
        self.rejects(padding, padding +
                     "\n  call void @llvm.memset.p0.i64(ptr %_0, i8 0, i64 8, i1 false)")
        backend = next(line for line in lines if "store i8 %_10.1," in line)
        self.rejects(backend, backend.replace("%_10.1", "1"))
        niche = next(line for line in lines if "store i8 %_41.sroa.17.456.copyload," in line)
        self.rejects(niche, niche.replace("%_41.sroa.17.456.copyload", "0"))

    def test_iterator_cursor_provenance_and_failure_cleanup(self):
        lines = self.body.splitlines()
        for owner in ("inner", "outer"):
            copy = next(line for line in lines if "@llvm.memcpy" in line
                        and f".0.{owner}.sroa_idx.i," in line and "i64 440," in line)
            self.rejects(copy, copy.replace("i64 440,", "i64 439,"))
        cursor = next(line for line in lines if "store i64 %_11.i.i.i.us.i.i.i.lcssa," in line)
        self.rejects(cursor, cursor.replace("%_11.i.i.i.us.i.i.i.lcssa", "3"), long_key=True)
        # Removing all remaining iterator drops leaks admitted owners on error.
        calls = self.calls(lambda symbol: "Flatten" in symbol)
        self.assertTrue(calls)
        symbol = calls[0][1][0]
        self.rejects(symbol, "unrecognized_iterator")
        drops = self.calls(lambda symbol: construct.shared.owner_drop(symbol, "sha1"))
        pointers = construct.syntax.pointers(self.body, ("%state.i", "%inner.i", "%outer.i"))
        post_key = [(line, args) for line, (_, args) in drops
                    if pointers.get(construct.syntax.operand(args[0]), (None,))[0]
                    in ("%state.i", "%inner.i", "%outer.i")]
        self.assertTrue(post_key)
        for line, args in post_key:
            pointer = construct.syntax.operand(args[0])
            changed = self.body.replace(line, line.replace(pointer, "%lost_owner"), 1)
            # The full profile union covers normalization-only drops as well
            # as pad-initialization rejection and unwind paths.
            llvm = self.llvm.replace(self.body, changed, 1)
            with self.assertRaises(ValueError):
                construct.validate(llvm, self.fixture, "unwind")

    def test_inlined_abort_cleanup_is_checked(self):
        artifacts = driver.emit(self.root / "abort", "1.99.1", "x86_64-unknown-linux-gnu", "abort")
        llvm, fixture = artifacts[1][1], artifacts[0][1]
        construct.validate(llvm, fixture, "abort")
        definitions, aliases = construct.flow.definitions_and_aliases(llvm)
        _, (_, body) = construct.admission.final.method(definitions, aliases, "with_tag_length")
        self.assertNotIn("Flatten", "\n".join(line for line in body.splitlines() if construct.syntax.call(line)))
        pointers = construct.syntax.pointers(body, ("%streams", "%state.i", "%inner.i", "%outer.i", "%first", "%second"))
        calls = [line for line in body.splitlines() if (item := construct.syntax.call(line))
                 and construct.shared.owner_drop(item[0], "sha1")
                 and pointers.get(construct.syntax.operand(item[1][0]), (None,))[0]
                 not in ("%state.i", "%inner.i", "%outer.i", "%first", "%second")]
        self.assertTrue(calls)
        changed = body
        for line in calls:
            changed = changed.replace(line, "")
        with self.assertRaises(ValueError):
            construct.validate(llvm.replace(body, changed, 1), fixture, "abort")

    def test_compiled_initialization_and_return_mutants(self):
        work, leaf = self.root / "fixture", self.root / "leaf"
        source = driver.ROOT / "crates/brynja-legacy-hmac"
        shutil.copytree(source / "src", leaf / "src")
        shutil.copyfile(source / "README.md", leaf / "README.md")
        manifest = (source / "Cargo.toml").read_text()
        workspace = tomllib.loads((driver.ROOT / "Cargo.toml").read_text())["workspace"]
        for field in ("edition", "rust-version", "license", "repository"):
            manifest = manifest.replace(field + ".workspace = true", field + ' = "' + workspace["package"][field] + '"')
        for dependency in ("brynja-core", "brynja-legacy-sha1", "brynja-legacy-md5"):
            inherited = (dependency + ".workspace = true" if dependency == "brynja-core" else
                         dependency + " = { workspace = true, default-features = false }")
            manifest = manifest.replace(inherited, dependency + ' = { path = "'
                                        + str(driver.ROOT / "crates" / dependency) + '", default-features = false }')
        manifest = manifest.replace('path = "../', 'path = "' + str(driver.ROOT / "crates") + "/")
        (leaf / "Cargo.toml").write_text(manifest.replace("[lints]\nworkspace = true", "") + "\n[workspace]\n")
        fixture = driver.FIXTURE.parent
        shutil.copytree(fixture / "src", work / "src")
        manifest = (fixture / "Cargo.toml").read_text().replace("../../crates/brynja-legacy-hmac", str(leaf))
        (work / "Cargo.toml").write_text(manifest.replace("../../crates/", str(driver.ROOT / "crates") + "/"))
        shutil.copyfile(fixture / "Cargo.lock", work / "Cargo.lock")
        path = leaf / "src/engine.rs"
        original = path.read_text()
        baseline = driver.emit(work, "1.99.1", "x86_64-unknown-linux-gnu", "unwind", work / "Cargo.toml")
        construct.validate(baseline[1][1], baseline[0][1], "unwind")
        for before, after in (("            inner,\n            outer,", "            inner: outer,\n            outer: inner,"),
                              ("A::update(&mut outer, &pad.0)?;", "A::update(&mut inner, &pad.0)?;"),
                              ("A::update(&mut state, key)?;", "A::update(&mut state, &[])?;"),
                              ("            tag_bytes,", "            tag_bytes: 10,")):
            self.assertIn(before, original)
            path.write_text(original.replace(before, after, 1))
            artifacts = driver.emit(work, "1.99.1", "x86_64-unknown-linux-gnu", "unwind", work / "Cargo.toml")
            with self.assertRaises(ValueError):
                construct.validate(artifacts[1][1], artifacts[0][1], "unwind")


if __name__ == "__main__":
    unittest.main()
