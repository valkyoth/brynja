#!/usr/bin/env python3
"""Actual legacy caller graphs and source-compiled ownership regressions."""
import importlib.util
from pathlib import Path
import re
import shutil
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("legacy_engine_driver", Path(__file__).with_name("check-legacy-hmac-engine-cleanup.py"))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
codegen = driver.codegen


class EngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = driver.runner.cargo_environment.private_directory(driver.ROOT)
        cls.addClassCleanup(cls.directory.cleanup)
        cls.root = Path(cls.directory.name)
        cls.artifacts = driver.collect(cls.root / "baseline", "1.99.1", "x86_64-unknown-linux-gnu", "unwind")
        cls.llvm = cls.artifacts[1]
        cls.functions, cls.definitions, cls.aliases = codegen.emitted(cls.llvm)

    def rejects(self, text):
        with self.assertRaises(ValueError):
            driver.validate(text, "unwind")

    def test_population_aliases_and_trusted_import_origins(self):
        self.rejects(self.llvm.replace("4sha16cancel", "4sha16invent"))
        self.rejects(self.llvm + self.llvm)
        with patch.dict(sys.modules, {"hmac_engine_codegen": SimpleNamespace(__file__="/fake/hmac_engine_codegen.py")}):
            with self.assertRaisesRegex(ValueError, "origin"):
                codegen.load("hmac_engine_codegen")
        # The private legacy instances must not mutate modern population/rules.
        self.assertNotEqual(codegen.flow.IDENTITIES, codegen.IDENTITIES)
        modern = codegen.load("hmac_engine_scratch")
        self.assertEqual(modern.SCRATCH["construct"]["pad"], 144)
        self.assertEqual(driver.scratch.flow.SCRATCH["construct"]["pad"], 64)

    def test_cancellation_and_update_owner_binding(self):
        for identity in codegen.IDENTITIES:
            for operation in ("cancel", "update_cancel"):
                body = self.functions[identity, operation]
                mutations = [body.replace("start:", "start:\n  ret void\nunused:", 1),
                             re.sub(r"(getelementptr inbounds nuw i8, ptr %[-\w.]+, i64 )8\b", r"\g<1>9", body, count=1),
                             re.sub(r"(ptr [^\n]*?)%state, i64 (240|880), i1 false", r"\1%wrong, i64 \2, i1 false", body, count=1)]
                for mutated in mutations:
                    self.assertNotEqual(body, mutated)
                    self.rejects(self.llvm.replace(body, mutated, 1))
                # Wrong legacy hash destructor must not count as cleanup.
                calls = re.findall(r'@("[^"]+"|[-\w.$]+)\(', body)
                drops = {symbol for symbol in calls if codegen.owner_drop(symbol.strip('"'), identity)}
                self.assertTrue(drops)
                for symbol in drops:
                    mutated = body.replace(symbol, "wrong_destructor", 1)
                    self.rejects(self.llvm.replace(body, mutated, 1))

    def test_update_observer_unwind_and_unknown_alias(self):
        for identity in codegen.IDENTITIES:
            body = self.functions[identity, "update_cancel"]
            changed = re.sub(r"(invoke void %observer\(\)\s+to label %[-\w.]+ unwind label )%[-\w.]+",
                             r"\1%escape", body)
            self.assertNotEqual(body, changed)
            changed += "\nescape:\n  resume { ptr, i32 } zeroinitializer\n"
            self.rejects(self.llvm.replace(body, changed, 1))
            changed = body.replace("invoke void %observer()", "call void %observer()", 1)
            self.rejects(self.llvm.replace(body, changed, 1))
            changed = body.replace("start:", "start:\n  %alias = phi ptr [ %state, %start ]", 1)
            self.rejects(self.llvm.replace(body, changed, 1))

    def test_each_scratch_pointer_and_extent(self):
        count = 0
        seen = set()
        for identity in codegen.IDENTITIES:
            for operation in driver.scratch.flow.SCRATCH:
                body = driver.scratch.consumer(self.functions[identity, operation], identity, operation,
                                               self.definitions, self.aliases)
                if body in seen:
                    continue
                seen.add(body)
                owners = driver.scratch.flow.allocations(body, operation)
                for line in body.splitlines():
                    if re.search(driver.scratch.flow.CLEAR, line):
                        for owner, size in owners.items():
                            anchor = re.search(re.escape(owner) + r", i64(?: noundef)? " + str(size) + r"\)", line)
                            if anchor:
                                for replacement in (anchor[0].replace(owner, "%wrong_scratch"),
                                                    anchor[0].replace(str(size) + ")", str(size - 1) + ")")):
                                    mutated = body.replace(line, line.replace(anchor[0], replacement), 1)
                                    self.assertNotEqual(body, mutated)
                                    self.rejects(self.llvm.replace(body, mutated, 1))
                                    count += 1
        self.assertGreaterEqual(count, 40)

    def test_finalizers_reject_undispatched_owner_and_wrong_hash(self):
        count = 0
        for identity in codegen.IDENTITIES:
            for operation in ("public", "secret", "verify"):
                body = driver.scratch.consumer(self.functions[identity, operation], identity, operation,
                                               self.definitions, self.aliases)
                for symbol in re.findall(r'@("[^"]+"|[-\w.$]+)\(', body):
                    if not driver.final.hash_finalizer(symbol.strip('"'), identity):
                        continue
                    changed = body.replace(symbol, "unknown_hash_finalizer", 1)
                    self.rejects(self.llvm.replace(body, changed, 1))
                    count += 1
                # Exact copy geometry and owner provenance, not marker presence.
                width = driver.final.geometry(identity)[0]
                changed = re.sub(r"i64 " + str(width) + r", i1 false", "i64 1, i1 false", body, count=1)
                self.assertNotEqual(body, changed)
                self.rejects(self.llvm.replace(body, changed, 1))
                with self.assertRaises(ValueError):
                    driver.final.check("start:\n  ret void\n", identity, self.definitions, self.aliases, "unwind")
        self.assertGreaterEqual(count, 12)

    def test_outlined_calls_are_bound_to_the_consumed_input(self):
        count = 0
        for identity in codegen.IDENTITIES:
            for operation in ("public", "secret", "verify", "public_bits", "secret_bits", "verify_bits"):
                body = self.functions[identity, operation]
                size = codegen.layout(identity)[0]
                copies = re.findall(r"(%[-\w.]+) = alloca \[" + str(size) + r" x i8\],", body)
                self.assertEqual(len(copies), 1)
                call_lines = [line for line in body.splitlines() if re.search(r"\b(?:call|invoke)\b", line)
                              and "18brynja_legacy_hmac6engine" in line]
                self.assertEqual(len(call_lines), 1)
                changed = call_lines[0].replace(copies[0] + ",", "%state,", 1)
                self.assertNotEqual(call_lines[0], changed)
                self.rejects(self.llvm.replace(body, body.replace(call_lines[0], changed), 1))
                changed = body.replace("start:", "start:\n  ret i8 0\nunused:", 1)
                self.rejects(self.llvm.replace(body, changed, 1))
                count += 1
        self.assertEqual(count, 12)

    def test_compiled_forgotten_owner_and_error_cleanup_mutants(self):
        source = driver.FIXTURE.parent
        original = (source / "src/lib.rs").read_text()
        mutations = (
            ("state.cancel();", "core::mem::forget(state);"),
            ("state.update(input)?;", "if state.update(input).is_err() { core::mem::forget(state); return Err(Error::MessageTooLong); }"),
            ("observer();", "let _ = observer;"),
        )
        for number, (before, after) in enumerate(mutations):
            work = self.root / f"mutant-{number}"
            (work / "src").mkdir(parents=True)
            (work / "Cargo.toml").write_text((source / "Cargo.toml").read_text().replace(
                "../../crates/", str(driver.ROOT / "crates") + "/"))
            shutil.copyfile(source / "Cargo.lock", work / "Cargo.lock")
            path = work / "src/lib.rs"
            path.write_text(original)
            baseline = driver.emit(work, "1.99.1", "x86_64-unknown-linux-gnu", "unwind", work / "Cargo.toml")
            driver.validate(baseline[1], "unwind")
            self.assertIn(before, original)
            path.write_text(original.replace(before, after, 1))
            artifacts = driver.emit(work, "1.99.1", "x86_64-unknown-linux-gnu", "unwind", work / "Cargo.toml")
            # Real compilation must succeed; compiler errors are not a killed mutation.
            self.rejects(artifacts[1])

    def test_constructor_initialization_and_returned_owner_binding(self):
        for identity in codegen.IDENTITIES:
            body = self.functions[identity, "construct"]
            width, _, fields = driver.final.geometry(identity)
            # Last initialized byte removed: no owner may be used before all
            # bytes of the actual inline constructor have been initialized.
            initializers = re.findall(r"(  store i8 0, ptr %[-\w.]+, align 1[^\n]*)", body)
            self.assertTrue(initializers)
            rejected = 0
            for line in initializers:
                changed = body.replace(line, "", 1)
                try:
                    driver.construct.check(changed, identity, "unwind")
                except ValueError:
                    rejected += 1
            self.assertGreaterEqual(rejected, 3)
            lifetime = re.search(r"(  call void @llvm.lifetime.start.p0\(ptr nonnull (%state\.[-\w.]+)\)[^\n]*)", body)
            self.assertIsNotNone(lifetime)
            changed = body.replace(lifetime[1], lifetime[1] + "\n  %premature = load i8, ptr " + lifetime[2], 1)
            self.rejects(self.llvm.replace(body, changed, 1))
            for offset in fields:
                before = "ptr %_0, i64 " + str(offset + 8)
                self.assertIn(before, body)
                changed = body.replace(before, "ptr %_0, i64 " + str(offset + 9), 1)
                self.rejects(self.llvm.replace(body, changed, 1))
            changed = re.sub(r"i64 " + str(width) + r", i1 false", "i64 1, i1 false", body, count=1)
            self.assertNotEqual(body, changed)
            self.rejects(self.llvm.replace(body, changed, 1))
            with self.assertRaises(ValueError):
                driver.construct.check(body.replace("start:", "start:\n  ret void\nunused:", 1), identity, "unwind")

    def test_constructor_cannot_overwrite_or_mislabel_exported_state(self):
        for identity in codegen.IDENTITIES:
            body = self.functions[identity, "construct"]
            insertion = ("  %overwrite = getelementptr inbounds i8, ptr %_0, i64 16\n"
                         "  store i8 0, ptr %overwrite\n")
            changed = body.replace("  ret void", insertion + "  ret void")
            self.assertNotEqual(body, changed)
            self.rejects(self.llvm.replace(body, changed, 1))
            # Successful output must be paired with both owned hash fields,
            # not merely a Result success discriminant or marker.
            changed = re.sub(r"store i8 %[-\w.]+, ptr %_0,", "store i8 1, ptr %_0,", body)
            self.assertNotEqual(body, changed)
            self.rejects(self.llvm.replace(body, changed, 1))


if __name__ == "__main__":
    unittest.main()
