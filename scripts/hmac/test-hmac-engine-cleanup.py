#!/usr/bin/env python3
"""Real caller cleanup graphs and compiled owner/scratch regression mutants."""
import importlib.util
import json
from pathlib import Path
import re
import shutil
import unittest

spec = importlib.util.spec_from_file_location(
    "hmac_engine_driver", Path(__file__).with_name("check-hmac-engine-cleanup.py"))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
codegen = driver.codegen


class EngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = driver.verifier.cargo_environment.private_directory(driver.ROOT)
        cls.addClassCleanup(cls.directory.cleanup)
        cls.root = Path(cls.directory.name)
        cls.llvm = driver.collect(cls.root / "baseline", "1.99.1",
                                  "x86_64-unknown-linux-gnu", "unwind")[1]
        cls.functions = codegen.emitted(cls.llvm)
        cls.definitions, cls.aliases = codegen.definitions_and_aliases(cls.llvm)
        cls.raw_functions = dict(cls.functions)
        for (identity, operation), body in cls.functions.items():
            if operation in driver.scratch.SCRATCH:
                cls.functions[identity, operation] = driver.scratch.consumer(
                    body, operation, cls.definitions, cls.aliases)

    def rejects(self, body, identity="sha256"):
        with self.assertRaises(ValueError):
            codegen.cancellation(body, identity)

    def test_population_and_aliases(self):
        self.assertEqual(len(self.functions), 108)
        for mutant in (self.llvm + self.llvm, self.llvm.replace("6sha2566cancel", "6sha2566absent")):
            with self.assertRaises(ValueError):
                codegen.emitted(mutant)
        alias = re.search(r"^@(\w+) = ([^\n]*\balias\b[^\n]*, ptr )@(\w+)$",
                          self.llvm, re.M)
        self.assertIsNotNone(alias)
        for target in (alias[1], "missing_definition"):
            mutant = self.llvm.replace(alias[0], f"@{alias[1]} = {alias[2]}@{target}", 1)
            with self.assertRaises(ValueError):
                codegen.emitted(mutant)

    def test_all_owner_offsets_and_copy_extents(self):
        for identity in codegen.IDENTITIES:
            body = self.functions[identity, "cancel"]
            with self.subTest(identity=identity):
                changed = re.sub(r"(getelementptr inbounds(?: nuw)? i8, ptr %[-\w.]+, i64 )\d+",
                                 r"\g<1>9999", body, count=1)
                self.assertNotEqual(body, changed)
                self.rejects(changed, identity)
                changed = re.sub(r"(i64 )(2088|2352)(, i1 false)", r"\g<1>1\3", body)
                self.assertNotEqual(body, changed)
                self.rejects(changed, identity)
                self.rejects(body.replace("%state,", "%other,", 1), identity)

    def test_branch_and_unwind_bypass(self):
        for identity in codegen.IDENTITIES:
            body = self.functions[identity, "cancel"]
            self.rejects(body.replace("start:", "start:\n  ret void\nunused:", 1), identity)
            changed = re.sub(r"unwind label %[-\w.]+", "unwind label %escape", body, count=1)
            self.assertNotEqual(body, changed)
            self.rejects(changed + "\nescape:\n  resume { ptr, i32 } zeroinitializer\n", identity)
            self.rejects(body.replace("unwind label %cleanup.i.i", "unwind label %absent", 1),
                         identity)

    def test_lifetime_duplicate_owner_and_post_cleanup_effects(self):
        body = self.functions["sha256", "cancel"]
        self.rejects(body.replace("i64 1178", "i64 8"))
        self.rejects(body.replace("start:", "start:\n  call void @llvm.lifetime.end.p0(ptr %_2)", 1))
        for instruction in ("store i8 42, ptr %_2", "call void @unknown(ptr %_2)",
                            "call void %callback(ptr %_2)",
                            "call void @llvm.memset.p0.i64(ptr %_2, i8 1, i64 2352, i1 false)"):
            self.rejects(body.replace("ret void", instruction + "\n  ret void"))
        self.rejects(body.replace("4Drop4drop(", "4Drop4noop("))
        self.rejects(body + "\nstart:\n  ret void\n")

    def test_copy_must_dominate_cleanup(self):
        body = self.functions["sha256", "cancel"]
        copy = next(line for line in body.splitlines() if "@llvm.memcpy." in line)
        moved = body.replace(copy, "", 1)
        self.rejects(moved + "\nunvisited:\n" + copy + "\n  ret void\n")
        self.rejects(moved.replace("ret void", copy + "\n  ret void"))

    def test_real_scratch_population_ranges_and_missing_clears(self):
        for identity in codegen.IDENTITIES:
            for operation in driver.scratch.SCRATCH:
                body = self.functions[identity, operation]
                owners = driver.scratch.allocations(body, operation)
                for owner, size in owners.items():
                    with self.subTest(identity=identity, operation=operation, owner=owner):
                        mutants = [body.replace(owner + " = alloca", owner + "_lost = alloca")]
                        for replacement in ("%wrong_scratch", owner):
                            lines = []
                            for line in body.splitlines():
                                if "clear_owned_region" in line and owner + "," in line:
                                    if replacement == owner:
                                        line = line.replace(f"i64 noundef {size})",
                                                            f"i64 noundef {size - 1})")
                                    else:
                                        line = line.replace(owner + ",", replacement + ",")
                                lines.append(line)
                            mutants.append("\n".join(lines))
                        for mutant in mutants:
                            self.assertNotEqual(mutant.strip(), body.strip())
                            with self.assertRaises(ValueError):
                                driver.scratch.check(mutant, operation)

    def test_real_scratch_paths_and_post_clear_writes(self):
        for operation in driver.scratch.SCRATCH:
            body = self.functions["sha256", operation]
            owner = next(iter(driver.scratch.allocations(body, operation)))
            start = next(line for line in body.splitlines()
                         if "llvm.lifetime.start" in line and owner + ")" in line)
            early = body.replace(start, start + "\n  ret void\nbypassed:", 1)
            lifetime = next(line for line in body.splitlines()
                            if "llvm.lifetime.end" in line and owner + ")" in line)
            for mutant in (
                    early,
                    body.replace(lifetime, "  store i8 42, ptr " + owner + "\n" + lifetime),
                    body.replace(lifetime, "  call void @unknown()\n" + lifetime),
                    body.replace(lifetime, lifetime + "\n  store i8 42, ptr " + owner)):
                with self.subTest(operation=operation), self.assertRaises(ValueError):
                    driver.scratch.check(mutant, operation)

    def test_output_guard_exception_is_bound_to_separate_storage(self):
        body = self.functions["sha256", "secret"]
        guard = re.search(r"(%initialization(?:\.[-\w]+)*) = alloca \[24 x i8\]", body)[1]
        owner = next(iter(driver.scratch.allocations(body, "secret")))
        for mutant in (body.replace(guard, owner),
                       body.replace(guard + " = alloca [24 x i8]",
                                    guard + " = alloca [16 x i8]"),
                       body.replace("26SecretRegionInitialization", "26UnknownRegionInitialization")):
            self.assertNotEqual(body, mutant)
            with self.assertRaises(ValueError):
                driver.scratch.check(mutant, "secret")

    def test_scratch_unwind_edges_and_clear_identity(self):
        body = self.functions["sha256", "construct"]
        bypass = re.sub(r"unwind label %[-\w.]+", "unwind label %escaped", body, count=1)
        self.assertNotEqual(body, bypass)
        mutants = (
            bypass + "\nescaped:\n  resume { ptr, i32 } zeroinitializer\n",
            bypass,
            body.replace("18clear_owned_region", "18other_owned_region"),
            body.replace("ret void", "unreachable"),
        )
        for mutant in mutants:
            with self.assertRaises(ValueError):
                driver.scratch.check(mutant, "construct")

    def test_outlined_scratch_is_bound_to_actual_callee(self):
        operation = "public_bits"
        body = self.raw_functions["sha256", operation]
        calls = re.findall(r'@("[^"]+"|\w+)\(', body)
        symbol = next(name.strip('"') for name in calls if "15brynja_mac_hmac6engine" in name)
        for mutant in (body.replace(symbol, symbol.replace("6public", "6secret")),
                       body.replace(symbol, "absent"),
                       body + "\n  call void @" + symbol + "()"):
            with self.assertRaises(ValueError):
                driver.scratch.consumer(mutant, operation, self.definitions, self.aliases)
        with self.assertRaises(ValueError):
            driver.scratch.consumer(body, operation, self.definitions,
                                    {**self.aliases, symbol: symbol})
        arguments, actual = codegen.resolve(symbol, self.definitions, self.aliases)
        damaged = actual.replace("18clear_owned_region", "18other_owned_region")
        definitions = {**self.definitions, symbol: (arguments, damaged)}
        checked = driver.scratch.consumer(body, operation, definitions, self.aliases)
        with self.assertRaises(ValueError):
            driver.scratch.check(checked, operation)

    def test_update_all_identities_reject_bypasses_and_wrong_owners(self):
        for identity in codegen.IDENTITIES:
            body = self.functions[identity, "update_cancel"]
            mutants = (
                body.replace("start:", "start:\n  ret i8 0\nunused:", 1),
                re.sub(r"(getelementptr inbounds(?: nuw)? i8, ptr %[-\w.]+, i64 )\d+",
                       r"\g<1>9999", body, count=1),
                re.sub(r"(i64 )(2088|2352)(, i1 false)", r"\g<1>1\3", body),
                body.replace("ret i8", "call void %observer()\n  ret i8"),
            )
            for mutant in mutants:
                self.assertNotEqual(mutant, body)
                with self.subTest(identity=identity), self.assertRaises(ValueError):
                    driver.update.check(mutant, identity, self.definitions, self.aliases)

    def test_update_unwind_helper_is_checked_not_just_named(self):
        identity = "sha256"
        body = self.functions[identity, "update_cancel"]
        symbol = next(name.strip('"') for name in re.findall(r'@("[^"]+"|\w+)\(', body)
                      if "drop_glue" in name or "drop_in_place" in name)
        arguments, actual = codegen.resolve(symbol, self.definitions, self.aliases)
        damaged = actual.replace("i64 1178", "i64 8")
        self.assertNotEqual(actual, damaged)
        with self.assertRaises(ValueError):
            driver.update.check(body, identity,
                                {**self.definitions, symbol: (arguments, damaged)}, self.aliases)
        with self.assertRaises(ValueError):
            driver.update.check(body, identity, self.definitions,
                                {**self.aliases, symbol: symbol})
        with self.assertRaises(ValueError):
            driver.update.check(body, identity,
                                {**self.definitions, symbol: ("ptr %other, ptr %extra", actual)},
                                self.aliases)
        bypass = re.sub(r"unwind label %[-\w.]+", "unwind label %escaped", body, count=1)
        with self.assertRaises(ValueError):
            driver.update.check(bypass + "\nescaped:\n  resume { ptr, i32 } zeroinitializer\n",
                                identity, self.definitions, self.aliases)

    def test_fatal_path_requires_actual_core_panic_identity(self):
        mutant = self.llvm.replace("16panic_in_cleanup(", "16panic_in_cleanup_fake(")
        self.assertNotEqual(self.llvm, mutant)
        with self.assertRaises(ValueError):
            driver.validate(mutant)
        for symbol in ("_RNvNtCsABC_4core9panicking16panic_in_cleanup_fake",
                       "unknown_panic_in_cleanup"):
            self.assertFalse(codegen.panic_cleanup(symbol))

    def test_compiled_owner_and_scratch_mutants(self):
        work = self.root / "mutant"
        leaf = work / "leaf"
        shutil.copytree(driver.ROOT / "crates/brynja-mac-hmac/src", leaf / "src")
        manifest = ('[workspace]\n[package]\nname="brynja-mac-hmac"\nversion="0.1.0"\n'
                    'edition="2024"\n[features]\ndefault=[]\n[dependencies]\n')
        for name in ("brynja-core", "brynja-hash-sha2", "brynja-hash-sha3"):
            features = ',features=["general-sha512-t"]' if name == "brynja-hash-sha2" else ""
            manifest += (f'{name}={{path={json.dumps(str(driver.ROOT / "crates" / name))},'
                         f'default-features=false{features}}}\n')
        (leaf / "Cargo.toml").write_text(manifest)
        fixture = work / "consumer"
        shutil.copytree(driver.FIXTURE.parent / "src", fixture / "src")
        (fixture / "Cargo.toml").write_text(driver.FIXTURE.read_text().replace(
            "../../crates/brynja-mac-hmac", str(leaf)))
        env = driver.verifier.environment(work)
        driver.verifier.run(["cargo", "+1.99.1", "generate-lockfile", "--offline",
                             "--manifest-path", str(fixture / "Cargo.toml")], env)
        baseline = driver.emit(work, "1.99.1", "x86_64-unknown-linux-gnu",
                               "unwind", fixture / "Cargo.toml")
        driver.validate(baseline[1])
        for filename, anchor, replacement in (
                ("lib.rs", "pub fn cancel(self) {}",
                 "pub fn cancel(self) { core::mem::forget(self); }"),
                ("scratch.rs", "let _ = clear_owned_region(&mut self.0);",
                 "let _ = &mut self.0;"),
                ("scratch.rs", "let _ = clear_owned_region(&mut self.0);",
                 "let _ = clear_owned_region(&mut self.0[..N / 2]);")):
            source = leaf / "src" / filename
            original = source.read_text()
            self.assertEqual(original.count(anchor), 1)
            source.write_text(original.replace(anchor, replacement))
            mutant = driver.emit(work, "1.99.1", "x86_64-unknown-linux-gnu",
                                 "unwind", fixture / "Cargo.toml")
            # Compilation must succeed; a compiler error does not kill this mutant.
            with self.assertRaises(ValueError):
                driver.validate(mutant[1])
            source.write_text(original)
            restored = driver.emit(work, "1.99.1", "x86_64-unknown-linux-gnu",
                                   "unwind", fixture / "Cargo.toml")
            driver.validate(restored[1])
        source = fixture / "src/lib.rs"
        original = source.read_text()
        for anchor, replacement, reason in (
            ("state.update(input)?;", """
                if let Err(error) = state.update(input) {
                    core::mem::forget(state);
                    return Err(error);
                }
            """, "update exits without both cleanup dispatches"),
            ("observer();\n                state.cancel();", """
                let state = core::mem::ManuallyDrop::new(state);
                observer();
                core::mem::ManuallyDrop::into_inner(state).cancel();
            """, "unwind-capable callback lacks cleanup edge"),
        ):
            self.assertEqual(original.count(anchor), 1)
            source.write_text(original.replace(anchor, replacement))
            mutant = driver.emit(work, "1.99.1", "x86_64-unknown-linux-gnu",
                                 "unwind", fixture / "Cargo.toml")
            with self.assertRaisesRegex(ValueError, reason):
                driver.validate(mutant[1])
            source.write_text(original)
            restored = driver.emit(work, "1.99.1", "x86_64-unknown-linux-gnu",
                                   "unwind", fixture / "Cargo.toml")
            driver.validate(restored[1])


if __name__ == "__main__":
    unittest.main()
