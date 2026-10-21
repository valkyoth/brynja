#!/usr/bin/env python3
"""Static-only feature, metadata, owner-transfer and compiled leak regressions."""
import copy
import importlib.util
import json
from pathlib import Path
import re
import shutil
import unittest
from unittest import mock
from hmac_static_final_tests import StaticFinalTests
from hmac_execution_final_tests import FinalTests

spec = importlib.util.spec_from_file_location(
    "hmac_static_cleanup", Path(__file__).with_name("check-hmac-static-cleanup.py"))
static = importlib.util.module_from_spec(spec)
spec.loader.exec_module(static)
driver = static.driver


class StaticTests(StaticFinalTests, unittest.TestCase):
    driver = driver
    @classmethod
    def setUpClass(cls):
        cls.directory = driver.verifier.cargo_environment.private_directory(driver.ROOT)
        cls.addClassCleanup(cls.directory.cleanup)
        cls.root = Path(cls.directory.name)
        cls.llvm = static.collect(cls.root / "baseline", "1.99.1",
                                  "x86_64-unknown-linux-gnu", "unwind")[1]
        cls.functions, cls.definitions, cls.aliases = driver.emitted(cls.llvm)

    def test_resolved_features_are_independent(self):
        command = ["cargo", "+1.99.1", "metadata", "--manifest-path", str(driver.FIXTURE),
                   "--locked", "--offline", "--format-version", "1", "--no-default-features"]
        document = json.loads(driver.verifier.run(command, driver.verifier.environment(self.root)))
        driver.profiles.graph(document, "static")
        for name in (*driver.profiles.OWNERS, "brynja-hmac-execution-cleanup"):
            package = next(row for row in document["packages"] if row["name"] == name)
            for change in ("runtime", "missing", "registry"):
                mutant = copy.deepcopy(document)
                node = next(row for row in mutant["resolve"]["nodes"] if row["id"] == package["id"])
                if change == "runtime":
                    node["features"].append("runtime-execution")
                elif change == "missing":
                    mutant["resolve"]["nodes"].remove(node)
                else:
                    next(row for row in mutant["packages"] if row["id"] == package["id"])["source"] = "registry"
                with self.subTest(name=name, change=change), self.assertRaises(ValueError):
                    driver.profiles.graph(mutant, "static")
        for field in ("packages", "nodes"):
            mutant = copy.deepcopy(document)
            rows = mutant[field] if field == "packages" else mutant["resolve"][field]
            rows.append(copy.deepcopy(rows[0]))
            with self.assertRaises(ValueError):
                driver.profiles.graph(mutant, "static")
        with self.assertRaises(ValueError):
            driver.profiles.graph(document, "runtime")
        for name in driver.profiles.OWNERS:
            mutant = copy.deepcopy(document)
            identity = next(row["id"] for row in mutant["packages"] if row["name"] == name)
            node = next(row for row in mutant["resolve"]["nodes"] if row["id"] == identity)
            node["features"].remove("hardened-execution")
            with self.subTest(name=name), self.assertRaises(ValueError):
                driver.profiles.graph(mutant, "static")
        with self.assertRaises(ValueError):
            driver.validate_retained(self.llvm)  # Static bytes are not runtime-layout evidence.

    def test_exact_population_and_runtime_artifact_rejected(self):
        self.assertEqual(len(self.functions), 24)
        with self.assertRaises(ValueError):
            static.validate(self.llvm + self.llvm)
        with self.assertRaises(ValueError):
            static.validate(self.llvm.replace("6sha2566cancel", "6sha2566absent"))
        injected = self.llvm + '\n@fake29brynja_hmac_execution_cleanup6sha25617construct_runtime = alias void (), ptr @missing\n'
        with self.assertRaises(ValueError):
            static.validate(injected)

    def test_real_feature_unification_rejects_before_compiling(self):
        work = self.root / "unified"
        shutil.copytree(driver.FIXTURE.parent / "src", work / "src")
        manifest = driver.FIXTURE.read_text().replace(
            "../../crates/brynja-mac-hmac", str(driver.ROOT / "crates/brynja-mac-hmac"))
        # Dependency-side activation must be detected even though the fixture's
        # own runtime feature stays disabled and its runtime probe is absent.
        manifest = manifest.replace('features = ["hardened-execution"]',
                                    'features = ["runtime-execution"]')
        (work / "Cargo.toml").write_text(manifest)
        driver.verifier.run(["cargo", "+1.99.1", "generate-lockfile", "--offline",
                             "--manifest-path", str(work / "Cargo.toml")],
                            driver.verifier.environment(work))
        with mock.patch.object(driver.verifier, "run", wraps=driver.verifier.run) as run:
            with self.assertRaisesRegex(ValueError, "profile contaminated"):
                driver.emit(work, "1.99.1", "x86_64-unknown-linux-gnu", "unwind",
                            work / "Cargo.toml", profile="static")
            self.assertEqual(len(run.call_args_list), 1)
            self.assertEqual(run.call_args[0][0][2], "metadata")

    def test_all_retained_copy_fragments_and_exits(self):
        for (identity, operation), body in self.functions.items():
            line = next(row for row in body.splitlines() if "@llvm.memcpy." in row)
            for replacement in ("", re.sub(r"i64 \d+, i1 false", "i64 1, i1 false", line),
                                line.replace("%state,", "%other,")):
                with self.subTest(identity=identity, operation=operation), self.assertRaises(ValueError):
                    altered = body.replace(line, replacement, 1)
                    if operation == "cancel":
                        driver.cleanup.cancellation(altered, identity, self.definitions, self.aliases,
                                                    profile="static")
                    else:
                        driver.update.check(altered, identity, self.definitions, self.aliases,
                                            "1.99.1", "unwind", profile="static")
        body = self.functions["sha256", "update_cancel"]
        for old, new in (("%input.0,", "%other,"), ("%input.1)", "%other_length)"),
                         ("%observer()", "%other()")):
            self.assertIn(old, body)
            with self.assertRaises(ValueError):
                driver.update.check(body.replace(old, new), "sha256", self.definitions, self.aliases,
                                    "1.99.1", "unwind", profile="static")
        lines = body.splitlines()
        index = next(i for i, row in enumerate(lines) if "%observer()" in row)
        self.assertIn("invoke", lines[index])
        lines[index + 1] = re.sub(r"unwind label %[-\w.]+", "unwind label %escaped", lines[index + 1])
        altered = "\n".join(lines) + "\nescaped:\n resume { ptr, i32 } zeroinitializer\n"
        with self.assertRaises(ValueError):
            driver.update.check(altered, "sha256", self.definitions, self.aliases,
                                "1.99.1", "unwind", profile="static")

    def test_metadata_widths_and_independent_owner_populations(self):
        for identity in driver.common.IDENTITIES:
            shape = driver.cleanup.layout(identity, "static")
            for population in range(16):
                memory, events = driver.cleanup.initial(identity, population, True, profile="static")
                self.assertIn((shape.core_kind, shape.core), events)
                self.assertIn((shape.core_kind, shape.stride + shape.core), events)
                if shape.core_kind == "sha2":
                    for index, base in enumerate((0, shape.stride)):
                        self.assertEqual(("scratch", base + 80) in events, bool(population & (4 << index)))
                        with self.assertRaises(ValueError):
                            driver.cleanup.metadata(memory, base + 64, "i64")
                with self.assertRaises(ValueError):
                    driver.cleanup.metadata(memory, shape.discriminator, "i64")
                empty, events = driver.cleanup.initial(identity, population, False, profile="static")
                self.assertFalse(events)
                self.assertEqual(empty, {shape.discriminator: ("i8", 2)})
        for old, new in (("load i8,", "load i64,"), ("icmp eq ptr", "icmp ne ptr"),
                         ("load ptr,", "load i64,"), ("i64 64", "i64 63")):
            self.assertIn(old, self.llvm)
            with self.subTest(old=old), self.assertRaises(ValueError):
                driver.validate_retained(self.llvm.replace(old, new), profile="static")

    def test_actual_helpers_and_leaf_identities(self):
        queue, helpers = list(self.functions.values()), {}
        while queue:
            for name in re.findall(r'@("[^"]+"|\w+)\(', queue.pop()):
                symbol = name.strip('"')
                if "drop_glue" in symbol and symbol not in helpers:
                    _, body = driver.common.resolve(symbol, self.definitions, self.aliases)
                    helpers[symbol] = body
                    queue.append(body)
        self.assertTrue(helpers)
        for name, body in helpers.items():
            with self.subTest(helper=name), self.assertRaises(ValueError):
                driver.validate_retained(self.llvm.replace(body, "start:\n ret void\n", 1), profile="static")
        leaves = {name for _, body in self.definitions.values()
                  for name in re.findall(r'@("[^"]+"|[-\w.$]+)\(', body)
                  if driver.cleanup.leaf(name.strip('"'))}
        self.assertEqual(len(leaves), 4)
        for name in leaves:
            with self.assertRaises(ValueError):
                driver.validate_retained(self.llvm.replace(name, name + "_fake"), profile="static")

    def test_normal_entry_cannot_claim_fatal_cleanup(self):
        symbol = next(name for name in re.findall(r"@(\w+)\(", self.llvm)
                      if driver.common.panic_cleanup(name))
        body = f"start:\n call void @{symbol}()\n unreachable\n"
        with self.assertRaises(ValueError):
            driver.cleanup.cancellation(body, "sha256", self.definitions, self.aliases, profile="static")
        with self.assertRaises(ValueError):
            driver.update.check(body, "sha256", self.definitions, self.aliases,
                                "1.99.1", "unwind", profile="static")

    def test_wrapper_scalar_fragments_and_empty_output(self):
        functions, definitions, aliases = driver.emitted(self.llvm, driver.final.syntax.OPERATIONS)
        self.assertEqual(len(functions), 72)
        for (identity, operation), body in functions.items():
            copies = [row for row in body.splitlines() if "@llvm.memcpy." in row]
            self.assertTrue(copies)
            for line in copies:
                with self.subTest(identity=identity, operation=operation), self.assertRaises(ValueError):
                    driver.wrapper.check(body.replace(line, "", 1), identity, operation,
                                         definitions, aliases, profile="static")
            for line in (row for row in body.splitlines() if re.search(r"store i8 %", row)):
                mutant = re.sub(r"store i8 %[-\w.]+", "store i8 0", line)
                with self.assertRaises(ValueError):
                    driver.wrapper.check(body.replace(line, mutant, 1), identity, operation,
                                         definitions, aliases, profile="static")
            if operation.startswith("secret"):
                line = next(row for row in body.splitlines() if "18clear_owned_region" in row)
                with self.assertRaises(ValueError):
                    driver.wrapper.check(body.replace(line, "", 1), identity, operation,
                                         definitions, aliases, present=False, profile="static")

    def test_compiled_static_leaks(self):
        work = self.root / "mutants"
        leaf, fixture = work / "leaf", work / "consumer"
        shutil.copytree(driver.ROOT / "crates/brynja-mac-hmac/src", leaf / "src")
        manifest = ('[workspace]\n[package]\nname="brynja-mac-hmac"\nversion="0.1.0"\n'
                    'edition="2024"\n[features]\ndefault=[]\nhardened-execution=[]\n'
                    'runtime-execution=["hardened-execution"]\n[dependencies]\n')
        for name in ("brynja-core", "brynja-crypto-cpu", "brynja-hash-sha2", "brynja-hash-sha3"):
            features = ["hardened-execution"] if name != "brynja-core" else []
            if name == "brynja-hash-sha2":
                features.append("general-sha512-t")
            manifest += (f'{name}={{path={json.dumps(str(driver.ROOT / "crates" / name))},'
                         f'default-features=false,features={json.dumps(features)}}}\n')
        (leaf / "Cargo.toml").write_text(manifest)
        shutil.copytree(driver.FIXTURE.parent / "src", fixture / "src")
        (fixture / "Cargo.toml").write_text(driver.FIXTURE.read_text().replace(
            "../../crates/brynja-mac-hmac", str(leaf)))
        driver.verifier.run(["cargo", "+1.99.1", "generate-lockfile", "--offline",
                             "--manifest-path", str(fixture / "Cargo.toml")],
                            driver.verifier.environment(work))

        def emitted():
            return driver.emit(work, "1.99.1", "x86_64-unknown-linux-gnu", "unwind",
                               fixture / "Cargo.toml", profile="static")[1]

        static.validate(emitted())
        mutants = [
            (leaf / "src/execution/mod.rs", "pub fn cancel(self) {}",
             "pub fn cancel(self) { core::mem::forget(self); }"),
            (leaf / "src/execution/retained.rs", "let _ = self.slot.take();",
             "core::mem::forget(self.slot.take());"),
            (fixture / "src/lib.rs", "state.update(input)?;",
             "if let Err(error) = state.update(input) { core::mem::forget(state); return Err(error); }"),
            (fixture / "src/lib.rs", "observer();\n                state.cancel();",
             "let state = core::mem::ManuallyDrop::new(state);\n"
             "observer();\n core::mem::ManuallyDrop::into_inner(state).cancel();"),
        ]
        for role, size in (("inner_digest", 64), ("tag", 64), ("difference", 1)):
            anchor = f"let mut {role} = Scratch::<{size}>::new();"
            mutants.append((leaf / "src/engine.rs", anchor,
                            f"let mut {role} = core::mem::ManuallyDrop::new(Scratch::<{size}>::new());"))
        final_mutants = FinalTests.final_mutants(leaf)
        mutants.extend(final_mutants)
        for path, anchor, replacement in mutants:
            original = path.read_text()
            self.assertEqual(original.count(anchor), 1)
            try:
                path.write_text(original.replace(anchor, replacement))
                llvm = emitted()  # Compiler failure is not a rejection result.
                if (path, anchor, replacement) in final_mutants:
                    functions, definitions, aliases = driver.emitted(llvm, ("public",))
                    body = driver.scratch.consumer(functions["sha256", "public"], "public", definitions, aliases)
                    with self.assertRaises(ValueError):
                        driver.final.check(body, "sha256", definitions, aliases, profile="static", route=15)
                with self.subTest(anchor=anchor), self.assertRaises(ValueError):
                    static.validate(llvm)
            finally:
                path.write_text(original)
            static.validate(emitted())
        print("Static-only HMAC mutants: 11 compiled/rejected; restored baselines PASS", flush=True)


if __name__ == "__main__":
    unittest.main()
