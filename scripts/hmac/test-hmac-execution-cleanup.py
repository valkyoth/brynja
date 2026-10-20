#!/usr/bin/env python3
"""Fail-closed accelerated caller graphs and successfully compiled leak mutants."""
import importlib.util
import json
from pathlib import Path
import re
import shutil
import unittest
from hmac_execution_scratch_tests import ScratchTests

spec = importlib.util.spec_from_file_location(
    "hmac_execution_cleanup", Path(__file__).with_name("check-hmac-execution-cleanup.py"))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class ExecutionTests(ScratchTests, unittest.TestCase):
    driver = driver

    @classmethod
    def setUpClass(cls):
        cls.directory = driver.verifier.cargo_environment.private_directory(driver.ROOT)
        cls.addClassCleanup(cls.directory.cleanup)
        cls.root = Path(cls.directory.name)
        cls.llvm = driver.collect(cls.root / "baseline", "1.99.1",
                                  "x86_64-unknown-linux-gnu", "unwind")[1]
        cls.functions, cls.definitions, cls.aliases = driver.emitted(cls.llvm)

    def rejects(self, body, identity="sha256", operation="cancel", definitions=None):
        with self.assertRaises(ValueError):
            if operation == "cancel":
                driver.cleanup.cancellation(body, identity, definitions or self.definitions, self.aliases)
            else:
                driver.update.check(body, identity, definitions or self.definitions, self.aliases,
                                    "1.99.1", "unwind")

    def test_exact_population_and_aliases(self):
        self.assertEqual(len(self.functions), 24)
        for mutant in (self.llvm + self.llvm,
                       self.llvm.replace("6sha2566cancel", "6sha2566absent"),
                       self.llvm.replace("6sha25613update_cancel", "6sha25613absent_method")):
            with self.assertRaises(ValueError):
                driver.validate(mutant)
        name = next(iter(self.aliases))
        for target in (name, "missing"):
            with self.assertRaises(ValueError):
                driver.common.resolve(name, self.definitions, {**self.aliases, name: target})

    def test_all_identity_copy_extent_source_order_and_exit(self):
        for (identity, operation), body in self.functions.items():
            copy = next(line for line in body.splitlines() if "@llvm.memcpy." in line)
            size = re.search(r"i64 (\d+), i1 false", copy)[1]
            for replacement in ("", copy.replace(f"i64 {size}, i1 false", "i64 1, i1 false"),
                                copy.replace("%state,", "%wrong,")):
                with self.subTest(identity=identity, operation=operation):
                    self.rejects(body.replace(copy, replacement, 1), identity, operation)
            changed = body.replace("start:", "start:\n  ret void\nunused:", 1)
            self.rejects(changed, identity, operation)
            changed = body.replace("start:", "start:\n  store i8 42, ptr %state\n", 1)
            self.rejects(changed, identity, operation)
            if operation == "update_cancel":
                shape = driver.cleanup.layout(identity)
                changed = body.replace(copy, copy.replace(
                    f"i64 {size}, i1 false", f"i64 {shape.size}, i1 false"), 1)
                self.assertNotEqual(changed, body)
                self.rejects(changed, identity, operation)

    def test_actual_helper_bodies_not_names(self):
        # Only the cancellation/update helper graphs have owner obligations.
        # Constructor iterator destruction remains a separate typed premise.
        queue = list(self.functions.values())
        helpers = {}
        while queue:
            for name in re.findall(r'@("[^"]+"|\w+)\(', queue.pop()):
                symbol = name.strip('"')
                if "drop_glue" in symbol and symbol not in helpers:
                    arguments, body = driver.common.resolve(symbol, self.definitions, self.aliases)
                    helpers[symbol] = (arguments, body)
                    queue.append(body)
        self.assertTrue(helpers)
        for symbol, (arguments, body) in helpers.items():
            replacements = ("start:\n  ret void\n", body.replace(
                "start:", "start:\n  ret void\nunused:", 1))
            for replacement in replacements:
                with self.subTest(helper=symbol), self.assertRaises(ValueError):
                    driver.validate(self.llvm.replace(body, replacement, 1))
            for line in body.splitlines():
                if "getelementptr" in line:
                    replacement = re.sub(r"i64 \d+", "i64 99999", line)
                    with self.subTest(pointer=line), self.assertRaises(ValueError):
                        driver.validate(self.llvm.replace(line, replacement))
            mutant = re.sub(r"to label %[-\w.]+", "to label %escaped", body, count=1)
            self.assertNotEqual(mutant, body)
            mutant += "\nescaped:\n  ret void\n"
            with self.subTest(normal_helper=symbol), self.assertRaises(ValueError):
                driver.validate(self.llvm.replace(body, mutant, 1))
            if "6Option" in symbol:
                # These helpers run before unwinding. Hash-only helpers run
                # during existing cleanup; a second throw is fatal and excluded.
                mutant = re.sub(r"unwind label %[-\w.]+", "unwind label %escaped", body, count=1)
                mutant += "\nescaped:\n  resume { ptr, i32 } zeroinitializer\n"
                with self.subTest(unwind_helper=symbol), self.assertRaises(ValueError):
                    driver.validate(self.llvm.replace(body, mutant, 1))

    def test_leaf_identity_and_discriminators(self):
        symbols = set()
        for _, body in self.definitions.values():
            for symbol in re.findall(r'@("[^"]+"|[-\w.$]+)\(', body):
                if driver.cleanup.leaf(symbol.strip('"')):
                    symbols.add(symbol)
        self.assertEqual(len(symbols), 4)
        for symbol in symbols:
            with self.subTest(symbol=symbol), self.assertRaises(ValueError):
                driver.validate(self.llvm.replace(symbol, symbol + "_fake"))
        for old, new in (("icmp eq i64 %1, -1", "icmp eq i64 %1, 0"),
                         ("icmp eq i64 %1, 2", "icmp eq i64 %1, 1"),
                         ("store i64 -1,", "store i64 0,"),
                         ("store i64 2,", "store i64 0,")):
            self.assertIn(old, self.llvm)
            with self.assertRaises(ValueError):
                driver.validate(self.llvm.replace(old, new))

    def test_update_arguments_lifetimes_and_unwind(self):
        for identity in driver.common.IDENTITIES:
            body = self.functions[identity, "update_cancel"]
            for old, new in (("%input.0,", "%wrong_input,"),
                             ("%input.1)", "%wrong_length)"),
                             ("%observer()", "%other()")):
                self.assertIn(old, body)
                self.rejects(body.replace(old, new), identity, "update_cancel")
            lines = body.splitlines()
            observer = next(index for index, line in enumerate(lines) if "%observer()" in line)
            self.assertIn("invoke", lines[observer])
            lines[observer + 1] = re.sub(r"unwind label %[-\w.]+", "unwind label %escaped",
                                          lines[observer + 1])
            mutant = "\n".join(lines) + "\nescaped:\n resume { ptr, i32 } zeroinitializer\n"
            self.rejects(mutant, identity, "update_cancel")
            lifetime = next(line for line in body.splitlines() if "llvm.lifetime.end" in line)
            mutant = body.replace("start:", "start:\n" + lifetime, 1)
            self.rejects(mutant, identity, "update_cancel")

    def test_no_fatal_cleanup_exemption_on_normal_entry(self):
        symbol = next(name for name in re.findall(r"@(\w+)\(", self.llvm)
                      if driver.common.panic_cleanup(name))
        for operation in ("cancel", "update_cancel"):
            body = f"start:\n call void @{symbol}()\n unreachable\n"
            self.rejects(body, operation=operation)
        with self.assertRaises(ValueError):
            driver.validate(self.llvm.replace(symbol, symbol + "_fake"))

    def test_shared_arm_switch_facts_do_not_hide_missing_cleanup(self):
        llvm = driver.collect(self.root / "arm", "1.90.0",
                              "aarch64-unknown-linux-gnu", "abort")[1]
        # ARM repeats the update-result comparison after the default switch
        # edge; it must remain constrained by the very same SSA result.
        functions, definitions, aliases = driver.emitted(llvm)
        body = functions["sha224", "update_cancel"]
        comparison = re.search(r"(%[-\w.]+ = icmp eq i8 )(%[-\w.]+)(, 13)", body)
        self.assertIsNotNone(comparison)
        mutated = body.replace(comparison[0], comparison[1] + "%independent" + comparison[3])
        with self.assertRaises(ValueError):
            driver.update.check(mutated, "sha224", definitions, aliases, "1.90.0", "abort")
        changed = body.replace("store i64 3,", "store i64 0,")
        self.assertNotEqual(changed, body)
        with self.assertRaises(ValueError):
            driver.update.check(changed, "sha224", definitions, aliases, "1.90.0", "abort")

    def test_compiled_cancellation_retention_and_caller_leaks(self):
        work = self.root / "compiled"
        leaf = work / "leaf"
        shutil.copytree(driver.ROOT / "crates/brynja-mac-hmac/src", leaf / "src")
        manifest = ('[workspace]\n[package]\nname="brynja-mac-hmac"\nversion="0.1.0"\n'
                    'edition="2024"\n[features]\ndefault=[]\nhardened-execution=[]\n'
                    'runtime-execution=["hardened-execution"]\n[dependencies]\n')
        for name in ("brynja-core", "brynja-crypto-cpu", "brynja-hash-sha2", "brynja-hash-sha3"):
            features = ["runtime-execution", "hardened-execution"] if name != "brynja-core" else []
            if name == "brynja-hash-sha2":
                features.append("general-sha512-t")
            manifest += (f'{name}={{path={json.dumps(str(driver.ROOT / "crates" / name))},'
                         f'default-features=false,features={json.dumps(features)}}}\n')
        (leaf / "Cargo.toml").write_text(manifest)
        fixture = work / "consumer"
        shutil.copytree(driver.FIXTURE.parent / "src", fixture / "src")
        (fixture / "Cargo.toml").write_text(driver.FIXTURE.read_text().replace(
            "../../crates/brynja-mac-hmac", str(leaf)))
        driver.verifier.run(["cargo", "+1.99.1", "generate-lockfile", "--offline",
                             "--manifest-path", str(fixture / "Cargo.toml")],
                            driver.verifier.environment(work))

        def emitted():
            return driver.emit(work, "1.99.1", "x86_64-unknown-linux-gnu", "unwind",
                               fixture / "Cargo.toml")[1]

        driver.validate(emitted())
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
        for role, size in (("pad", 144), ("normalized", 64), ("inner_digest", 64),
                           ("tag", 64), ("difference", 1)):
            anchor = f"let mut {role} = Scratch::<{size}>::new();"
            replacement = (f"let mut {role} = core::mem::ManuallyDrop::new("
                           f"Scratch::<{size}>::new());")
            mutants.append((leaf / "src/engine.rs", anchor, replacement))
        for path, anchor, replacement in mutants:
            original = path.read_text()
            self.assertEqual(original.count(anchor), 1)
            try:
                path.write_text(original.replace(anchor, replacement))
                llvm = emitted()  # Compilation errors never count as rejection.
                with self.subTest(path=path, anchor=anchor), self.assertRaises(ValueError):
                    driver.validate(llvm)
            finally:
                path.write_text(original)
            driver.validate(emitted())
        print("Accelerated HMAC compiler mutants: 9 compiled/rejected; restored baselines PASS",
              flush=True)


if __name__ == "__main__":
    unittest.main()
