#!/usr/bin/env python3
"""Real emitted retained graphs plus compiling downstream rejection mutants."""
import copy
import importlib.util
from pathlib import Path
import re
import shutil
import tomllib
import unittest

spec = importlib.util.spec_from_file_location("legacy_execution_driver", Path(__file__).with_name("check-legacy-hmac-execution-cleanup.py"))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
model = driver.graph.model


class ExecutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = driver.runner.cargo_environment.private_directory(driver.ROOT)
        cls.addClassCleanup(cls.directory.cleanup)
        cls.root = Path(cls.directory.name)
        cls.artifacts = driver.collect(cls.root / "baseline", "1.99.1", "x86_64-unknown-linux-gnu", "unwind")
        cls.graph = driver.graph.Graph(cls.artifacts[0][1], cls.artifacts[1][1], "1.99.1", "unwind")

    def rejects(self, module, before, after):
        self.assertNotEqual(before, after)
        self.assertIn(before, self.artifacts[module][1])
        artifacts = copy.deepcopy(self.artifacts)
        artifacts[module][1] = artifacts[module][1].replace(before, after, 1)
        with self.assertRaises(ValueError):
            driver.validate(artifacts, "1.99.1", "unwind")

    def leaf(self, operation):
        names = [name for name in self.graph.modules[1][0] if model.method(name, operation)]
        self.assertEqual(len(names), 1)
        return self.graph.resolve(names[0], 1)[2]

    def test_population_abi_and_module_boundary(self):
        for operation in ("cancel", "update", "update_cancel", "hmac_ok", "stream_length", "owner_size"):
            symbol = self.graph.consumer(operation)
            self.rejects(0, symbol, symbol + "invented")
        for operation in ("hmac_ok", "hmac_length", "hmac_fatal", "owner_size", "stream_ok", "stream_length"):
            body = self.graph.resolve(self.graph.consumer(operation), 0)[2]
            self.rejects(0, body, body.replace("ret ", "ret i8 17\n; ", 1))
        artifacts = copy.deepcopy(self.artifacts)
        artifacts[0][1] += artifacts[1][1]
        with self.assertRaises(ValueError):
            driver.validate(artifacts, "1.99.1", "unwind")

    def test_cancel_checks_both_owner_pointers_and_identity(self):
        body = self.leaf("cancel")
        for before, after in (("i64 16", "i64 17"), ("i64 464", "i64 463"),
                              ("i64 897", "i64 896"), ("dereferenceable(433)", "dereferenceable(432)"),
                              ("start:", "start:\n  ret void\nunused:")):
            # Include the normal-return occurrence: destructor-panic blocks
            # are outside the separately reviewed non-panicking Drop premise.
            self.rejects(1, body, body.replace(before, after))
        drops = [symbol.strip('"') for symbol in re.findall(r'@("[^"]+"|[-\w.$]+)\(', body)
                 if model.shared.owner_drop(symbol.strip('"'), "sha1")]
        self.assertTrue(drops)
        self.rejects(1, body, body.replace(drops[0], "unknown_destructor"))

    def test_update_copies_and_fatal_slot_transition(self):
        body = self.leaf("update")
        for before, after in (("i64 904, i1 false", "i64 903, i1 false"),
                              ("ptr %self, i64 8", "ptr %self, i64 9"),
                              ("store i8 2,", "store i8 1,"),
                              ("%input.0,", "%self,"), ("%input.1)", "%missing_length)")):
            self.rejects(1, body, body.replace(before, after, 1))
        line = re.search(r"  store i8 2, ptr %[-\w.]+[^\n]*", body)[0]
        self.rejects(1, body, body.replace(line, "", 1))
        # Removing the actual cleanup call is not equivalent to clearing a flag.
        calls = re.findall(r"  (?:tail )?call void @[^\n]*Sha1Owner[^\n]*", body)
        self.assertTrue(calls)
        self.rejects(1, body, body.replace(calls[-1], "", 1))

    def test_preserve_classification_and_result_mapping(self):
        body = self.leaf("update")
        for before, after in (("icmp eq i8 %12, -1", "icmp eq i8 %12, 0"),
                              ("icmp eq i8 %13, 0", "icmp eq i8 %13, 1"),
                              ("i8 0, i8 4", "i8 4, i8 0")):
            self.rejects(1, body, body.replace(before, after, 1))

    def test_actual_unwind_guard_is_inspected(self):
        definitions = self.graph.modules[1][0]
        names = [name for name in definitions if model.helper(name) and "5Guard" in name]
        self.assertEqual(len(names), 1)
        body = definitions[names[0]][1]
        self.rejects(1, body, body.replace("start:", "start:\n  ret void\nunused:", 1))
        caller = self.leaf("update")
        changed = re.sub(r"(to label %[-\w.]+ unwind label )%cleanup\.i\b", r"\1%escape", caller, count=1)
        self.rejects(1, caller, changed + "\nescape:\n  resume { ptr, i32 } zeroinitializer\n")

    def test_caller_observer_unwind_and_owner_lifetime(self):
        body = self.graph.resolve(self.graph.consumer("update_cancel"), 0)[2]
        changed = re.sub(r"(invoke void %observer\(\)\s+to label %[-\w.]+ unwind label )%[-\w.]+",
                         r"\1%escape", body)
        self.rejects(0, body, changed + "\nescape:\n  resume { ptr, i32 } zeroinitializer\n")
        self.rejects(0, body, body.replace("invoke void %observer()", "call void %observer()", 1))
        self.rejects(0, body, body.replace("i64 912, i1 false", "i64 911, i1 false", 1))
        self.rejects(0, body, body.replace("start:", "start:\n  %alias = phi ptr [ %state, %start ]", 1))

    def test_storage_model_rejects_overflow_alias_and_post_drop_copy(self):
        state = model.State(0)
        state.storage["small"] = None
        state.capacity["small"] = model.ENGINE
        with self.assertRaises(ValueError):
            state.transfer(("small", 0), ("state", 0), model.SIZE)
        with self.assertRaises(ValueError):
            state.transfer(("state", 0), ("state", 0), model.ENGINE)
        state.transfer(("small", 0), ("state", 0), model.ENGINE)
        with self.assertRaises(ValueError):
            state.end(("small", 0))
        state.destroy(("small", 16))
        with self.assertRaises(ValueError):
            state.destroy(("state", 16))
        state.storage["new"] = None
        state.capacity["new"] = model.SIZE
        with self.assertRaises(ValueError):
            state.transfer(("new", 0), ("state", 0), model.SIZE)

    def test_compiled_caller_cleanup_regressions(self):
        source = driver.FIXTURE.parent
        original = (source / "src/lib.rs").read_text()
        mutations = (("state.cancel();", "core::mem::forget(state);"),
                     ("state.update(input)?;", "if state.update(input).is_err() { core::mem::forget(state); return Err(Error::MessageTooLong); }"),
                     ("observer();", "let _ = observer;"))
        for number, (before, after) in enumerate(mutations):
            work = self.root / f"mutant-{number}"
            (work / "src").mkdir(parents=True)
            (work / "Cargo.toml").write_text((source / "Cargo.toml").read_text().replace(
                "../../crates/", str(driver.ROOT / "crates") + "/"))
            shutil.copyfile(source / "Cargo.lock", work / "Cargo.lock")
            path = work / "src/lib.rs"
            path.write_text(original)
            baseline = driver.emit(work, "1.99.1", "x86_64-unknown-linux-gnu", "unwind", work / "Cargo.toml")
            driver.validate(baseline, "1.99.1", "unwind")
            self.assertIn(before, original)
            path.write_text(original.replace(before, after, 1))
            artifacts = driver.emit(work, "1.99.1", "x86_64-unknown-linux-gnu", "unwind", work / "Cargo.toml")
            with self.assertRaises(ValueError):
                driver.validate(artifacts, "1.99.1", "unwind")

    def test_compiled_real_retained_guard_regressions(self):
        work = self.root / "leaf-mutants"
        source = driver.ROOT / "crates/brynja-legacy-hmac"
        leaf = self.root / "leaf-mutant-source"
        shutil.copytree(source / "src", leaf / "src")
        shutil.copyfile(source / "README.md", leaf / "README.md")
        manifest = (source / "Cargo.toml").read_text()
        workspace = tomllib.loads((driver.ROOT / "Cargo.toml").read_text())["workspace"]
        for field in ("edition", "rust-version", "license", "repository"):
            manifest = manifest.replace(field + ".workspace = true", field + ' = "' + workspace["package"][field] + '"')
        manifest = manifest.replace("brynja-core.workspace = true", 'brynja-core = { path = "'
                                    + str(driver.ROOT / "crates/brynja-core") + '", default-features = false }')
        manifest = manifest.replace('path = "../', 'path = "' + str(driver.ROOT / "crates") + "/")
        manifest = manifest.replace("[lints]\nworkspace = true", "")
        # Keep the leaf a dependency, not an implicit member of the probe's
        # workspace; otherwise `cargo rustc -p` changes its feature selection.
        (leaf / "Cargo.toml").write_text(manifest + "\n[workspace]\n")
        fixture = driver.FIXTURE.parent
        shutil.copytree(fixture / "src", work / "src")
        manifest = (fixture / "Cargo.toml").read_text().replace("../../crates/brynja-legacy-hmac", str(leaf))
        (work / "Cargo.toml").write_text(manifest.replace("../../crates/", str(driver.ROOT / "crates") + "/"))
        shutil.copyfile(fixture / "Cargo.lock", work / "Cargo.lock")
        path = leaf / "src/execution/retained.rs"
        original = path.read_text()
        baseline = driver.emit(work, "1.99.1", "x86_64-unknown-linux-gnu", "unwind", work / "Cargo.toml")
        driver.validate(baseline, "1.99.1", "unwind")
        for before, after in (
                ("matches!(result, Ok(()) | Err(Error::MessageTooLong))", "true"),
                ("matches!(result, Ok(()) | Err(Error::MessageTooLong))", "matches!(result, Ok(()))"),
                ("let _ = self.slot.take();", "core::mem::forget(self.slot.take());")):
            self.assertIn(before, original)
            path.write_text(original.replace(before, after, 1))
            artifacts = driver.emit(work, "1.99.1", "x86_64-unknown-linux-gnu", "unwind", work / "Cargo.toml")
            with self.assertRaises(ValueError):
                driver.validate(artifacts, "1.99.1", "unwind")
        path.write_text(original)


if __name__ == "__main__":
    unittest.main()
