#!/usr/bin/env python3
"""Real artifact mutations, source mutants and pointer-root regressions."""
import importlib.util
from pathlib import Path
import re
import shutil
import tomllib
import unittest

spec = importlib.util.spec_from_file_location("md5_driver", Path(__file__).with_name("check-legacy-hmac-md5-cleanup.py"))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
rows = driver.rows


class Md5CleanupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = driver.runner.cargo_environment.private_directory(driver.ROOT)
        cls.addClassCleanup(cls.directory.cleanup)
        cls.root = Path(cls.directory.name)
        cls.artifacts = driver.emit(cls.root / "baseline", "1.99.1", "x86_64-unknown-linux-gnu", "unwind", True)
        cls.fixture, cls.llvm = cls.artifacts[0][1], cls.artifacts[1][1]
        cls.definitions, cls.aliases = rows.flow.definitions_and_aliases(cls.llvm)
        driver.validate(cls.artifacts, "unwind")

    def rejects(self, body, before, after):
        self.assertIn(before, body)
        self.assertNotEqual(before, after)
        with self.subTest(before=before, after=after), self.assertRaises(ValueError):
            rows.validate(self.llvm.replace(body, body.replace(before, after, 1), 1), "unwind")

    def selected(self):
        for method in ("authenticate", "authenticate_secret", "verify"):
            _, (signature, body) = rows.method(self.definitions, self.aliases, method)
            yield signature, body, "rows"
        for name, (signature, body) in self.definitions.items():
            if name.endswith("4pads"):
                yield signature, body, "normalization"
            elif name.startswith("_RNCNv") and "Md5Batch6verify" in name:
                yield signature, body, "comparison"

    def test_each_actual_clear_is_required_and_full_width(self):
        count = 0
        for _, body, operation in self.selected():
            owners = rows.scratch.allocations(body, operation)
            lines = [line for line in body.splitlines() if "18clear_owned_region" in line]
            for owner, width in owners.items():
                clears = [line for line in lines if re.search(re.escape(owner) + r",", line)]
                self.assertTrue(clears)
                for line in clears:
                    self.rejects(body, line, line.replace("i64 noundef " + str(width) + ")",
                                                         "i64 noundef " + str(width - 1) + ")"))
                    # Removing an invoke requires preserving its normal edge;
                    # this tests absent clearing, not malformed control flow.
                    if "invoke " in line:
                        following = body[body.index(line) + len(line):].splitlines()[1]
                        normal = re.search(r"to label (%[-\w.]+)", following)[1]
                        self.rejects(body, line + "\n" + following, "  br label " + normal)
                    else:
                        self.rejects(body, line, "")
                    count += 1
        self.assertGreaterEqual(count, 30)

    def test_clear_pointer_identity_and_allocation_extent(self):
        _, body = rows.method(self.definitions, self.aliases, "authenticate")[1]
        for name, width in rows.scratch.allocations(body, "rows").items():
            clear = next(line for line in body.splitlines() if "18clear_owned_region" in line
                         and re.search(re.escape(name) + r",", line))
            self.rejects(body, clear, clear.replace(name, "%different_buffer"))
            call = rows.syntax.call(clear)
            self.rejects(body, clear, clear.replace(call[0], call[0] + "_fake"))
            self.rejects(body, name + f" = alloca [{width} x i8]", name + f" = alloca [{width + 1} x i8]")

    def test_writes_after_clear_through_derived_pointer_are_rejected(self):
        _, body = rows.method(self.definitions, self.aliases, "authenticate")[1]
        graph = rows.flow.blocks(body)
        owner = next(name for name in rows.scratch.allocations(body, "rows") if name.startswith("%pad."))
        line = next(line for line in body.splitlines() if "18clear_owned_region" in line and owner + "," in line)
        edge = body[body.index(line) + len(line):].splitlines()[1]
        normal = re.search(r"to label %([-\w.]+)", edge)[1]
        self.assertIn(normal, graph)
        anchor = normal + ":"
        for write in (f"  store i8 91, ptr {owner}, align 1",
                      f"  %late_row = getelementptr inbounds i8, ptr {owner}, i64 1\n  store i8 91, ptr %late_row, align 1",
                      "  call void %unexpected_callback()"):
            self.rejects(body, anchor, anchor + "\n" + write)

    def test_workspace_all_eight_lanes_and_helper_binding(self):
        helpers = [(name, body) for name, (_, body) in self.definitions.items()
                   if rows.contracts.workspace_drop(name)]
        self.assertEqual(len(helpers), 1)
        name, body = helpers[0]
        for before, after in (("i64 799", "i64 798"), ("i64 121", "i64 122"),
                              ("start:", "start:\n  ret void\nunused:")):
            self.rejects(body, before, after)
        _, caller = rows.method(self.definitions, self.aliases, "authenticate")[1]
        call = next(line for line in caller.splitlines() if name in line and "invoke " in line)
        self.rejects(caller, call, call.replace("%workspace.i.i", "%pad.i.i"))
        self.rejects(caller, call, call.replace(name, "unreviewed_workspace_drop"))

    def test_non_refilling_source_premises_are_load_bearing(self):
        root = self.root / "pinned"
        for name in rows.contracts.PINS:
            destination = root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(driver.ROOT / name, destination)
        rows.contracts.validate(root)
        for name in rows.contracts.PINS:
            path = root / name
            original = path.read_bytes()
            path.write_bytes(original + b"\n// source drift\n")
            with self.assertRaises(ValueError):
                rows.contracts.validate(root)
            path.write_bytes(original)

    def test_pointer_captures_and_unknown_loads_remain_conservative(self):
        signature = "ptr %external"
        prefix = "start:\n  %row = alloca [128 x i8], align 1\n  %capture = alloca [8 x i8], align 8\n"
        cases = (
            ("  %p = getelementptr i8, ptr %row, i64 1", "%p", False),
            ("  store ptr %row, ptr %capture, align 8\n  %p = load ptr, ptr %capture, align 8", "%p", False),
            ("  %p = load ptr, ptr %capture, align 8", "%p", False),
            ("  %p = load ptr, ptr %external, align 8", "%p", True),
            ("  store ptr %row, ptr %external, align 8\n  %p = load ptr, ptr %external, align 8", "%p", False),
            ("  %p = inttoptr i64 17 to ptr", "%p", False),
            ("  %p = select i1 %condition, ptr %row, ptr %external", "%p", False),
        )
        for text, pointer, disjoint in cases:
            with self.subTest(text=text):
                origins = rows.Origins(signature, prefix + text, {"%row": 128})
                self.assertEqual(origins.disjoint_store(f"store i8 0, ptr {pointer}, align 1"), disjoint)
        body = prefix + "  %copy = alloca [8 x i8], align 8\n  store ptr %row, ptr %capture, align 8\n" + \
            "  call void @llvm.memcpy.p0.p0.i64(ptr %copy, ptr %capture, i64 8, i1 false)\n" + \
            "  %p = load ptr, ptr %copy, align 8"
        self.assertFalse(rows.Origins(signature, body, {"%row": 128}).disjoint_store("store i8 0, ptr %p, align 1"))

    def test_downstream_consumer_binding(self):
        definitions, aliases = rows.flow.definitions_and_aliases(self.fixture)
        for name, (_, body) in definitions.items():
            if "30brynja_legacy_hmac_md5_cleanup" not in name or not name.endswith(("6public", "6secret", "6verify")):
                continue
            calls = [line for line in body.splitlines() if "8Md5Batch" in line and re.search(r"\bcall\b", line)]
            self.assertEqual(len(calls), 1)
            line = calls[0]
            for argument in ("%selection", "%inputs", "%control"):
                mutated = self.fixture.replace(body, body.replace(line, line.replace(argument, "%wrong"), 1), 1)
                with self.assertRaises(ValueError):
                    driver.consumers(mutated, self.llvm)

    def test_constructor_admission_predicates_and_effects(self):
        signature, body = rows.method(self.definitions, self.aliases, "with_tag_length")[1]
        tag = rows.syntax.parameters(signature)[2].split()[-1]
        mutations = ((f"add i64 {tag}, -10", f"add i64 {tag}, -9"),
                     (", 7\n", ", 8\n"), ("icmp ult i64", "icmp ugt i64"),
                     ("icmp eq i8", "icmp ne i8"),
                     ("ptr %executor, i64 9", "ptr %executor, i64 8"),
                     ("store i8 1, ptr %_0", "store i8 3, ptr %_0"),
                     ("store i8 3, ptr %_0", "store i8 1, ptr %_0"),
                     ("start:", "start:\n  call void @unreviewed_callback()"),
                     ("start:", "start:\n  store i8 1, ptr %executor, align 1"))
        for before, after in mutations:
            self.assertIn(before, body)
            with self.subTest(before=before), self.assertRaises(ValueError):
                driver.admission.validate(self.fixture, self.llvm.replace(body, body.replace(before, after, 1), 1))
        call = next(line for line in body.splitlines() if "9Workspace3new(" in line)
        for changed in (call.replace("%executor", "%_0"), call.replace("9Workspace3new", "9Workspace7fake_new")):
            with self.assertRaises(ValueError):
                driver.admission.validate(self.fixture, self.llvm.replace(body, body.replace(call, changed, 1), 1))

    def test_admission_probes_are_not_assumed(self):
        definitions, aliases = rows.flow.definitions_and_aliases(self.fixture)
        for name, before, after in (("tag_rejection", "store i8 1", "store i8 3"),
                                    ("authority_rejection", "store i8 3", "store i8 1"),
                                    ("portable_backend", "ret i8 2", "ret i8 1"),
                                    ("backend", "i64 9", "i64 8"),
                                    ("select", "%bytes)", "%wrong)")):
            body = driver.admission.probe(definitions, aliases, name)
            self.assertIn(before, body)
            with self.subTest(name=name), self.assertRaises(ValueError):
                driver.admission.validate(self.fixture.replace(body, body.replace(before, after, 1), 1), self.llvm)

    def test_compiled_rows_drop_mutants(self):
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
        manifest = manifest.replace("../../crates/brynja-legacy-md5", str(driver.ROOT / "crates/brynja-legacy-md5"))
        manifest = manifest.replace("../../crates/brynja-core", str(driver.ROOT / "crates/brynja-core"))
        (work / "Cargo.toml").write_text(manifest)
        shutil.copyfile(fixture / "Cargo.lock", work / "Cargo.lock")
        path = leaf / "src/md5_batch/engine.rs"
        original = path.read_text()
        baseline = driver.emit(work, "1.99.1", "x86_64-unknown-linux-gnu", "unwind", True, work / "Cargo.toml")
        driver.validate(baseline, "unwind")
        for before, after in (("clear_owned_region(self.0.as_flattened_mut())", "clear_owned_region(&mut self.0[0])"),
                              ("let _ = brynja_core::clear_owned_region(self.0.as_flattened_mut());", "core::hint::black_box(&mut self.0);"),
                              ("let result = consume(truncated.0.as_flattened())?;", "let result = consume(truncated.0.as_flattened())?; core::mem::forget(truncated);")):
            self.assertIn(before, original)
            path.write_text(original.replace(before, after, 1))
            artifacts = driver.emit(work, "1.99.1", "x86_64-unknown-linux-gnu", "unwind", True, work / "Cargo.toml")
            with self.assertRaises(ValueError):
                driver.validate(artifacts, "unwind")
        path.write_text(original)
        for replacements in (
                (("&outer_inputs, &mut final_tags.0", "&messages, &mut final_tags.0"),),
                (("let mut inner = Rows::<16>::new();", "let mut inner = Rows::<16>::new();\n    let mut wrong_inner = Rows::<16>::new();"),
                 ("&messages, &mut inner.0", "&messages, &mut wrong_inner.0"))):
            mutated = original
            for before, after in replacements:
                self.assertIn(before, mutated)
                mutated = mutated.replace(before, after, 1)
            path.write_text(mutated)
            artifacts = driver.emit(work, "1.99.1", "x86_64-unknown-linux-gnu", "unwind", True, work / "Cargo.toml")
            with self.assertRaises(ValueError):
                driver.phases.validate(artifacts[1][1])
        path.write_text(original)
        descriptor = "let messages = inputs.each_ref().map(|i| i.as_ref().map(|i| i.message));"
        self.assertIn(descriptor, original)
        for mutation in ("messages.swap(0, 7);", "messages.rotate_left(1);"):
            replacement = descriptor.replace("let messages", "let mut messages") + "\n    " + mutation
            path.write_text(original.replace(descriptor, replacement, 1))
            artifacts = driver.emit(work, "1.99.1", "x86_64-unknown-linux-gnu", "unwind", True, work / "Cargo.toml")
            with self.assertRaises(ValueError):
                driver.descriptors.validate(artifacts[0][1], artifacts[1][1])
        path.write_text(original)
        for before, after in (("mask(pad, 0x36)?;", "mask(pad, 0x35)?;"),
                              (".get(lane)", ".get((lane + 1) % 8)")):
            self.assertIn(before, original)
            path.write_text(original.replace(before, after, 1))
            artifacts = driver.emit(work, "1.99.1", "x86_64-unknown-linux-gnu", "unwind", True, work / "Cargo.toml")
            with self.assertRaises(ValueError):
                driver.pads.validate(artifacts[0][1], artifacts[1][1])
        path.write_text(original)
        for before, after in (("let mut normalized = Rows::<16>::new();",
                               "let mut normalized = Rows::<16>::new();\n    let mut wrong_normalized = Rows::<16>::new();"),
                              ("Some(secret)", "{ core::mem::forget(secret); None }")):
            self.assertIn(before, original)
            mutant = original.replace(before, after, 1)
            if "wrong_normalized" in after:
                mutant = mutant.replace("digest_secret(&keys, &mut normalized.0, control)",
                                        "digest_secret(&keys, &mut wrong_normalized.0, control)", 1)
            path.write_text(mutant)
            artifacts = driver.emit(work, "1.99.1", "x86_64-unknown-linux-gnu", "unwind", True, work / "Cargo.toml")
            with self.assertRaises(ValueError):
                driver.normalization.validate(artifacts[0][1], artifacts[1][1])
        path.write_text(original)
        for before, after in (("input.key.len() > 64", "input.key.len() >= 64"),
                              ("eligible(&keys, selection.backend.lane_width())", "eligible(inputs, selection.backend.lane_width())"),
                              ("if active == 0 {", "if active <= 1 {")):
            self.assertIn(before, original)
            path.write_text(original.replace(before, after, 1))
            artifacts = driver.emit(work, "1.99.1", "x86_64-unknown-linux-gnu", "unwind", True, work / "Cargo.toml")
            with self.assertRaises(ValueError):
                driver.keys.validate(artifacts[0][1], artifacts[1][1])
        path.write_text(original)
        for before, after in (("report = checked_report(selection, actual, active)?;", "report = actual.work;"),
                              ("report = actual;", "report = Md5BatchReport::default();")):
            self.assertIn(before, original)
            path.write_text(original.replace(before, after, 1))
            artifacts = driver.emit(work, "1.99.1", "x86_64-unknown-linux-gnu", "unwind", True, work / "Cargo.toml")
            with self.assertRaises(ValueError):
                driver.reports.validate(artifacts[0][1], artifacts[1][1])
        path.write_text(original)
        for before, after in (("mask(pad, 0x36 ^ 0x5c)?;", "mask(pad, 0x5c)?;"),
                              ("BitString::new(digest, 8)", "BitString::new(&digest[..15], 8)"),
                              ("if input.is_some() {\n            mask", "if input.is_none() {\n            mask")):
            self.assertIn(before, original)
            path.write_text(original.replace(before, after, 1))
            artifacts = driver.emit(work, "1.99.1", "x86_64-unknown-linux-gnu", "unwind", True, work / "Cargo.toml")
            with self.assertRaises(ValueError):
                driver.outer.validate(artifacts[0][1], artifacts[1][1])
        path.write_text(original)
        selection = leaf / "src/md5_batch/mod.rs"
        original_selection = selection.read_text()
        for before, after in (("10..=16", "9..=16"), ("10..=16", "10..=17")):
            self.assertIn(before, original_selection)
            selection.write_text(original_selection.replace(before, after))
            artifacts = driver.emit(work, "1.99.1", "x86_64-unknown-linux-gnu", "unwind", True, work / "Cargo.toml")
            with self.assertRaises(ValueError):
                driver.validate(artifacts, "unwind")
        selection.write_text(original_selection)
        for predicate in ("report.backend != Some(selection.backend)",
                          "report.vector_width != selection.backend.lane_width()",
                          "report.work.vector_blocks < selection.backend.lane_width()",
                          "report.work.active_lanes != active"):
            self.assertIn(predicate, original)
            path.write_text(original.replace(predicate, "false", 1))
            artifacts = driver.emit(work, "1.99.1", "x86_64-unknown-linux-gnu", "unwind", True, work / "Cargo.toml")
            with self.assertRaises(ValueError):
                driver.inner_report.validate(artifacts[0][1], artifacts[1][1])
        path.write_text(original)
        for before, after, validator in (
                ("            normalization,", "            normalization: inner,", driver.normalization_return.validate),
                ("            normalization,", "            normalization: Md5BatchReport { scalar_blocks: 0, ..normalization },", driver.normalization_return.validate),
                ("vector_width: selection.backend.lane_width(),", "vector_width: selection.backend.lane_width() + 1,", driver.return_header.validate),
                ("backend: selection.backend,", "backend: brynja_legacy_md5::Md5Backend::Aarch64Neon,", driver.return_header.validate),
                ("            inner,\n            outer,", "            inner: outer,\n            outer: inner,", driver.report_return.validate),
                ("            outer,", "            outer: Md5BatchReport { scalar_blocks: inner.scalar_blocks, ..outer },", driver.report_return.validate),
                ("tag.get(..selection.tag_bytes)", "tag.get(1..selection.tag_bytes)", driver.truncation.validate),
                ("        if input.is_some() {\n            copy_secret_region(",
                 "        if input.is_none() {\n            copy_secret_region(", driver.truncation.validate),
                ("let mut truncated = Rows::<16>::new();",
                 "let mut truncated = Rows::<16>::new(); truncated.0[0][15] = 1;", driver.truncation.validate)):
            self.assertIn(before, original)
            path.write_text(original.replace(before, after, 1))
            artifacts = driver.emit(work, "1.99.1", "x86_64-unknown-linux-gnu", "unwind", True, work / "Cargo.toml")
            with self.assertRaises(ValueError):
                validator(artifacts[0][1], artifacts[1][1])
        path.write_text(original)
        frontier = '''    // No cancellation callback or secret computation follows this final check.
    workspace
        .with(|batch| batch.cancel())
        .map_err(execution_error)?;
    let result = consume(truncated.0.as_flattened())?;'''
        self.assertIn(frontier, original)
        for changed in ("    let result = consume(truncated.0.as_flattened())?;",
                        '''    let result = consume(truncated.0.as_flattened())?;
    workspace.with(|batch| batch.cancel()).map_err(execution_error)?;'''):
            path.write_text(original.replace(frontier, changed, 1))
            artifacts = driver.emit(work, "1.99.1", "x86_64-unknown-linux-gnu", "unwind", True, work / "Cargo.toml")
            with self.assertRaises(ValueError):
                driver.validate(artifacts, "unwind")
        path.write_text(original)
        for before, after in (
                ("inputs.each_ref().map(Option::is_some)", "inputs.each_ref().map(Option::is_none)"),
                ("let tag_bytes = self.tag_bytes;", "let tag_bytes = 10;"),
                ("copy_secret_region(output.as_flattened_mut(), bytes)?;", "let _ = copy_secret_region(output.as_flattened_mut(), bytes);"),
                ("        })\n    }\n\n    fn run<R>", "        }).map(|(_, report)| (Verification::new(brynja_core::Choice::FALSE), report))\n    }\n\n    fn run<R>")):
            self.assertIn(before, original_selection)
            selection.write_text(original_selection.replace(before, after, 1))
            artifacts = driver.emit(work, "1.99.1", "x86_64-unknown-linux-gnu", "unwind", True, work / "Cargo.toml")
            with self.assertRaises(ValueError):
                driver.consumer_return.validate(artifacts[0][1], artifacts[1][1])
        selection.write_text(original_selection)

        # Caller-side defects must compile; rejection is by emitted ownership or
        # admission semantics, not by a broken Rust mutation.
        begin = "let mut initialization = SecretRegionInitialization::begin(output.as_flattened_mut())?;"
        moved = original_selection.replace(begin, "", 1).replace(
            "initialization.write(bytes)?;", begin + "\n            initialization.write(bytes)?;", 1)
        self.assertIn(begin, original_selection)
        selection.write_text(moved)
        artifacts = driver.emit(work, "1.99.1", "x86_64-unknown-linux-gnu", "unwind", True, work / "Cargo.toml")
        with self.assertRaises(ValueError):
            driver.initialization.validate(artifacts[0][1], artifacts[1][1])
        selection.write_text(original_selection)
        before = "return Err(Error::IneligibleWorkload);"
        self.assertIn(before, original)
        path.write_text(original.replace(before, "core::mem::forget(consume); " + before, 1))
        artifacts = driver.emit(work, "1.99.1", "x86_64-unknown-linux-gnu", "unwind", True, work / "Cargo.toml")
        with self.assertRaises(ValueError):
            driver.initialization.validate(artifacts[0][1], artifacts[1][1])
        path.write_text(original)
        for before, after in (
                ("bytes.len() == self.tag_bytes", "bytes.len() >= self.tag_bytes"),
                ("(None, None) => ()", "(None, _) => ()"),
                ("inputs.iter().zip(candidates)", "inputs.iter().zip(candidates).take(7)"),
                ("inputs.iter().zip(candidates)", "inputs.iter().zip(candidates.iter().rev())")):
            self.assertIn(before, original_selection)
            selection.write_text(original_selection.replace(before, after, 1))
            artifacts = driver.emit(work, "1.99.1", "x86_64-unknown-linux-gnu", "unwind", True, work / "Cargo.toml")
            with self.subTest(before=before, after=after), self.assertRaises(ValueError):
                driver.candidates.validate(artifacts[0][1], artifacts[1][1])
        selection.write_text(original_selection)
        output_path = leaf / "src/md5_batch/output.rs"
        output_original = output_path.read_text()
        for before, after in (("self.bytes.get(lane)?", "self.bytes.get(0)?"),
                              ("if !self.active.get(lane)", "if self.active.get(lane)")):
            self.assertIn(before, output_original)
            output_path.write_text(output_original.replace(before, after, 1))
            artifacts = driver.emit(work, "1.99.1", "x86_64-unknown-linux-gnu", "unwind", True, work / "Cargo.toml")
            with self.assertRaises(ValueError):
                driver.output_views.validate(artifacts[0][1], artifacts[1][1])
        output_path.write_text(output_original)
        for before, after, kind in (
                ("initialization.write(bytes)?;", "let _ = initialization.write(bytes);", "secret"),
                ("initialization.write(bytes)?;", "initialization.write(&bytes[..127])?;", "secret"),
                ("initialization.write(bytes)?;",
                 "if let Err(error) = initialization.write(bytes) { core::mem::forget(initialization); return Err(error.into()); }", "secret"),
                ("row.iter().take(tag_bytes)", "row.iter().take(tag_bytes.saturating_sub(1))", "comparison"),
                (".zip(*candidate)", ".zip(candidate.iter().rev())", "comparison"),
                ("let mut difference = crate::scratch::Scratch::<1>::new();",
                 "let mut difference = crate::scratch::Scratch::<1>::new(); difference.0[0] = 1;", "comparison")):
            self.assertIn(before, original_selection)
            selection.write_text(original_selection.replace(before, after, 1))
            artifacts = driver.emit(work, "1.99.1", "x86_64-unknown-linux-gnu", "unwind", True, work / "Cargo.toml")
            with self.subTest(kind=kind, before=before), self.assertRaises(ValueError):
                if kind == "secret":
                    driver.secret_consumer.validate(artifacts[0][1], artifacts[1][1], "unwind")
                else:
                    driver.comparison.validate(artifacts[1][1], "unwind")
        selection.write_text(original_selection)


if __name__ == "__main__":
    unittest.main()
