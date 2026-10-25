#!/usr/bin/env python3
"""Mutate real emitted finalizers and compile downstream handoff regressions."""
import importlib.util
from pathlib import Path
import re
import shutil
import unittest

spec = importlib.util.spec_from_file_location("handoff_driver", Path(__file__).with_name(
    "check-legacy-hmac-execution-cleanup.py"))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
handoff = driver.handoff


class HandoffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = driver.runner.cargo_environment.private_directory(driver.ROOT)
        cls.addClassCleanup(cls.directory.cleanup)
        cls.root = Path(cls.directory.name)
        cls.artifacts = driver.collect(cls.root / "baseline", "1.99.1", "x86_64-unknown-linux-gnu", "unwind")
        _, cls.definitions, cls.aliases = driver.final.bodies(cls.artifacts[1][1])
        cls.graph = driver.graph.Graph(cls.artifacts[0][1], cls.artifacts[1][1], "1.99.1", "unwind")

    def leaf(self, operation):
        method = {"public": "finalize_tag", "public_bits": "finalize_bits_tag",
                  "verify": "verify", "verify_bits": "verify_bits", "secret": "secret"}[operation]
        return driver.final.method(self.definitions, self.aliases, method)[1][1]

    def check(self, operation, body):
        calls = [item[0] for line in self.leaf(operation).splitlines()
                 if (item := handoff.syntax.call(line)) and "6engine" in item[0]
                 and not handoff.model.helper(item[0])]
        handoff.check(body, operation, self.definitions, self.aliases, "unwind", calls[0] if calls else None)

    def reject(self, operation, before, after):
        body = self.leaf(operation)
        self.assertIn(before, body)
        self.assertNotEqual(before, after)
        with self.subTest(operation=operation, before=before, after=after):
            with self.assertRaises(ValueError):
                self.check(operation, body.replace(before, after, 1))

    def test_complete_moves_niche_and_early_return(self):
        for operation in ("public", "public_bits", "verify", "verify_bits", "secret"):
            for before, after in (("i64 896, i1 false", "i64 895, i1 false"),
                                  ("i64 6, i1 false", "i64 5, i1 false"),
                                  ("ptr %self, i64 897", "ptr %self, i64 896"),
                                  ("start:", "start:\n  ret void\nunused:")):
                self.reject(operation, before, after)
            # The scalar niche byte is a necessary part of the split move.
            stores = [line for line in self.leaf(operation).splitlines()
                      if line.strip().startswith("store i8") and ".copyload," in line]
            self.assertEqual(len(stores), 2)
            self.reject(operation, stores[1], "")

    def test_core_arguments_and_none_tail(self):
        for operation in ("public", "public_bits", "verify", "verify_bits"):
            body = self.leaf(operation)
            line = next(line for line in body.splitlines() if (item := handoff.syntax.call(line))
                        and "6engine" in item[0])
            _, args = handoff.syntax.call(line)
            position = 0 if operation.startswith("verify") else 1
            owner = handoff.syntax.operand(args[position])
            output = "%candidate.0" if operation.startswith("verify") else "%output.0"
            length = "%candidate.1" if operation.startswith("verify") else "%output.1"
            for before, after in ((owner + ",", "%wrong_owner,"), (output, "%wrong_output"),
                                  (length, "%wrong_length")):
                self.reject(operation, line, line.replace(before, after, 1))
            if operation.endswith("_bits"):
                self.reject(operation, line, line.replace("%tail,", "%wrong_tail,", 1))
            else:
                self.reject(operation, "store ptr null,", "store ptr %tail,")
                store = next(line for line in body.splitlines() if "store ptr null," in line)
                pointer = re.search(r"ptr (%[-\w.]+),", store)[1]
                for instruction in (f"call void @llvm.memset.p0.i64(ptr {pointer}, i8 1, i64 8, i1 false)",
                                    f"call void @llvm.memcpy.p0.p0.i64(ptr {pointer}, ptr %tail, i64 8, i1 false)"):
                    self.reject(operation, store, store + "\n  " + instruction)

    def test_verification_range_assumption_is_not_authentication(self):
        for operation in ("verify", "verify_bits"):
            body = self.leaf(operation)
            assumptions = [line for line in body.splitlines()
                           if (call := handoff.syntax.call(line)) and call[0] == 'llvm.assume']
            self.assertEqual(len(assumptions), 1)
            assume = assumptions[0]
            _, args = handoff.syntax.call(assume)
            predicate = args[0].split()[-1]
            compare = next(line for line in body.splitlines()
                           if line.strip().startswith(predicate + ' = icmp ult i8 '))
            for edit in (compare.replace(', 8', ', 9'),
                         compare.replace('icmp ult', 'icmp eq'),
                         re.sub(r'icmp ult i8 %[-\w.]+', 'icmp ult i8 %unbound', compare)):
                self.reject(operation, compare, edit)
            for value in ('true', 'false', '%unbound'):
                self.reject(operation, assume, assume.replace(predicate, value))
            self.reject(operation, assume, assume + '\n' + assume)
            self.reject(operation, 'start:', 'start:\n  call void @llvm.assume(i1 true)')

    def test_secret_consumption_and_unwind(self):
        body = self.leaf("secret")
        calls = [line for line in body.splitlines() if (item := handoff.syntax.call(line))
                 and (driver.final.stream_finalizer(item[0], "sha1") or handoff.shared.owner_drop(item[0], "sha1"))]
        self.assertGreater(len(calls), 4)
        for line in calls:
            symbol, args = handoff.syntax.call(line)
            dropping = handoff.shared.owner_drop(symbol, "sha1")
            owner = handoff.syntax.operand(args[0 if dropping else 1])
            self.reject("secret", line, line.replace(owner, "%wrong_stream", 1))
            if not dropping:
                output = handoff.syntax.operand(args[-2])
                self.reject("secret", line, line.replace(output + ",", owner + ",", 1))
        line = next(line for line in body.splitlines() if (item := handoff.syntax.call(line))
                    and handoff.model.stream_update(item[0]))
        _, args = handoff.syntax.call(line)
        self.reject("secret", line, line.replace(handoff.syntax.operand(args[0]), "%wrong_outer", 1))
        edge = next(line for line in body.splitlines() if "to label %bb1.i.i.i.i unwind" in line)
        changed = body.replace(edge, re.sub(r"unwind label %[-\w.]+", "unwind label %escape", edge), 1)
        with self.assertRaises(ValueError):
            self.check("secret", changed + "\nescape:\n  resume { ptr, i32 } zeroinitializer\n")

    def test_captured_prefix_pointer_and_copies(self):
        body = self.leaf("secret")
        capture = next(line for line in body.splitlines() if "store ptr %_14.i," in line)
        # A stream pointer cannot replace the public-prefix-only capture.
        self.reject("secret", capture, capture.replace("%_14.i,", "%11,", 1))
        self.reject("secret", capture, capture + "\n  store ptr null, ptr %13, align 8")
        self.reject("secret", capture, capture +
                    "\n  call void @llvm.memset.p0.i64(ptr %13, i8 0, i64 8, i1 false)")
        for offset, width in ((15, 8), (17, 7)):
            self.reject("secret", capture, capture + f"\n  %partial_ref = getelementptr inbounds i8, ptr %_12.i.i, i64 {offset}\n"
                        + f"  call void @llvm.memcpy.p0.p0.i64(ptr %_13.i.i.i, ptr %partial_ref, i64 {width}, i1 false)")
        for before, after in (("i64 472, i1 false", "i64 471, i1 false"),
                              ("i64 472, i1 false", "i64 473, i1 false"),
                              ("%_13.i.i.i = alloca [472", "%_13.i.i.i = alloca [471"),
                              ("%_15.val.i.i.i.i = load i64", "%_15.val.i.i.i.i = load i32")):
            self.reject("secret", before, after)
        load = next(line for line in body.splitlines() if "%_15.val.i.i.i.i = load" in line)
        self.reject("secret", load, "  call void @llvm.lifetime.end.p0(ptr %_14.i)\n" + load)
        self.reject("secret", load, "  %bad_prefix = getelementptr inbounds i8, ptr %_15.i.i.i.i, i64 8\n"
                    + load.replace("ptr %_15.i.i.i.i,", "ptr %bad_prefix,"))

    def test_empty_secret_clears_exact_destination(self):
        line = next(line for line in self.leaf("secret").splitlines()
                    if "18clear_owned_region" in line and "%output.0," in line)
        for replacement in ("", line.replace("%output.0", "%wrong_output"),
                            line.replace("%output.1", "%wrong_length")):
            self.reject("secret", line, replacement)

    def test_six_real_consumer_forwarding_edges(self):
        for operation in ("public", "public_bits", "secret", "secret_bits", "verify", "verify_bits"):
            body = self.graph.resolve(self.graph.consumer(operation), 0)[2]
            call = next(line for line in body.splitlines() if (item := handoff.syntax.call(line))
                        and "8Sha1Hmac" in item[0])
            target, _ = handoff.syntax.call(call)
            handoff.forwarding(body, operation, target)
            output = "%candidate.0" if operation.startswith("verify") else "%output.0"
            mutations = [body.replace("%state", "%wrong_owner"),
                         body.replace(output, "%wrong_output"), body.replace(call, ""),
                         body.replace(call, call + "\n" + call),
                         body.replace("start:", "start:\n  call void @escape(ptr %state)"),
                         body.replace("start:", "start:\n  ret i8 0\nunused:")]
            if operation.endswith("_bits"):
                mutations.append(body.replace("%input", "%wrong_tail"))
            if not operation.startswith("verify"):
                _, args = handoff.syntax.call(call)
                result = handoff.syntax.operand(args[0])
                mutations.append(body.replace(call, call.replace(result + ",", "%state,", 1)))
            for changed in mutations:
                with self.subTest(operation=operation), self.assertRaises(ValueError):
                    handoff.forwarding(changed, operation, target)

    def test_secret_none_fact_requires_live_dominating_store(self):
        _, (_, body) = driver.final.method(self.definitions, self.aliases, "finalize_secret")
        target, _ = driver.final.method(self.definitions, self.aliases, "secret")
        store = next(line for line in body.splitlines() if "store ptr null," in line)
        pointer = re.search(r"ptr (%[-\w.]+),", store)[1]
        handoff.forwarding(body, "secret", target, leaf=True)
        mutations = [body.replace(store, ""), body.replace(store, store.replace("null", "%tail")),
                     body.replace(store, store + f"\n  store ptr %tail, ptr {pointer}, align 8"),
                     body.replace(store, store + f"\n  call void @llvm.lifetime.end.p0(ptr {pointer})"),
                     body.replace(store, "") + "\nunused:\n" + store + "\n  ret void\n",
                     body.replace(store, "  br i1 %unknown, label %set, label %dispatch\nset:\n"
                                  + store + "\n  br label %dispatch\ndispatch:")]
        for changed in mutations:
            with self.assertRaises(ValueError):
                handoff.forwarding(changed, "secret", target, leaf=True)

    def test_compiled_downstream_handoff_mutants(self):
        fixture = driver.FIXTURE.parent
        work = self.root / "compiled-mutants"
        shutil.copytree(fixture / "src", work / "src")
        (work / "Cargo.toml").write_text((fixture / "Cargo.toml").read_text().replace(
            "../../crates/", str(driver.ROOT / "crates") + "/"))
        shutil.copyfile(fixture / "Cargo.lock", work / "Cargo.lock")
        path = work / "src/lib.rs"
        original = path.read_text()
        baseline = driver.emit(work, "1.99.1", "x86_64-unknown-linux-gnu", "unwind", work / "Cargo.toml")
        handoff.validate(baseline[1][1], "unwind", baseline[0][1])
        for before, after in (("core::hint::black_box(state.finalize_tag(output)?.as_bytes());", "core::mem::forget(state);"),
                              ("state.finalize_bits_tag(input, output)?", "state.finalize_tag(output)?"),
                              ("state.verify(candidate)", "state.verify(&candidate[..0])")):
            self.assertIn(before, original)
            path.write_text(original.replace(before, after, 1))
            emitted = driver.emit(work, "1.99.1", "x86_64-unknown-linux-gnu", "unwind", work / "Cargo.toml")
            with self.assertRaises(ValueError):
                handoff.validate(emitted[1][1], "unwind", emitted[0][1])


if __name__ == "__main__":
    unittest.main()
