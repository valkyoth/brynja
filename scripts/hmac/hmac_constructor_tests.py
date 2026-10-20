"""Mutation controls mixed into the real emitted HMAC engine test suite."""
import json
import re
import shutil

import hmac_engine_construct as construct
import hmac_engine_final as final
from hmac_constructor_state import State


class ConstructorTests:
    def test_constructor_partial_moves_and_allocations(self):
        for identity in self.identities:
            body = self.functions[identity, "construct"]
            width = final.geometry(identity)[0]
            copies = [line for line in body.splitlines() if "@llvm.memcpy." in line
                      and any(f"i64 {size}, i1 false" in line
                              for size in (width, width - 1, width * 2))]
            self.assertTrue(copies)
            for line in copies:
                size = int(re.search(r"i64 (\d+), i1 false", line)[1])
                for replacement in ("", line.replace(f"i64 {size}, i1 false",
                                                     f"i64 {size - 1}, i1 false")):
                    with self.subTest(identity=identity, copy=line), self.assertRaises(ValueError):
                        construct.check(body.replace(line, replacement, 1), identity)
            for role in ("hash", "inner", "outer"):
                changed = re.sub(r"(%" + role + r"(?:\.[-\w]+)*) = alloca", r"\1_lost = alloca",
                                 body, count=1)
                self.assertNotEqual(body, changed)
                with self.assertRaises(ValueError):
                    construct.check(changed, identity)

    def test_constructor_result_and_unwind_paths(self):
        for identity in self.identities:
            body = self.functions[identity, "construct"]
            final_status = next(line for line in body.splitlines()
                                if "store i8 " in line and ", ptr %_0," in line)
            for value in ("0", "1"):
                changed = body.replace(final_status, re.sub(r"store i8 [^,]+,", "store i8 " + value + ",",
                                                           final_status), 1)
                with self.subTest(identity=identity, status=value), self.assertRaises(ValueError):
                    construct.check(changed, identity)
            lines = body.splitlines()
            index = next(i for i, line in enumerate(lines)
                         if (parsed := final.call(line)) and construct.is_update(parsed[0])
                         and "%outer." in line)
            self.assertIn("invoke", lines[index])
            self.assertIn("unwind label", lines[index + 1])
            lines[index + 1] = re.sub(r"unwind label %[-\w.]+", "unwind label %escaped", lines[index + 1])
            changed = "\n".join(lines) + "\nescaped:\n  resume { ptr, i32 } zeroinitializer\n"
            with self.subTest(identity=identity), self.assertRaisesRegex(ValueError, "undispatched hash owner"):
                construct.check(changed, identity)

    def test_constructor_discriminant_and_first_byte(self):
        body = self.functions["sha256", "construct"]
        first_byte = next(line for line in body.splitlines()
                          if "store i8 " in line and ", ptr %inner." in line)
        changed = re.sub(r"store i8 [^,]+,", "store i8 0,", first_byte)
        with self.assertRaisesRegex(ValueError, "incomplete"):
            construct.check(body.replace(first_byte, changed, 1), "sha256")
        tag = next(line for line in body.splitlines() if "trunc nuw i8" in line)
        # Remove the result branch's binding to the initialized/error result.
        altered = re.sub(r"trunc nuw i8 %[-\w.]+ to i1", "icmp eq i8 %unrelated, 0", tag)
        with self.assertRaises(ValueError):
            construct.check(body.replace(tag, altered, 1), "sha256")

    def test_constructor_scalar_provenance(self):
        state = State()
        state.birth(("result", 1), 1170, 0)
        byte = state.load(("result", 1), 1)
        state.transfer(("hash", 1), ("result", 2), 1169)
        state.end("result")
        with self.assertRaises(ValueError):
            state.complete(("hash", 0), 1170)
        state.store(("hash", 0), 1, byte)
        self.assertEqual(state.complete(("hash", 0), 1170), 0)
        with self.assertRaises(ValueError):
            state.store(("hash", 0), 1, byte)
        state.done.add(0)
        for operation in (
            lambda: state.complete(("hash", 0), 1170),
            lambda: state.transfer(("other", 0), ("hash", 0), 1170),
            lambda: state.load(("hash", 0), 1),
            lambda: state.store(("other", 0), 1, byte),
        ):
            with self.assertRaises(ValueError):
                operation()
        wrong = State()
        wrong.birth(("result", 1), 1170, 0)
        wrong.transfer(("hash", 1), ("result", 2), 1169)
        wrong.store(("hash", 0), 1, (0, 1, 1))
        with self.assertRaisesRegex(ValueError, "byte order"):
            wrong.complete(("hash", 0), 1170)

    def test_constructor_unknown_calls_and_general_parameter(self):
        for identity in self.identities:
            body = self.functions[identity, "construct"]
            line = next(line for line in body.splitlines()
                        if (parsed := final.call(line)) and construct.is_update(parsed[0]))
            symbol = final.call(line)[0]
            with self.assertRaisesRegex(ValueError, "unknown constructor call"):
                construct.check(body.replace(symbol, symbol + "_fake"), identity)
            for line in body.splitlines():
                if (parsed := final.call(line)) and final.hash_finalizer(parsed[0], identity):
                    self.assertFalse(construct.start(parsed[0], identity))
            if identity.startswith("general"):
                changed = body.replace("i16 noundef " + identity[7:] + ")",
                                       "i16 noundef 256)")
                self.assertNotEqual(body, changed)
                with self.assertRaisesRegex(ValueError, "parameter changed"):
                    construct.check(changed, identity)

    def test_constructor_births_and_normalization_identity(self):
        for identity in self.identities:
            body = self.functions[identity, "construct"]
            line = next(line for line in body.splitlines()
                        if (parsed := final.call(line)) and final.hash_finalizer(parsed[0], identity))
            owner = final.operand(final.call(line)[1][1])
            with self.subTest(identity=identity), self.assertRaises(ValueError):
                construct.check(body.replace(line, line.replace(owner + ",", "%uninitialized,"), 1),
                                identity)
            if identity.startswith("sha3_"):
                line = next(line for line in body.splitlines()
                            if "@llvm.memset." in line and "%inner." in line)
                with self.assertRaisesRegex(ValueError, "inline constructor initialization"):
                    construct.check(body.replace(line, line.replace("i8 0", "i8 1"), 1), identity)
            else:
                line = next(line for line in body.splitlines()
                            if (parsed := final.call(line)) and construct.start(parsed[0], identity))
                with self.assertRaisesRegex(ValueError, "creation population changed"):
                    construct.check(body.replace(line, "", 1), identity)

    def test_constructor_start_unwind_does_not_create_a_returned_owner(self):
        for identity in ("sha256", "general129"):
            body = self.functions[identity, "construct"]
            lines = body.splitlines()
            starts = [index for index, line in enumerate(lines)
                      if (parsed := final.call(line)) and construct.start(parsed[0], identity)]
            self.assertEqual(len(starts), 3)
            for position in (0, 2):
                changed = list(lines)
                self.assertIn("invoke", changed[starts[position]])
                changed[starts[position] + 1] = re.sub(r"unwind label %[-\w.]+",
                                                      "unwind label %escaped",
                                                      changed[starts[position] + 1])
                mutant = "\n".join(changed) + "\nescaped:\n  resume { ptr, i32 } zeroinitializer\n"
                if position == 2:
                    # Failed outer construction still owes the existing inner.
                    with self.assertRaisesRegex(ValueError, "undispatched hash owner"):
                        construct.check(mutant, identity)
                else:
                    # No hash owner has reached the caller yet. This partial
                    # check passes; the separate scratch check must still reject
                    # bypassing cleanup of the already-live key pad.
                    construct.check(mutant, identity)
                    with self.assertRaises(ValueError):
                        self.driver.scratch.check(mutant, "construct")

    def test_constructor_compiled_owner_leaks(self):
        driver = self.driver
        work = self.root / "constructor-mutants"
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
        driver.verifier.run(["cargo", "+1.99.1", "generate-lockfile", "--offline",
                             "--manifest-path", str(fixture / "Cargo.toml")],
                            driver.verifier.environment(work))

        def emitted():
            return driver.emit(work, "1.99.1", "x86_64-unknown-linux-gnu", "unwind",
                               fixture / "Cargo.toml")[1]

        driver.validate(emitted())
        path = leaf / "src/engine.rs"
        original = path.read_text()
        mutations = (
            ("A::update(&mut hash, key)?;", """if let Err(error) = A::update(&mut hash, key) {
                core::mem::forget(hash);
                return Err(error);
            }"""),
            ("let mut outer = start()?;", """let mut outer = match start() {
                Ok(outer) => outer,
                Err(error) => { core::mem::forget(inner); return Err(error); }
            };"""),
            ("A::update(&mut outer, pad)?;", """if let Err(error) = A::update(&mut outer, pad) {
                core::mem::forget(outer);
                return Err(error);
            }"""),
        )
        for anchor, replacement in mutations:
            self.assertEqual(original.count(anchor), 1)
            try:
                path.write_text(original.replace(anchor, replacement))
                llvm = emitted()  # A failed compile is not a killed mutant.
                definitions, aliases = driver.codegen.definitions_and_aliases(llvm)
                body = driver.scratch.consumer(driver.codegen.emitted(llvm)["sha256", "construct"],
                                               "construct", definitions, aliases)
                with self.assertRaisesRegex(ValueError, "undispatched hash owner"):
                    construct.check(body, "sha256")
            finally:
                path.write_text(original)
            driver.validate(emitted())
