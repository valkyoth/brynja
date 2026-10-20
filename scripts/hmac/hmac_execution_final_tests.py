"""Mutation checks for accelerated finalizer owner and adapter paths."""
import re


class FinalTests:
    def final_data(self):
        driver = self.driver
        functions, _, _ = driver.emitted(self.llvm, driver.final.syntax.OPERATIONS)
        return {key: driver.scratch.consumer(body, key[1], self.definitions, self.aliases)
                for key, body in functions.items()}

    def final_rejects(self, body, identity, definitions=None):
        driver = self.driver
        with self.assertRaises(ValueError):
            driver.final.check(body, identity, definitions or self.definitions, self.aliases)

    def test_final_owner_copies_offsets_and_early_returns(self):
        driver = self.driver
        functions = self.final_data()
        self.assertEqual(len(functions), 72)
        for (identity, operation), body in functions.items():
            driver.final.check(body, identity, self.definitions, self.aliases)
            # The whole-Engine mirror can supply only tag-length metadata.
            # Mutate the actual outer-owner handoff into the consuming closure.
            copy = next(line for line in body.splitlines()
                        if "llvm.memcpy" in line and "%absorb_inner." in line)
            size = re.search(r"i64 (\d+), i1 false", copy)[1]
            _, args = driver.final.syntax.call(copy)
            source = driver.final.syntax.operand(args[1])
            mutants = (
                body.replace(copy, "", 1),
                body.replace(copy, copy.replace(f"i64 {size},", "i64 1,"), 1),
                body.replace(copy, copy.replace(source + ",", "%wrong,"), 1),
                body.replace("start:", "start:\n ret void\nunused:", 1),
            )
            for mutant in mutants:
                self.assertNotEqual(body, mutant)
                with self.subTest(identity=identity, operation=operation):
                    self.final_rejects(mutant, identity)

    def test_final_actual_adapter_bodies_and_aliases(self):
        driver = self.driver
        functions = self.final_data()
        for identity in ("sha256", "sha3_256", "general129"):
            body = functions[identity, "public"]
            names = re.findall(r'@("[^"]+"|\w+)\(', body)
            name = next(name.strip('"') for name in names
                        if driver.final.contracts.adapter(name.strip('"')))
            args, actual = driver.common.resolve(name, self.definitions, self.aliases)
            driver.final.check(body, identity, self.definitions, self.aliases)
            for changed in ("start:\n ret i8 0\n", actual.replace(
                    "start:", "start:\n ret i8 0\nunused:", 1)):
                self.final_rejects(body, identity, {**self.definitions, name: (args, changed)})
            with self.assertRaises(ValueError):
                driver.final.check(body, identity, self.definitions, {**self.aliases, name: name})
            # Do not infer ownership from a finish-like function name.
            for substitute in ("unknown", name + "_fake"):
                self.final_rejects(body.replace(name, substitute), identity,
                                   {**self.definitions, substitute: (args, actual)})

    def test_final_adapter_state_and_closure_arguments(self):
        driver = self.driver
        for identity, body in ((identity, self.final_data()[identity, "public"])
                               for identity in ("sha256", "sha3_256", "general129")):
            line = next(line for line in body.splitlines()
                        if "invoke " in line and "finish_cpu" in line and "@" in line)
            _, args = driver.final.syntax.call(line)
            self.assertEqual(len(args), 4)
            state = driver.final.syntax.operand(args[0])
            closure = driver.final.syntax.operand(args[-1])
            for old, new in ((state + ",", "%missing,"), (closure + ")", "%missing)")):
                changed = line.replace(old, new)
                self.assertNotEqual(line, changed)
                self.final_rejects(body.replace(line, changed, 1), identity)
            self.final_rejects(body.replace(line, line.replace(closure + ")", state + ")"), 1), identity)

    def test_final_inner_error_and_outer_unwind_obligations(self):
        driver = self.driver
        body = self.final_data()["sha256", "public"]
        name = next(name.strip('"') for name in re.findall(r'@("[^"]+"|\w+)\(', body)
                    if driver.final.contracts.adapter(name.strip('"')))
        args, nested = driver.common.resolve(name, self.definitions, self.aliases)
        for marker in ("20finalize_bits_secret", "10update_cpu"):
            lines = nested.splitlines()
            index = next(index for index, line in enumerate(lines)
                         if "invoke " in line and marker in line)
            self.assertIn("unwind label", lines[index + 1])
            lines[index + 1] = re.sub(r"unwind label %[-\w.]+",
                                      "unwind label %escaped", lines[index + 1])
            changed = "\n".join(lines) + "\nescaped:\n resume { ptr, i32 } zeroinitializer\n"
            self.final_rejects(body, "sha256", {**self.definitions, name: (args, changed)})

    def test_final_each_core_and_cpu_scratch_cleanup_required(self):
        driver = self.driver
        for identity in ("sha256", "sha3_256", "general129"):
            body = self.final_data()[identity, "public"]
            name = next(name.strip('"') for name in re.findall(r'@("[^"]+"|\w+)\(', body)
                        if driver.final.contracts.adapter(name.strip('"')))
            args, nested = driver.common.resolve(name, self.definitions, self.aliases)
            symbols = {name.strip('"') for name in re.findall(r'@("[^"]+"|\w+)\(', nested)
                       if driver.cleanup.leaf(name.strip('"'))}
            self.assertEqual(len(symbols), 2)
            for symbol in symbols:
                changed = nested.replace(symbol, symbol + "_fake")
                self.final_rejects(body, identity, {**self.definitions, name: (args, changed)})
            changed = nested.replace("i64 704", "i64 703")
            if identity.startswith("sha3_"):
                changed = nested.replace("i64 624", "i64 623")
            self.assertNotEqual(nested, changed)
            self.final_rejects(body, identity, {**self.definitions, name: (args, changed)})

    def test_final_wrong_leaf_identity_and_fatal_entry(self):
        driver = self.driver
        body = self.final_data()["sha256", "public"]
        name = next(name.strip('"') for name in re.findall(r'@("[^"]+"|\w+)\(', body)
                    if driver.final.contracts.adapter(name.strip('"')))
        args, nested = driver.common.resolve(name, self.definitions, self.aliases)
        changed = nested.replace("6Sha25620finalize_bits_secret", "6Sha22420finalize_bits_secret")
        self.assertNotEqual(nested, changed)
        self.final_rejects(body, "sha256", {**self.definitions, name: (args, changed)})
        symbol = next(name for name in re.findall(r"@(\w+)\(", self.llvm)
                      if driver.common.panic_cleanup(name))
        changed = body.replace("start:", "start:\n call void @" + symbol
                               + "()\n unreachable\nunused:", 1)
        self.final_rejects(changed, "sha256")

    def test_final_cleanup_helpers_and_unsupported_pointer_escapes(self):
        driver = self.driver
        for identity in ("sha256", "sha3_256", "general129"):
            body = self.final_data()[identity, "public"]
            name = next(name.strip('"') for name in re.findall(r'@("[^"]+"|\w+)\(', body)
                        if "drop_glue" in name)
            args, helper = driver.common.resolve(name, self.definitions, self.aliases)
            self.final_rejects(body, identity, {**self.definitions, name: (args, "start:\n ret void\n")})
            with self.assertRaises(ValueError):
                driver.final.check(body, identity, self.definitions, {**self.aliases, name: name})
            escape = "  %escaped = insertvalue { ptr } poison, ptr %self, 0\n"
            self.final_rejects(body.replace("start:", "start:\n" + escape, 1), identity)
            offset = driver.cleanup.layout(identity).discriminator
            read = (f"  %late_ptr = getelementptr inbounds i8, ptr %self, i64 {offset}\n"
                    "  %late_read = load i64, ptr %late_ptr, align 8\n")
            self.final_rejects(body.replace("ret void", read + "ret void"), identity)

    @staticmethod
    def final_mutants(leaf):
        return [
            (leaf / "src/execution/backends.rs", "consume(($digest)(&result))",
             "core::mem::forget(consume); Ok(())"),
            (leaf / "src/execution/backends.rs", ".map_err($error)?;",
             ".map_err($error);\nlet result = match result { Ok(value) => value, "
             "Err(error) => { core::mem::forget(consume); return Err(error); } };"),
            (leaf / "src/execution/backends.rs", "Self::update_cpu(&mut state, digest)?;",
             "if let Err(error) = Self::update_cpu(&mut state, digest) { "
             "core::mem::forget(state); return Err(error); }"),
            (leaf / "src/execution/backends.rs", "Self::update_cpu(&mut state, digest)?;",
             "let mut state = core::mem::ManuallyDrop::new(state);\n"
             "let result = Self::update_cpu(&mut state, digest);\n"
             "let state = core::mem::ManuallyDrop::into_inner(state);\nresult?;"),
        ]
