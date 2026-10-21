"""Static-only Engine/adapter ownership regressions on actual emitted bodies."""
import re


class StaticFinalTests:
    def final_data(self):
        driver = self.driver
        functions, _, _ = driver.emitted(self.llvm, driver.final.syntax.OPERATIONS)
        return {key: driver.scratch.consumer(body, key[1], self.definitions, self.aliases)
                for key, body in functions.items()}

    def rejects_final(self, body, identity="sha256", definitions=None, population=15):
        with self.assertRaises(ValueError):
            self.driver.final.check(body, identity, definitions or self.definitions,
                                    self.aliases, profile="static", route=population)

    def adapter_body(self, identity):
        driver = self.driver
        body = self.final_data()[identity, "public"]
        name = next(name.strip('"') for name in re.findall(r'@("[^"]+"|\w+)\(', body)
                    if driver.final.contracts.adapter(name.strip('"')))
        args, nested = driver.common.resolve(name, self.definitions, self.aliases)
        return body, name, args, nested

    def test_static_final_moves_and_early_returns(self):
        for (identity, operation), body in self.final_data().items():
            width = self.driver.cleanup.layout(identity, "static").stride
            copies = [line for line in body.splitlines()
                      if "llvm.memcpy" in line and f"i64 {width}, i1 false" in line]
            self.assertTrue(copies)
            for copy in copies:
                _, args = self.driver.final.syntax.call(copy)
                source = self.driver.final.syntax.operand(args[1])
                for replacement in ("", re.sub(r"i64 \d+, i1 false", "i64 1, i1 false", copy),
                                    copy.replace(source + ",", "%missing,")):
                    with self.subTest(identity=identity, operation=operation, copy=copy):
                        self.rejects_final(body.replace(copy, replacement, 1), identity)
            self.rejects_final(body.replace("start:", "start:\n ret void\nunused:", 1), identity)

    def test_static_final_actual_adapters_and_cleanup_helpers(self):
        driver = self.driver
        for identity in ("sha256", "sha3_256", "general129"):
            body, name, args, nested = self.adapter_body(identity)
            self.rejects_final(body, identity, {**self.definitions, name: (args, "start:\n ret i8 0\n")})
            with self.assertRaises(ValueError):
                driver.final.check(body, identity, self.definitions, {**self.aliases, name: name},
                                   profile="static", route=15)
            self.rejects_final(body.replace(name, name + "_fake"), identity,
                               {**self.definitions, name + "_fake": (args, nested)})
            helper = next(name.strip('"') for name in re.findall(r'@("[^"]+"|\w+)\(', body)
                          if "drop_glue" in name)
            formals, _ = driver.common.resolve(helper, self.definitions, self.aliases)
            self.rejects_final(body, identity,
                               {**self.definitions, helper: (formals, "start:\n ret void\n")})

    def test_static_final_adapter_arguments_and_unwind(self):
        for identity in ("sha256", "sha3_256", "general129"):
            body, name, args, nested = self.adapter_body(identity)
            call = next(line for line in body.splitlines()
                        if "invoke " in line and "finish_cpu" in line and "@" in line)
            _, parameters = self.driver.final.syntax.call(call)
            self.assertEqual(len(parameters), 4)
            state = self.driver.final.syntax.operand(parameters[0])
            closure = self.driver.final.syntax.operand(parameters[-1])
            self.rejects_final(body.replace(call, call.replace(state + ",", "%missing,"), 1), identity)
            self.rejects_final(body.replace(call, call.replace(closure + ")", state + ")"), 1), identity)
        body, name, args, nested = self.adapter_body("sha256")
        for marker in ("20finalize_bits_secret", "10update_cpu"):
            lines = nested.splitlines()
            index = next(i for i, line in enumerate(lines) if "invoke " in line and marker in line)
            self.assertIn("unwind label", lines[index + 1])
            lines[index + 1] = re.sub(r"unwind label %[-\w.]+", "unwind label %escaped", lines[index + 1])
            mutant = "\n".join(lines) + "\nescaped:\n resume { ptr, i32 } zeroinitializer\n"
            self.rejects_final(body, definitions={**self.definitions, name: (args, mutant)})

    def test_static_final_scratch_pointer_and_leaf_identity(self):
        for identity in ("sha256", "sha3_256", "general129"):
            body, name, args, nested = self.adapter_body(identity)
            symbols = {symbol.strip('"') for symbol in re.findall(r'@("[^"]+"|\w+)\(', nested)
                       if self.driver.cleanup.leaf(symbol.strip('"'))}
            self.assertEqual(len(symbols), 2)
            for symbol in symbols:
                self.rejects_final(body, identity,
                                   {**self.definitions, name: (args, nested.replace(symbol, symbol + "_fake"))})
            if identity == "sha3_256":
                mutations = (("i64 624", "i64 623"),)
            else:
                mutations = (("load ptr,", "load i64,"), ("i64 64", "i64 63"),
                             ("icmp eq ptr", "icmp ne ptr"))
            for old, new in mutations:
                self.assertIn(old, nested)
                self.rejects_final(body, identity, {**self.definitions, name: (args, nested.replace(old, new))})
        body, name, args, nested = self.adapter_body("sha256")
        mutant = nested.replace("6Sha25620finalize_bits_secret", "6Sha22420finalize_bits_secret")
        self.assertNotEqual(mutant, nested)
        self.rejects_final(body, definitions={**self.definitions, name: (args, mutant)})

    def test_static_final_metadata_after_partial_and_complete_consumption(self):
        driver = self.driver
        body, _, _, _ = self.adapter_body("sha256")
        # All sixteen concrete metadata populations are valid: in the no-Cpu
        # case core destruction precedes a legitimate null-niche read. But a
        # consuming hash finalizer/adapter also consumes the enclosing owner.
        for population in range(16):
            driver.final.check(body, "sha256", self.definitions, self.aliases,
                               profile="static", route=population)
        late = (" %late_ptr = getelementptr inbounds i8, ptr %self, i64 64\n"
                " %late_read = load ptr, ptr %late_ptr, align 8\n")
        self.assertIn("ret void", body)
        with self.assertRaisesRegex(ValueError, "read after accelerated owner consumption"):
            driver.final.check(body.replace("ret void", late + "ret void"), "sha256",
                               self.definitions, self.aliases, profile="static", route=0)
        escape = " %escape = insertvalue { ptr } poison, ptr %self, 0\n"
        self.rejects_final(body.replace("start:", "start:\n" + escape, 1))
        symbol = next(name for name in re.findall(r"@(\w+)\(", self.llvm)
                      if driver.common.panic_cleanup(name))
        self.rejects_final(body.replace("start:", f"start:\n call void @{symbol}()\n unreachable\nunused:", 1))
