"""Adversarial checks of the actual pre-key constructor admission graph."""
import re


class AdmissionTests:
    def admission_data(self):
        driver = self.driver
        functions, _, _ = driver.emitted(self.llvm, ("construct_static", "construct_runtime"))
        return {key: driver.scratch.consumer(body, key[1], self.definitions, self.aliases)
                for key, body in functions.items()}

    def admission_rejects(self, body, identity="sha256", long_key=True, definitions=None,
                          aliases=None):
        with self.assertRaises(ValueError):
            self.driver.admission.check(body, identity, definitions or self.definitions,
                                        aliases or self.aliases, long_key=long_key)

    def test_admission_population_authority_and_parameter_binding(self):
        driver = self.driver
        functions = self.admission_data()
        self.assertEqual(len(functions), 24)
        for (identity, _), body in functions.items():
            for route in (0, 1):
                for long_key in (False, True):
                    driver.admission.check(body, identity, self.definitions, self.aliases,
                                           route=route, long_key=long_key)
            calls = [line for line in body.splitlines() if re.search(r"\b(call|invoke)\b.*@", line)
                     and not line.lstrip().startswith(";")]
            factories = [(line, driver.final.syntax.call(line.strip())) for line in calls]
            factories = [(line, symbol, args) for line, (symbol, args) in factories
                         if driver.admission.contracts.factory(symbol, identity)]
            self.assertEqual(len(factories), 6 if identity.startswith("general") else 3)
            for line, symbol, args in factories:
                self.admission_rejects(body.replace(line, line.replace(symbol, symbol + "_fake")),
                                       identity)
                if args[1].startswith("i16 "):
                    changed = line.replace(args[1], "i16 noundef 128")
                else:
                    changed = line.replace("%1)", "%wrong_owner)")
                    self.admission_rejects(body.replace(line, line.replace("%0,", "%wrong_route,")),
                                           identity)
                self.assertNotEqual(changed, line)
                self.admission_rejects(body.replace(line, changed), identity)
                result = driver.final.syntax.operand(args[0])
                self.admission_rejects(body.replace(line, line.replace(result + ",", "%missing,")),
                                       identity)

    def test_admission_partial_copies_and_scalar_pieces(self):
        for identity in ("sha256", "sha3_256", "general129"):
            body = self.admission_data()[identity, "construct_static"]
            prefix = body[:body.index("call void @llvm.memset")]
            copies = [line for line in prefix.splitlines() if "call void @llvm.memcpy" in line]
            stores = [line for line in prefix.splitlines()
                      if re.match(r"\s*store i(?:8|64) %", line) and "ptr %_0," not in line]
            self.assertGreaterEqual(len(copies), 8)
            self.assertGreaterEqual(len(stores), 6)
            for line in copies:
                changed = re.sub(r"i64 \d+, i1 false", "i64 1, i1 false", line)
                self.admission_rejects(body.replace(line, changed, 1), identity)
                self.admission_rejects(body.replace(line, "", 1), identity)
            for line in stores:
                self.admission_rejects(body.replace(line, "", 1), identity)

    def test_admission_key_boundary_and_iterator_metadata(self):
        driver = self.driver
        for identity in driver.common.IDENTITIES:
            body = self.admission_data()[identity, "construct_static"]
            key_line = next(line for line in body.splitlines()
                            if "ugt i64 %key.1" in line)
            self.admission_rejects(body.replace(key_line, key_line.replace("ugt", "uge")), identity)
            width = driver.admission.contracts.block_bytes(identity)
            changed = key_line.replace(f", {width}", f", {width + 1}")
            self.admission_rejects(body.replace(key_line, changed), identity)
            prefix = body[:body.index("call void @llvm.memset")]
            metadata = [line for line in prefix.splitlines()
                        if re.match(r"\s*store i(?:8|64|128) -?\d+, ptr %", line)
                        and ("states" in line or "ptr %states," in line)]
            self.assertEqual(len(metadata), 5)
            for line in metadata:
                self.admission_rejects(body.replace(line, "", 1), identity)
            for statement in ("%read = load i8, ptr %key.0, align 1",
                              "%alias = getelementptr i8, ptr %key.0, i64 1"):
                self.admission_rejects(body.replace("start:", "start:\n  " + statement, 1),
                                       identity)

    def test_admission_failure_and_recoverable_unwind_cleanup(self):
        driver = self.driver
        body = self.admission_data()["sha256", "construct_static"]
        # The second admission must keep the first owner alive on ordinary
        # success, and destroy it on both a failed Result and unwinding.
        lines = body.splitlines()
        index = next(index for index, line in enumerate(lines)
                     if "invoke " in line and "Backend6create" in line and "@" in line)
        altered = list(lines)
        altered[index + 1] = re.sub(r"unwind label %[-\w.]+", "unwind label %escaped",
                                    altered[index + 1])
        self.admission_rejects("\n".join(altered)
                               + "\nescaped:\n resume { ptr, i32 } zeroinitializer\n")
        for kind in ("sha2", "scratch"):
            names = {name.strip('"') for name in re.findall(r'@("[^"]+"|\w+)\(', body)
                     if driver.cleanup.leaf(name.strip('"')) == kind}
            self.assertEqual(len(names), 1)
            symbol = next(iter(names))
            self.admission_rejects(body.replace(symbol, symbol + "_fake"))
        self.admission_rejects(body.replace("i64 816", "i64 815"))

    def test_admission_actual_helper_body_and_fatal_scope(self):
        driver = self.driver
        for identity in ("sha256", "sha3_256", "general129"):
            body = self.admission_data()[identity, "construct_static"]
            name = next(name.strip('"') for name in re.findall(r'@("[^"]+"|\w+)\(', body)
                        if "drop_glue" in name and "Flatten" not in name)
            args, _ = driver.common.resolve(name, self.definitions, self.aliases)
            self.admission_rejects(body, identity,
                                   definitions={**self.definitions, name: (args, "start:\n ret void\n")})
            self.admission_rejects(body, identity, aliases={**self.aliases, name: name})
            symbol = next(name for name in re.findall(r"@(\w+)\(", body)
                          if driver.common.panic_cleanup(name))
            self.admission_rejects(body.replace("start:", "start:\n call void @" + symbol
                                               + "()\n unreachable\nunused:", 1), identity)
            self.admission_rejects(body.replace("start:", "start:\n br label %start\nunused:", 1),
                                   identity)

    def test_admission_arm_vector_metadata_is_not_ignored(self):
        driver = self.driver
        llvm = driver.emit(self.root / "admission-arm", "1.90.0",
                           "aarch64-unknown-linux-gnu", "abort")[1]
        functions, definitions, aliases = driver.emitted(llvm, ("construct_static",))
        for identity in ("sha256", "sha3_256", "general129"):
            body = driver.scratch.consumer(functions[identity, "construct_static"],
                                           "construct_static", definitions, aliases)
            driver.admission.check(body, identity, definitions, aliases,
                                   "1.90.0", "abort", long_key=True)
            line = next(line for line in body.splitlines()
                        if "store <2 x i64> <i64 0, i64 3>" in line)
            for changed in ("", line.replace("i64 0,", "i64 1,"),
                            line.replace("i64 3>", "i64 2>"),
                            line.replace("i64 0,", "i64 %unknown,")):
                with self.assertRaises(ValueError):
                    driver.admission.check(body.replace(line, changed), identity, definitions, aliases,
                                           "1.90.0", "abort", long_key=True)

    def test_admission_formal_argument_binding(self):
        driver = self.driver
        functions, _, _ = driver.emitted(self.llvm, ("construct_static",))
        for identity in ("sha256", "sha3_256", "general129"):
            body = functions[identity, "construct_static"]
            name = re.search(r'@("[^"]+"|\w+)\(', body)[1].strip('"')
            arguments, implementation = driver.common.resolve(name, self.definitions, self.aliases)
            for parameter in ("%_0", "%0", "%1", "%key.0", "%key.1"):
                changed = re.sub(re.escape(parameter) + r"(?=,|$)", "%other", arguments)
                self.assertNotEqual(changed, arguments)
                with self.assertRaises(ValueError):
                    driver.scratch.consumer(body, "construct_static", {
                        **self.definitions, name: (changed, implementation)}, self.aliases)

    @staticmethod
    def admission_mutants(leaf):
        path = leaf / "src/execution/mod.rs"
        return [
            (path, "let second = A::create(owner)?;",
             "let second = match A::create(owner) { Ok(value) => value, "
             "Err(error) => { core::mem::forget(first); return Err(error); } };"),
            (path, "Some(A::create(owner)?)",
             "Some(match A::create(owner) { Ok(value) => value, Err(error) => { "
             "core::mem::forget(first); core::mem::forget(second); return Err(error); } })"),
            (path, "let first = A::create(owner)?;",
             "core::hint::black_box(key.first().copied()); let first = A::create(owner)?;"),
        ]
