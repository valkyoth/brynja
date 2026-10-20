"""Regressions for real accelerated constructor and finalizer scratch graphs."""
import re


class ScratchTests:
    def test_scratch_exact_population(self):
        driver = self.driver
        functions, _, _ = driver.emitted(self.llvm, driver.scratch.OPERATIONS)
        self.assertEqual(len(functions), 96)
        for operation in driver.scratch.OPERATIONS:
            token = "6sha256" + str(len(operation)) + operation
            self.assertIn(token, self.llvm)
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                driver.validate(self.llvm.replace(token, token + "_absent"))

    def test_scratch_all_roles_extents_and_callees(self):
        driver = self.driver
        functions, _, _ = driver.emitted(self.llvm, driver.scratch.OPERATIONS)
        for (identity, operation), raw in functions.items():
            body = driver.scratch.consumer(raw, operation, self.definitions, self.aliases)
            driver.scratch.check_body(body, operation, self.definitions, self.aliases)
            owners = driver.scratch.scratch.allocations(body, driver.scratch.method(operation))
            for owner, size in owners.items():
                for replacement in ("%wrong_scratch", owner):
                    lines = []
                    for line in body.splitlines():
                        if "clear_owned_region" in line and owner + "," in line:
                            if replacement == owner:
                                line = line.replace(f"i64 noundef {size})", f"i64 noundef {size-1})")
                            else:
                                line = line.replace(owner + ",", replacement + ",")
                        lines.append(line)
                    changed = "\n".join(lines)
                    self.assertNotEqual(changed.strip(), body.strip())
                    with self.subTest(identity=identity, operation=operation, owner=owner):
                        with self.assertRaises(ValueError):
                            driver.scratch.check_body(changed, operation, self.definitions, self.aliases)

    def test_scratch_lifetime_and_unwind_bypasses(self):
        driver = self.driver
        functions, _, _ = driver.emitted(self.llvm, driver.scratch.OPERATIONS)
        for operation in driver.scratch.OPERATIONS:
            body = driver.scratch.consumer(
                functions["sha256", operation], operation, self.definitions, self.aliases)
            driver.scratch.check_body(body, operation, self.definitions, self.aliases)
            owner = next(iter(driver.scratch.scratch.allocations(body, driver.scratch.method(operation))))
            start = next(line for line in body.splitlines()
                         if "lifetime.start" in line and owner + ")" in line)
            clear = next(line for line in body.splitlines()
                         if "clear_owned_region" in line and owner + "," in line)
            lines = body.splitlines()
            invoke = next(index for index, line in enumerate(lines)
                          if "invoke " in line and owner + "," in line
                          and "clear_owned_region" not in line)
            self.assertIn("unwind label", lines[invoke + 1])
            lines[invoke + 1] = re.sub(r"unwind label %[-\w.]+",
                                      "unwind label %escaped", lines[invoke + 1])
            unwind = "\n".join(lines)
            mutants = (
                body.replace(start, start + "\n ret void\nbypassed:", 1),
                body.replace(clear, clear.replace("18clear_owned_region", "18other_owned_region")),
                unwind + "\nescaped:\n resume { ptr, i32 } zeroinitializer\n",
            )
            for mutant in mutants:
                self.assertNotEqual(mutant, body)
                with self.subTest(operation=operation), self.assertRaises(ValueError):
                    driver.scratch.check_body(mutant, operation, self.definitions, self.aliases)

    def test_scratch_real_outlined_body_and_aliases(self):
        driver = self.driver
        functions, _, _ = driver.emitted(self.llvm, driver.scratch.OPERATIONS)
        for operation in driver.scratch.OPERATIONS:
            body = functions["sha256", operation]
            names = re.findall(r'\b(?:call|invoke)\b[^\n]*@("[^"]+"|\w+)\(', body)
            symbol = next(name.strip('"') for name in names if "15brynja_mac_hmac" in name)
            args, actual = driver.common.resolve(symbol, self.definitions, self.aliases)
            changed = actual.replace("18clear_owned_region", "18other_owned_region")
            self.assertNotEqual(actual, changed)
            definitions = {**self.definitions, symbol: (args, changed)}
            with self.assertRaises(ValueError):
                driver.scratch.check(body, operation, definitions, self.aliases)
            for replacement in ("missing", symbol + "_fake"):
                with self.assertRaises(ValueError):
                    driver.scratch.check(body.replace(symbol, replacement), operation,
                                         {**self.definitions, replacement: (args, actual)}, self.aliases)
            with self.assertRaises(ValueError):
                driver.scratch.check(body, operation, self.definitions, {**self.aliases, symbol: symbol})

    def test_constructor_forwarding_is_bound(self):
        driver = self.driver
        functions, _, _ = driver.emitted(self.llvm, driver.scratch.OPERATIONS)
        for identity in driver.common.IDENTITIES:
            for operation, route in (("construct_static", 0), ("construct_runtime", 1)):
                body = functions[identity, operation]
                mutants = (
                    body.replace("%owner", "%other_owner"),
                    body.replace("%key.0", "%other_key"),
                    body.replace("%key.1", "%other_length"),
                    body.replace(f"i64 noundef {route},", f"i64 noundef {1-route},"),
                    body.replace("%_0", "%other_result"),
                    body.replace("start:", "start:\n ret void\nunused:", 1),
                )
                for mutant in mutants:
                    self.assertNotEqual(mutant, body)
                    with self.subTest(identity=identity, operation=operation), self.assertRaises(ValueError):
                        driver.scratch.check(mutant, operation, self.definitions, self.aliases)

    def test_iterator_exception_cannot_alias_scratch(self):
        driver = self.driver
        functions, _, _ = driver.emitted(self.llvm, driver.scratch.OPERATIONS)
        for identity in ("sha256", "general129", "sha3_256"):
            body = driver.scratch.consumer(functions[identity, "construct_static"],
                                           "construct_static", self.definitions, self.aliases)
            line = next(line.strip() for line in body.splitlines()
                        if "invoke " in line and "Flatten" in line and "@" in line)
            self.assertTrue(driver.scratch.independent_iterator(
                body, line, self.definitions, self.aliases))
            symbol = re.search(r'@("[^"]+"|\w+)\(', line)[1].strip('"')
            extent = re.search(r"dereferenceable\((\d+)\)", line)[1]
            for changed in (line.replace("%states", "%pad.i"),
                            line.replace("%states", "%missing"),
                            line.replace("dereferenceable(" + extent + ")", "dereferenceable(1)"),
                            line.replace(symbol, symbol + "_fake")):
                with self.assertRaises(ValueError):
                    driver.scratch.independent_iterator(body, changed, self.definitions, self.aliases)
            with self.assertRaises(ValueError):
                driver.scratch.independent_iterator(body, line, self.definitions,
                                                    {**self.aliases, symbol: symbol})
            # Unknown callees must dirty the pad even if they use another slot.
            changed = body.replace(symbol, "unknown")
            with self.assertRaises(ValueError):
                driver.scratch.scratch.check(changed, "construct", lambda line:
                    driver.scratch.independent_iterator(changed, line, self.definitions, self.aliases))

    def test_scratch_does_not_waive_normal_fatal_or_post_clear_writes(self):
        driver = self.driver
        functions, _, _ = driver.emitted(self.llvm, driver.scratch.OPERATIONS)
        body = driver.scratch.consumer(functions["sha256", "public"],
                                       "public", self.definitions, self.aliases)
        owner = next(iter(driver.scratch.scratch.allocations(body, "public")))
        end = next(line for line in body.splitlines() if "lifetime.end" in line and owner + ")" in line)
        for write in ("store i8 42, ptr " + owner, "call void @unknown()"):
            with self.assertRaises(ValueError):
                driver.scratch.check(body.replace(end, write + "\n" + end), "public",
                                     self.definitions, self.aliases)
        symbol = next(name for name in re.findall(r"@(\w+)\(", self.llvm)
                      if driver.common.panic_cleanup(name))
        changed = body.replace("start:", "start:\n call void @" + symbol
                               + "()\n unreachable\nunused:", 1)
        with self.assertRaises(ValueError):
            driver.scratch.check(changed, "public", self.definitions, self.aliases)
