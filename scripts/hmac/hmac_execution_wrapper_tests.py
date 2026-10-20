"""Regressions for actual Retained::take scalarized Engine transfers."""
import re


class WrapperTests:
    def wrapper_data(self):
        return self.driver.emitted(self.llvm, self.driver.final.syntax.OPERATIONS)[0]

    def wrapper_rejects(self, body, identity, operation, present=True):
        with self.assertRaises(ValueError):
            self.driver.wrapper.check(body, identity, operation, self.definitions,
                                      self.aliases, present=present)

    def test_wrapper_all_identities_and_scalarized_move_pieces(self):
        functions = self.wrapper_data()
        self.assertEqual(len(functions), 72)
        for (identity, operation), body in functions.items():
            for route, present in ((0, True), (1, True), (0, False)):
                self.driver.wrapper.check(body, identity, operation, self.definitions,
                                          self.aliases, route=route, present=present)
            copies = [line for line in body.splitlines() if "call void @llvm.memcpy" in line]
            stores = [line for line in body.splitlines()
                      if re.search(r"store i(?:8|64) %[-\w.]*copyload", line)]
            self.assertEqual(len(copies), 2)
            self.assertEqual(len(stores), 2)
            for line in copies + stores:
                self.wrapper_rejects(body.replace(line, "", 1), identity, operation)
            for line in copies:
                short = re.sub(r"i64 \d+, i1 false", "i64 1, i1 false", line)
                self.wrapper_rejects(body.replace(line, short, 1), identity, operation)
            for line in stores:
                forged = re.sub(r"(store i(?:8|64)) %[-\w.]+,", r"\1 0,", line)
                self.wrapper_rejects(body.replace(line, forged, 1), identity, operation)

    def test_wrapper_move_sources_extents_and_overlaps(self):
        for identity in ("sha256", "sha3_256", "general129"):
            operation = "public"
            body = self.wrapper_data()[identity, operation]
            copy = next(line for line in body.splitlines() if "call void @llvm.memcpy" in line)
            _, args = self.driver.final.syntax.call(copy.strip())
            source = self.driver.final.syntax.operand(args[1])
            destination = self.driver.final.syntax.operand(args[0])
            for changed in (copy.replace(source + ",", "%unknown,"),
                            copy.replace(source + ",", destination + ","),
                            re.sub(r"i64 \d+, i1 false", "i64 99999, i1 false", copy)):
                self.wrapper_rejects(body.replace(copy, changed, 1), identity, operation)
            self.wrapper_rejects(body.replace(copy, copy + "\n" + copy, 1), identity, operation)
            offset = 1448 if identity.startswith("sha3_") else 712
            self.wrapper_rejects(body.replace(f"i64 {offset}", f"i64 {offset + 1}"),
                                 identity, operation)

    def test_wrapper_wrong_input_and_destination_arguments(self):
        for (identity, operation), body in self.wrapper_data().items():
            call = next(line for line in body.splitlines()
                        if "call " in line and "@_" in line and "15brynja_mac_hmac6engine" in line)
            _, args = self.driver.final.syntax.call(call.strip())
            index = 0 if operation.startswith("verify") else 1
            for argument in (args[index], args[index + 1], args[-2]):
                pointer = self.driver.final.syntax.operand(argument)
                changed = call.replace(argument, argument.removesuffix(pointer) + "%wrong", 1)
                self.wrapper_rejects(body.replace(call, changed, 1), identity, operation)
            length = "%candidate.1" if operation.startswith("verify") else "%output.1"
            changed = call.replace(length, "%wrong_length")
            self.wrapper_rejects(body.replace(call, changed, 1), identity, operation)
            if not operation.endswith("_bits"):
                changed = body.replace("store ptr null,", "store ptr %input,")
                self.assertNotEqual(changed, body)
                self.wrapper_rejects(changed, identity, operation)

    def test_wrapper_empty_state_and_destination_clearing(self):
        for (identity, operation), body in self.wrapper_data().items():
            niche = 2 if identity.startswith("sha3_") else -1
            comparison = next(line for line in body.splitlines()
                              if f", {niche}" in line and "icmp eq i64" in line)
            self.wrapper_rejects(body.replace(comparison, comparison.replace(
                f", {niche}", ", 88")), identity, operation, False)
            if operation.startswith("secret"):
                clear = next(line for line in body.splitlines()
                             if "call " in line and "18clear_owned_region" in line)
                for changed in ("", clear.replace("%output.0", "%wrong"),
                                clear.replace("%output.1", "%wrong_length")):
                    self.wrapper_rejects(body.replace(clear, changed), identity, operation, False)
            early_read = "  %absent = load i8, ptr %state, align 1\n"
            self.wrapper_rejects(body.replace("start:", "start:\n" + early_read, 1),
                                 identity, operation, False)

    def test_wrapper_consumption_lifetimes_and_pointer_escapes(self):
        for identity in ("sha256", "sha3_256", "general129"):
            body = self.wrapper_data()[identity, "public"]
            for statement in ("ret i8 0", "unreachable", "br label %start",
                              "%escape = ptrtoint ptr %state to i64",
                              "%end = getelementptr i8, ptr %state, i64 99999\n"
                              "  %escape = ptrtoint ptr %end to i64",
                              "%escape = insertvalue { ptr } poison, ptr %state, 0"):
                self.wrapper_rejects(body.replace("start:", "start:\n  " + statement, 1),
                                     identity, "public")
            call = next(line for line in body.splitlines()
                        if "call " in line and "@_" in line and "15brynja_mac_hmac6engine" in line)
            self.wrapper_rejects(body.replace(call, call + "\n" + call), identity, "public")
            self.wrapper_rejects(body.replace(call, "", 1), identity, "public")
            read = "  %late = load i8, ptr %state, align 1"
            self.wrapper_rejects(body.replace(call, call + "\n" + read), identity, "public")
            allocation = next(line for line in body.splitlines() if "%val.i = alloca" in line)
            self.wrapper_rejects(body.replace(allocation, re.sub(
                r"\[\d+ x i8\]", "[1 x i8]", allocation)), identity, "public")

    def test_wrapper_scalar_escape_and_live_storage_restart(self):
        for identity in ("sha256", "sha3_256", "general129"):
            body = self.wrapper_data()[identity, "public"]
            scalar = next(line for line in body.splitlines()
                          if "= load i8, ptr %state," in line)
            value = scalar.strip().split(" =")[0]
            for statement in (f"%escape = xor i8 {value}, 0",
                              f"call void @llvm.umin.i64(i8 {value})",
                              'call void asm sideeffect "", "r,~{memory}"(ptr nonnull %state)'):
                self.wrapper_rejects(body.replace(scalar, scalar + "\n  " + statement),
                                     identity, "public")
            copy = next(line for line in body.splitlines() if "call void @llvm.memcpy" in line)
            self.wrapper_rejects(body.replace(copy, copy + "\n"
                                 "  call void @llvm.lifetime.start.p0(ptr nonnull %val.i)"),
                                 identity, "public")

    @staticmethod
    def wrapper_mutants(leaf):
        return [
            (leaf / "src/execution/retained.rs", "self.0.take().ok_or(Error::ExecutionFailed)",
             "let value = self.0.take(); core::mem::forget(value); Err(Error::ExecutionFailed)"),
            (leaf / "src/execution/mod.rs",
             "let _ = brynja_core::clear_owned_region(output);\n                Err(error)",
             "let _ = output;\n                Err(error)"),
        ]
