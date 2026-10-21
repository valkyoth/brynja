"""Mutation regressions for static constructor entries, admission and ownership."""
import re
import hmac_static_construct as static


class StaticConstructorTests:
    def static_body(self, identity="sha256"):
        return static.entry(identity, self.definitions, self.aliases)

    def check_static_constructor(self, llvm):
        definitions, aliases = self.driver.common.definitions_and_aliases(llvm)
        body = static.entry("sha256", definitions, aliases)
        types = static.construct.iterator.array_types(llvm, "static")
        for long_key in (False, True):
            static.construct.check(body, "sha256", definitions, aliases,
                                   long_key=long_key, types=types, profile="static")

    def rejects_static_constructor(self, body, identity="sha256", definitions=None,
                                    aliases=None, long_key=True):
        with self.assertRaises(ValueError):
            static.construct.check(body, identity, definitions or self.definitions,
                                   aliases or self.aliases, long_key=long_key,
                                   types=static.construct.iterator.array_types(self.llvm, "static"),
                                   profile="static")

    def test_static_constructor_formal_factory_and_key_binding(self):
        driver = self.driver
        for identity in ("sha256", "sha3_256", "general129"):
            body = self.static_body(identity)
            name = next(name for name, (_, implementation) in self.definitions.items() if implementation == body)
            arguments, _ = self.definitions[name]
            for formal in ("%_0", "%owner", "%key.0", "%key.1"):
                changed = re.sub(re.escape(formal) + r"(?=,|$)", "%other", arguments)
                self.assertNotEqual(changed, arguments)
                with self.assertRaises(ValueError):
                    static.entry(identity, {**self.definitions, name: (changed, body)}, self.aliases)
            calls = [(line, driver.final.syntax.call(line)) for line in body.splitlines()
                     if "@" in line and not line.lstrip().startswith(";")]
            factories = [(line, call) for line, call in calls
                         if call and driver.admission.contracts.factory(call[0], identity)]
            self.assertEqual(len(factories), 6 if identity.startswith("general") else 3)
            for line, (symbol, args) in factories:
                self.rejects_static_constructor(body.replace(line, line.replace(symbol, symbol + "_fake")), identity)
                changed = line.replace("%owner)", "%other)") if len(args) == 2 else line.replace(
                    args[1], "i16 noundef 128")
                self.assertNotEqual(changed, line)
                self.rejects_static_constructor(body.replace(line, changed), identity)
            for instruction in ("%read = load i8, ptr %key.0, align 1",
                                "%alias = getelementptr i8, ptr %key.0, i64 1"):
                self.rejects_static_constructor(body.replace("start:", "start:\n " + instruction), identity)

    def test_static_constructor_admission_copies_and_niches(self):
        for identity in ("sha256", "sha3_256", "general129"):
            body = self.static_body(identity)
            prefix = body[:body.index("call void @llvm.memset")]
            copies = [line for line in prefix.splitlines() if "call void @llvm.memcpy" in line]
            self.assertGreaterEqual(len(copies), 7)  # SHA-3 also uses scalar tail moves.
            for line in copies:
                self.rejects_static_constructor(body.replace(line, "", 1), identity)
            stores = [line for line in prefix.splitlines() if re.match(r"\s*store i(?:8|32) %", line)
                      and "ptr %_0," not in line]
            self.assertGreaterEqual(len(stores), 6)
            for line in stores:
                self.rejects_static_constructor(body.replace(line, "", 1), identity)
            metadata = [line for line in prefix.splitlines()
                        if re.match(r"\s*store i(?:8|64|128) -?\d+, ptr %", line) and "states" in line]
            self.assertEqual(len(metadata), 5)
            for line in metadata:
                self.rejects_static_constructor(body.replace(line, "", 1), identity)
            key = next(line for line in prefix.splitlines() if "ugt i64 %key.1" in line)
            self.rejects_static_constructor(body.replace(key, key.replace("ugt", "uge")), identity)

    def test_static_constructor_returned_owners_and_roles(self):
        for identity in ("sha256", "sha3_256", "general129"):
            body = self.static_body(identity)
            roles = static.construct.layout.roles(body, "static")
            calls = [line for line in body.splitlines() if "@" in line and "update" in line
                     and roles["inner"] + "," in line and not line.lstrip().startswith(";")]
            self.assertEqual(len(calls), 1)
            self.rejects_static_constructor(body.replace(calls[0], calls[0].replace(
                roles["inner"] + ",", roles["outer"] + ",")), identity)
            width = self.driver.cleanup.layout(identity, "static").stride
            lines = body.splitlines()
            pointer = next(line.split(" = ")[0].strip() for line in lines
                           if re.search(r"getelementptr.*ptr %_0, i64 " + str(width * 2) + r"(?:,|$)", line))
            store = next(line for line in lines if "store i64 " in line and "ptr " + pointer + "," in line)
            self.rejects_static_constructor(body.replace(store, re.sub(r"store i64 \d+", "store i64 1", store)), identity)
            # Returned fields can be split byte/aggregate moves; reject removal
            # of each copy whose destination is in the actual result storage.
            allocs = re.findall(r"(%[-\w.]+) = alloca", body)
            ptrs = self.driver.final.syntax.pointers(body, (*allocs, "%_0"))
            copies = []
            for line in lines:
                call = self.driver.final.syntax.call(line)
                if call and call[0] == "llvm.memcpy.p0.p0.i64":
                    name = self.driver.final.syntax.operand(call[1][0])
                    if ptrs.get(name, (name, 0))[0] == "%_0":
                        copies.append(line)
            self.assertTrue(copies)
            for line in copies:
                self.rejects_static_constructor(body.replace(line, "", 1), identity)

    def test_static_constructor_error_unwind_and_cleanup(self):
        driver = self.driver
        for identity in ("sha256", "sha3_256", "general129"):
            body = self.static_body(identity)
            lines = body.splitlines()
            sites = [i for i, line in enumerate(lines) if "invoke " in line and "@" in line
                     and ("create" in line or "update" in line)]
            self.assertGreaterEqual(len(sites), 3)
            for index in sites:
                changed = list(lines)
                changed[index + 1] = re.sub(r"unwind label %[-\w.]+", "unwind label %escaped", changed[index + 1])
                self.assertNotEqual(changed, lines)
                self.rejects_static_constructor("\n".join(changed) +
                    "\nescaped:\n resume { ptr, i32 } zeroinitializer\n", identity)
            symbols = {name.strip('"') for name in re.findall(r'@("[^"]+"|\w+)\(', body)
                       if driver.cleanup.leaf(name.strip('"'))}
            self.assertTrue(symbols)
            for symbol in symbols:
                self.rejects_static_constructor(body.replace(symbol, symbol + "_fake"), identity)
            self.rejects_static_constructor(body.replace("start:", "start:\n ret void\nunused:"), identity)

    def test_static_iterator_all_suffixes_and_owner_populations(self):
        iterator = static.construct.iterator
        types = iterator.array_types(self.llvm, "static")
        for identity in self.driver.common.IDENTITIES:
            body = self.static_body(identity)
            symbol = next(name.strip('"') for name in re.findall(r'@("[^"]+"|\w+)\(', body)
                          if "Flatten" in name and "drop_" in name)
            for cursor in range(4):
                for long_key in (False, True):
                    for population in range(8):
                        for unwinding in (False, True):
                            iterator.check(symbol, identity, self.definitions, self.aliases,
                                           "1.99.1", "unwind", cursor, long_key, population,
                                           unwinding, types, "static")
            args, nested = self.driver.common.resolve(symbol, self.definitions, self.aliases)
            self.rejects_static_constructor(body, identity,
                definitions={**self.definitions, symbol: (args, "start:\n ret void\n")})
            self.rejects_static_constructor(body, identity, aliases={**self.aliases, symbol: symbol})
            increment = next(line for line in nested.splitlines() if " = add " in line and ", 1" in line)
            self.rejects_static_constructor(body, identity, definitions={**self.definitions, symbol: (
                args, nested.replace(increment, increment.replace(", 1", ", 2")))})

    def test_static_iterator_byte_layout_and_pointer_metadata(self):
        iterator = static.construct.iterator
        text = '%"core::option::Option<test>" = type { [859 x i8], i8, [4 x i8] }\n'
        self.assertEqual(iterator.array_types(text, "static"), {'%"core::option::Option<test>"': 864})
        for profile, fields in (("runtime", "[859 x i8], i8, [4 x i8]"),
                                ("static", "i8, i64"), ("static", "ptr")):
            with self.assertRaises(ValueError):
                iterator.array_types('%"core::option::Option<test>" = type { ' + fields + ' }\n', profile)
        for instruction, memory in (
            ("%v = load i64, ptr %base, align 8", {(64, "ptr"): ("nonnull", True)}),
            ("%v = load ptr, ptr %base, align 8", {(64, 8): 1}),
            ("%v = icmp eq ptr %base, null", {}),
        ):
            with self.assertRaises(ValueError):
                iterator.metadata(instruction, {"%base": ("ptr", 64)}, memory, None, {})

    def test_static_constructor_compiler_niches_and_session_kind_scope(self):
        layout = static.construct.layout
        for identity in ("sha256", "sha3_256", "general129"):
            self.assertEqual(layout.geometry(identity, "1.90.0", "static")[2:4], (2, 3))
            self.assertEqual(layout.geometry(identity, "1.99.1", "static")[2:4], (2, -1))
        self.assertEqual(layout.session_error("1.90.0"), 4)
        self.assertEqual(layout.session_error("1.99.1"), -1)
        body = self.static_body("general129")
        # Session kind is opaque: only its Result error test is admitted, never
        # an assumed subset of successful backend variants.
        condition = next(line for line in body.splitlines() if "icmp eq i8 %1, -1" in line)
        for value in (0, 1, 2, 3):
            mutant = body.replace(condition, f" %kind_probe = icmp eq i8 %1, {value}\n" + condition)
            with self.assertRaisesRegex(ValueError, "unreviewed static session-kind condition"):
                self.driver.admission.check(mutant, "general129", self.definitions, self.aliases,
                                            profile="static", long_key=True)
