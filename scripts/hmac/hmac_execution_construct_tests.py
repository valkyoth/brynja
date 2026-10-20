"""Regression controls for post-admission ownership and emitted iterators."""
from pathlib import Path
import re
import tempfile
from unittest import mock


class ConstructTests:
    def construct_body(self, identity="sha256"):
        functions, _, _ = self.driver.emitted(self.llvm, ("construct_static",))
        return self.driver.scratch.consumer(functions[identity, "construct_static"],
                                            "construct_static", self.definitions, self.aliases)

    def construct_rejects(self, body, identity="sha256", definitions=None, aliases=None,
                          long_key=True):
        with self.assertRaises(ValueError):
            self.driver.construct.check(body, identity, definitions or self.definitions,
                                        aliases or self.aliases, long_key=long_key,
                                        types=self.driver.construct.iterator.array_types(self.llvm))

    def test_constructor_post_admission_all_identities_and_routes(self):
        driver = self.driver
        for identity in driver.common.IDENTITIES:
            for route in (0, 1):
                for long_key in (False, True):
                    driver.construct.check(self.construct_body(identity), identity,
                                            self.definitions, self.aliases, route=route, long_key=long_key,
                                            types=driver.construct.iterator.array_types(self.llvm))

    def test_constructor_returned_copies_roles_and_tag_metadata(self):
        for identity in ("sha256", "sha3_256", "general129"):
            body = self.construct_body(identity)
            width = self.driver.cleanup.layout(identity).stride
            lines = body.splitlines()
            final = next(i for i, line in enumerate(lines)
                         if re.search(r"= getelementptr.*ptr %_0, i64 " + str(width * 2) + r"$", line))
            pointer = lines[final].strip().split(" = ")[0]
            store = next(line for line in lines[final + 1:] if "store i64 " in line and pointer in line)
            self.construct_rejects(body.replace(store, re.sub(r"store i64 \d+", "store i64 1", store)),
                                   identity)
            copies = [line for line in lines[final - 20:final + 1] if "call void @llvm.memcpy" in line]
            self.assertGreaterEqual(len(copies), 2)
            for line in copies:
                self.construct_rejects(body.replace(line, "", 1), identity)
                self.construct_rejects(body.replace(line, re.sub(r"i64 \d+, i1 false",
                                                                  "i64 1, i1 false", line)), identity)
            calls = [line for line in lines if "update" in line and "@" in line
                     and not line.lstrip().startswith(";") and "%inner.i," in line]
            self.assertEqual(len(calls), 1)
            self.construct_rejects(body.replace(calls[0], calls[0].replace("%inner.i,", "%outer.i,")), identity)

    def test_constructor_cursor_and_remaining_iterator_integrity(self):
        for identity in ("sha256", "sha3_256", "general129"):
            body = self.construct_body(identity)
            cutoff = body.index("call void @llvm.memset")
            suffix = body[cutoff:]
            stores = [line for line in suffix.splitlines()
                      if re.match(r"\s*store i64 %", line) and "states" in line]
            self.assertGreater(len(stores), 0)
            changed = body
            for line in stores:
                changed = changed.replace(line, re.sub(r"store i64 %[-\w.]+", "store i64 4", line), 1)
            self.construct_rejects(changed, identity)
            geps = [line for line in suffix.splitlines()
                    if re.search(r"getelementptr.*\[\d+ x i8\].*i64 %", line)]
            self.assertGreater(len(geps), 0)
            changed = body
            for line in geps:
                changed = changed.replace(line, re.sub(r", i64 %[-\w.]+$", ", i64 5", line))
            self.construct_rejects(changed, identity)

    def test_iterator_all_remaining_suffixes_normal_and_unwind(self):
        driver = self.driver
        for identity in driver.common.IDENTITIES:
            body = self.construct_body(identity)
            symbol = next(name.strip('"') for name in re.findall(r'@("[^"]+"|\w+)\(', body)
                          if "Flatten" in name and "drop_" in name)
            for cursor in range(4):
                for long_key in (False, True):
                    for route in (0, 1):
                        for unwinding in (False, True):
                            driver.construct.iterator.check(
                                symbol, identity, self.definitions, self.aliases,
                                "1.99.1", "unwind", cursor, long_key, route, unwinding,
                                driver.construct.iterator.array_types(self.llvm))

    def test_iterator_body_alias_range_and_cleanup_mutations(self):
        driver = self.driver
        for identity in ("sha256", "sha3_256", "general129"):
            body = self.construct_body(identity)
            name = next(name.strip('"') for name in re.findall(r'@("[^"]+"|\w+)\(', body)
                        if "Flatten" in name and "drop_" in name)
            arguments, nested = driver.common.resolve(name, self.definitions, self.aliases)
            self.construct_rejects(body, identity, definitions={
                **self.definitions, name: (arguments, "start:\n ret void\n")}, long_key=False)
            self.construct_rejects(body, identity, aliases={**self.aliases, name: name})
            for kind in ("scratch", "keccak", "sha2", "memory"):
                callees = {item.strip('"') for item in re.findall(r'@("[^"]+"|\w+)\(', nested)
                           if driver.cleanup.leaf(item.strip('"')) == kind}
                for callee in callees:
                    self.construct_rejects(body, identity, definitions={
                        **self.definitions, name: (arguments, nested.replace(callee, callee + "_fake"))})
            increment = next(line for line in nested.splitlines() if " = add " in line and ", 1" in line)
            changed = nested.replace(increment, increment.replace(", 1", ", 2"))
            self.construct_rejects(body, identity, definitions={**self.definitions, name: (arguments, changed)},
                                   long_key=False)

    def test_constructor_non_unwinding_premise_is_source_bound(self):
        contracts = self.driver.construct.contracts
        contracts.validate()
        with tempfile.TemporaryDirectory(dir=self.root) as directory:
            root = Path(directory)
            for name in contracts.CLEAR_INPUTS:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((contracts.ROOT / name).read_bytes())
            contracts.validate(root)
            for name in contracts.CLEAR_INPUTS:
                path = root / name
                original = path.read_bytes()
                path.write_bytes(original + b"\n// injected drift\n")
                with self.assertRaises(ValueError):
                    contracts.validate(root)
                path.write_bytes(original)
        self.assertFalse(contracts.non_unwinding("fake_clear_owned_region"))
        with mock.patch.object(contracts, "non_unwinding", return_value=False):
            self.construct_rejects(self.construct_body())

    def test_iterator_named_layout_and_unbound_metadata_rejected(self):
        iterator = self.driver.construct.iterator
        self.assertEqual(iterator.array_types(
            '%"core::option::Option<test>" = type { [2 x i64], i64, [3 x i64] }\n'),
            {'%"core::option::Option<test>"': 48})
        with self.assertRaises(ValueError):
            iterator.array_types('%"core::option::Option<test>" = type { i8, i64 }\n')
        for instruction in (
            "%p = getelementptr inbounds [2000 x i8], ptr %base, i64 %unbound",
            "%p = getelementptr inbounds %\"unknown\", ptr %base, i64 1",
            "%v = load i64, ptr %base, align 8",
        ):
            with self.assertRaises(ValueError):
                iterator.metadata(instruction, {"%base": ("ptr", 0)}, {}, None, {})

    def test_constructor_split_metadata_store_preserves_only_unmodified_bytes(self):
        driver = self.driver
        seed = driver.admission.State()
        seed.constants["%states", 16, 16] = 3 << 64
        state = driver.construct.model.State(seed, {})
        state.store(("%states", 16), 8, 2)
        self.assertEqual(driver.admission.contracts.constant(state, ("%states", 16), 8), 2)
        self.assertEqual(driver.admission.contracts.constant(state, ("%states", 24), 8), 3)
        state.store(("%states", 20), 8, None)
        self.assertIsNone(driver.admission.contracts.constant(state, ("%states", 16), 8))
        self.assertIsNone(driver.admission.contracts.constant(state, ("%states", 24), 8))
        self.assertEqual(driver.admission.contracts.constant(state, ("%states", 28), 4), 0)

    def test_constructor_general_update_adapter_binding(self):
        driver = self.driver
        body = self.construct_body("general129")
        names = {name.strip('"') for name in re.findall(r'@("[^"]+"|\w+)\(', body)
                 if driver.construct.contracts.update_adapter(name.strip('"'))}
        self.assertTrue(names)
        for name in names:
            arguments, nested = driver.common.resolve(name, self.definitions, self.aliases)
            self.construct_rejects(body, "general129", definitions={
                **self.definitions, name: (arguments, nested.replace("%state,", "%other,"))})
            self.construct_rejects(body, "general129", definitions={
                **self.definitions, name: (arguments, "start:\n ret i8 -1\n")})

    @staticmethod
    def construct_mutants(leaf):
        execution = leaf / "src/execution/mod.rs"
        engine = leaf / "src/engine.rs"
        return [
            (execution, "|| states.next().ok_or(Error::SecretMemory)",
             "|| states.nth(1).ok_or(Error::SecretMemory)"),
            (execution, "let engine = Engine::new_with(key, tag_bytes, || states.next().ok_or(Error::SecretMemory))?;",
             "let engine = match Engine::new_with(key, tag_bytes, || states.next().ok_or(Error::SecretMemory)) { "
             "Ok(value) => value, Err(error) => { core::mem::forget(states); return Err(error); } };"),
            (engine, "Ok(Self {\n            inner,\n            outer,\n            tag_bytes,\n        })",
             "Ok(Self {\n            inner: outer,\n            outer: inner,\n            tag_bytes,\n        })"),
            (engine, "A::update(&mut outer, pad)?;",
             "if let Err(error) = A::update(&mut outer, pad) { core::mem::forget(inner); return Err(error); }"),
        ]
