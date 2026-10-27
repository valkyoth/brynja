"""Actual emitted prefix wrapper, argument/admission and abstraction mutations."""


class PrefixTests:
    def prepare_prefix(self):
        driver = self.driver
        llvm = self.profiles[driver.TARGETS[0]][0]
        self.definitions, self.aliases = driver.common.definitions_and_aliases(llvm)
        self.names = driver.lifecycle.demangle(set(self.definitions) | set(self.aliases))
        self.symbol = next(s for s in self.definitions if self.names[s].endswith(driver.prefix.SUFFIX))
        self.arguments, self.body = self.definitions[self.symbol]

    def check(self, body=None, arguments=None, names=None, aliases=None):
        return self.driver.prefix.check(self.symbol, {**self.definitions, self.symbol:
            (arguments or self.arguments, body or self.body)}, aliases or self.aliases,
            names or self.names, '1.99.1')

    def test_actual_wrapper_and_abstraction(self):
        self.prepare_prefix()
        driver = self.driver
        target = self.check()
        normalized = driver.prefix.abstract(self.definitions, self.aliases, self.names, '1.99.1')
        self.assertEqual(normalized[self.symbol], self.definitions[self.symbol])
        changed = [s for s in normalized if normalized[s] != self.definitions[s]]
        self.assertTrue(changed)
        for symbol in changed:
            original = self.definitions[symbol][1]
            abstracted = normalized[symbol][1]
            self.assertEqual(abstracted.replace('@' + target + '(', '@' + self.symbol + '('),
                             original.replace('@' + target + '(', '@' + self.symbol + '('))

    def test_every_instruction_and_argument_is_load_bearing(self):
        self.prepare_prefix()
        driver = self.driver
        count = 0
        for line in self.body.splitlines():
            if not line.strip() or line.strip().startswith(';') or line.rstrip().endswith(':'):
                continue
            with self.subTest(line=line), self.assertRaises(ValueError):
                self.check(body=self.body.replace(line, '', 1))
            count += 1
        for before, after in [('2305843009213693951', '18446744073709551615'),
                              ('2305843009213693950', '0'), ('i64 %tag_bytes, 16', 'i64 %tag_bytes, 17'),
                              ('store i8 -1', 'store i8 0'), ('store i8 8', 'store i8 7'),
                              ('ptr %_0, align 16', 'ptr %owner, align 16')]:
            self.assertIn(before, self.body)
            with self.subTest(change=after), self.assertRaises(ValueError):
                self.check(body=self.body.replace(before, after))
            count += 1
        call = next(line for line in self.body.splitlines() if driver.syntax.call(line))
        for value in ('%_0', '%owner', '%key.0', '%key.1', '%tag_bytes'):
            with self.subTest(argument=value), self.assertRaises(ValueError):
                self.check(body=self.body.replace(call, call.replace(value, '%substituted')))
            count += 1
        self.assertGreater(count, 25)

    def test_extra_access_unknown_identity_and_alias_cycle_reject(self):
        self.prepare_prefix()
        driver = self.driver
        for extra in ('%secret = load i8, ptr %key.0, align 1',
                      'store i8 0, ptr %key.0, align 1', 'call void @unexpected(ptr %owner)'):
            with self.assertRaises(ValueError):
                self.check(body=self.body.replace('start:', 'start:\n' + extra))
        with self.assertRaises(ValueError):
            self.check(names={**self.names, self.symbol: self.names[self.symbol].replace('129', '511')})
        with self.assertRaises(ValueError):
            self.check(aliases={**self.aliases, self.symbol: self.symbol})
        for value in ('%_0', '%owner', '%key.0', '%key.1', '%tag_bytes'):
            with self.assertRaises(ValueError):
                self.check(arguments=self.arguments.replace(value, '%substituted'))
        with self.assertRaises(ValueError):
            driver.prefix.check(self.symbol, self.definitions, self.aliases, self.names, 'unknown')
