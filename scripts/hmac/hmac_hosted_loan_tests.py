"""Actual public-loan emissions and compiling host API regression mutants."""
import re
from unittest import mock


class LoanTests:
    def test_loan_flow_undefined_shift_and_unreviewed_effects(self):
        flow = self.driver.loans.flow
        def forbidden(*_):
            self.fail('unexpected call')
        for width in (8, 16, 64):
            mask = (1 << width) - 1
            for amount in (0, 1, width - 1):
                body = f'start:\n%x = lshr i{width} %source, {amount}\nret i64 %x'
                for number in (0, 1, 0xAB34, mask):
                    outcome, value, _ = flow.run(body, {'%source': number}, {}, forbidden)
                    self.assertEqual((outcome, value), ('return', (number & mask) >> amount))
            with self.assertRaises(ValueError):
                flow.run(f'start:\n%x = lshr i{width} %source, {width}\nret i64 %x',
                         {'%source': 1}, {}, forbidden)
        body = 'start:\n%x = lshr i16 %source, 8\nret i16 %x'
        _, value, _ = flow.run(body, {'%source': flow.expressions.Unknown(0xAB34, 255)}, {}, forbidden)
        with self.assertRaises(ValueError):
            flow.expressions.integer(value, 8)
        _, value, _ = flow.run(body, {'%source': flow.expressions.Unknown(0xAB34, 0xFF00)}, {}, forbidden)
        self.assertEqual(value, 0xAB)
        for mutant in ('start:\nstore i8 0, ptr %source, align 1\nret void',
                       'start:\n%x = load i8, ptr %source, align 1\nret i8 %x',
                       'start:\nbr label %start',
                       'start:\nbr i1 undef, label %yes, label %no\nyes:\nret void\nno:\nret void'):
            with self.assertRaises(ValueError):
                flow.run(mutant, {'%source': ('unknown', 0)}, {}, forbidden)

    def loan_rows(self, profile):
        d = self.driver
        _, definitions, aliases, names, _ = profile
        for identity in d.common.IDENTITIES:
            for method in d.loans.METHODS:
                expected = 'brynja_hmac_hosted_cleanup_fixture::' + identity + '::' + method
                symbols = [s for s in (*definitions, *aliases) if names[s] == expected]
                self.assertEqual(len(symbols), 1)
                args, body = d.common.resolve(symbols[0], definitions, aliases)
                yield identity, method, symbols[0], args, body

    def loan_mutations(self, profile, target, compiler='1.99.1'):
        d, count = self.driver, 0
        _, definitions, aliases, names, _ = profile
        for identity, method, symbol, args, body in self.loan_rows(profile):
            d.loans.check(args, body, names, target, compiler, 'unwind', method)
            mutants = [body.replace('start:', 'start:\nstore i8 0, ptr %output.0, align 1', 1)]
            for line in body.splitlines():
                if '= getelementptr' in line:
                    mutants.append(body.replace(line, re.sub(r'i64 (\d+)', lambda m: 'i64 ' + str(int(m[1]) + 1), line), 1))
                if '= icmp eq ' in line:
                    mutants.append(body.replace(line, line.replace('icmp eq', 'icmp ne'), 1))
                call = d.syntax.call(line)
                if call and (d.loans.resources.names_for(target)[0] == names.get(call[0])
                             or call[0] == 'llvm.memcpy.p0.p0.i64'):
                    if 'invoke ' not in line:
                        mutants.append(body.replace(line, '', 1))
                    mutants.append(body.replace(line, line.replace('%output.0', '%destination.0'), 1)
                                   if '%output.0' in line else body.replace(line, line.replace(call[1][2], 'i64 0'), 1))
                if call and call[0] == 'llvm.memcpy.p0.p0.i64':
                    source = d.syntax.operand(call[1][1])
                    mutants.append(body.replace(line, line.replace(source + ',', '%destination.0,'), 1))
                if line.strip().startswith('ret ') and line.strip() != 'ret void':
                    mutants.append(body.replace(line, 'ret void', 1))
            for mutant in mutants:
                self.assertNotEqual(mutant, body)
                with self.subTest(target=target, identity=identity, method=method), self.assertRaises(ValueError):
                    d.loans.check(args, mutant, names, target, compiler, 'unwind', method)
                count += 1
            with self.assertRaises(ValueError):
                d.loans.check(args.replace('%output', '%wrong'), body, names, target, compiler, 'unwind', method)
            count += 1
        for identity in d.common.IDENTITIES:
            for compiled, method in ((False, 'compute'), (True, 'compiled_compute')):
                symbol = next(s for s in (*definitions, *aliases)
                              if names[s] == 'brynja_hmac_hosted_cleanup_fixture::' + identity + '::' + method)
                args, body = d.common.resolve(symbol, definitions, aliases)
                mutants = []
                for line in body.splitlines():
                    if '= getelementptr' in line:
                        mutants.append(body.replace(line, re.sub(r'i64 (192|248|8|9)\b',
                            lambda m: 'i64 ' + str(int(m[1]) + 1), line), 1))
                    if line.strip().startswith('store '):
                        mutants.append(body.replace(line, '', 1))
                    if '= icmp eq ' in line:
                        mutants.append(body.replace(line, line.replace('icmp eq', 'icmp ne'), 1))
                    call = d.syntax.call(line)
                    if call and names.get(call[0], '').endswith('::execute'):
                        for old, new in (('%request,', '%session,'), ('%cancel)', '%session)'),
                                         (' null,', ' %session,')):
                            mutants.append(body.replace(line, line.replace(old, new), 1))
                for mutant in mutants:
                    self.assertNotEqual(mutant, body)
                    with self.subTest(target=target, identity=identity, compiled=compiled), self.assertRaises(ValueError):
                        d.loan_creation.check(args, mutant, names, target, compiler, identity, compiled)
                    count += 1
        # Both aliases and exact populations are part of the fixture boundary.
        identity, method, symbol, _, _ = next(self.loan_rows(profile))
        with self.assertRaises(ValueError):
            d.loans.validate(definitions, {**aliases, symbol: symbol}, names, target, compiler, 'unwind')
        with self.assertRaises(ValueError):
            d.loans.validate(definitions, aliases, {**names, symbol: 'unreviewed::' + names[symbol]}, target, compiler, 'unwind')
        return count + 2

    def test_actual_public_loan_and_construction_mutations(self):
        count = sum(self.loan_mutations(profile, target) for target, profile in self.profiles.items())
        self.assertGreater(count, 1000)
        print(f'Hosted public loan/creation mutations: {count} rejected', flush=True)

    def test_public_loan_clear_guard_is_load_bearing(self):
        d = self.driver
        for target, profile in self.profiles.items():
            _, _, _, names, _ = profile
            row = next(row for row in self.loan_rows(profile) if row[0] == 'sha256' and row[1] == 'output_clear')
            _, method, _, args, body = row
            clear = d.loans.resources.names_for(target)[0]
            lines = [line for line in body.splitlines() if (call := d.syntax.call(line)) and names.get(call[0]) == clear]
            self.assertEqual(len(lines), 1)
            mutant = body.replace(lines[0], '', 1)
            with self.assertRaisesRegex(ValueError, 'loan drop lost clear'):
                d.loans.check(args, mutant, names, target, '1.99.1', 'unwind', method)
            require = d.loans.require
            def without_drop_guard(condition, message):
                if message != 'loan drop lost clear':
                    require(condition, message)
            with mock.patch.object(d.loans, 'require', side_effect=without_drop_guard):
                d.loans.check(args, mutant, names, target, '1.99.1', 'unwind', method)

    def test_msrv_public_loan_and_construction_mutations(self):
        d, count = self.driver, 0
        for target in d.TARGETS:
            llvm = d.emit(self.root / ('loan-msrv-' + target), '1.90.0', target, 'unwind')[1]
            profile = (llvm, *d.validate(llvm, target, '1.90.0'))
            count += self.loan_mutations(profile, target, '1.90.0')
        self.assertGreater(count, 1000)
        print(f'MSRV hosted public loan/creation mutations: {count} rejected', flush=True)

    def test_actual_public_loan_resource_mutations(self):
        d, count = self.driver, 0
        for target in d.TARGETS:
            llvm = d.emit_callees(self.root / target, '1.99.1', target, 'unwind')
            for args, body, names, method in d.loans.resources.validate(llvm, target):
                mutants = []
                for line in body.splitlines():
                    if '= getelementptr' in line:
                        mutants.append(body.replace(line, re.sub(r'i64 (\d+)', lambda m: 'i64 ' + str(int(m[1]) + 1), line), 1))
                    if '= icmp ' in line:
                        mutants.append(body.replace(line, line.replace('icmp eq', 'icmp ne') if 'icmp eq' in line
                                                     else line.replace('icmp ne', 'icmp eq'), 1))
                    call = d.syntax.call(line)
                    if call and call[0] == 'getpid':
                        result = re.match(r'\s*(' + d.syntax.VALUE + ') =', line)[1]
                        mutant = body.replace(line, result + ' = or i32 91, 0', 1)
                        with self.assertRaises(ValueError):
                            d.loans.resources.check(args, mutant, names, target, method)
                        # A single fixed PID sample would accept this forgery.
                        product = d.loans.resources.itertools.product
                        with mock.patch.object(d.loans.resources.itertools, 'product',
                                side_effect=lambda *axes: (row for row in product(*axes) if row[-1] == 91)):
                            d.loans.resources.check(args, mutant, names, target, method)
                        count += 1
                    if call and names.get(call[0]) == 'brynja_core::secret_memory::clear_owned_region':
                        mutants += [body.replace(line, '', 1), body.replace(line, line.replace(call[1][1], 'i64 1'), 1)]
                    if line.strip().startswith('ret ') and line.strip() != 'ret void':
                        mutants.append(body.replace(line, 'ret void', 1))
                for mutant in mutants:
                    self.assertNotEqual(mutant, body)
                    with self.assertRaises(ValueError):
                        d.loans.resources.check(args, mutant, names, target, method)
                    count += 1
        self.assertGreater(count, 25)
        print(f'Actual loan mapping-helper mutations: {count} rejected', flush=True)

    def test_real_compiling_public_loan_mutants(self):
        d, count = self.driver, 0
        work = self.root / 'compiled-loan-mutants'
        host, fixture = self.compiled_fixture(work)
        for target, module, access in ((d.TARGETS[0], 'strict_hmac', 'as_bytes'),
                                       (d.TARGETS[2], 'macos_resident/hmac', 'bytes')):
            path = host / ('src/' + module + '/mod.rs')
            original = path.read_text()
            mutations = (
                ('pub const fn bit_len(&self) -> usize {\n        self.bits',
                 'pub const fn bit_len(&self) -> usize {\n        0', 'output_bits'),
                ('pub fn expose(&self) -> &[u8] {\n        self.storage.' + access + '()',
                 'pub fn expose(&self) -> &[u8] {\n        &[]', 'output_expose'),
                ('if destination.len() != self.storage.', 'if destination.len() == self.storage.', 'output_declassify'),
                ('destination.copy_from_slice(self.expose());', 'let _ = &destination;', 'output_declassify'),
                ("impl<A: Algorithm> Drop for Output<'_, A> {\n    fn drop(&mut self) {\n        self.storage.clear();",
                 "impl<A: Algorithm> Drop for Output<'_, A> {\n    fn drop(&mut self) {\n        let _ = &self.storage;", 'output_clear'),
                ('storage: &mut self.output,', 'storage: &mut self.staging,', 'compute'),
            )
            for old, new, method in mutations:
                self.assertEqual(original.count(old), 1)
                try:
                    path.write_text(original.replace(old, new, 1))
                    llvm = d.emit(work / target, '1.99.1', target, 'unwind', fixture / 'Cargo.toml')[1]
                    definitions, aliases = d.common.definitions_and_aliases(llvm)
                    names = d.lifecycle.demangle({s.strip('"') for s in re.findall(r'@("[^"]+"|[-\w.$]+)', llvm)})
                    for identity in d.common.IDENTITIES:
                        symbol = next(s for s in (*definitions, *aliases)
                                      if names[s] == 'brynja_hmac_hosted_cleanup_fixture::' + identity + '::' + method)
                        args, body = d.common.resolve(symbol, definitions, aliases)
                        with self.subTest(target=target, identity=identity, method=method), self.assertRaises(ValueError):
                            if method == 'compute':
                                d.loan_creation.check(args, body, names, target, '1.99.1', identity, False)
                            else:
                                d.loans.check(args, body, names, target, '1.99.1', 'unwind', method)
                    count += 1
                finally:
                    path.write_text(original)
            d.validate(d.emit(work / target, '1.99.1', target, 'unwind', fixture / 'Cargo.toml')[1], target)
        self.assertEqual(count, 12)
        print(f'Hosted public loans: {count} compiling source mutants rejected across all twelve identities', flush=True)
