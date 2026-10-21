"""Host transaction/destructor regressions against real emissions and compiling source mutants."""
import re
import itertools


class TransactionTests:
    def test_transaction_undefined_bits_and_unsigned_extension(self):
        v = self.driver.transaction.values
        resolve = {'%byte': -1, '%undefined': v.Unknown()}.__getitem__
        self.assertEqual(v.evaluate('zext i8 %byte to i16', resolve), 255)
        self.assertEqual(v.evaluate('trunc i8 %byte to i1', resolve), 1)
        unknown = v.evaluate('zext i8 %undefined to i16', resolve)
        shifted = v.evaluate('shl i16 %unknown, 8', lambda token: unknown if token == '%unknown' else int(token))
        result = v.evaluate('or i16 %high, 255', lambda token: shifted if token == '%high' else int(token))
        self.assertEqual(v.integer(result, 8), 255)
        with self.assertRaises(ValueError):
            v.integer(result, 16)
        with self.assertRaises(ValueError):
            v.evaluate('icmp eq i8 %undefined, 0', lambda token: v.Unknown() if token == '%undefined' else 0)
        # Compare the unknown-bit abstraction with every concrete value of
        # these small domains, including unknown high-byte bits. A bit marked
        # known must agree with every concretization, not merely one example.
        for width in (8, 16):
            mask = (1 << width) - 1
            domains = []
            for base, positions in itertools.product((0, mask, 0x55), ((0,), (1, width - 1))):
                known = mask ^ sum(1 << bit for bit in positions)
                concrete = [base & known | sum(value << bit for bit, value in zip(positions, assignment))
                            for assignment in itertools.product((0, 1), repeat=len(positions))]
                domains.append((v.Unknown(base, known | ~mask), concrete))
            for (left, ls), (right, rs), op in itertools.product(domains, domains, ('or', 'and', 'xor')):
                output = v.evaluate(f'{op} i{width} %left, %right', {'%left': left, '%right': right}.__getitem__)
                number, known = v.parts(output)
                for a, b in itertools.product(ls, rs):
                    actual = {'or': a | b, 'and': a & b, 'xor': a ^ b}[op]
                    self.assertEqual((actual ^ number) & known & mask, 0)
            for unknown, concrete in domains:
                for shift in (0, 1, width - 1):
                    output = v.evaluate(f'shl i{width} %word, {shift}',
                                        lambda token: unknown if token == '%word' else int(token))
                    number, known = v.parts(output)
                    for actual in concrete:
                        self.assertEqual(((actual << shift) ^ number) & known & mask, 0)

    def transaction_model(self, arguments, body, names, target, compiled, compiler):
        d = self.driver
        record = d.capture.Record(arguments, body, names, target, compiled)
        model = d.transaction.check(record, compiled, compiler)
        d.guard_paths.check(model)
        return model

    def transaction_mutants(self, model, body):
        d, r = self.driver, model.r
        mutants = []
        for point, (name, args) in model.calls.items():
            line = r.graph[point[0]][point[1]]
            if name == model.drop:
                # Preserve invoke normal/unwind successors when deleting a call.
                replacement = ''
                old = line
                if 'invoke ' in line:
                    edges = r.graph[point[0]][point[1] + 1]
                    old += '\n' + edges
                    replacement = 'br label %' + re.search('to label %' + d.common.LABEL, edges)[1]
                mutants.append(body.replace(old, replacement, 1))
            elif name.endswith(('Mapping>::clear', 'ProtectedBytes>::clear')):
                if r.destination(d.syntax.operand(args[0])) in (('self', 136), ('self', 192)):
                    mutants.append(body.replace(line, line.replace(args[0], 'ptr %self'), 1))
            elif name == model.cancel and r.before(model.start, point):
                mutants.append(body.replace(line, line.replace(args[0], 'ptr %self'), 1))
                # A forced passing Result is valid LLVM, not a parser typo.
                result = re.match('(' + d.syntax.VALUE + ') = ', line)[1]
                old = line
                replacement = result + ' = insertvalue { i8, i8 } { i8 ' + str(model.ok) + ', i8 0 }, i8 0, 1'
                if 'invoke ' in line:
                    edges = r.graph[point[0]][point[1] + 1]
                    old += '\n' + edges
                    replacement += '\nbr label %' + re.search('to label %' + d.common.LABEL, edges)[1]
                mutants.append(body.replace(old, replacement, 1))
        for mode, point, dest, _, source, kind in r.writes:
            address = r.destination(dest)
            line = r.graph[point[0]][point[1]]
            if address in ((model.guard, 16), ('self', 256)):
                for number in ('0', '1'):
                    changed = line.replace('store i8 ' + source + ',', 'store i8 ' + number + ',', 1)
                    if changed != line:
                        mutants.append(body.replace(line, changed, 1))
            if address in ((model.guard, 0), (model.guard, 8)):
                mutants.append(body.replace(line, line.replace('store ptr ' + source + ',', 'store ptr %self,'), 1))
        for label, lines in r.graph.items():
            for index, line in enumerate(lines):
                if not r.before(model.start, (label, index)):
                    continue
                if 'icmp eq i8 ' in line or 'icmp ne i8 ' in line:
                    changed = line.replace('icmp eq', 'icmp ne') if 'icmp eq' in line else line.replace('icmp ne', 'icmp eq')
                    # llvm.assume is a separate valid-enum premise; mutate the
                    # admission/shape/quarantine branches, not that premise.
                    if index + 1 < len(lines) and '@llvm.assume' not in lines[index + 1]:
                        mutants.append(body.replace(line, changed, 1))
                if line.startswith('ret i16 '):
                    mutants.append(body.replace(line, 'ret i16 ' + str(model.ok | 2 << 8), 1))
                if re.search(r'= load i8, ptr %result,', line):
                    mutants.append(body.replace(line, line.replace('ptr %result,', 'ptr %kernel,'), 1))
                if line.startswith('store i8 ') and (label, index) in model.keep:
                    mutants.append(body.replace(line, line + '\nstore i8 ' + str(model.ok) + ', ptr %result, align 1', 1))
        return mutants

    def check_transaction_profile(self, target, profile, compiler):
        d, count = self.driver, 0
        _, definitions, _, names, checked = profile
        for symbol in checked:
            arguments, original = definitions[symbol]
            compiled = 'CompiledSession<' in names[symbol]
            body = '\n'.join(label + ':\n' + '\n'.join(lines) for label, lines in d.common.blocks(original).items())
            model = self.transaction_model(arguments, body, names, target, compiled, compiler)
            self.assertEqual(model.check(), 180)
            for case, mutant in enumerate(self.transaction_mutants(model, body)):
                self.assertNotEqual(mutant, body)
                with self.subTest(target=target, executor=names[symbol], case=case), self.assertRaises(ValueError):
                    self.transaction_model(arguments, mutant, names, target, compiled, compiler)
                count += 1
        return count

    def test_joined_host_transaction_mutations(self):
        count = sum(self.check_transaction_profile(target, profile, '1.99.1') for target, profile in self.profiles.items())
        self.assertGreater(count, 1000)
        print(f'Hosted final transaction: {count} emitted mutations rejected', flush=True)

    def test_msrv_joined_host_transaction_mutations(self):
        d, count = self.driver, 0
        for target in d.TARGETS:
            llvm = d.emit(self.root / ('transaction-msrv-' + target), '1.90.0', target, 'abort')[1]
            count += self.check_transaction_profile(target, (llvm, *d.validate(llvm, target, '1.90.0', 'abort')), '1.90.0')
        self.assertGreater(count, 1000)
        print(f'Hosted MSRV final transaction: {count} emitted mutations rejected', flush=True)

    def test_emitted_buffer_destructor_mutations(self):
        d, count = self.driver, 0
        for compiler in ('1.90.0', '1.99.1'):
            for target in d.TARGETS:
                llvm = d.emit_callees(self.root / ('buffers-' + compiler + '-' + target), compiler, target, 'unwind')
                arguments, body, names = d.buffers.validate(llvm, target)
                mutants = []
                for line in body.splitlines():
                    call = d.syntax.call(line)
                    if call and names.get(call[0]) == 'brynja_core::secret_memory::clear_owned_region':
                        mutants.extend((body.replace(line, '', 1),
                                        body.replace(line, line.replace(call[1][0], 'ptr %self'), 1),
                                        body.replace(line, line.replace(call[1][1], 'i64 1'), 1)))
                    if '= icmp eq ' in line or '= icmp ne ' in line:
                        mutants.append(body.replace(line, line.replace('icmp eq', 'icmp ne') if 'icmp eq' in line
                                                    else line.replace('icmp ne', 'icmp eq'), 1))
                    if line.strip() == 'ret void':
                        mutants.append(body.replace(line, 'store i8 1, ptr %self, align 1\nret void', 1))
                for case, mutant in enumerate(mutants):
                    with self.subTest(compiler=compiler, target=target, case=case), self.assertRaises(ValueError):
                        d.buffers.check(arguments, mutant, names, target)
                    count += 1
        self.assertGreater(count, 40)
        print(f'Hosted buffer destructor: {count} emitted mutations rejected', flush=True)

    def test_hosted_actual_constructor_authority_binding(self):
        d, count = self.driver, 0
        for target, (_, definitions, aliases, names, checked) in self.profiles.items():
            for arguments, body, identity, compiled in self.output_workers(definitions, aliases, names, checked, target):
                if not compiled:
                    continue
                model = d.keyed.check(body, names, '1.99.1', identity, True)
                symbol = d.callee_admission.check(model, identity, definitions, aliases, '1.99.1', 'unwind')
                formals, constructor = d.common.resolve(symbol, definitions, aliases)
                missing = dict(definitions)
                del missing[symbol]
                with self.assertRaises(ValueError):
                    d.callee_admission.check(model, identity, missing, aliases, '1.99.1', 'unwind')
                count += 1
                for line in constructor.splitlines():
                    call = d.syntax.call(line)
                    if call and d.callee_admission.admission.contracts.factory(call[0], identity) and '%owner' in line:
                        for replacement in ('%key.0', '%_0'):
                            mutant = dict(definitions)
                            mutant[symbol] = formals, constructor.replace(line, line.replace('%owner', replacement), 1)
                            with self.subTest(target=target, identity=identity), self.assertRaises(ValueError):
                                d.callee_admission.check(model, identity, mutant, aliases, '1.99.1', 'unwind')
                            count += 1
                mutant = dict(definitions)
                mutant[symbol] = formals.replace('%owner', '%other'), constructor
                with self.assertRaises(ValueError):
                    d.callee_admission.check(model, identity, mutant, aliases, '1.99.1', 'unwind')
                count += 1
        self.assertEqual(count, 288)
        print(f'Hosted actual constructor authority: {count} callee binding mutations rejected', flush=True)

    def test_real_compiled_host_transaction_mutants(self):
        d, count = self.driver, 0
        work = self.root / 'compiled-host-transaction'
        host, fixture = self.compiled_fixture(work)
        for target, prefix in ((d.TARGETS[0], 'strict_hmac'), (d.TARGETS[2], 'macos_resident/hmac')):
            for file in ('mod.rs', 'compiled.rs'):
                path = host / 'src' / prefix / file
                original = path.read_text()
                start = original.index('    fn execute(')
                end = original.index('\n}\n', start)
                function = original[start:end]
                variants = [function.replace('guard.keep = !verifying;', 'guard.keep = true;'),
                            function.replace('guard.keep = !verifying;', 'guard.keep = false;'),
                            function.replace('if value.is_some() != verifying {' if file == 'compiled.rs'
                                             else 'if result.is_some() != verifying {', 'if false {')]
                position = function.rindex('cancel.check()?;')
                variants.append(function[:position] + '/* lost final cancellation */' + function[position + len('cancel.check()?;'):])
                variants.append(function[:position] + 'cancel.check().map_err(|_| Error::Invariant)?;'
                                + function[position + len('cancel.check()?;'):])
                if file == 'compiled.rs':
                    variants.extend((function.replace('self.quarantined = true;', 'self.quarantined = false;'),
                                     function.replace('self.quarantined = false;', 'self.quarantined = true;'),
                                     function.replace('Error::InvalidBits', 'Error::Invariant'),
                                     function.replace('Err(error) => Err(error),',
                                         'Err(error @ Error::Backend(brynja_crypto_cpu::static_execution::Error::WrongOperation))'
                                         ' => { self.quarantined = false; Err(error) },\nErr(error) => Err(error),')))
                for case, changed in enumerate(variants):
                    self.assertNotEqual(changed, function)
                    try:
                        path.write_text(original[:start] + changed + original[end:])
                        llvm = d.emit(work / target, '1.99.1', target, 'unwind', fixture / 'Cargo.toml')[1]
                        with self.subTest(target=target, file=file, case=case), self.assertRaises(ValueError):
                            d.validate(llvm, target)
                        count += 1
                    finally:
                        path.write_text(original)
            path = host / 'src' / prefix / 'mod.rs'
            original = path.read_text()
            start = original.index("impl Drop for Buffers<'_>")
            end = original.index('\n}\n', start) + 2
            destructor = original[start:end]
            for changed in (destructor.replace('self.staging.clear();', ''),
                            destructor.replace('if !self.keep {', 'if self.keep {'),
                            destructor.replace('self.output.clear();', 'self.staging.clear();')):
                try:
                    path.write_text(original[:start] + changed + original[end:])
                    llvm = d.emit_callees(work / target, '1.99.1', target, 'unwind', fixture / 'Cargo.toml')
                    with self.assertRaises(ValueError):
                        d.buffers.validate(llvm, target)
                    count += 1
                finally:
                    path.write_text(original)
            d.validate(d.emit(work / target, '1.99.1', target, 'unwind', fixture / 'Cargo.toml')[1], target)
        self.assertEqual(count, 34)
        print(f'Hosted transaction: {count} real compiling host/destructor mutants rejected', flush=True)
