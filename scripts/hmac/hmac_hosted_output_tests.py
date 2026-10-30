"""Output provenance and cleanup mutants in actual hosted worker emissions."""
import re


class OutputTests:
    def output_workers(self, definitions, aliases, names, checked, target):
        for body, identity, compiled in self.keyed_workers(definitions, aliases, names, checked, target):
            arguments = [args for args, candidate in definitions.values() if candidate == body]
            self.assertEqual(len(arguments), 1)
            yield arguments[0], body, identity, compiled

    def test_output_provenance_lifetimes_and_cleanup_paths(self):
        d, cases = self.driver, 0
        for target, (_, definitions, aliases, names, checked) in self.profiles.items():
            for arguments, body, identity, compiled in self.output_workers(definitions, aliases, names, checked, target):
                model = d.keyed.check(body, names, '1.99.1', identity, compiled)
                output = d.output.check(model, arguments)
                mutants = []
                visited = d.output.paths.check(output, 'unwind')
                for symbol, _, point in model.calls:
                    if names.get(symbol) not in ('core::panicking::panic_in_cleanup', 'core::panicking::panic_cannot_unwind'):
                        continue
                    if point[0] not in {row[0] for row in visited}:
                        continue
                    line = model.graph[point[0]][point[1]]
                    mutants.append(body.replace(line, line.replace(symbol, 'impostor_panic_in_cleanup'), 1))
                for name, point in output.origins.items():
                    line = model.graph[point[0]][point[1]]
                    rhs = model.defs[name][0]
                    if rhs.startswith('getelementptr'):
                        match = re.search(r'i64 (\d+)', line)
                        self.assertIsNotNone(match)
                        changed = line[:match.start()] + 'i64 ' + str(int(match[1]) + 8) + line[match.end():]
                    elif rhs.startswith('select'):
                        changed = line.replace('ptr inttoptr (i64 1 to ptr)', 'ptr null') if 'ptr ' in rhs else line.replace('i64 0', 'i64 1')
                    else:
                        self.assertTrue(rhs.startswith('load'))
                        changed = re.sub(r'ptr ' + d.syntax.VALUE + ',', 'ptr %unknown,', line)
                    self.assertNotEqual(changed, line)
                    mutants.append(body.replace(line, changed, 1))
                for args, point in (output.verify, output.final, output.copy):
                    line = model.graph[point[0]][point[1]]
                    for index in (2, 3) if point == output.verify[1] else ((3, 4) if point == output.final[1] else range(4)):
                        replacement = 'ptr %unknown' if args[index].startswith('ptr ') else 'i64 0'
                        mutants.append(body.replace(line, line.replace(args[index], replacement, 1), 1))
                for point in output.stores:
                    line = model.graph[point[0]][point[1]]
                    mutants += [body.replace(line, '', 1), body.replace(line, line + '\n' + line, 1)]
                    other = next(at for at in output.stores if at != point)
                    mutants.append(body.replace(line, model.graph[other[0]][other[1]], 1))
                copy_line = model.graph[output.copy[1][0]][output.copy[1][1]]
                for root in (output.owner[0], output.result[0]):
                    for extra in ('%escaped_output = ptrtoint ptr ' + root + ' to i64',
                                  'store ptr ' + root + ', ptr %unknown, align 8',
                                  '%aliased_output = getelementptr i8, ptr ' + root + ', i64 %offset',
                                  'call void @unreviewed_output(ptr ' + root + ')'):
                        mutants.append(body.replace(copy_line, extra + '\n' + copy_line, 1))
                    start = next(point for symbol, args, point in model.calls
                                 if symbol == 'llvm.lifetime.start.p0'
                                 and model.pointer(d.syntax.operand(args[-1])) == (root, 0))
                    line = model.graph[start[0]][start[1]]
                    mutants.extend((body.replace(line, '', 1), body.replace(line, line + '\n' + line, 1)))
                for value in output.payload:
                    kind = 'i1' if model.defs[value][0].startswith('icmp') else (
                        'ptr' if re.match(r'(?:load ptr|select i1 .*?, ptr )', model.defs[value][0]) else 'i64')
                    mutants.append(body.replace(copy_line, 'store ' + kind + ' ' + value
                                                + ', ptr %escaped_destination, align 1\n' + copy_line, 1))
                for args, point in output.drops:
                    line = model.graph[point[0]][point[1]]
                    mutants.append(body.replace(line, line.replace(args[0], 'ptr %unknown', 1), 1))
                    if 'invoke ' in line:
                        edges = model.graph[point[0]][point[1] + 1]
                        edge = re.match(r'to label %' + d.common.LABEL, edges)
                        self.assertIsNotNone(edge)
                        mutants.append(body.replace(line, 'br label %' + edge[1], 1).replace(edges, '', 1))
                    else:
                        mutants += [body.replace(line, '', 1), body.replace(line, line + '\n' + line, 1)]
                        mutants.append(body.replace(line, line + '\n%late_output = load i8, ptr '
                                                    + output.owner[0] + ', align 1', 1))
                for extra in ('ret void', 'resume {ptr, i32} zeroinitializer',
                              'call void @llvm.lifetime.end.p0(ptr ' + output.owner[0] + ')',
                              'call void @unknown_may_unwind()'):
                    cut = model.graph[output.cut[0]][output.cut[1]]
                    mutants.append(body.replace(cut, cut + '\n' + extra, 1))
                # Reversing Result admission must not turn an Err into a live owner.
                success, failure = output.guard()
                branch = next(line for lines in model.graph.values() for line in lines
                              if line.startswith('br i1 ') and set(re.findall(
                                  r'label %' + d.common.LABEL, line)) == {success, failure})
                flipped = branch.replace('label %' + success, 'label %__swap', 1).replace(
                    'label %' + failure, 'label %' + success, 1).replace('label %__swap', 'label %' + failure)
                mutants.append(body.replace(branch, flipped, 1))
                for mutant in mutants:
                    with self.subTest(target=target, identity=identity, compiled=compiled, case=cases):
                        self.assertNotEqual(mutant, body)
                        with self.assertRaises(ValueError):
                            changed = d.keyed.Admission(mutant, names, '1.99.1', identity, compiled)
                            d.output.check(changed, arguments)
                    cases += 1
        self.assertGreater(cases, 3000)
        print(f'Hosted output provenance/cleanup: {cases} mutations rejected', flush=True)

    def test_msrv_output_speculation_is_not_admission(self):
        d, cases, hoisted, extents = self.driver, 0, 0, 0
        for target in d.TARGETS:
            llvm = d.emit(self.root / ('output-msrv-' + target), '1.90.0', target, 'abort')[1]
            definitions, aliases, names, checked = d.validate(llvm, target, '1.90.0', 'abort')
            for arguments, body, identity, compiled in self.output_workers(definitions, aliases, names, checked, target):
                model = d.keyed.check(body, names, '1.90.0', identity, compiled)
                output = d.output.check(model, arguments, 'abort')
                success, failure = output.guard()
                for symbol, args, point in model.calls:
                    if not symbol.startswith('llvm.lifetime.') or len(args) != 2:
                        continue
                    address = model.pointer(d.syntax.operand(args[-1]))
                    if not address or address[0] not in (output.owner[0], output.result[0]):
                        continue
                    line = model.graph[point[0]][point[1]]
                    mutant = body.replace(line, line.replace(args[0], 'i64 1', 1), 1)
                    with self.assertRaisesRegex(ValueError, 'output lifetime extent'):
                        changed = d.keyed.Admission(mutant, names, '1.90.0', identity, compiled)
                        d.output.check(changed, arguments, 'abort')
                    extents += 1
                for value in output.payload:
                    rhs, point = model.defs[value]
                    if point not in output.reads or model.before((success, -1), point):
                        continue
                    hoisted += 1
                    first = model.graph[failure][0]
                    # Place after the first instruction (which may be a phi).
                    kind = 'ptr' if rhs.startswith('load ptr') else 'i64'
                    mutant = body.replace(first, first + '\nstore ' + kind + ' ' + value
                                          + ', ptr %escaped_error_value, align 1', 1)
                    with self.assertRaisesRegex(ValueError, 'unreviewed returned output value'):
                        changed = d.keyed.Admission(mutant, names, '1.90.0', identity, compiled)
                        d.output.check(changed, arguments, 'abort')
                    cases += 1
        self.assertGreater(hoisted, 0)
        self.assertEqual(cases, hoisted)
        self.assertGreaterEqual(extents, 288)
        print(f'Hosted MSRV output: {cases} error-path escapes and {extents} lifetime extents rejected', flush=True)

    def check_compiled_output_mutants(self, host, fixture, work):
        d = self.driver
        for target, directory in ((d.TARGETS[0], 'strict_hmac'), (d.TARGETS[2], 'macos_resident/hmac')):
            for compiled in (False, True):
                path = host / 'src' / directory / ('compiled/worker.rs' if compiled else 'worker.rs')
                original = path.read_text()
                call = 'checkpoint(cancel, &owner)' if compiled else 'checkpoint(cancel)'
                anchor = '.finalize_bits_secret(tail, staging)\n            .map_err(Error::Mac)?;\n        ' + call + '?;'
                self.assertEqual(original.count(anchor), 1)
                forgotten = anchor.rsplit('\n', 1)[0] + '\n        if let Err(error) = ' + call + ' { core::mem::forget(secret); return Err(error); }'
                shortened = original.replace('        let secret = state',
                                             '        let staging_len = staging.len().saturating_sub(1);\n        let secret = state')
                variants = [original.replace(anchor, forgotten),
                            shortened.replace('.finalize_bits_secret(tail, staging)',
                                              '.finalize_bits_secret(tail, &mut staging[..staging_len])')]
                for case, mutant in enumerate(variants):
                    try:
                        path.write_text(mutant)
                        llvm = d.emit(work / target, '1.99.1', target, 'unwind', fixture / 'Cargo.toml')[1]
                        definitions, aliases = d.common.definitions_and_aliases(llvm)
                        names = d.lifecycle.demangle({n.strip('"') for n in re.findall(r'@("[^"]+"|[-\w.$]+)', llvm)})
                        workers = [symbol for symbol in definitions if '::thread::enter' in names[symbol]
                                   and ('CompiledSession<' in names[symbol]) == compiled and '::execute::' in names[symbol]]
                        self.assertEqual(len(workers), 12)
                        for worker in workers:
                            identity = next(identity for identity in d.common.IDENTITIES
                                            if ('general::Sha512T<' + identity[7:] + '>' if identity.startswith('general')
                                                else 'algorithms::Sha' + identity[3:] + '>') in names[worker])
                            arguments, body = d.common.resolve(worker, definitions, aliases)
                            with self.subTest(target=target, compiled=compiled, case=case, identity=identity):
                                # Exercise output lifetime/cleanup rejection even
                                # when the mutant also fails earlier admission.
                                model = d.keyed.Admission(body, names, '1.99.1', identity, compiled)
                                with self.assertRaises(ValueError):
                                    d.output.check(model, arguments)
                        with self.assertRaises(ValueError):
                            d.validate(llvm, target)
                    finally:
                        path.write_text(original)
                    d.validate(d.emit(work / target, '1.99.1', target, 'unwind', fixture / 'Cargo.toml')[1], target)
        print('Hosted output: eight real compiled Rust mutants rejected; restored baselines pass', flush=True)
