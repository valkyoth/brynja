"""Constructor-result transfer regressions on actual emitted worker bodies."""
import re


class KeyedTests:
    def keyed_workers(self, definitions, aliases, names, checked, target):
        driver = self.driver
        for executor in checked:
            worker = driver.lifecycle.check_host(definitions[executor][1], names, definitions, target)
            compiled = 'CompiledSession<' in names[executor]
            identities = [identity for identity in driver.common.IDENTITIES
                          if ('brynja_mac_hmac::general::Sha512T<' + identity[7:] + '>'
                              if identity.startswith('general') else
                              'brynja_mac_hmac::algorithms::Sha' + identity[3:] + '>') in names[executor]]
            self.assertEqual(len(identities), 1)
            yield driver.common.resolve(worker, definitions, aliases)[1], identities[0], compiled

    def test_keyed_result_admission_transfer_and_lifetimes(self):
        driver = self.driver
        cases = 0
        for target, (_, definitions, aliases, names, checked) in self.profiles.items():
            for body, identity, compiled in self.keyed_workers(definitions, aliases, names, checked, target):
                model = driver.keyed.check(body, names, '1.99.1', identity, compiled)
                mutants = []
                renamed = re.sub(re.escape(model.owner) + r'(?![-\w.])', '%renamed_live_hmac', body)
                driver.keyed.check(renamed, names, '1.99.1', identity, compiled)
                for root, consumer, move in model.terminals:
                    copy = model.graph[move[0]][move[1]]
                    line = model.graph[consumer[0]][consumer[1]]
                    mutants += [body.replace(copy, '', 1),
                                body.replace(copy, copy.replace('i64 ' + str(model.size),
                                                               'i64 ' + str(model.size - 1)), 1)]
                    for extra in ('call void @llvm.lifetime.end.p0(ptr ' + root + ')',
                                  'store i8 0, ptr ' + root + ', align 1',
                                  'call void @unreviewed_keyed(ptr ' + root + ')',
                                  'store ptr ' + root + ', ptr %argument, align 8',
                                  '%escaped_terminal = ptrtoint ptr ' + root + ' to i64'):
                        mutants.append(body.replace(line, '  ' + extra + '\n' + line, 1))
                    starts = [point for symbol, args, point in model.calls
                              if symbol == 'llvm.lifetime.start.p0'
                              and model.pointer(driver.syntax.operand(args[-1])) == (root, 0)]
                    self.assertEqual(len(starts), 1)
                    start = model.graph[starts[0][0]][starts[0][1]]
                    mutants.append(body.replace(start, '', 1))
                    mutants.append(body.replace(line, line + '\n' + line, 1))
                for mode, point, dest, data in model.writes:
                    address = model.address(dest)
                    if (not address or point[0] not in model.ancestors
                            or not (point == model.cut or model.can_precede(point, model.cut))):
                        continue
                    # Policy-generated Err stores are not copies of keyed state.
                    if mode != 'copy' and address[0] in model.results:
                        continue
                    line = model.graph[point[0]][point[1]]
                    mutants.append(body.replace(line, '', 1))
                    if mode == 'copy':
                        extent = int(data[2].split()[1])
                        mutants.append(body.replace(line, line.replace(data[2], 'i64 ' + str(extent - 1), 1), 1))
                        mutants.append(body.replace(line, line.replace(data[1], 'ptr ' + model.owner, 1), 1))
                    else:
                        mutants.append(body.replace(line, line.replace(data, 'i8 0', 1), 1))
                    for extra in (
                            'call void @llvm.lifetime.end.p0(ptr ' + address[0] + ')',
                            'call void @unreviewed_keyed(ptr ' + address[0] + ')',
                            'store ptr ' + address[0] + ', ptr %argument, align 8',
                            '%escaped = ptrtoint ptr ' + address[0] + ' to i64',
                            'call void @llvm.memcpy.p0.p0.i64(ptr %argument, ptr '
                            + address[0] + ', i64 1, i1 false)'):
                        mutants.append(body.replace(line, '  ' + extra + '\n' + line, 1))
                for point in model.factories:
                    line = model.graph[point[0]][point[1]]
                    root = model.factories[point][0]
                    mutants.append(body.replace(line, '%premature_keyed_read = load i8, ptr '
                                                + root + ', align 1\n' + line, 1))
                    following = model.graph[point[0]][point[1] + 1]
                    edge = re.fullmatch(r'to label %' + driver.common.LABEL + r' unwind label %'
                                        + driver.common.LABEL, following)
                    self.assertIsNotNone(edge)
                    mutants.append(body.replace(line, 'br label %' + edge[1], 1).replace(following, '', 1))
                    mutants.append(body.replace(following, 'to label %' + edge[2] + ' unwind label %' + edge[1], 1))
                if compiled:
                    # Mutate only the HMAC result guard, not cancellation/authority.
                    for rhs, point in model.defs.values():
                        match = re.fullmatch(r'icmp eq i8 (' + driver.syntax.VALUE + '), -1', rhs)
                        if match and match[1] in model.defs:
                            load = re.match(r'load i8, ptr (' + driver.syntax.VALUE + '),', model.defs[match[1]][0])
                            if load and (address := model.address(load[1])) and address[0] in model.results:
                                line = model.graph[point[0]][point[1]]
                                mutants += [body.replace(line, line.replace('icmp eq', 'icmp ne'), 1),
                                            body.replace(line, line.replace(', -1', ', 3'), 1)]
                for mutant in mutants:
                    with self.subTest(target=target, identity=identity, compiled=compiled, case=cases):
                        self.assertNotEqual(mutant, body)
                        with self.assertRaises(ValueError):
                            driver.keyed.check(mutant, names, '1.99.1', identity, compiled)
                    cases += 1
        self.assertGreaterEqual(cases, 4000)
        print(f'Hosted keyed admission/transfer/lifetime: {cases} mutations rejected', flush=True)

    def test_msrv_keyed_error_niche_is_not_interchangeable(self):
        driver = self.driver
        count = 0
        for target in driver.TARGETS:
            llvm = driver.emit(self.root / ('keyed-msrv-' + target), '1.90.0', target, 'abort')[1]
            definitions, aliases, names, checked = driver.validate(llvm, target, '1.90.0', 'abort')
            for body, identity, compiled in self.keyed_workers(definitions, aliases, names, checked, target):
                if not compiled:
                    continue
                model = driver.keyed.check(body, names, '1.90.0', identity, True)
                matches = []
                for rhs, point in model.defs.values():
                    match = re.fullmatch(r'icmp eq i8 (' + driver.syntax.VALUE + '), 3', rhs)
                    if not match or match[1] not in model.defs:
                        continue
                    load = re.match(r'load i8, ptr (' + driver.syntax.VALUE + '),', model.defs[match[1]][0])
                    if load and (address := model.address(load[1])) and address[0] in model.results:
                        matches.append(point)
                self.assertEqual(len(matches), 1)
                point = matches[0]
                line = model.graph[point[0]][point[1]]
                with self.assertRaises(ValueError):
                    driver.keyed.check(body.replace(line, line.replace(', 3', ', -1'), 1), names,
                                       '1.90.0', identity, True)
                count += 1
        self.assertEqual(count, 36)

    def check_compiled_keyed_mutants(self, host, fixture, work):
        driver = self.driver
        for target, directory in ((driver.TARGETS[0], 'strict_hmac'),
                                  (driver.TARGETS[2], 'macos_resident/hmac')):
            for compiled in (False, True):
                path = host / 'src' / directory / ('compiled/worker.rs' if compiled else 'worker.rs')
                original = path.read_text()
                anchor = '\n    .map_err(Error::Mac)?;\n'
                self.assertEqual(original.count(anchor), 1)
                replacement = ('Hmac::<A>::from_static(&owner, b"replacement key for regression")' if compiled
                               else 'mac::Hmac::<A>::new(b"replacement key for regression")')
                try:
                    # Safe Rust replaces the correctly constructed keyed state
                    # with a second, unrelated key. Compile first; source pins
                    # and placement checks must not be the reason it is killed.
                    path.write_text(original.replace(anchor, anchor + '    state = '
                                                     + replacement + '.map_err(Error::Mac)?;\n'))
                    llvm = driver.emit(work / target, '1.99.1', target, 'unwind', fixture / 'Cargo.toml')[1]
                    definitions, aliases = driver.common.definitions_and_aliases(llvm)
                    names = driver.lifecycle.demangle({n.strip('"') for n in re.findall(r'@("[^"]+"|[-\w.$]+)', llvm)})
                    workers = [symbol for symbol in definitions if '::thread::enter' in names[symbol]
                               and ('CompiledSession<' in names[symbol]) == compiled and '::execute::' in names[symbol]]
                    self.assertEqual(len(workers), 12)
                    for worker in workers:
                        identity = next(identity for identity in driver.common.IDENTITIES
                                        if ('general::Sha512T<' + identity[7:] + '>' if identity.startswith('general')
                                            else 'algorithms::Sha' + identity[3:] + '>') in names[worker])
                        with self.assertRaises(ValueError):
                            driver.keyed.check(driver.common.resolve(worker, definitions, aliases)[1], names,
                                               '1.99.1', identity, compiled)
                finally:
                    path.write_text(original)
                driver.validate(driver.emit(work / target, '1.99.1', target, 'unwind', fixture / 'Cargo.toml')[1], target)
