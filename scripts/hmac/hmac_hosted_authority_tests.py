"""Authority transfer/admission mutations against emitted hosted callbacks."""
import re


class AuthorityTests:
    def test_worker_authority_transfer_admission_and_lifetime(self):
        driver = self.driver
        cases = 0
        for target, (_, definitions, aliases, names, checked) in self.profiles.items():
            for symbol in checked:
                if 'CompiledSession<' not in names[symbol]:
                    continue
                worker = driver.lifecycle.check_host(definitions[symbol][1], names, definitions, target)
                body = driver.common.resolve(worker, definitions, aliases)[1]
                transfer = driver.authority.check(body, names)
                mutants = []
                for mode, point, dest, data in transfer.writes:
                    address = transfer.pointer(dest)
                    if not address or address[0] != transfer.owner:
                        continue
                    line = transfer.graph[point[0]][point[1]]
                    mutants.append(body.replace(line, '', 1))
                    if mode == 'copy':
                        extent = int(data[2].split()[1])
                        changed = line.replace(data[2], 'i64 ' + str(extent - 1), 1)
                        wrong_source = line.replace(data[1], 'ptr ' + transfer.owner, 1)
                        mutants.append(body.replace(line, wrong_source, 1))
                    else:
                        changed = line.replace(data, 'i8 0', 1)
                    mutants.append(body.replace(line, changed, 1))
                    mutants.append(body.replace(line, line + '\n' + line, 1))
                guard = transfer.graph[transfer.guard[0]][transfer.guard[1]]
                flipped = guard.replace('icmp eq', 'icmp ne') if 'icmp eq' in guard else guard.replace('icmp ne', 'icmp eq')
                mutants.extend((body.replace(guard, flipped, 1), body.replace(guard, guard.replace(', -1', ', 6'), 1)))
                ctor = next(point for symbol, _, point in transfer.calls
                            if names.get(symbol) == '<brynja_crypto_cpu::static_execution::Authority>::new')
                edges = transfer.graph[ctor[0]][ctor[1] + 1]
                edge = re.fullmatch(r'to label %' + driver.common.LABEL + r' unwind label %' + driver.common.LABEL, edges)
                self.assertIsNotNone(edge)
                mutants.append(body.replace(edges, 'to label %' + edge[2] + ' unwind label %' + edge[1], 1))
                entry = next(iter(transfer.graph.values()))[-1]
                bypass = re.sub(r'label %' + driver.common.LABEL,
                                'label %' + transfer.returned[0], entry, count=1)
                self.assertNotEqual(entry, bypass)
                mutants.append(body.replace(entry, bypass, 1))
                consumer = next((args, point) for symbol, args, point in transfer.calls
                                if names.get(symbol, '').startswith('<brynja_mac_hmac::execution::Hmac<')
                                and names[symbol].endswith('>::create'))
                line = transfer.graph[consumer[1][0]][consumer[1][1]]
                for extra in (
                        'call void @llvm.lifetime.end.p0(ptr ' + transfer.owner + ')',
                        'store ptr ' + transfer.owner + ', ptr %argument, align 8',
                        'call void @unreviewed_authority(ptr ' + transfer.owner + ')',
                        'call void @llvm.memcpy.p0.p0.i64(ptr %argument, ptr ' + transfer.owner + ', i64 16, i1 false)',
                        'store i8 0, ptr ' + transfer.result + ', align 1',
                        '%escaped = ptrtoint ptr ' + transfer.owner + ' to i64'):
                    mutants.append(body.replace(line, '  ' + extra + '\n' + line, 1))
                # Result lifetime cannot end before its first component read.
                point = min(transfer.reads, key=lambda p: list(transfer.graph).index(p[0]) * 10000 + p[1])
                line = transfer.graph[point[0]][point[1]]
                mutants.append(body.replace(line, '  call void @llvm.lifetime.end.p0(ptr '
                                            + transfer.result + ')\n' + line, 1))
                for symbol, args, point in transfer.calls:
                    if names.get(symbol) in driver.authority.CHECKPOINTS:
                        line = transfer.graph[point[0]][point[1]]
                        extra = '  %wrong_owner = getelementptr i8, ptr ' + transfer.owner + ', i64 1\n'
                        mutants.append(body.replace(line, extra + line.replace(args[1], 'ptr %wrong_owner', 1), 1))
                        break
                for mutant in mutants:
                    with self.subTest(target=target, worker=names[worker], case=cases):
                        self.assertNotEqual(mutant, body)
                        with self.assertRaises(ValueError):
                            driver.authority.check(mutant, names)
                    cases += 1
        self.assertGreaterEqual(cases, 800)
        print(f'Hosted authority admission/transfer/lifetime: {cases} mutations rejected', flush=True)

    def test_msrv_authority_error_niche_is_not_interchangeable(self):
        driver = self.driver
        count = 0
        for target in driver.TARGETS:
            llvm = driver.emit(self.root / ('authority-msrv-' + target), '1.90.0', target, 'abort')[1]
            definitions, aliases, names, checked = driver.validate(llvm, target, '1.90.0', 'abort')
            for symbol in checked:
                if 'CompiledSession<' not in names[symbol]:
                    continue
                worker = driver.lifecycle.check_host(definitions[symbol][1], names, definitions, target)
                body = driver.common.resolve(worker, definitions, aliases)[1]
                transfer = driver.authority.check(body, names, '1.90.0')
                guard = transfer.graph[transfer.guard[0]][transfer.guard[1]]
                self.assertTrue(guard.endswith(', 6'))
                with self.assertRaises(ValueError):
                    driver.authority.check(body.replace(guard, guard.replace(', 6', ', -1'), 1), names, '1.90.0')
                count += 1
        self.assertEqual(count, 36)

    def test_emitted_compiler_identity_cannot_borrow_other_niche(self):
        driver = self.driver
        for target, (llvm, _, _, _, _) in self.profiles.items():
            for compiler in ('1.90.0', '2.0.0'):
                with self.assertRaises(ValueError):
                    driver.validate(llvm, target, compiler)
            with self.assertRaises(ValueError):
                driver.validate(llvm.replace('rustc version 1.99.1 ', 'rustc version unknown '), target)

    def check_compiled_authority_mutants(self, host, fixture, work):
        driver = self.driver
        for target, directory in ((driver.TARGETS[0], 'strict_hmac'),
                                  (driver.TARGETS[2], 'macos_resident/hmac')):
            path = host / 'src' / directory / 'compiled/worker.rs'
            original = path.read_text()
            anchor = 'let owner = Authority::new(kernel).map_err(Error::Backend)?;'
            self.assertEqual(original.count(anchor), 2)  # Probe and request path.
            try:
                # A real safe-Rust change to the freshly admitted authority,
                # compiled successfully before inspecting its emitted stores.
                path.write_text(original.replace(anchor, anchor + '\n    owner.quarantine();'))
                llvm = driver.emit(work / target, '1.99.1', target, 'unwind', fixture / 'Cargo.toml')[1]
                definitions, aliases = driver.common.definitions_and_aliases(llvm)
                names = driver.lifecycle.demangle({n.strip('"') for n in re.findall(r'@("[^"]+"|[-\w.$]+)', llvm)})
                workers = [symbol for symbol in definitions if '::thread::enter' in names[symbol]
                           and 'CompiledSession<' in names[symbol] and '::execute::' in names[symbol]]
                self.assertEqual(len(workers), 12)
                for worker in workers:
                    # Call the new checker directly: rejection must not come
                    # merely from an unrelated source pin or population guard.
                    with self.assertRaises(ValueError):
                        driver.authority.check(driver.common.resolve(worker, definitions, aliases)[1], names)
            finally:
                path.write_text(original)
            driver.validate(driver.emit(work / target, '1.99.1', target, 'unwind', fixture / 'Cargo.toml')[1], target)
