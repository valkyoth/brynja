"""Live-storage and scalar/compiled cleanup mutations on actual emissions."""
import re


class RetainedTests:
    def test_retained_storage_lifetimes(self):
        driver, cases = self.driver, 0
        for target, (_, definitions, aliases, names, checked) in self.profiles.items():
            for body, identity, compiled in self.keyed_workers(definitions, aliases, names, checked, target):
                model = driver.keyed.check(body, names, '1.99.1', identity, compiled)
                roots, copies, uses, starts, ends = driver.storage.check(model, identity)
                mutants = []
                for root in roots:
                    point = starts[root][0]
                    line = model.graph[point[0]][point[1]]
                    mutants.append(body.replace(line, '', 1))
                    mutants.append(body.replace(line, line + '\n' + line, 1))
                    # At each use, inject an early end rather than relying on
                    # one representative happy-path consumer.
                    for point in uses[root]:
                        line = model.graph[point[0]][point[1]]
                        mutants.append(body.replace(line, 'call void @llvm.lifetime.end.p0(ptr '
                                                    + root + ')\n' + line, 1))
                    point = next(iter(uses[root]))
                    line = model.graph[point[0]][point[1]]
                    for extra in ('%escaped_retained = ptrtoint ptr ' + root + ' to i64',
                                  'store ptr ' + root + ', ptr %argument, align 8',
                                  '%alias_retained = getelementptr i8, ptr ' + root + ', i64 %unknown_offset'):
                        mutants.append(body.replace(line, extra + '\n' + line, 1))
                for root, point in copies.items():
                    line = model.graph[point[0]][point[1]]
                    old = 'i64 ' + str(model.allocs[root])
                    mutants.append(body.replace(line, line.replace(old, 'i64 ' + str(model.allocs[root] - 1)), 1))
                for mutant in mutants:
                    with self.subTest(target=target, identity=identity, compiled=compiled, case=cases):
                        # Construct the admission parser without checking it:
                        # rejection must come from storage, not earlier guards.
                        with self.assertRaises(ValueError):
                            changed = driver.keyed.Admission(mutant, names, '1.99.1', identity, compiled)
                            driver.storage.check(changed, identity)
                    cases += 1
        self.assertGreater(cases, 2500)
        print(f'Hosted retained storage: {cases} lifetime/alias/extent mutations rejected', flush=True)

    def test_scalar_worker_cleanup_paths_and_helpers(self):
        driver, cases, helper_cases = self.driver, 0, 0
        for target, (_, definitions, aliases, names, checked) in self.profiles.items():
            for body, identity, compiled in self.keyed_workers(definitions, aliases, names, checked, target):
                if compiled:
                    continue
                model = driver.keyed.check(body, names, '1.99.1', identity, False)
                helpers = driver.scalar.check(model, identity, definitions, aliases, 'unwind')
                mutants = []
                for symbol, args, point in model.calls:
                    if not (driver.common.owner_drop(symbol, identity) or symbol in helpers):
                        continue
                    line = model.graph[point[0]][point[1]]
                    destination = driver.syntax.operand(args[0])
                    mutants.append(body.replace(line, line.replace(args[0], 'ptr %argument', 1), 1))
                    if 'invoke ' in line:
                        edges = model.graph[point[0]][point[1] + 1]
                        edge = re.match(r'to label %' + driver.common.LABEL, edges)
                        self.assertIsNotNone(edge)
                        mutants.append(body.replace(line, 'br label %' + edge[1], 1).replace(edges, '', 1))
                    else:
                        mutants.append(body.replace(line, '', 1))
                        mutants.append(body.replace(line, line + '\n' + line, 1))
                    # An ordinary scalar read after cleanup is not a valid borrow.
                    if 'invoke ' not in line:
                        mutants.append(body.replace(line, line + '\n%late_secret = load i8, ptr '
                                                    + destination + ', align 1', 1))
                for symbol, args, point in model.calls:
                    if not driver.syntax.adapter_update(symbol):
                        continue
                    line = model.graph[point[0]][point[1]]
                    mutants.append(body.replace(line, line.replace(args[0], 'ptr %argument', 1), 1))
                    edges = model.graph[point[0]][point[1] + 1]
                    match = re.fullmatch(r'to label %' + driver.common.LABEL + r' unwind label %'
                                         + driver.common.LABEL + r'(?:,.*)?', edges)
                    self.assertIsNotNone(match)
                    mutants.append(body.replace(line, line.replace('invoke ', 'call ', 1), 1)
                                   .replace(edges, 'br label %' + match[1], 1))
                for mutant in mutants:
                    with self.subTest(target=target, identity=identity, case=cases):
                        with self.assertRaises(ValueError):
                            changed = driver.keyed.Admission(mutant, names, '1.99.1', identity, False)
                            driver.scalar.check(changed, identity, definitions, aliases, 'unwind')
                    cases += 1
                for helper in helpers:
                    formal, helper_body = driver.common.resolve(helper, definitions, aliases)
                    calls = [line for line in helper_body.splitlines()
                             if re.search(r'\b(?:call|invoke)\b', line)
                             and (call := driver.syntax.call(line)) and driver.common.owner_drop(call[0], identity)]
                    self.assertTrue(calls)
                    for line in calls:
                        changed = dict(definitions)
                        changed[helper] = formal, helper_body.replace(line, '', 1)
                        with self.assertRaises(ValueError):
                            driver.scalar.check(model, identity, changed, aliases, 'unwind')
                        helper_cases += 1
        self.assertGreater(cases, 300)
        self.assertGreaterEqual(helper_cases, 72)
        print(f'Hosted scalar cleanup: {cases} caller and {helper_cases} actual-helper mutations rejected', flush=True)

    def check_compiled_retained_mutants(self, host, fixture, work):
        driver = self.driver
        cases = [(target, directory, compiled)
                 for target, directory in ((driver.TARGETS[0], 'strict_hmac'),
                                           (driver.TARGETS[2], 'macos_resident/hmac'))
                 for compiled in (False, True)]
        for target, directory, compiled in cases:
            path = host / 'src' / directory / ('compiled/worker.rs' if compiled else 'worker.rs')
            original = path.read_text()
            split = original.index('    for chunk in request')
            prefix, loop = original[:split], original[split:]
            call = 'checkpoint(cancel, &owner)' if compiled else 'checkpoint(cancel)'
            anchor = '        ' + call + '?;'
            self.assertIn(anchor, loop)
            mutant = '        if let Err(error) = ' + call + ' { core::mem::forget(state); return Err(error); }'
            try:
                path.write_text(prefix + loop.replace(anchor, mutant, 1))
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
                    body = driver.common.resolve(worker, definitions, aliases)[1]
                    model = driver.keyed.check(body, names, '1.99.1', identity, compiled)
                    driver.storage.check(model, identity)
                    with self.assertRaisesRegex(ValueError,
                            r'without (both|engine) cleanup/consumption|'
                            r'lifetime ends (with unconsumed owner|without engine consumption)'):
                        if compiled:
                            driver.compiled_worker.check(model, identity, definitions, aliases, '1.99.1', 'unwind')
                        else:
                            driver.scalar.check(model, identity, definitions, aliases, 'unwind')
            finally:
                path.write_text(original)
            driver.validate(driver.emit(work / target, '1.99.1', target, 'unwind', fixture / 'Cargo.toml')[1], target)
        print('Hosted Rust forget-on-error: four compiled mutants rejected; restored baselines pass', flush=True)

    def test_compiled_worker_cleanup_paths_and_helpers(self):
        driver, cases, helper_cases = self.driver, 0, 0
        for target, (_, definitions, aliases, names, checked) in self.profiles.items():
            for body, identity, compiled in self.keyed_workers(definitions, aliases, names, checked, target):
                if not compiled:
                    continue
                model = driver.keyed.check(body, names, '1.99.1', identity, True)
                visited = set()
                helpers = driver.compiled_worker.check(model, identity, definitions, aliases, '1.99.1', 'unwind', visited)
                mutants = []
                for symbol, args, point in model.calls:
                    update = names.get(symbol, '').endswith(('>::update_cpu', '::Sha512T>::update'))
                    if point not in visited or symbol not in helpers and not update:
                        continue
                    line = model.graph[point[0]][point[1]]
                    mutants.append(body.replace(line, line.replace(args[0], 'ptr %argument', 1), 1))
                    if 'invoke ' in line:
                        edges = model.graph[point[0]][point[1] + 1]
                        edge = re.match(r'to label %' + driver.common.LABEL, edges)
                        self.assertIsNotNone(edge)
                        mutants.append(body.replace(line, 'br label %' + edge[1], 1).replace(edges, '', 1))
                        if update:
                            mutants.append(body.replace(line, line.replace('invoke ', 'call ', 1), 1)
                                           .replace(edges, 'br label %' + edge[1], 1))
                    else:
                        mutants.append(body.replace(line, '', 1))
                        mutants.append(body.replace(line, line + '\n' + line, 1))
                for mode, point, dest, data in model.writes:
                    if point in visited and mode == 'store' and data == 'i8 2' and model.pointer(dest)[0] == model.owner:
                        line = model.graph[point[0]][point[1]]
                        mutants.extend((body.replace(line, '', 1),
                                        body.replace(line, line.replace('i8 2', 'i8 0'), 1)))
                for mutant in mutants:
                    with self.subTest(target=target, identity=identity, case=cases), self.assertRaises(ValueError):
                        changed = driver.keyed.Admission(mutant, names, '1.99.1', identity, True)
                        driver.compiled_worker.check(changed, identity, definitions, aliases, '1.99.1', 'unwind')
                    cases += 1
                # Mutate the actual resolved helper, including nested helpers.
                pending, seen = list(helpers), set()
                while pending:
                    symbol = pending.pop()
                    resolved = aliases.get(symbol, symbol)
                    if resolved in seen:
                        continue
                    seen.add(resolved)
                    formal, helper_body = driver.common.resolve(symbol, definitions, aliases)
                    for line in helper_body.splitlines():
                        call = driver.syntax.call(line)
                        if not call:
                            continue
                        if driver.compiled_worker.cleanup.leaf(call[0]):
                            changed = dict(definitions)
                            changed[resolved] = formal, helper_body.replace(line, '', 1)
                            with self.assertRaises(ValueError):
                                driver.compiled_worker.check(model, identity, changed, aliases, '1.99.1', 'unwind')
                            helper_cases += 1
                        elif 'drop_in_place' in call[0] or 'drop_glue' in call[0]:
                            pending.append(call[0])
        self.assertGreater(cases, 250)
        self.assertGreaterEqual(helper_cases, 100)
        print(f'Hosted compiled cleanup: {cases} caller and {helper_cases} actual-helper mutations rejected', flush=True)

    def test_msrv_inline_cleanup_and_loop_lifetimes(self):
        driver, cases = self.driver, 0
        for target in driver.TARGETS:
            llvm = driver.emit(self.root / ('inline-' + target), '1.90.0', target, 'abort')[1]
            definitions, aliases, names, checked = driver.validate(llvm, target, '1.90.0', 'abort')
            for body, identity, compiled in self.keyed_workers(definitions, aliases, names, checked, target):
                if not compiled:
                    continue
                model = driver.keyed.check(body, names, '1.90.0', identity, True)
                visited = set()
                driver.compiled_worker.check(model, identity, definitions, aliases, '1.90.0', 'abort', visited)
                for symbol, args, point in model.calls:
                    if not driver.compiled_worker.cleanup.leaf(symbol) or point not in visited:
                        continue
                    line = model.graph[point[0]][point[1]]
                    for replacement in ('', line.replace(args[0], 'ptr %argument', 1), line + '\n' + line):
                        with self.subTest(target=target, identity=identity, case=cases), self.assertRaises(ValueError):
                            changed = driver.keyed.Admission(body.replace(line, replacement, 1), names,
                                                             '1.90.0', identity, True)
                            driver.compiled_worker.check(changed, identity, definitions, aliases, '1.90.0', 'abort')
                        cases += 1
                _, _, uses, starts, ends = driver.storage.check(model, identity)
                for root in ends:
                    for end in ends[root]:
                        if not any(model.can_precede(end, point) for point in uses[root]):
                            continue
                        # Removing the restart must expose the next loop use.
                        start = starts[root][0]
                        line = model.graph[start[0]][start[1]]
                        changed = driver.keyed.Admission(body.replace(line, '', 1), names, '1.90.0', identity, True)
                        with self.assertRaises(ValueError):
                            driver.storage.check(changed, identity)
                        cases += 1
        self.assertGreater(cases, 150)
        print(f'Hosted MSRV inline/loop cleanup: {cases} mutations rejected', flush=True)
