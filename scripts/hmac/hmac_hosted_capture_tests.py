"""Adversarial capture/selected-factory checks against real emitted functions."""
import re
import shutil


class CaptureTests:
    def check_compiled_capture_mutants(self, host, fixture, work):
        driver = self.driver
        cases = 0
        for target, directory in ((driver.TARGETS[0], 'strict_hmac'),
                                  (driver.TARGETS[2], 'macos_resident/hmac')):
            for file, old, new in (
                    ('mod.rs', 'cancel, staging, destination);', 'cancel, destination, staging);'),
                    ('mod.rs', 'let policy = self.policy;', 'let policy = TagPolicy::Bytes(16);'),
                    ('compiled.rs', '                staging,\n                destination,',
                     '                destination,\n                staging,'),
                    ('worker.rs', 'request.key', 'request.tail.bytes'),
                    ('compiled/worker.rs', 'request.key', 'request.tail.bytes')):
                path = host / 'src' / directory / file
                original = path.read_text()
                self.assertIn(old, original)
                try:
                    path.write_text(original.replace(old, new))
                    emitted = driver.emit(work / target, '1.99.1', target, 'unwind',
                                          fixture / 'Cargo.toml')[1]
                    with self.subTest(target=target, file=file, mutation=old):
                        with self.assertRaises(ValueError):
                            driver.validate(emitted, target)
                finally:
                    path.write_text(original)
                cases += 1
            restored = driver.emit(work / target, '1.99.1', target, 'unwind', fixture / 'Cargo.toml')[1]
            driver.validate(restored, target)
        self.assertEqual(cases, 10)

    def test_capture_fields_reject_substitution_and_missing_initialization(self):
        driver = self.driver
        cases = 0
        for target, (_, definitions, _, names, checked) in self.profiles.items():
            for symbol in checked:
                arguments, body = definitions[symbol]
                compiled = 'CompiledSession<' in names[symbol]
                record = driver.capture.check(arguments, body, names, target, compiled)
                launch, job = record.create
                job = driver.capture.address(record.value(job, 'ptr', launch))[0]
                mutations = []
                # Remove or redirect every meaningful job write, not a handful
                # of representative fields. Both scalar and compiled layouts.
                for mode, point, dest, size, source, kind in record.writes:
                    if record.destination(dest)[0] not in (job, '%policy', '%candidate', '%kernel'):
                        continue
                    line = record.graph[point[0]][point[1]]
                    mutations.append(body.replace(line, '', 1))
                    if mode == 'store':
                        replacement = 'null' if kind == 'ptr' else '1'
                        if kind == '<2 x i64>':
                            replacement = '%unrelated_policy'
                        changed = line.replace(' ' + source + ', ptr', ' ' + replacement + ', ptr', 1)
                    else:
                        changed = line.replace('i64 ' + str(size), 'i64 ' + str(size - 1), 1)
                    self.assertNotEqual(line, changed)
                    mutations.append(body.replace(line, changed, 1))
                create = record.graph[launch[0]][launch[1]]
                extra = ('  %extra_capture = getelementptr i8, ptr ' + job
                         + ', i64 ' + str(135 if compiled else 127)
                         + '\n  store i8 1, ptr %extra_capture, align 1\n')
                mutations.extend((
                    body.replace(create, extra + create, 1),
                    body.replace(create, create + '\n  store i8 0, ptr ' + job + ', align 1', 1),
                    body.replace('alloca [' + str(record.allocs[job]) + ' x i8]',
                                 'alloca [512 x i8]', 1),
                ))
                for local in ('%result', '%policy', '%candidate', *(('%kernel',) if compiled else ())):
                    end = '  call void @llvm.lifetime.end.p0(i64 ' + str(record.allocs[local]) + ', ptr ' + local + ')\n'
                    mutations.append(body.replace(create, end + create, 1))
                # A moved write is not initialization merely because its text
                # remains present. Also exercise unreachable/sibling blocks.
                mode, point, dest, _, _, _ = next(row for row in record.writes
                                                 if record.destination(row[2])[0] == job)
                line = record.graph[point[0]][point[1]]
                mutations.append(body.replace(line, '', 1) + '\nnever_reached:\n' + line + '\n  unreachable\n')
                for mutant in mutations:
                    with self.subTest(target=target, executor=names[symbol], case=cases):
                        with self.assertRaises(ValueError):
                            driver.capture.check(arguments, mutant, names, target, compiled)
                    cases += 1
        self.assertGreater(cases, 2000)
        print(f'Hosted launch-record provenance: {cases} emitted mutations rejected', flush=True)

    def test_worker_factory_inputs_and_local_destinations(self):
        driver = self.driver
        cases = 0
        for target, (_, definitions, aliases, names, checked) in self.profiles.items():
            for symbol in checked:
                _, host = definitions[symbol]
                compiled = 'CompiledSession<' in names[symbol]
                algorithm = re.search(r'Session<(.*)>>::execute$', names[symbol])[1]
                worker = driver.lifecycle.check_host(host, names, definitions, target)
                arguments, body = driver.common.resolve(worker, definitions, aliases)
                driver.placement.check(arguments, body, names, algorithm, compiled)
                direct = [(line, call) for line in body.splitlines()
                          if re.search(r'\b(?:call|invoke)\b.*?@', line)
                          and (call := driver.syntax.call(line))]
                factories = [(line, name, args) for line, (name, args) in direct
                             if 'brynja_mac_hmac::' in names.get(name, '')
                             and ('::new_with::<' in names[name] or names[name].endswith('>::create'))]
                mutants = []
                missing = body
                for line, name, args in factories:
                    missing = missing.replace(line, '', 1)
                    key = 2 if compiled else 1
                    for index in (0, key, key + 1, *((1,) if compiled else ())):
                        replacement = 'i64 0' if index == key + 1 else 'ptr %argument'
                        mutants.append(body.replace(line, line.replace(args[index], replacement, 1), 1))
                    changed_names = dict(names)
                    changed_names[name] = names[name].replace(algorithm, 'OtherAlgorithm')
                    with self.assertRaises(ValueError):
                        driver.placement.check(arguments, body, changed_names, algorithm, compiled)
                    cases += 1
                mutants.append(missing)
                for line, (name, args) in direct:
                    if names.get(name) == '<brynja_crypto_cpu::static_execution::Authority>::new':
                        for index, replacement in ((0, 'ptr %argument'), (1, 'i8 0')):
                            mutants.append(body.replace(line, line.replace(args[index], replacement, 1), 1))
                        mutants.append(body.replace(line, '', 1))
                for mutant in mutants:
                    with self.subTest(target=target, worker=names[worker], case=cases):
                        with self.assertRaises(ValueError):
                            driver.placement.check(arguments, mutant, names, algorithm, compiled)
                    cases += 1
        self.assertGreater(cases, 600)
        print(f'Hosted worker factory placement: {cases} emitted mutations rejected', flush=True)

    def test_capture_type_declarations_do_not_admit_owned_keyed_state(self):
        driver = self.driver
        root = self.root / 'capture-types'
        for directory in ('strict_hmac', 'macos_resident/hmac'):
            for file in ('mod.rs', 'compiled.rs', 'types.rs'):
                relative = driver.capture_types.PREFIX + directory + '/' + file
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(driver.ROOT / relative, path)
        driver.capture_types.validate(root)
        cases = 0
        for directory in ('strict_hmac', 'macos_resident/hmac'):
            for file, name, kind in driver.capture_types.declarations(directory):
                path = root / (driver.capture_types.PREFIX + directory + '/' + file)
                original = path.read_text()
                declaration = re.search(r'pub (?:struct|enum) ' + name + r'\b[^\{]*\{', original)
                self.assertIsNotNone(declaration)
                offset = declaration.end()
                added = 'Extra([u8; 64]),' if kind == 'enum' else 'keyed: [u8; 64],'
                try:
                    path.write_text(original[:offset] + added + original[offset:])
                    with self.assertRaises(ValueError):
                        driver.capture_types.validate(root)
                finally:
                    path.write_text(original)
                cases += 1
        self.assertEqual(cases, 10)
        driver.capture_types.validate(root)
