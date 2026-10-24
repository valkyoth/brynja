"""Adversarial capture and buffer projections over actual compiler artifacts."""
from pathlib import Path
import re
import shutil
import tomllib


class CaptureTests:
    def workers(self):
        h = self.driver.hosted
        for case, identity, worker, (defs, aliases, names), _ in self.hosts():
            arguments, body = h.flow.resolve(worker, defs, aliases)
            model = h.envelope.check(arguments, body, names, identity)
            yield identity, arguments, body, names, model

    def test_worker_capture_reads_and_take_order(self):
        h, count = self.driver.hosted, 0
        for identity, arguments, body, names, model in self.workers():
            graph = h.flow.blocks(body)
            take = graph[model['take'][0]][model['take'][1]]
            for site, _ in model['loads'].values():
                line = graph[site[0]][site[1]]
                # Moving the read after Option::take must fail even when its
                # former textual occurrence is replaced at a reachable site.
                changed = body.replace(line, '', 1).replace(take, take + '\n' + line, 1)
                with self.subTest(identity=identity), self.assertRaises(ValueError):
                    h.envelope.check(arguments, changed, names, identity)
                count += 1
        self.assertGreater(count, 200)

    def test_worker_completion_panic_and_result_order(self):
        h = self.driver.hosted
        for identity, arguments, body, names, model in self.workers():
            graph = h.flow.blocks(body)
            done = graph[model['completed'][0]][model['completed'][1]]
            tag = graph[model['result'][0]][model['result'][1]]
            take = graph[model['take'][0]][model['take'][1]]
            result_ptr = re.search(r', ptr (%[-\w.]+),', tag)[1]
            mutants = [body.replace(done, '', 1), body.replace(done, done.replace('store i8 1', 'store i8 0'), 1),
                       body.replace(take, '', 1), body.replace(tag, '', 1),
                       body.replace(tag, '', 1).replace(done, done + '\n' + tag, 1),
                       body.replace('ret ptr null', 'ret ptr %argument'),
                       body.replace(take, take + '\ncall void @unexpected(ptr %argument)', 1),
                       body.replace(take, take + '\nstore ptr null, ptr %argument, align 8', 1),
                       body.replace(tag, tag + '\ncall void @unexpected(ptr ' + result_ptr + ')', 1),
                       body.replace(tag, tag + '\nstore ptr ' + result_ptr + ', ptr @external, align 8', 1),
                       body.replace(tag, tag + '\n%outside_result = getelementptr i8, ptr ' + result_ptr + ', i64 2', 1)]
            for site in model['panic']:
                panic = graph[site[0]][site[1]]
                mutants.extend((body.replace(panic, '', 1), body.replace(panic, panic.replace('store i8 1', 'store i8 0'), 1)))
            for mutant in mutants:
                with self.subTest(identity=identity), self.assertRaises(ValueError):
                    h.envelope.check(arguments, mutant, names, identity)

    def records(self):
        h = self.driver.hosted
        for case, identity, _, (defs, aliases, names), body in self.hosts():
            symbol = case[2][identity][0]
            signature, _ = h.flow.resolve(symbol, defs, aliases)
            yield case, identity, signature, body, names, h.capture.check(signature, body, names, case[1], identity)

    def test_every_capture_field_initialization(self):
        h, count = self.driver.hosted, 0
        for case, identity, signature, body, names, record in self.records():
            for mode, site, dest, extent, value, kind in record.writes:
                if record.destination(dest)[0] not in record.borrowed:
                    continue
                line = record.graph[site[0]][site[1]]
                changed = (line.replace(' ' + value + ', ptr', ' ' + ('null' if kind == 'ptr' else '1') + ', ptr', 1)
                           if mode == 'store' else line.replace('i64 ' + str(extent) + ',', 'i64 ' + str(extent - 1) + ',', 1))
                self.assertNotEqual(changed, line)
                for mutant in (body.replace(line, '', 1), body.replace(line, changed, 1)):
                    with self.subTest(target=case[1], identity=identity, line=line), self.assertRaises(ValueError):
                        h.capture.check(signature, mutant, names, case[1], identity)
                    count += 1
        self.assertGreater(count, 700)
        print(f'Legacy hosted capture: {count} missing/substituted field writes rejected', flush=True)

    def test_capture_extra_late_conditional_and_escaped_writes(self):
        h = self.driver.hosted
        for case, identity, signature, body, names, record in self.records():
            launch, _ = record.create
            create = record.graph[launch[0]][launch[1]]
            first = next(row for row in record.writes if record.destination(row[2])[0] == record.job)
            line = record.graph[first[1][0]][first[1][1]]
            extra = ('%extra_capture = getelementptr i8, ptr ' + record.job + ', i64 '
                     + str(record.allocs[record.job] - 1) + '\nstore i8 1, ptr %extra_capture, align 1\n')
            mutants = [body.replace(create, extra + create, 1),
                       body.replace(line, line + '\n' + line, 1),
                       body.replace(create, create + '\nstore i8 0, ptr ' + record.job + ', align 1', 1),
                       body.replace(line, '', 1) + '\nnever_reached:\n' + line + '\n unreachable\n']
            for local in record.borrowed:
                end = 'call void @llvm.lifetime.end.p0(i64 ' + str(record.allocs[local]) + ', ptr ' + local + ')\n'
                mutants.append(body.replace(create, end + create, 1))
                # A known host callee cannot be used to mutate a borrowed record.
                validation = next(symbol for symbol, name in names.items() if name.endswith('::types::Cancellation>::check'))
                mutants.append(body.replace(create, 'call void @' + validation + '(ptr ' + local + ')\n' + create, 1))
                mutants.append(body.replace(create, 'store ptr ' + local + ', ptr ' + record.self_pointer
                                            + ', align 8\n' + create, 1))
            for mutant in mutants:
                with self.subTest(target=case[1], identity=identity), self.assertRaises(ValueError):
                    h.capture.check(signature, mutant, names, case[1], identity)

    def test_capture_source_contracts(self):
        h = self.driver.hosted
        work = Path(self.directory.name) / 'type-contracts'
        for directory in ('strict_execution', 'macos_resident'):
            for file, _, _ in h.capture_types.declarations(directory == 'macos_resident'):
                relative = h.capture_types.PREFIX + directory + '/' + file
                dest = work / relative
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(self.driver.ROOT / relative, dest)
        memory = work / h.capture_types.MEMORY
        memory.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.driver.ROOT / h.capture_types.MEMORY, memory)
        h.capture_types.validate(work)
        for directory in ('strict_execution', 'macos_resident'):
            for (file, name, kind), _ in h.capture_types.declarations(directory == 'macos_resident').items():
                path = work / (h.capture_types.PREFIX + directory + '/' + file)
                original = path.read_text()
                # Inserting a field/variant tests the real parser, not token deletion.
                declaration = re.search(r'\b' + kind + r' ' + name + r'\b[^\{]*\{', original)
                self.assertIsNotNone(declaration)
                extra = 'Unexpected,' if kind == 'enum' else 'unexpected: usize,'
                path.write_text(original[:declaration.end()] + extra + original[declaration.end():])
                try:
                    with self.assertRaises(ValueError):
                        h.capture_types.validate(work)
                finally:
                    path.write_text(original)
        memory.write_text(memory.read_text() + '\n// drift\n')
        with self.assertRaises(ValueError):
            h.capture_types.validate(work)

    def test_buffer_destructor_identity_order_and_keep(self):
        h, count = self.driver.hosted, 0
        for artifacts, target, _, _ in self.cases:
            defs, aliases = h.flow.definitions_and_aliases(artifacts['brynja-legacy-hmac-std'])
            names = h.model.demangle({name.strip('"') for name in re.findall(r'@("[^"]+"|[-\w.$]+)',
                                                                          artifacts['brynja-legacy-hmac-std'])})
            symbol = next(s for s in (*defs, *aliases) if names[s] == '<' + h.profile(target)[0]
                          + '::Buffers as core::ops::drop::Drop>::drop')
            arguments, body = h.flow.resolve(symbol, defs, aliases)
            h.buffers.check(arguments, body, names, target)
            calls = [(line, args) for line in body.splitlines() if (call := h.syntax.call(line))
                     for symbol, args in (call,) if names.get(symbol, '').endswith('>::clear')]
            self.assertEqual(len(calls), 2)
            branch = next(line for line in body.splitlines() if 'br i1 ' in line)
            mutants = [body.replace(branch, re.sub(r'br i1 %[-\w.]+,', 'br i1 true,', branch), 1),
                       body.replace('i64 16', 'i64 8', 1)]
            targets = re.findall('label %' + h.flow.LABEL, branch)
            mutants.append(body.replace(branch, branch.replace('label %' + targets[0] + ', label %' + targets[1],
                                                              'label %' + targets[1] + ', label %' + targets[0]), 1))
            for line, args in calls:
                mutants.extend((body.replace(line, '', 1), body.replace(line, line + '\n' + line, 1),
                                body.replace(line, line.replace(args[0], 'ptr %unrelated'), 1)))
            for mutant in mutants:
                with self.subTest(target=target), self.assertRaises(ValueError):
                    h.buffers.check(arguments, mutant, names, target)
                count += 1
        self.assertEqual(count, 54)

    def test_compiled_host_capture_and_buffer_defects(self):
        d, h = self.driver, self.driver.hosted
        work = Path(self.directory.name) / 'host-mutants'
        leaf, fixture = work / 'host', work / 'fixture'
        source = d.ROOT / 'crates/brynja-legacy-hmac-std'
        shutil.copytree(source / 'src', leaf / 'src')
        shutil.copyfile(source / 'README.md', leaf / 'README.md')
        manifest = (source / 'Cargo.toml').read_text()
        workspace = tomllib.loads((d.ROOT / 'Cargo.toml').read_text())['workspace']
        for field in ('edition', 'rust-version', 'license', 'repository'):
            manifest = manifest.replace(field + '.workspace = true', field + ' = "' + workspace['package'][field] + '"')
        for dependency in ('brynja-core', 'brynja-crypto-cpu-std'):
            before = dependency + ('.workspace = true' if dependency == 'brynja-core' else ' = { workspace = true, optional = true }')
            manifest = manifest.replace(before, dependency + ' = { path = "' + str(d.ROOT / 'crates' / dependency)
                                        + '", default-features = false' + (', optional = true' if dependency.endswith('-std') else '') + ' }')
        manifest = manifest.replace('path = "../', 'path = "' + str(d.ROOT / 'crates') + '/')
        (leaf / 'Cargo.toml').write_text(manifest.replace('[lints]\nworkspace = true', '') + '\n[workspace]\n')
        shutil.copytree(d.FIXTURE.parent / 'src', fixture / 'src')
        shutil.copyfile(d.FIXTURE.parent / 'Cargo.lock', fixture / 'Cargo.lock')
        (fixture / 'Cargo.toml').write_text(d.FIXTURE.read_text().replace('../../crates/brynja-legacy-hmac-std', str(leaf)))
        count = 0
        for target, directory in ((d.TARGETS[0], 'strict_execution'), (d.TARGETS[2], 'macos_resident')):
            def emit():
                return d.emit(work / target, '1.99.1', target, 'unwind', True,
                              fixture / 'Cargo.toml', leaf / 'Cargo.toml')
            h.validate(emit(), target, 'unwind')
            for file, before, after in (
                    ('mod.rs', 'let bytes = self.bytes;', 'let bytes = 10;'),
                    ('mod.rs', 'cancel, staging, destination);', 'cancel, destination, staging);'),
                    ('sha1_compiled.rs', 'cancel, staging, output);', 'cancel, output, staging);'),
                    ('sha1_compiled.rs', 'let bytes = self.inner.bytes;', 'let bytes = 10;'),
                    ('md5_compiled.rs', 'budget: self.limits.max_compressions,', 'budget: 1,'),
                    ('md5_compiled.rs', 'cancel, staging, output);', 'cancel, output, staging);'),
                    ('mod.rs', '        self.staging.clear();\n        if !self.keep', '        if !self.keep'),
                    ('mod.rs', 'if !self.keep {', 'if self.keep {'),
                    ('sha1_compiled/worker.rs', '&owner, request.key, bytes)', '&owner, request.tail.bytes, bytes)'),
                    ('sha1_compiled/worker.rs', '&owner, request.key, bytes)', '&owner, request.key, 8)'),
                    ('md5_compiled/worker.rs', '&owner, parameters.bytes)', '&owner, 8)'),
                    ('sha1_compiled/worker.rs', 'owner.report().backend != Some(backend)', 'owner.report().backend == Some(backend)'),
                    ('md5_compiled/worker.rs', 'owner.backend() != Some(parameters.backend)', 'owner.backend() == Some(parameters.backend)'),
                    ('sha1_compiled/worker.rs', '    {\n        checkpoint(&owner, cancel)?;\n        for part',
                     '    {\n        if let Err(error) = checkpoint(&owner, cancel) {\n'
                     '            core::mem::forget(state); return Err(error);\n        }\n        for part'),
                    ('worker.rs', '    {\n        checkpoint(cancel)?;\n        for part',
                     '    {\n        if let Err(error) = checkpoint(cancel) {\n'
                     '            core::mem::forget(state); return Err(error);\n        }\n        for part'),
                    ('worker.rs', 'LegacyUse::acknowledge(), request.key, bytes)',
                     'LegacyUse::acknowledge(), request.tail.bytes, bytes)'),
                    *[(kind + '_compiled/worker.rs',
                       mode + '::Require)\n        .map_err(|_| Error::Mac(brynja_legacy_hmac::Error::ExecutionFailed))?',
                       mode + '::Prefer)\n        .map_err(|_| Error::Mac(brynja_legacy_hmac::Error::ExecutionFailed))?')
                      for kind, mode in (('sha1', 'Sha1Mode'), ('md5', 'Md5Mode'))]):
                path = leaf / 'src' / directory / file
                original = path.read_text()
                self.assertIn(before, original)
                try:
                    path.write_text(original.replace(before, after, 1))
                    artifacts = emit()  # Malformed/uncompilable mutants are test failures.
                    rejection = (self.assertRaisesRegex(ValueError, 'without keyed cleanup/consumption|without consumption|'
                                                        'without both cleanup/consumption|with unconsumed owner')
                                 if 'core::mem::forget(state)' in after else self.assertRaises(ValueError))
                    if file == 'worker.rs' and 'request.tail.bytes' in after:
                        rejection = self.assertRaisesRegex(ValueError, 'scalar constructor key capture|'
                                                           'scalar short-key pad copy|scalar normalization key')
                    with self.subTest(target=target, file=file, before=before), rejection:
                        h.validate(artifacts, target, 'unwind')
                finally:
                    path.write_text(original)
                count += 1
            h.validate(emit(), target, 'unwind')
        self.assertEqual(count, 36)
        print('Legacy hosted capture/destructor/authority/selection/retained: 36 compiled Rust defects rejected', flush=True)
