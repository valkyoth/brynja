"""Checkpoint argument/edge/result mutations, plus compiling worker regressions."""
import re
import copy


class CheckpointTests:
    def checkpoint_model(self, arguments, body, names, identity, compiled, target, compiler):
        d = self.driver
        model = d.keyed.check(body, names, compiler, identity, compiled)
        d.checkpoints.preflight(model, arguments, target, compiler)
        flow = d.input_flow.check(model, arguments, compiler)
        output = d.output.Output(model, arguments).check()
        return d.checkpoints.check(model, flow, output, target, compiler)

    def checkpoint_mutations(self, check, body):
        d, m = self.driver, check.m
        mutations = []
        for point, (_, discriminator, success, failure) in check.guards.items():
            line = m.graph[point[0]][point[1]]
            _, args = d.syntax.call(line)
            for arg in args:
                mutations.append(body.replace(line, line.replace(arg, 'ptr %wrong_checkpoint_owner', 1), 1))
            # Replace the call while leaving a well-typed passing Result.
            value = re.match('(' + d.syntax.VALUE + ') = ', line)[1]
            replacement = value + ' = insertvalue { i8, i8 } { i8 ' + str(check.ok) + ', i8 0 }, i8 0, 1'
            if 'invoke ' in line:
                normal = check.flow.returned(point)[0]
                old = line + '\n' + m.graph[point[0]][point[1] + 1]
                mutations.append(body.replace(old, replacement + '\nbr label %' + normal, 1))
            else:
                mutations.append(body.replace(line, replacement, 1))
            guard = check.flow.returned(point)[0]
            branch = m.graph[guard][-1]
            mutations.extend((
                body.replace(branch, branch.replace('label %' + success, 'label %' + failure, 1), 1),
                body.replace(branch, branch.replace('label %' + failure, 'label %' + success, 1), 1)))
            test = next(line for line in m.graph[guard] if 'icmp eq i8 ' + discriminator + ',' in line)
            mutations.extend((body.replace(test, test.replace('icmp eq', 'icmp ne'), 1),
                              body.replace(test, test.replace(', ' + str(check.ok), ', 0'), 1)))
        for point in check.points:
            line = m.graph[point[0]][point[1]]
            if line.startswith('store i'):
                for value in (check.ok & 255, 6, 9):
                    changed = re.sub(r'^(store i(?:8|16)) ' + d.syntax.VALUE + ',',
                                     r'\1 ' + str(value) + ',', line)
                    if changed != line:
                        mutations.append(body.replace(line, changed, 1))
        pointer = d.checkpoints.results.result_slot(check)
        capture = m.graph[m.defs[pointer][1][0]][m.defs[pointer][1][1]]
        mutations.append(body.replace(capture, capture + '\n' + capture.replace(pointer, '%second_result', 1), 1))
        store = next(line for lines in m.graph.values() for line in lines
                     if line.startswith('store i16 ') and ', ptr ' + pointer + ',' in line)
        mutations.extend((body.replace(store, store + '\ncall void @unreviewed_result(ptr ' + pointer + ')', 1),
                          body.replace(store, store + '\n%result_alias = getelementptr i8, ptr ' + pointer
                                       + ', i64 0\nstore i16 ' + str(check.ok & 255) + ', ptr %result_alias, align 1', 1)))
        return list(dict.fromkeys(mutant for mutant in mutations if mutant != body))

    def check_checkpoint_profile(self, target, profile, compiler):
        d, count = self.driver, 0
        _, definitions, aliases, names, checked = profile
        for arguments, body, identity, compiled in self.output_workers(definitions, aliases, names, checked, target):
            checked_model = self.checkpoint_model(arguments, body, names, identity, compiled, target, compiler)
            # Mutations operate on the normalized emitted CFG so multiline
            # invoke whitespace cannot turn replacement into a no-op.
            normalized = '\n'.join(label + ':\n' + '\n'.join(lines)
                                   for label, lines in checked_model.m.graph.items())
            for mutant in self.checkpoint_mutations(checked_model, normalized):
                with self.subTest(target=target, identity=identity, compiled=compiled, case=count):
                    with self.assertRaises(ValueError):
                        # Keep input/output landmarks from the reviewed baseline:
                        # checkpoint regressions must be caught by this checker,
                        # not incidentally by an earlier input/cleanup guard.
                        model = d.keyed.Admission(mutant, names, compiler, identity, compiled)
                        model.factories = checked_model.m.factories
                        flow = copy.copy(checked_model.flow)
                        flow.m = model
                        d.checkpoints.check(model, flow, checked_model.output, target, compiler)
                count += 1
        return count

    def test_worker_checkpoint_arguments_guards_and_results(self):
        count = sum(self.check_checkpoint_profile(target, profile, '1.99.1')
                    for target, profile in self.profiles.items())
        self.assertGreater(count, 2500)
        print(f'Hosted checkpoints: {count} emitted argument/edge/result mutations rejected', flush=True)

    def test_msrv_worker_checkpoint_guards_and_results(self):
        d, count = self.driver, 0
        for target in d.TARGETS:
            llvm = d.emit(self.root / ('checkpoint-msrv-' + target), '1.90.0', target, 'abort')[1]
            profile = (llvm, *d.validate(llvm, target, '1.90.0', 'abort'))
            count += self.check_checkpoint_profile(target, profile, '1.90.0')
        self.assertGreater(count, 2500)
        print(f'Hosted MSRV checkpoints: {count} emitted argument/edge/result mutations rejected', flush=True)

    def test_real_compiled_worker_checkpoint_mutants(self):
        d = self.driver
        work = self.root / 'compiled-checkpoint-mutants'
        host, fixture = self.compiled_fixture(work)
        count = 0
        for target, directory in ((d.TARGETS[0], 'strict_hmac'), (d.TARGETS[2], 'macos_resident/hmac')):
            for compiled in (False, True):
                path = host / 'src' / directory / ('compiled/worker.rs' if compiled else 'worker.rs')
                original = path.read_text()
                start = original.index('pub(super) fn run<')
                prefix, run = original[:start], original[start:]
                checkpoint = 'checkpoint(cancel, &owner)?;' if compiled else 'checkpoint(cancel)?;'
                self.assertEqual(run.count(checkpoint), 6)
                # Remove each required boundary independently, including empty
                # chunks and the final post-copy/post-comparison checkpoint.
                offsets = [m.start() for m in re.finditer(re.escape(checkpoint), run)]
                variants = [run[:offset] + '/* missing checkpoint */' + run[offset + len(checkpoint):]
                            for offset in offsets]
                variants.append(run.replace(checkpoint, checkpoint.replace('?', '.ok()'), 1))
                if compiled:
                    variants.append(run.replace('    cancel.check()?;', '    /* missing early cancellation */', 1))
                for case, mutant in enumerate(variants):
                    try:
                        path.write_text(prefix + mutant)
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
                                # A missing boundary can also change keyed-admission
                                # codegen. Prove checkpoint rejection independently,
                                # before requiring the complete pipeline to fail closed.
                                model = d.keyed.Admission(body, names, '1.99.1', identity, compiled)
                                with self.assertRaisesRegex(ValueError, 'checkpoint'):
                                    d.checkpoints.preflight(model, arguments, target, '1.99.1')
                                with self.assertRaises(ValueError):
                                    self.checkpoint_model(arguments, body, names, identity,
                                                          compiled, target, '1.99.1')
                        count += 1
                    finally:
                        path.write_text(original)
                d.validate(d.emit(work / target, '1.99.1', target, 'unwind', fixture / 'Cargo.toml')[1], target)
        self.assertEqual(count, 30)
        print('Hosted checkpoints: thirty real compiled Rust mutants rejected; restored baselines pass', flush=True)

    def test_emitted_checkpoint_callees(self):
        d, count = self.driver, 0
        for compiler in ('1.90.0', '1.99.1'):
            for target in d.TARGETS:
                llvm = d.emit_callees(self.root / ('callee-' + compiler + target), compiler, target, 'unwind')
                names, checked = d.checkpoint_callees.validate(llvm, target, compiler)
                for arguments, body, compiled in checked:
                    mutants = [body.replace(' acquire,', ' monotonic,'),
                               body.replace('icmp eq i8', 'icmp ne i8'),
                               body.replace(', i8 6', ', i8 0'),
                               body.replace('load atomic i8, ptr %cancel', 'load atomic i8, ptr %owner'),
                               body.replace('i64 8\n', 'i64 9\n')]
                    if compiled:
                        mutants.extend((body.replace('icmp eq ptr', 'icmp ne ptr'),
                                        body.replace('[ 9,', '[ 6,'),
                                        body.replace(' %owner)', ' %cancel)')))
                        payload = next(line for line in body.splitlines() if 'phi i8' in line and '[ undef,' in line)
                        mutants.append(body.replace(payload, re.sub(r'\[ ' + d.syntax.VALUE + ',', '[ 0,', payload, count=1)))
                    for mutant in set(mutants) - {body}:
                        with self.subTest(compiler=compiler, target=target, compiled=compiled, case=count):
                            with self.assertRaises(ValueError):
                                for healthy in ((False, True) if compiled else (True,)):
                                    for cancelled in (False, True):
                                        d.checkpoint_callees.run(arguments, mutant, names, compiled,
                                                                healthy, cancelled, compiler)
                        count += 1
        self.assertGreaterEqual(count, 72)
        print(f'Hosted checkpoint callees: {count} atomic/order/argument/payload mutations rejected', flush=True)

    def test_real_compiled_checkpoint_callee_mutants(self):
        d, count = self.driver, 0
        work = self.root / 'compiled-checkpoint-callees'
        host, fixture = self.compiled_fixture(work)
        for target, directory in ((d.TARGETS[0], 'strict_hmac'), (d.TARGETS[2], 'macos_resident/hmac')):
            for relative in ('types.rs', 'compiled/worker.rs'):
                path = host / 'src' / directory / relative
                original = path.read_text()
                if relative == 'types.rs':
                    variants = [original.replace('self.0.load(Ordering::Acquire)', 'self.0.load(Ordering::Relaxed)'),
                                original.replace('if self.0.load(Ordering::Acquire)', 'if !self.0.load(Ordering::Acquire)')]
                else:
                    anchor = 'let _ = owner.session().map_err(Error::Backend)?;\n    cancel.check()'
                    self.assertIn(anchor, original)
                    variants = [original.replace(anchor, 'cancel.check()?;\n    owner.session().map(|_| ()).map_err(Error::Backend)'),
                                original.replace(anchor, 'let _ = owner.session();\n    cancel.check()'),
                                original.replace(anchor, 'let _ = owner.session().map_err(|_| Error::Cancelled)?;\n    cancel.check()')]
                for mutant in variants:
                    self.assertNotEqual(original, mutant)
                    try:
                        path.write_text(mutant)
                        llvm = d.emit_callees(work / target, '1.99.1', target, 'unwind', fixture / 'Cargo.toml')
                        with self.assertRaises(ValueError):
                            d.checkpoint_callees.validate(llvm, target, '1.99.1')
                        count += 1
                    finally:
                        path.write_text(original)
                d.checkpoint_callees.validate(d.emit_callees(work / target, '1.99.1', target, 'unwind',
                                                          fixture / 'Cargo.toml'), target, '1.99.1')
        self.assertEqual(count, 10)
        print('Hosted checkpoint callees: ten real compiled Rust mutants rejected; restored baselines pass', flush=True)
