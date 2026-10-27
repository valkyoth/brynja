"""Public verify bridges and final emitted-profile reconciliation."""
import re
from contextlib import ExitStack
from unittest import mock


class VerifyTests:
    @staticmethod
    def forged_result(line, field, value=None):
        aggregate = line.strip().removeprefix('ret { i8, i8 } ')
        prefix = ''
        if value is None:
            prefix = (f'%original = extractvalue {{ i8, i8 }} {aggregate}, {field}\n'
                      '%flipped = xor i8 %original, 1\n')
            value = '%flipped'
        return (prefix + f'%forged = insertvalue {{ i8, i8 }} {aggregate}, i8 {value}, {field}\n'
                'ret { i8, i8 } %forged')

    def test_composed_hosted_checker_reaches_every_boundary(self):
        d = self.driver
        # Wrap real validators, never replace them with PASS results. The same
        # artifact must reach every host/worker/callee/output boundary.
        stages = ((d.prefix, 'abstract', 1), (d.capture, 'check', 24), (d.lifecycle, 'check_host', 24),
                  (d.transaction, 'check', 24), (d.guard_paths, 'check', 24),
                  (d.placement, 'check', 24), (d.authority, 'check', 12),
                  (d.keyed, 'check', 24), (d.constructor, 'check', 12),
                  (d.constructor, 'scalar', 12), (d.checkpoints, 'preflight', 24),
                  (d.scalar, 'check', 12), (d.compiled_worker, 'check', 12),
                  (d.consumers, 'scalar', 12), (d.consumers, 'compiled', 12),
                  (d.output, 'check', 24), (d.input_flow, 'check', 24),
                  (d.checkpoints, 'check', 24), (d.loan_creation, 'check', 24),
                  (d.loans, 'check', 48), (d.public_verify, 'check', 24))
        for target, profile in self.profiles.items():
            with ExitStack() as stack:
                watched = [(stack.enter_context(mock.patch.object(module, name, wraps=getattr(module, name))), count)
                           for module, name, count in stages]
                d.validate(profile[0], target)
                for wrapped, count in watched:
                    self.assertEqual(wrapped.call_count, count)
            with ExitStack() as stack:
                watched = [stack.enter_context(mock.patch.object(module, 'validate', wraps=module.validate))
                           for module in (d.checkpoint_callees, d.buffers, d.loans.resources)]
                commands = stack.enter_context(mock.patch.object(d.verifier, 'run', wraps=d.verifier.run))
                stack.enter_context(mock.patch.dict('os.environ', {'MACOSX_DEPLOYMENT_TARGET': '99.0'}))
                emitted = d.emit(self.root / target, '1.99.1', target, 'unwind')[1]
                d.artifact_profile(emitted, target, '1.99.1')
                self.assertTrue(all(wrapped.call_count == 1 for wrapped in watched))
                if target == d.TARGETS[2]:
                    self.assertTrue(all(row.args[1]['MACOSX_DEPLOYMENT_TARGET'] == '11.0'
                                        for row in commands.call_args_list))
        print('Composed hosted graph: prefix abstraction, all 20 boundary populations and three dependency checks executed', flush=True)

    def verification_rows(self, profile):
        d = self.driver
        _, definitions, aliases, names, _ = profile
        for identity in d.common.IDENTITIES:
            for compiled, method in ((False, 'verify'), (True, 'compiled_verify')):
                symbol = next(s for s in (*definitions, *aliases)
                              if names[s] == 'brynja_hmac_hosted_cleanup_fixture::' + identity + '::' + method)
                yield identity, compiled, symbol, *d.common.resolve(symbol, definitions, aliases)

    def verification_mutants(self, profile, target, compiler='1.99.1'):
        d, count = self.driver, 0
        _, definitions, aliases, names, _ = profile
        for identity, compiled, symbol, args, body in self.verification_rows(profile):
            d.public_verify.check(args, body, names, target, compiler, identity, compiled)
            mutants = []
            for line in body.splitlines():
                call = d.syntax.call(line)
                if call and names.get(call[0], '').endswith('::execute'):
                    for index, replacement in ((0, 'ptr %request'), (1, 'ptr %session'),
                                               (2, 'ptr null'), (3, 'i64 0'), (4, 'ptr %session')):
                        mutants.append(body.replace(line, line.replace(call[1][index], replacement), 1))
                    mutants.append(body.replace(line, line + '\n' + line.replace('%0 =', '%duplicate ='), 1))
                if '= icmp eq ' in line:
                    mutants.append(body.replace(line, line.replace('icmp eq', 'icmp ne'), 1))
                if line.strip().startswith('ret { i8, i8 } '):
                    for result in ('255', '12', '11', '10', '0'):
                        mutants.append(body.replace(line, self.forged_result(line, 0, result), 1))
                    for field in (0, 1):
                        mutants.append(body.replace(line, self.forged_result(line, field), 1))
            mutants += [body.replace('start:', 'start:\nstore i8 0, ptr %candidate.0, align 1', 1),
                        body.replace('start:', 'start:\n%early = load i8, ptr %candidate.0, align 1', 1)]
            for mutant in mutants:
                self.assertNotEqual(mutant, body)
                with self.subTest(target=target, identity=identity, compiled=compiled), self.assertRaises(ValueError):
                    d.public_verify.check(args, mutant, names, target, compiler, identity, compiled)
                count += 1
            with self.assertRaises(ValueError):
                d.public_verify.check(args.replace('%candidate', '%wrong'), body, names, target, compiler, identity, compiled)
            count += 1
        first = next(self.verification_rows(profile))[2]
        with self.assertRaises(ValueError):
            d.public_verify.validate(definitions, {**aliases, first: first}, names, target, compiler)
        with self.assertRaises(ValueError):
            d.public_verify.validate(definitions, aliases, {**names, first: 'unreviewed::' + names[first]}, target, compiler)
        return count + 2

    def test_actual_public_verification_mutations(self):
        count = sum(self.verification_mutants(profile, target) for target, profile in self.profiles.items())
        self.assertGreater(count, 1000)
        print(f'Hosted public verify mutations: {count} rejected', flush=True)

    def test_msrv_public_verification_mutations(self):
        d, count = self.driver, 0
        for target in d.TARGETS:
            llvm = d.emit(self.root / ('verify-msrv-' + target), '1.90.0', target, 'unwind')[1]
            profile = (llvm, *d.validate(llvm, target, '1.90.0'))
            count += self.verification_mutants(profile, target, '1.90.0')
        self.assertGreater(count, 1000)
        print(f'MSRV public verify mutations: {count} rejected', flush=True)

    def test_public_verification_decision_guard_is_load_bearing(self):
        d = self.driver
        for target, profile in self.profiles.items():
            identity, compiled, _, args, body = next(self.verification_rows(profile))
            names = profile[3]
            line = next(line for line in body.splitlines() if line.strip().startswith('ret { i8, i8 } '))
            mutant = body.replace(line, self.forged_result(line, 1), 1)
            with self.assertRaisesRegex(ValueError, 'public verify decision/error payload changed'):
                d.public_verify.check(args, mutant, names, target, '1.99.1', identity, compiled)
            require = d.public_verify.require
            def without_decision_guard(condition, message):
                if message != 'public verify decision/error payload changed':
                    require(condition, message)
            with mock.patch.object(d.public_verify, 'require', side_effect=without_decision_guard):
                d.public_verify.check(args, mutant, names, target, '1.99.1', identity, compiled)

    def test_public_verification_result_domain_and_profile(self):
        d = self.driver
        for compiler in ('1.90.0', '1.99.1'):
            rows = list(d.public_verify.results(compiler))
            self.assertEqual(len(rows), 2339)
            self.assertEqual(rows[:3], [(255 if compiler == '1.99.1' else 12, n, True) for n in (0, 1, 2)])
            for category in range(12):
                population = [p for c, p, meaningful in rows if c == category]
                self.assertEqual(population, list(range({0: 14, 7: 11, 9: 7}.get(category, 256))))
        for target, (llvm, *_) in self.profiles.items():
            d.artifact_profile(llvm, target, '1.99.1')
            declaration = re.search(r'^target triple = .*$', llvm, re.M)[0]
            for replacement in ('', 'target triple = "x86_64-pc-windows-msvc"', declaration + '\n' + declaration):
                with self.assertRaises(ValueError):
                    d.artifact_profile(llvm.replace(declaration, replacement, 1), target, '1.99.1')
            with self.assertRaises(ValueError):
                d.artifact_profile(llvm, target, '1.90.0')
        with self.assertRaises(ValueError):
            list(d.public_verify.results('unreviewed'))

    def test_real_compiling_public_verification_mutants(self):
        d, count = self.driver, 0
        work = self.root / 'compiled-public-verify'
        host, fixture = self.compiled_fixture(work)
        for target, prefix in ((d.TARGETS[0], 'strict_hmac'), (d.TARGETS[2], 'macos_resident/hmac')):
            for compiled, file in ((False, '/mod.rs'), (True, '/compiled.rs')):
                path = host / ('src/' + prefix + file)
                original = path.read_text()
                changes = (
                    ('Some(candidate), cancel)?', 'Some(&[]), cancel)?'),
                    ('Some(false) => Err(Error::Mismatch)', 'Some(false) => Ok(())'),
                    ('None => Err(Error::Invariant)', 'None => Ok(())'),
                )
                for old, new in changes:
                    self.assertEqual(original.count(old), 1)
                    try:
                        path.write_text(original.replace(old, new, 1))
                        llvm = d.emit(work / target, '1.99.1', target, 'unwind', fixture / 'Cargo.toml')[1]
                        definitions, aliases = d.common.definitions_and_aliases(llvm)
                        names = d.lifecycle.demangle({s.strip('"') for s in re.findall(r'@("[^"]+"|[-\w.$]+)', llvm)})
                        profile = (llvm, definitions, aliases, names, set())
                        rows = [row for row in self.verification_rows(profile) if row[1] == compiled]
                        self.assertEqual(len(rows), 12)
                        for identity, _, _, args, body in rows:
                            with self.subTest(target=target, identity=identity, mutant=new), self.assertRaises(ValueError):
                                d.public_verify.check(args, body, names, target, '1.99.1', identity, compiled)
                        count += 1
                    finally:
                        path.write_text(original)
                d.validate(d.emit(work / target, '1.99.1', target, 'unwind', fixture / 'Cargo.toml')[1], target)
        self.assertEqual(count, 12)
        print(f'Public verify: {count} compiling source mutants rejected across all twelve identities', flush=True)
