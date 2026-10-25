"""Compiled and emitted candidate/decision transport regressions."""
from pathlib import Path
import re

from legacy_hmac_hosted_compiled_fixture import prepare


class Md5DecisionTests:
    def test_md5_typed_decision_and_success_modes(self):
        h, count = self.driver.hosted, 0
        for case in self.cases:
            llvm = case[0]['brynja-legacy-hmac-hosted-cleanup']
            compiler, = re.findall(r'!"rustc version ([\d.]+) ', llvm)
            population = self.report_population(llvm)
            h.md5_decision.typed(population, compiler)
            for symbol, (_, body) in population[0].items():
                if '::decision::' not in population[2].get(symbol, ''):
                    continue
                mutants = []
                for line in body.splitlines():
                    if 'getelementptr' in line:
                        mutants.append(body.replace(line, re.sub(r'i64 (\d+)',
                            lambda m: 'i64 ' + str(int(m[1]) + 8), line), 1))
                    elif ' = load ' in line:
                        mutants.append(body.replace(line, re.sub(r'ptr %[-\w.]+', 'ptr %unbound', line), 1))
                    elif ' = icmp ' in line:
                        mutants.append(body.replace(line, line.replace('icmp eq', 'icmp ne') if 'icmp eq' in line
                                                    else line.replace('icmp ne', 'icmp eq'), 1))
                    elif ' = select ' in line:
                        mutants.append(body.replace(line, re.sub(r'select i1 %[-\w.]+', 'select i1 false', line), 1))
                    elif line.strip().startswith('ret i16 '):
                        mutants.append(body.replace(line, re.sub(r'i16 (\d+)',
                            lambda m: 'i16 ' + str(int(m[1]) ^ 256), line), 1))
                        mutants.append(body.replace(line, re.sub(r'i16 (\d+)',
                            lambda m: 'i16 ' + str(int(m[1]) ^ 1), line), 1))
                for mutant in mutants:
                    self.assertNotEqual(mutant, body)
                    with self.subTest(target=case[1], mutation=count), self.assertRaises(ValueError):
                        h.md5_decision.typed(self.report_population(llvm.replace(body, mutant, 1)), compiler)
                    count += 1
        self.assertGreater(count, 60)
        print(f'MD5 decision probes: {count} candidate/layout/Boolean/status substitutions rejected', flush=True)

    def test_md5_candidate_and_decision_transport(self):
        h, count = self.driver.hosted, 0
        for case, arguments, body, names, compiler in self.md5_models():
            def validate(candidate):
                model, health, boundaries = self.md5_check(arguments, candidate, names, compiler, case[1])
                envelope = h.envelope.check(arguments, candidate, names, 'md5_compiled')
                transfers = h.md5_result_transport.check(model, health, case[1])
                return model, h.md5_decision.check(model, envelope, boundaries, transfers, compiler)

            model, decision = validate(body)
            mutants = []
            # The public mismatch adapter can convert the Boolean before report
            # admission. Mutate that transport too, not just the final suffix.
            for block, index in sorted(decision.points | decision.verify.points):
                line = model.graph[block][index]
                if ' = icmp ' in line:
                    mutants.append(body.replace(line, line.replace('icmp eq', 'icmp ne') if 'icmp eq' in line
                                                else line.replace('icmp ne', 'icmp eq'), 1))
                elif line.startswith('br i1 '):
                    for target in re.findall('label %' + h.flow.LABEL, line):
                        mutants.append(body.replace(line, 'br label %' + target, 1))
                elif ' = load ptr' in line:
                    mutants.append(body.replace(line, re.sub(r'ptr %[-\w.]+', 'ptr %unbound', line), 1))
                elif ' = zext i1 ' in line:
                    for value in ('true', 'false'):
                        mutants.append(body.replace(line, re.sub(r'zext i1 %[-\w.]+', 'zext i1 ' + value, line), 1))
                elif ' = phi i8 ' in line:
                    for before, after in ((decision.verify.decision, '0'), ('[ 2,', '[ 0,')):
                        if before in line:
                            mutants.append(body.replace(line, line.replace(before, after), 1))
                    mutants.append(body.replace(line, re.sub(r'\[ %[-\w.]+,', '[ 0,', line, count=1), 1))
                elif line.startswith('store i16 '):
                    for value in (255, 511, 767):
                        mutants.append(body.replace(line, re.sub(r'store i16 %[-\w.]+', 'store i16 ' + str(value), line), 1))
                if (block, index) in (decision.auth.consumer, decision.verify.consumer):
                    call = h.syntax.call(line)
                    mutants.append(body.replace(line, line.replace(call[1][3], 'ptr %unbound'), 1))
            # Keep all Result tags intact but corrupt the success payload chain.
            pending, reached = [decision.success], set()
            while pending:
                block = pending.pop()
                if block in reached:
                    continue
                reached.add(block)
                pending.extend(re.findall('label %' + h.flow.LABEL, '\n'.join(model.graph[block])))
            for block in reached:
                for line in model.graph[block]:
                    if ' = phi i8 ' in line and decision.payload in line:
                        mutants.append(body.replace(line, line.replace(decision.payload, '0'), 1))
                    if ' = shl ' in line and ', 8' in line:
                        mutants.append(body.replace(line, line.replace(', 8', ', 7'), 1))
            verify_line = model.graph[decision.verify.consumer[0]][decision.verify.consumer[1]]
            mutants.append(body.replace(verify_line, 'call void @escape(ptr ' + decision.candidate + ')\n  ' + verify_line, 1))
            for mutant in mutants:
                self.assertNotEqual(mutant, body)
                with self.subTest(target=case[1], mutation=count), self.assertRaises(ValueError):
                    validate(mutant)
                count += 1
        self.assertGreater(count, 100)
        print(f'MD5 candidate/decision transport: {count} mode/operand/payload defects rejected', flush=True)

    def test_compiled_md5_decision_defects(self):
        d, h = self.driver, self.driver.hosted
        work = Path(self.directory.name) / 'md5-decision-mutants'
        leaf, fixture = prepare(d, work)
        count = 0
        for target, directory in ((d.TARGETS[0], 'strict_execution'), (d.TARGETS[2], 'macos_resident')):
            def emit():
                return d.emit(work / target, '1.99.1', target, 'unwind', True,
                              fixture / 'Cargo.toml', leaf / 'Cargo.toml')
            h.validate(emit(), target, 'unwind')
            path = leaf / 'src' / directory / 'md5_compiled/worker.rs'
            original = path.read_text()
            edits = (
                ('.verify(&lanes, candidates, &mut control)', '.verify(&lanes, &[None; 8], &mut control)'),
                ('Some(decision)', 'Some(true)'),
                ('Some(decision)', 'Some(false)'),
                ('Some(decision)', 'Some(!decision)'),
                ('Some(decision)', 'None'),
                ('        None\n    };', '        Some(true)\n    };'),
                ('let result = if let Some(candidates) = candidates {',
                 'let result = if let Some(candidates) = candidates.filter(|_| false) {'),
                ('let (rows, remainder) = staging.as_chunks_mut::<16>();',
                 'let mut unrelated = [0u8; 128]; let (rows, remainder) = unrelated.as_chunks_mut::<16>();'),
            )
            for before, after in edits:
                self.assertIn(before, original)
                try:
                    path.write_text(original.replace(before, after, 1))
                    artifacts = emit()
                    with self.subTest(target=target, mutation=count), self.assertRaises(ValueError):
                        h.validate(artifacts, target, 'unwind')
                finally:
                    path.write_text(original)
                count += 1
            h.validate(emit(), target, 'unwind')
        self.assertEqual(count, 16)
        print('MD5 decision transport: 16 compiled Rust defects rejected; restored baselines pass', flush=True)
