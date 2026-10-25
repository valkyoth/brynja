"""Regress actual batch output artifacts and independently compiled defects."""
import difflib
from pathlib import Path
import re
from unittest.mock import patch

from legacy_hmac_hosted_compiled_fixture import prepare


class BatchLoanTests:
    def batch_populations(self, case):
        h = self.driver.hosted
        result = []
        for key in ('brynja-legacy-hmac-hosted-cleanup', 'brynja-legacy-hmac-std'):
            llvm = case[0][key]
            definitions, aliases = h.flow.definitions_and_aliases(llvm)
            names = h.model.demangle({n.strip('"') for n in re.findall(r'@("[^"]+"|[-\w.$]+)', llvm)})
            result.append((definitions, aliases, names))
        compiler = re.findall(r'!"rustc version ([\d.]+) ', llvm)[0]
        return *result, compiler

    def test_batch_loan_methods(self):
        h, count, scenarios, profiles = self.driver.hosted, 0, 0, 0
        for case in self.cases:
            fixture, leaf, compiler = self.batch_populations(case)
            rows = h.batch_loans.validate(fixture, leaf, case[1], compiler, case[3])
            for operation, args, body, names, reached, total in rows:
                def check(text):
                    if operation == 'expose':
                        return h.batch_loans.expose(args, text, names, case[1])
                    return h.batch_loans.consume(args, text, names, case[1], compiler, case[3], operation == 'clear')
                profiles += 1
                scenarios += total
                mutants = set()
                for label, lines in h.flow.blocks(body).items():
                    if label not in reached:
                        continue
                    for line in lines:
                        call = h.syntax.call(line)
                        if '= getelementptr' in line:
                            mutants.add(body.replace(line, re.sub(r'i64 (\d+)', lambda m: 'i64 ' + str(int(m[1]) + 1), line), 1))
                        for before, after in (('icmp ult ', 'icmp ugt '), ('icmp ugt ', 'icmp ult '),
                                              ('icmp eq ', 'icmp ne '), (', 4', ', 3')):
                            if before in line and ('icmp' in line or 'shl ' in line):
                                mutants.add(body.replace(line, line.replace(before, after), 1))
                        if call and (names.get(call[0], '').endswith(('>::clear', '>::as_bytes'))
                                     or names.get(call[0]) == h.batch_loans.copy.COPY):
                            mutants.add(body.replace(line, line.replace('@' + call[0], '@wrong_loan_call'), 1))
                            for arg in call[1]:
                                if arg.startswith('ptr '):
                                    mutants.add(body.replace(line, line.replace(arg, 'ptr %wrong_owner'), 1))
                            if names.get(call[0]) == h.batch_loans.copy.COPY:
                                mutants.add(body.replace(line, line.replace(call[1][1], 'i64 127'), 1))
                            if 'invoke ' not in line:
                                mutants.add(body.replace(line, '', 1))
                        if line.startswith('ret ') and line != 'ret void':
                            mutants.add(body.replace(line, 'ret void', 1))
                mutants.discard(body)
                for mutant in sorted(mutants):
                    delta = '\n'.join(difflib.unified_diff(body.splitlines(), mutant.splitlines(), n=1))
                    with self.subTest(target=case[1], operation=operation, delta=delta), self.assertRaises(ValueError):
                        check(mutant)
                    count += 1
        self.assertEqual(profiles, 18)
        self.assertGreater(count, 100)
        print(f'Batch legacy loans: {profiles} methods, {scenarios} outcomes, {count} mutations rejected', flush=True)

    def test_batch_loan_factories(self):
        h, count, scenarios = self.driver.hosted, 0, 0
        for case in self.cases:
            _, leaf, compiler = self.batch_populations(case)
            executor = leaf[2][case[2]['md5_compiled'][0]]
            args, body = h.batch_loans.selected(leaf, executor.removesuffix('execute') + 'compute')
            def check(text):
                return h.batch_creation.creation(args, text, leaf[2], case[1], compiler, executor)
            scenarios += check(body)
            mutants = set()
            for line in body.splitlines():
                if '= getelementptr' in line:
                    mutants.add(body.replace(line, re.sub(r'i64 (\d+)', lambda m: 'i64 ' + str(int(m[1]) + 1), line), 1))
                if line.strip().startswith('store '):
                    mutants.add(body.replace(line, '', 1))
                if '= icmp eq ' in line:
                    mutants.add(body.replace(line, line.replace('icmp eq ', 'icmp ne '), 1))
                call = h.syntax.call(line)
                if call and leaf[2].get(call[0]) == executor:
                    for arg in call[1]:
                        if arg.startswith('ptr '):
                            mutants.add(body.replace(line, line.replace(arg, 'ptr %wrong_owner'), 1))
            for mutant in sorted(mutants):
                self.assertNotEqual(body, mutant)
                with self.subTest(target=case[1], mutant=count), self.assertRaises(ValueError):
                    check(mutant)
                count += 1
        print(f'Batch legacy loan factories: {len(self.cases)} profiles, {scenarios} outcomes, {count} mutations rejected', flush=True)

    def test_batch_loan_forwarding_and_move(self):
        h, count = self.driver.hosted, 0
        for case in self.cases:
            fixture, leaf, compiler = self.batch_populations(case)
            owner = h.profile(case[1])[0] + '::md5_compiled::types::Md5BatchOutput'
            for operation in ('expose', 'declassify', 'clear'):
                wanted = 'brynja_legacy_hmac_hosted_cleanup::md5_compiled::output_' + operation
                args, body = h.batch_loans.selected(fixture, wanted)
                target = '<' + owner + (' as core::ops::drop::Drop>::drop' if operation == 'clear' else '>::' + operation)
                if operation != 'clear' and not any(fixture[2].get(s) == target and '@' + s in body for s in fixture[2]):
                    continue
                def check(text):
                    if operation == 'clear':
                        return h.batch_loans.moved_drop(args, text, fixture[2], target)
                    return h.batch_loans.forward(args, text, fixture[2], target, operation)
                check(body)
                for line in body.splitlines():
                    if call := h.syntax.call(line):
                        replacements = [line.replace('@' + call[0], '@wrong_forwarding_call')]
                        for arg in call[1]:
                            replacements.append(line.replace(arg, 'ptr %different' if arg.startswith('ptr ') else 'i64 23'))
                        for replacement in replacements:
                            with self.assertRaises(ValueError):
                                check(body.replace(line, replacement, 1))
                            count += 1
                definitions, aliases, names = fixture
                symbol = next(s for s in (*definitions, *aliases) if names.get(s) == wanted)
                with self.assertRaises(ValueError):
                    h.batch_loans.validate((definitions, aliases, {**names, symbol: 'missing'}), leaf, case[1], compiler, case[3])
                with self.assertRaises(ValueError):
                    h.batch_loans.validate((definitions, {**aliases, 'duplicate': symbol}, {**names, 'duplicate': wanted}),
                                          leaf, case[1], compiler, case[3])
        print(f'Batch legacy loan forwarding/moves: {count} call mutations and missing/duplicate probes rejected', flush=True)

    def test_batch_loan_scalar_walker(self):
        f = self.driver.hosted.batch_loans.flow
        def unexpected(*_):
            self.fail('scalar instruction reached external-call model')
        def run(expression, initial=None):
            return f.run('entry:\n %r = ' + expression + '\n ret i64 %r', initial or {}, {}, unexpected)[1]
        self.assertEqual(run('add i64 18446744073709551615, 1'), 0)
        self.assertEqual(run('add nuw i64 18446744073709551614, 1'), 2**64 - 1)
        for expression in ('add nuw i64 18446744073709551615, 1', 'add nsw i64 1, 2',
                           'add i64 undef, 1', 'add i64 %missing, 1', 'mul i64 1, 2'):
            with self.assertRaises(ValueError):
                run(expression)
        for a, b in ((0, 0), (2**64 - 1, 0), (2**64 - 1, 1)):
            for index, expected in ((0, (a + b) % (2**64)), (1, int(a + b >= 2**64))):
                body = ('entry:\n %sum = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %a, i64 %b)\n'
                        f' %value = extractvalue {{ i64, i1 }} %sum, {index}\n'
                        + (' %result = zext i1 %value to i64\n ret i64 %result' if index else ' ret i64 %value'))
                self.assertEqual(f.run(body, {'%a': a, '%b': b}, {}, unexpected)[1], expected)
        body = ('entry:\n %p = getelementptr inbounds i8, ptr %base, i64 %offset\n'
                ' %v = load i8, ptr %p, align 1\n ret i8 %v')
        self.assertEqual(f.run(body, {'%base': ('loan', 0), '%offset': 7}, {('loan', 7): 1}, unexpected)[1], 1)
        for offset in (-1, 8, 2**64, f.expressions.Unknown()):
            with self.assertRaises(ValueError):
                f.run(body, {'%base': ('loan', 0), '%offset': offset}, {('loan', 7): 1}, unexpected)

    def test_batch_loan_projection_cache_identity(self):
        h, case = self.driver.hosted, self.cases[2]
        fixture, leaf, compiler = self.batch_populations(case)
        rows = h.batch_loans.validate(fixture, leaf, case[1], compiler, case[3])
        _, args, body, names, _, _ = next(row for row in rows if row[0] == 'expose')
        baseline = (args, body, names, case[1])
        expected = h.batch_loans.expose(*baseline)
        with patch.object(h.batch_loans.flow, 'run', side_effect=ValueError('must recheck changed projection')):
            self.assertEqual(h.batch_loans.expose(*baseline), expected)
            for index, replacement in enumerate((args + ' ', body + '\n', {**names, 'new': 'different'}, 'different-target')):
                changed = list(baseline)
                changed[index] = replacement
                with self.assertRaises(ValueError):
                    h.batch_loans.expose(*changed)
        executor = leaf[2][case[2]['md5_compiled'][0]]
        args, body = h.batch_loans.selected(leaf, executor.removesuffix('execute') + 'compute')
        baseline = (args, body, leaf[2], case[1], compiler, executor)
        expected = h.batch_creation.creation(*baseline)
        with patch.object(h.batch_creation.flow, 'run', side_effect=ValueError('must recheck changed projection')):
            self.assertEqual(h.batch_creation.creation(*baseline), expected)
            changes = (args + ' ', body + '\n', {**leaf[2], 'new': 'different'}, 'different-target', '1.90.0', 'other-executor')
            for index, replacement in enumerate(changes):
                changed = list(baseline)
                changed[index] = replacement
                with self.assertRaises(ValueError):
                    h.batch_creation.creation(*changed)
        self.assertEqual(h.batch_creation.creation(*baseline), expected)

    def test_compiled_batch_loan_defects(self):
        d, h = self.driver, self.driver.hosted
        work = Path(self.directory.name) / 'batch-loan-mutants'
        leaf, fixture = prepare(d, work)
        count = 0
        for target, directory in ((d.TARGETS[0], 'strict_execution'), (d.TARGETS[2], 'macos_resident')):
            def emit():
                return d.emit(work / target, '1.99.1', target, 'unwind', True,
                              fixture / 'Cargo.toml', leaf / 'Cargo.toml')
            edits = [('md5_compiled.rs', 'storage: &mut self.output,', 'storage: &mut self.staging,'),
                     ('md5_compiled.rs', 'active: inputs.each_ref().map(Option::is_some),', 'active: [true; 8],'),
                     ('md5_compiled.rs', 'bytes: self.bytes,', 'bytes: 10,'),
                     ('md5_compiled/types.rs', 'lane.checked_mul(16)?', 'lane.checked_mul(15)?'),
                     ('md5_compiled/types.rs', 'self.storage.clear();', 'let _ = self.storage.as_bytes();'),
                     ('md5_compiled/types.rs', 'start.checked_add(self.bytes)?', 'start.checked_add(10)?')]
            for file, before, after in edits:
                path = leaf / 'src' / directory / file
                original = path.read_text()
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
        self.assertEqual(count, 12)
        print('Batch legacy loans: 12 compiled defects rejected; restored baselines pass', flush=True)
