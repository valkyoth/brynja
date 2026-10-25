"""Real emitted and compiled MD5 control/callback substitution regressions."""
from pathlib import Path
import re

from legacy_hmac_hosted_compiled_fixture import prepare


class Md5ControlTests:
    def test_md5_control_typed_layout_and_callbacks(self):
        h, count = self.driver.hosted, 0
        for case in self.cases:
            fixture = case[0]['brynja-legacy-hmac-hosted-cleanup']
            population = self.report_population(fixture)
            h.md5_control.typed(population)
            for symbol, (_, body) in population[0].items():
                if '::control::' not in population[2].get(symbol, ''):
                    continue
                mutants = []
                for line in body.splitlines():
                    if 'getelementptr' in line:
                        mutants.append(body.replace(line, re.sub(r'i64 (\d+)',
                            lambda m: 'i64 ' + str(int(m[1]) + 8), line), 1))
                    if line.strip().startswith('store ') or ' = load ' in line:
                        mutants.append(body.replace(line, re.sub(r'ptr %[-\w.]+', 'ptr %unbound', line), 1))
                        mutants.append(body.replace(line, '', 1))
                for mutant in mutants:
                    with self.subTest(mutation=count), self.assertRaises(ValueError):
                        h.md5_control.typed(self.report_population(fixture.replace(body, mutant, 1)))
                    count += 1
        self.assertGreater(count, 50)
        print(f'MD5 typed control: {count} constructor/budget defects rejected', flush=True)

    def test_md5_control_transport_and_vtable(self):
        h, count, callback_count = self.driver.hosted, 0, 0
        for case, arguments, body, names, compiler in self.md5_models():
            llvm = case[0]['brynja-legacy-hmac-std']
            population = self.report_population(llvm)

            def validate(candidate):
                model = h.keyed.check(candidate, names, compiler, 'md5_compiled')
                envelope = h.envelope.check(arguments, candidate, names, 'md5_compiled')
                return model, h.md5_control.check(model, envelope, llvm, population, case[1])

            model, control = validate(body)
            mutants = []
            for block, index in sorted(control.points):
                line = model.graph[block][index]
                call = h.syntax.call(line)
                if ' = getelementptr' in line:
                    mutants.append(body.replace(line, re.sub(r'i64 (\d+)$',
                        lambda m: 'i64 ' + str(int(m[1]) + 8), line), 1))
                elif line.startswith('store '):
                    mutants.append(body.replace(line, '', 1))
                    mutants.append(body.replace(line, line + '\n  ' + line, 1))
                    mutants.append(body.replace(line, re.sub(r'(store (?:ptr|i64) )(%[-\w.]+|@[-\w.$]+)',
                                                             r'\g<1>%unbound', line), 1))
                    if line.startswith('store i64 '):
                        for value in ('0', '-1'):
                            mutants.append(body.replace(line, re.sub(r'store i64 %[-\w.]+', 'store i64 ' + value, line), 1))
                elif call and call[0].startswith('llvm.lifetime.'):
                    # Post-consumer end completeness is not claimed here.
                    if call[0] == 'llvm.lifetime.start.p0':
                        mutants.append(body.replace(line, '', 1))
                    mutants.append(body.replace(line, line + '\n  ' + line, 1))
                elif (block, index) in control.consumers:
                    arg = call[1][4]
                    mutants.append(body.replace(line, line.replace(arg, 'ptr %unbound'), 1))
                    for root in (control.root, control.context):
                        for effect in ('store ptr %unbound, ptr ' + root + ', align 8',
                                       'call void @escape(ptr ' + root + ')'):
                            mutants.append(body.replace(line, effect + '\n  ' + line, 1))
                        end = next(row for rows in model.graph.values() for row in rows
                                   if 'llvm.lifetime.end.p0' in row and h.syntax.operand(h.syntax.call(row)[1][-1]) == root)
                        mutants.append(body.replace(line, end + '\n  ' + line, 1))
            for mutant in mutants:
                self.assertNotEqual(mutant, body)
                with self.subTest(target=case[1], mutation=count), self.assertRaises(ValueError):
                    validate(mutant)
                count += 1
            # Consistent SSA renaming does not change the accepted transport.
            renamed = body
            for index, root in enumerate((control.root, control.context)):
                renamed = re.sub(re.escape(root) + r'(?![-\w.])', '%control_storage_' + str(index), renamed)
            validate(renamed)
            row = next(line for line in llvm.splitlines() if line.startswith(control.table + ' = '))
            table_mutants = [llvm.replace(row, '', 1), llvm.replace(row, row + '\n' + row, 1)]
            for before, after in (('constant', 'global'), (r'\08', r'\10'), ('align 8', 'align 4'),
                                  ('[24 x i8]', '[16 x i8]')):
                table_mutants.append(llvm.replace(row, row.replace(before, after), 1))
            for entry in control.callbacks:
                table_mutants.append(llvm.replace(row, row.replace('@' + entry, '@unknown_callback'), 1))
                args, callback = h.flow.resolve(entry, *population[:2])
                changed = [callback.replace(' acquire,', ' monotonic,'), callback.replace('icmp ne', 'icmp eq'),
                           re.sub(r'ret i1 %[-\w.]+', 'ret i1 false', callback),
                           re.sub(r'load ptr, ptr %[-\w.]+', 'load ptr, ptr %unbound', callback),
                           callback.replace('ret i1', 'call void @escape()\n  ret i1')]
                table_mutants.extend(llvm.replace(callback, value, 1) for value in changed)
            for mutant in table_mutants:
                self.assertNotEqual(mutant, llvm)
                with self.subTest(target=case[1], mutation=callback_count), self.assertRaises(ValueError):
                    h.md5_control.vtable(mutant, control.table, self.report_population(mutant), case[1])
                callback_count += 1
        self.assertGreater(count, 180)
        self.assertEqual(callback_count, 90)
        print(f'MD5 control: {count} transfer/lifetime defects and {callback_count} vtable/callback defects rejected', flush=True)

    def test_compiled_md5_control_defects(self):
        d, h = self.driver, self.driver.hosted
        work = Path(self.directory.name) / 'md5-control-mutants'
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
                ('parameters.budget, &mut cancelled', '0, &mut cancelled'),
                ('parameters.budget, &mut cancelled', 'usize::MAX, &mut cancelled'),
                ('parameters.budget, &mut cancelled', 'parameters.bytes, &mut cancelled'),
                ('cancel.check().is_err()', 'false'),
                ('cancel.check().is_err()', 'true'),
                ('cancel.check().is_err()', 'cancel.check().is_ok()'),
                ('Md5BatchControl::with_cancellation(parameters.budget, &mut cancelled)',
                 'Md5BatchControl::new(parameters.budget)'),
            )
            mutants = [original.replace(before, after, 1) for before, after in edits]
            mutants.append(original.replace('let mut cancelled = || {',
                'let snapshot = cancel.check().is_err(); let mut cancelled = || {', 1)
                .replace('        cancel.check().is_err()', '        snapshot', 1))
            mutants.append(original.replace('let mut cancelled = || {',
                'let unrelated = Cancellation::new(); let mut cancelled = || {', 1)
                .replace('        cancel.check().is_err()', '        unrelated.check().is_err()', 1))
            for mutant in mutants:
                self.assertNotEqual(mutant, original)
                try:
                    path.write_text(mutant)
                    artifacts = emit()  # Compilation must succeed, not count as rejection.
                    with self.subTest(target=target, mutation=count), self.assertRaises(ValueError):
                        h.validate(artifacts, target, 'unwind')
                finally:
                    path.write_text(original)
                count += 1
            h.validate(emit(), target, 'unwind')
        self.assertEqual(count, 18)
        print('MD5 control: 18 compiled Rust defects rejected; restored baselines pass', flush=True)
