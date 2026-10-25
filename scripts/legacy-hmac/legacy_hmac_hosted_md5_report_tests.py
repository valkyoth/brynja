"""Adversarial report admission/count tests using actual compiler output."""
import re


class Md5ReportTests:
    def report_population(self, llvm):
        h = self.driver.hosted
        definitions, aliases = h.flow.definitions_and_aliases(llvm)
        names = h.model.demangle({n.strip('"') for n in re.findall(r'@("[^"]+"|[-\w.$]+)', llvm)})
        return definitions, aliases, names

    def test_md5_report_typed_layout_probes(self):
        h, count = self.driver.hosted, 0
        for case in self.cases:
            population = self.report_population(case[0]['brynja-legacy-hmac-hosted-cleanup'])
            h.md5_report_layout.validate(population)
            for symbol in (*population[0], *population[1]):
                name = population[2].get(symbol, '')
                if '::report::' not in name:
                    continue
                arguments, body = h.flow.resolve(symbol, *population[:2])
                if name.endswith('::backend_width'):
                    mutant = body.replace('i64 4, i64 8', 'i64 8, i64 4')
                elif '::slot' in name:
                    mutant = body.replace('icmp ne ptr', 'icmp eq ptr')
                elif name.endswith('::width'):
                    mutant = body.replace('ret i64 %_0', 'ret i64 8')
                else:
                    mutant = re.sub(r'(getelementptr[^\n]+, i64 )(\d+)',
                                    lambda m: m[1] + str(int(m[2]) + 8), body, count=1)
                self.assertTrue(mutant != body, name)
                altered = dict(case[0])
                altered['brynja-legacy-hmac-hosted-cleanup'] = altered['brynja-legacy-hmac-hosted-cleanup'].replace(body, mutant, 1)
                # The integration, not just the standalone layout helper, must
                # actually consume each independent typed probe.
                with self.subTest(name=name, target=case[1]), self.assertRaises(ValueError):
                    h.validate(altered, case[1], case[3])
                count += 1
        self.assertEqual(count, 90)
        print('MD5 report/slot typed layouts: 90 substitutions rejected', flush=True)

    def test_md5_report_decision_truth_table(self):
        h, count, profiles = self.driver.hosted, 0, 0
        for case, _, _, _, compiler in self.md5_models():
            population = self.report_population(case[0]['brynja-legacy-hmac-std'])
            wanted = h.checkpoints.owner(case[1]) + '::md5_compiled::worker::report'
            symbol, = [s for s in population[0] if population[2].get(s) == wanted]
            arguments, body = population[0][symbol]
            h.md5_report_logic.validate(arguments, body, compiler)
            before = h.md5_report_logic.validate.cache_info()
            self.assertIsInstance(h.md5_report_logic.validate(arguments, body, compiler), frozenset)
            self.assertEqual(h.md5_report_logic.validate.cache_info().hits, before.hits + 1)
            with self.assertRaises(ValueError):
                h.md5_report_logic.validate(arguments, body, 'unreviewed-compiler')
            mutants = []
            for rows in h.flow.blocks(body).values():
                for line in rows:
                    if '= getelementptr' in line:
                        mutants.append(body.replace(line, re.sub(r'i64 (\d+)$', lambda m: 'i64 ' + str(int(m[1]) + 8), line), 1))
                    elif ' = load ' in line:
                        mutants.append(body.replace(line, re.sub(r'ptr %[-\w.]+', 'ptr %unbound', line), 1))
                    elif ' = icmp ' in line:
                        for before, after in (('icmp eq', 'icmp ne'), ('icmp ne', 'icmp eq'), ('icmp ult', 'icmp uge')):
                            if before in line:
                                mutants.append(body.replace(line, line.replace(before, after), 1))
                    elif line.startswith('br i1 '):
                        for value in ('true', 'false'):
                            mutants.append(body.replace(line, re.sub(r'br i1 %[-\w.]+', 'br i1 ' + value, line), 1))
            mutants.extend((body.replace('[ 8,', '[ 6,').replace('i8 8,', 'i8 6,'),
                            re.sub(r'ret i8 %[-\w.]+', 'ret i8 ' + ('10' if compiler == '1.90.0' else '-1'), body),
                            body.replace('ret i8 ', 'call void @unexpected()\nret i8 ')))
            for mutant in mutants:
                self.assertTrue(mutant != body, 'mutation ' + str(count))
                with self.subTest(target=case[1], mutation=count), self.assertRaises(ValueError):
                    h.md5_report_logic.validate(arguments, mutant, compiler)
                count += 1
            renamed, signature = body, arguments
            values = [a.split()[-1] for a in h.syntax.parameters(arguments)]
            values.extend(re.findall(r'^\s*(%[-\w.]+) =', body, re.M))
            for index, value in enumerate(values):
                token = '%report_identity_' + str(index)
                renamed = re.sub(re.escape(value) + r'(?![-\w.])', token, renamed)
                signature = re.sub(re.escape(value) + r'(?![-\w.])', token, signature)
            h.md5_report_logic.validate(signature, renamed, compiler)
            self.rejects(case, body, 'icmp ult', 'icmp uge')
            profiles += 1
        self.assertEqual(profiles, 5)
        self.assertGreater(count, 100)
        print(f'MD5 report decisions: {count} emitted defects rejected; 128 abstract cases/profile', flush=True)

    def test_md5_report_count_backend_and_rejection_transport(self):
        h, count = self.driver.hosted, 0
        for case, arguments, body, names, compiler in self.md5_models():
            def validate(candidate):
                model = h.keyed.check(candidate, names, compiler, 'md5_compiled')
                transfer = h.authority.check(candidate, names, compiler, 'md5_compiled')
                env = h.envelope.check(arguments, candidate, names, 'md5_compiled')
                counter, points = h.md5_report_caller.check(model, transfer, env, compiler, case[1])
                return model, counter, points
            model, counter, points = validate(body)
            mutants = []
            for block, index in sorted(counter.points | points):
                line = model.graph[block][index]
                if '= getelementptr' in line:
                    mutants.append(body.replace(line, re.sub(r'i64 (\d+)$', lambda m: 'i64 ' + str(int(m[1]) + 8), line), 1))
                elif ' = load ptr' in line:
                    mutants.append(body.replace(line, re.sub(r'load ptr, ptr %[-\w.]+', 'load ptr, ptr %unbound', line), 1))
                elif ' = icmp ne ptr' in line:
                    mutants.append(body.replace(line, line.replace('icmp ne', 'icmp eq'), 1))
                elif ' = add ' in line:
                    operands = re.search(r'i64 (%[-\w.]+), (%[-\w.]+)', line)
                    self.assertIsNotNone(operands)
                    for bad in ('0', operands[1]):
                        mutants.append(body.replace(line, line.replace(', ' + operands[2], ', ' + bad), 1))
                elif ' = icmp eq i8' in line:
                    mutants.append(body.replace(line, line.replace('icmp eq', 'icmp ne'), 1))
                elif line.startswith('br i1 '):
                    condition, good, bad = re.fullmatch('br i1 (' + h.keyed.V + '), label %' + h.flow.LABEL
                                                       + ', label %' + h.flow.LABEL, line).groups()
                    mutants.append(body.replace(line, 'br label %' + good, 1))
                    mutants.append(body.replace(line, 'br label %' + bad, 1))
                elif line.startswith('store i16 '):
                    mutants.append(body.replace(line, re.sub(r'store i16 %[-\w.]+', 'store i16 0', line), 1))
                call = h.syntax.call(line)
                if call and names.get(call[0], '').endswith('::md5_compiled::worker::report'):
                    for arg in call[1][1:]:
                        mutants.append(body.replace(line, line.replace(arg, arg.split()[0] + ' 0', 1), 1))
            for mutant in mutants:
                self.assertTrue(mutant != body, 'mutation ' + str(count))
                with self.subTest(target=case[1], compiler=compiler, mutation=count), self.assertRaises(ValueError):
                    validate(mutant)
                count += 1
        self.assertGreater(count, 150)
        print(f'MD5 report caller: {count} count/backend/rejection defects rejected', flush=True)
