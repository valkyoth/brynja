"""Mutations of actual legacy constructor, retained-owner and cleanup emissions."""
import re


class KeyedTests:
    def keyed_models(self):
        h = self.driver.hosted
        for case, identity, _, body, names, transfer in self.authorities():
            compiler = re.findall(r'!"rustc version ([\d.]+) ', next(iter(case[0].values())))[0]
            model = h.keyed.check(body, names, compiler, identity)
            yield case, identity, body, names, compiler, model

    def test_keyed_admission_bytes_errors_and_renaming(self):
        h, count = self.driver.hosted, 0
        for case, identity, body, names, compiler, model in self.keyed_models():
            renamed = re.sub(re.escape(model.owner) + r'(?![-\w.])', '%renamed_retained_owner', body)
            h.keyed.check(renamed, names, compiler, identity)
            mutants = []
            for mode, site, dest, data in model.writes:
                pointer = model.address(dest)
                if not pointer or site not in model.initial:
                    continue
                line = model.graph[site[0]][site[1]]
                mutants.append(body.replace(line, '', 1))
                if mode == 'copy':
                    mutants.append(body.replace(line, line.replace(data[2], 'i64 ' + str(int(data[2].split()[-1]) - 1)), 1))
                    mutants.append(body.replace(line, line.replace(data[1], 'ptr ' + model.owner), 1))
                else:
                    mutants.append(body.replace(line, line.replace(data, data.split()[0] + ' 0'), 1))
                for extra in ('call void @unknown_keyed(ptr ' + pointer[0] + ')',
                              'call void @llvm.lifetime.end.p0(ptr ' + pointer[0] + ')',
                              '%escaped = ptrtoint ptr ' + pointer[0] + ' to i64'):
                    mutants.append(body.replace(line, extra + '\n' + line, 1))
            guards = []
            for rhs, site in model.defs.values():
                compare = re.fullmatch(r'icmp (eq|ne) i8 (%[-\w.]+), 2', rhs)
                if not compare or compare[2] not in model.defs:
                    continue
                load = re.match(r'load i8, ptr (%[-\w.]+),', model.defs[compare[2]][0])
                if load and (p := model.address(load[1])) and p[0] in model.results and p[1] == model.discriminator:
                    guards.append(site)
                    line = model.graph[site[0]][site[1]]
                    inverse = line.replace('icmp eq', 'icmp ne') if compare[1] == 'eq' else line.replace('icmp ne', 'icmp eq')
                    mutants.extend((body.replace(line, inverse, 1), body.replace(line, line.replace(', 2', ', 99'), 1)))
            self.assertEqual(len(guards), 1)
            for mutant in mutants:
                with self.subTest(identity=identity, target=case[1], mutation=count), self.assertRaises(ValueError):
                    h.keyed.check(mutant, names, compiler, identity)
                count += 1
        self.assertGreater(count, 200)
        print(f'Legacy keyed admission: {count} representation/error/lifetime mutants rejected', flush=True)

    def test_keyed_terminal_handoffs(self):
        h, count = self.driver.hosted, 0
        for case, identity, body, names, compiler, model in self.keyed_models():
            mutants = []
            for root, consumer, move in model.terminals:
                line = model.graph[consumer[0]][consumer[1]]
                copied = model.graph[move[0]][move[1]]
                mutants.extend((body.replace(copied, '', 1),
                                body.replace(copied, copied.replace('i64 912', 'i64 904'), 1)))
                for extra in ('call void @llvm.lifetime.end.p0(ptr ' + root + ')',
                              'store i8 0, ptr ' + root + ', align 1',
                              'call void @unknown_terminal(ptr ' + root + ')'):
                    mutants.append(body.replace(line, extra + '\n' + line, 1))
            for _, site, argument in model.consumers:
                line = model.graph[site[0]][site[1]]
                symbol, args = model.call_map[site]
                mutants.extend((body.replace(line, line.replace(symbol, symbol + '_wrong'), 1),
                                body.replace(line, line.replace(args[argument], 'ptr %unrelated'), 1)))
                other = 1 if argument == 0 else 0
                mutants.append(body.replace(line, line.replace(args[other], args[argument]), 1))
            for mutant in mutants:
                with self.subTest(identity=identity, target=case[1]), self.assertRaises(ValueError):
                    h.keyed.check(mutant, names, compiler, identity)
                count += 1
        self.assertGreater(count, 80)
        print(f'Legacy keyed terminals: {count} move/identity/argument mutants rejected', flush=True)

    def test_keyed_storage_lifetimes_and_escapes(self):
        h, count = self.driver.hosted, 0
        for case, identity, body, names, compiler, model in self.keyed_models():
            roots, copies, uses, starts, _ = h.storage.check(model)
            mutants = []
            for root in roots:
                site = starts[root][0]
                line = model.graph[site[0]][site[1]]
                mutants.extend((body.replace(line, '', 1), body.replace(line, line + '\n' + line, 1)))
                for site in uses[root]:
                    line = model.graph[site[0]][site[1]]
                    mutants.append(body.replace(line, 'call void @llvm.lifetime.end.p0(ptr ' + root + ')\n' + line, 1))
                site = next(iter(uses[root]))
                line = model.graph[site[0]][site[1]]
                mutants.append(body.replace(line, 'store ptr ' + root + ', ptr @external, align 8\n' + line, 1))
            for mutant in mutants:
                with self.subTest(identity=identity, target=case[1]), self.assertRaises(ValueError):
                    h.storage.check(h.keyed.Admission(mutant, names, compiler, identity))
                count += 1
        self.assertGreater(count, 200)
        print(f'Legacy keyed storage: {count} lifetime/escape mutants rejected', flush=True)

    def test_retained_cleanup_and_selector_immutability(self):
        h, count = self.driver.hosted, 0
        for case, identity, body, names, compiler, model in self.keyed_models():
            definitions, aliases, _ = case[2][identity][2]
            helpers = h.retained.check(model, definitions, aliases, case[3])
            mutants = []
            for symbol, args, site in model.calls:
                if symbol not in helpers:
                    continue
                line = model.graph[site[0]][site[1]]
                mutants.append(body.replace(line, line.replace(args[0], 'ptr %unrelated'), 1))
                if 'invoke ' in line:
                    edges = model.graph[site[0]][site[1] + 1]
                    normal = re.match('to label %' + h.flow.LABEL, edges)[1]
                    mutants.append(body.replace(line, 'br label %' + normal, 1).replace(edges, '', 1))
                else:
                    mutants.extend((body.replace(line, '', 1), body.replace(line, line + '\n' + line, 1)))
            for _, site, _ in model.consumers:
                line = model.graph[site[0]][site[1]]
                for extra in ('call void @unknown_retained(ptr ' + model.owner + ')',
                              'store i8 0, ptr ' + model.owner + ', align 1',
                              '%late_read = load i8, ptr ' + model.owner + ', align 1'):
                    mutants.append(body.replace(line, extra + '\n' + line, 1))
                if identity == 'sha1_compiled' and case[3] == 'unwind':
                    self.assertIn('invoke ', line)
                    edges = model.graph[site[0]][site[1] + 1]
                    normal = re.match('to label %' + h.flow.LABEL, edges)[1]
                    mutants.append(body.replace(line, line.replace('invoke ', 'call ', 1), 1)
                                   .replace(edges, 'br label %' + normal, 1))
            for mutant in mutants:
                with self.subTest(identity=identity, target=case[1]), self.assertRaises(ValueError):
                    changed = h.keyed.Admission(mutant, names, compiler, identity)
                    h.retained.check(changed, definitions, aliases, case[3])
                count += 1
            for helper in helpers:
                signature, code = h.flow.resolve(helper, definitions, aliases)
                # Every occurrence of one concrete owner offset is changed,
                # covering the normal path rather than only an impossible
                # exceptional edge from the non-panicking primitive Drop.
                for offset in (16, 464):
                    self.assertIn('i64 ' + str(offset), code)
                    altered = dict(definitions)
                    altered[helper] = signature, code.replace('i64 ' + str(offset), 'i64 17')
                    with self.assertRaises(ValueError):
                        h.retained.check(model, altered, aliases, case[3])
                    count += 1
        self.assertGreater(count, 60)
        print(f'Legacy retained cleanup/selector: {count} caller/helper mutants rejected', flush=True)
