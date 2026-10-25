"""Actual-emission mutations for scalar constructor provenance and Result flow."""
import re


class NormalizationTests:
    def normalized_models(self):
        h = self.driver.hosted
        for case, identity, body, names, compiler, env, retained, _ in self.scalar_models():
            prefix = h.scalar.construct.check(retained, env, case[3])
            initial = h.scalar.normalization.contracts.validate(case[2][identity][2])[identity]
            model = h.scalar.normalization.check(prefix, initial)
            yield case, identity, body, names, compiler, env, prefix, initial, model

    def rejects_normalization(self, case, identity, body, names, compiler, env, initial, mutant):
        h = self.driver.hosted
        self.assertNotEqual(body, mutant)
        changed = '\n'.join(row for row in mutant.splitlines() if row not in body.splitlines())[:500]
        with self.subTest(identity=identity, target=case[1], changed=changed), self.assertRaises(ValueError):
            retained = h.scalar.Retained(mutant, names, compiler, identity, env)
            prefix = h.scalar.construct.check(retained, env, case[3])
            h.scalar.normalization.check(prefix, initial)

    def test_normalization_routes_and_copy_results(self):
        h, count = self.driver.hosted, 0
        for case, identity, body, names, compiler, env, prefix, initial, n in self.normalized_models():
            m, mutants = prefix.m, []
            for name, (rhs, point) in m.defs.items():
                line = m.graph[point[0]][point[1]]
                if rhs.startswith('icmp') and prefix.length in re.findall(h.keyed.V, rhs):
                    mutants.extend(body.replace(line, re.sub(r', \d+$', ', ' + value, line), 1)
                                   for value in ('1', '63', '65'))
                    mutants.append(body.replace(line, line.replace('ugt', 'ult').replace('eq ', 'ne '), 1))
                if rhs.startswith('select') and re.search(r', i8 (?:8|-1), i8 2$', rhs):
                    mutants.append(body.replace(line, re.sub(r', i8 2$', ', i8 ' + ('8' if compiler == '1.90.0' else '-1'), line), 1))
            for symbol, args, point in m.calls:
                line = m.graph[point[0]][point[1]]
                if point == n.copy:
                    for position, value in ((0, 'ptr %unrelated'), (1, 'i64 0'), (2, 'ptr ' + prefix.key), (3, 'i64 1')):
                        mutants.append(body.replace(line, line.replace(args[position], value, 1), 1))
                    mutants.append(body.replace(line, line.replace(symbol, symbol + '_wrong'), 1))
                    result = re.match('(' + h.keyed.V + ') = ', line)[1]
                    compare = next((site, rhs) for rhs, site in m.defs.values() if result in re.findall(h.keyed.V, rhs))
                    old = m.graph[compare[0][0]][compare[0][1]]
                    mutants.append(body.replace(old, old.replace('icmp eq', 'icmp ne'), 1))
                if symbol == 'llvm.memset.p0.i64' and prefix.address(h.syntax.operand(args[0])) == prefix.pad:
                    mutants.append(body.replace(line, line.replace('i8 0', 'i8 1'), 1))
            mask = m.graph[n.stop[0]][n.stop[1]]
            mutants.append(body.replace(mask, 'store i8 0, ptr ' + prefix.pad[0] + ', align 1\n' + mask, 1))
            for mutant in mutants:
                self.rejects_normalization(case, identity, body, names, compiler, env, initial, mutant)
                count += 1
            self.assertEqual(n.successes, {'empty', 'short', 'long'})
        self.assertGreaterEqual(count, 198)
        print(f'Legacy normalization routes/copy/error: {count} defects rejected', flush=True)

    def test_normalization_descriptor_lifetimes_and_drops(self):
        h, count = self.driver.hosted, 0
        for case, identity, body, names, compiler, env, prefix, initial, n in self.normalized_models():
            m, mutants = prefix.m, []
            for label, lines in m.graph.items():
                for index, line in enumerate(lines):
                    point = label, index
                    if '= load ' in line and any(prefix.address(name)[0] in n.roots for name in re.findall(h.keyed.V, line)):
                        pointer = re.search(', ptr (' + h.keyed.V + '),', line)[1]
                        mutants.append(body.replace(line, line.replace(', ptr ' + pointer + ',', ', ptr %unrelated,'), 1))
                        mutants.append(body.replace(line, 'call void @llvm.lifetime.end.p0(ptr ' + n.result[0] + ')\n' + line, 1))
                    if line.startswith('store ') and any(prefix.address(name)[0] == n.region[0] for name in re.findall(h.keyed.V, line)):
                        mutants.extend((body.replace(line, '', 1), body.replace(line, line + '\n' + line, 1)))
                        mutants.append(body.replace(line, re.sub(r'^store (ptr|i64) ' + h.keyed.V + ',', r'store \1 %unrelated,', line), 1))
                    if point in n.drops:
                        symbol, args = m.call_map[point]
                        mutants.append(body.replace(line, line.replace(args[0], 'ptr %unrelated'), 1))
                        if 'invoke ' in line:
                            edge = lines[index + 1]
                            normal = re.match('to label %' + h.flow.LABEL, edge)[1]
                            mutants.append(body.replace(line, 'br label %' + normal, 1).replace(edge, '', 1))
                        else:
                            mutants.append(body.replace(line, '', 1))
                        mutants.append(body.replace(line, 'call void @llvm.lifetime.end.p0(ptr ' + n.region[0] + ')\n' + line, 1))
            copied = m.graph[n.copy[0]][n.copy[1]]
            for extra in ('store ptr ' + n.region[0] + ', ptr @escaped, align 8',
                          '%alias = ptrtoint ptr ' + n.region[0] + ' to i64',
                          'call void @unknown(ptr ' + n.result[0] + ')',
                          '%alias = getelementptr i8, ptr ' + n.result[0] + ', i64 %unknown'):
                mutants.append(body.replace(copied, extra + '\n' + copied, 1))
            for mutant in mutants:
                self.rejects_normalization(case, identity, body, names, compiler, env, initial, mutant)
                count += 1
            renamed = body
            for number, root in enumerate(sorted(n.roots)):
                renamed = re.sub(re.escape(root) + r'(?![-\w.])', '%renamed_result_' + str(number), renamed)
            retained = h.scalar.Retained(renamed, names, compiler, identity, env)
            h.scalar.normalization.check(h.scalar.construct.check(retained, env, case[3]), initial)
        self.assertGreater(count, 250)
        print(f'Legacy normalization descriptor/lifetime/Drop: {count} defects rejected', flush=True)

    def test_normalization_independent_layout_and_initial_bytes(self):
        h, count = self.driver.hosted, 0
        for case, identity, body, names, compiler, env, prefix, initial, n in self.normalized_models():
            for mode, point, dest, data in prefix.m.writes:
                if mode != 'store' or prefix.address(dest)[0] not in prefix.roles:
                    continue
                line = prefix.m.graph[point[0]][point[1]]
                changed = re.sub(r'i8 (-?\d+)', lambda m: 'i8 ' + str((int(m[1]) + 1) % 127), line, count=1)
                if changed == line:
                    changed = line.replace('store i64 0,', 'store i64 1,')
                if changed != line:
                    self.rejects_normalization(case, identity, body, names, compiler, env, initial, body.replace(line, changed, 1))
                    count += 1
            definitions, aliases, probe_names = case[2][identity][2]
            for operation in ('accepted', 'rejected'):
                symbol = next(s for s in (*definitions, *aliases) if probe_names[s] ==
                              'brynja_legacy_hmac_hosted_cleanup::normalization::' + identity + '::' + operation)
                signature, probe = h.flow.resolve(symbol, definitions, aliases)
                before = 'store i8 ' + ('0' if operation == 'accepted' else '1') + ', ptr %_0'
                self.assertIn(before, probe)
                for after in (before.replace('i8 0', 'i8 2').replace('i8 1', 'i8 0'), before.replace('%_0', '%unrelated')):
                    with self.assertRaises(ValueError):
                        h.scalar.normalization.contracts.result(signature, probe.replace(before, after), operation == 'accepted')
                    count += 1
        self.assertGreater(count, 100)
        print(f'Legacy normalization typed ABI/initialization: {count} defects rejected', flush=True)
