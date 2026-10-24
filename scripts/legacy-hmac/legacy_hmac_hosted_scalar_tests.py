"""Real emitted scalar-worker storage, transfer and cleanup regressions."""
import re


class ScalarTests:
    def scalar_models(self):
        h = self.driver.hosted
        for case, identity, worker, (defs, aliases, names), _ in self.hosts():
            if identity.endswith('_compiled'):
                continue
            signature, body = h.flow.resolve(worker, defs, aliases)
            envelope = h.envelope.check(signature, body, names, identity)
            compiler = re.findall(r'!"rustc version ([\d.]+) ', next(iter(case[0].values())))[0]
            model, helpers = h.scalar.check(body, names, compiler, identity, envelope, defs, aliases, case[3])
            yield case, identity, body, names, compiler, envelope, model, helpers

    def test_scalar_retained_initialization_and_terminals(self):
        h, count = self.driver.hosted, 0
        for case, identity, body, names, compiler, envelope, model, _ in self.scalar_models():
            mutants = []
            for mode, point, dest, data in model.writes:
                if point not in model.initial:
                    continue
                line = model.graph[point[0]][point[1]]
                if model.pointer(dest)[1] == model.size - 6:
                    # Padding is not a logical owner: removing its optional
                    # copy must not manufacture a cleanup failure.
                    h.scalar.Retained(body.replace(line, '', 1), names, compiler, identity, envelope)
                else:
                    mutants.append(body.replace(line, '', 1))
                mutants.append(body.replace(line, line + '\n' + line, 1))
                if mode == 'store':
                    mutants.append(body.replace(line, line.replace(data, 'i64 1'), 1))
                else:
                    mutants.append(body.replace(line, line.replace(data[2], 'i64 1'), 1))
                    other = next(root for root in model.sources if root != model.pointer(h.syntax.operand(data[1]))[0])
                    mutants.append(body.replace(line, line.replace(data[1], 'ptr ' + other), 1))
            for root, point, move in model.terminals:
                line = model.graph[point[0]][point[1]]
                copied = model.graph[move[0]][move[1]]
                mutants.extend((body.replace(copied, '', 1),
                                body.replace(copied, copied.replace('i64 ' + str(model.size), 'i64 1'), 1)))
                for extra in ('call void @llvm.lifetime.end.p0(ptr ' + root + ')',
                              'store i8 0, ptr ' + root + ', align 1',
                              'call void @unknown_terminal(ptr ' + root + ')'):
                    mutants.append(body.replace(line, extra + '\n' + line, 1))
            for _, point, argument in model.consumers:
                line = model.graph[point[0]][point[1]]
                symbol, args = model.call_map[point]
                mutants.extend((body.replace(line, line.replace(symbol, symbol + '_wrong'), 1),
                                body.replace(line, line.replace(args[argument], 'ptr %unrelated'), 1)))
                other = 1 if argument == 0 else 0
                mutants.append(body.replace(line, line.replace(args[other], args[argument]), 1))
            for mutant in mutants:
                with self.subTest(identity=identity, target=case[1], mutation=count), self.assertRaises(ValueError):
                    h.scalar.Retained(mutant, names, compiler, identity, envelope)
                count += 1
            renamed = re.sub(re.escape(model.owner) + r'(?![-\w.])', '%renamed_scalar_retained', body)
            h.scalar.check(renamed, names, compiler, identity, envelope, *case[2][identity][2][:2], case[3])
        self.assertGreaterEqual(count, 324)
        print(f'Legacy scalar retained initialization/terminals: {count} defects rejected', flush=True)

    def test_scalar_retained_storage(self):
        h, count = self.driver.hosted, 0
        for case, identity, body, names, compiler, envelope, model, _ in self.scalar_models():
            roots, _, uses, starts, _ = h.storage.check(model)
            mutants = []
            for root in roots:
                point = starts[root][0]
                line = model.graph[point[0]][point[1]]
                mutants.extend((body.replace(line, '', 1), body.replace(line, line + '\n' + line, 1)))
                for point in uses[root]:
                    line = model.graph[point[0]][point[1]]
                    mutants.append(body.replace(line, 'call void @llvm.lifetime.end.p0(ptr ' + root + ')\n' + line, 1))
                for extra in ('store ptr ' + root + ', ptr @escaped, align 8',
                              '%escaped = ptrtoint ptr ' + root + ' to i64'):
                    mutants.append(body.replace(line, extra + '\n' + line, 1))
            for mutant in mutants:
                with self.subTest(identity=identity, target=case[1], mutation=count), self.assertRaises(ValueError):
                    h.storage.check(h.scalar.Retained(mutant, names, compiler, identity, envelope))
                count += 1
        self.assertGreater(count, 300)
        print(f'Legacy scalar retained storage: {count} lifetime/escape defects rejected', flush=True)

    def test_scalar_retained_cleanup_and_actual_helpers(self):
        h, count, helper_count = self.driver.hosted, 0, 0
        for case, identity, body, names, compiler, envelope, model, helpers in self.scalar_models():
            defs, aliases, _ = case[2][identity][2]
            mutants = []
            for symbol, args, point in model.calls:
                if not model.can_precede(model.cut, point):
                    continue
                dropping = h.scalar.legacy.owner_drop(symbol, identity) or symbol in helpers
                updating = h.scalar.legacy.adapter_update(symbol, identity)
                terminal = point in {site for _, site, _ in model.terminals}
                if not (dropping or updating or terminal):
                    continue
                line = model.graph[point[0]][point[1]]
                if dropping or updating:
                    mutants.append(body.replace(line, line.replace(args[0], 'ptr %unrelated'), 1))
                if dropping:
                    if 'invoke ' in line:
                        edge = model.graph[point[0]][point[1] + 1]
                        normal = re.match('to label %' + h.flow.LABEL, edge)[1]
                        mutants.append(body.replace(line, 'br label %' + normal, 1).replace(edge, '', 1))
                    else:
                        mutants.extend((body.replace(line, '', 1), body.replace(line, line + '\n' + line, 1)))
                if updating or terminal:
                    for extra in ('call void @unknown_live(ptr ' + model.owner + ')',
                                  'store i8 0, ptr ' + model.owner + ', align 1',
                                  '%untyped_read = load i8, ptr ' + model.owner + ', align 1'):
                        mutants.append(body.replace(line, extra + '\n' + line, 1))
                    if case[3] == 'unwind':
                        self.assertIn('invoke ', line)
                        edge = model.graph[point[0]][point[1] + 1]
                        normal = re.match('to label %' + h.flow.LABEL, edge)[1]
                        mutants.append(body.replace(line, line.replace('invoke ', 'call ', 1), 1)
                                       .replace(edge, 'br label %' + normal, 1))
                    if terminal:
                        # On either return edge the consuming callee owns the
                        # object; the caller cannot inspect the old source.
                        if 'invoke ' in line:
                            edge = model.graph[point[0]][point[1] + 1]
                            destinations = re.findall('label %' + h.flow.LABEL, edge)
                            for destination in destinations:
                                old = model.graph[destination][0]
                                mutants.append(body.replace(old, old + '\n%late_scalar = load i8, ptr '
                                                            + model.owner + ', align 1', 1))
                        else:
                            mutants.append(body.replace(line, line + '\n%late_scalar = load i8, ptr '
                                                        + model.owner + ', align 1', 1))
            for mutant in mutants:
                with self.subTest(identity=identity, target=case[1], mutation=count), self.assertRaises(ValueError):
                    h.scalar.check(mutant, names, compiler, identity, envelope, defs, aliases, case[3])
                count += 1
            for helper in helpers:
                signature, code = h.flow.resolve(helper, defs, aliases)
                calls = [line for line in code.splitlines() if (call := h.syntax.call(line))
                         and h.scalar.legacy.owner_drop(call[0], identity)]
                self.assertTrue(calls)
                for line in calls:
                    changed = dict(defs)
                    changed[helper] = signature, code.replace(line, '', 1)
                    with self.assertRaises(ValueError):
                        h.scalar.check(body, names, compiler, identity, envelope, changed, aliases, case[3])
                    helper_count += 1
        self.assertGreater(count, 150)
        self.assertGreaterEqual(helper_count, 12)
        print(f'Legacy scalar retained cleanup: {count} caller and {helper_count} helper defects rejected', flush=True)
