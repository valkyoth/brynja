"""Temporary stream ownership/admission mutations in genuine compiler output."""
import re


class AcceleratedCheckpointTests:
    def test_accelerated_checkpoint_placement_and_error_results(self):
        h, count = self.driver.hosted, 0
        for case, identity, arguments, body, names, compiler in self.stream_workers():
            if identity != 'sha1_compiled':
                continue
            def validate(candidate):
                model, envelope = self.stream_model(arguments, candidate, names, compiler, identity)
                incoming = h.input_flow.check(model, arguments, envelope, case[3], compiler)
                outgoing = h.output.check(model, arguments, case[3])
                transfer = h.authority.check(candidate, names, compiler, identity)
                records, _ = h.checkpoint_inline.check(model, incoming, transfer, case[1])
                return h.checkpoint_boundaries.Boundaries(model, incoming, outgoing, transfer,
                                                          records, case[1], compiler).check()
            checked = validate(body)
            mutants = []
            for label, index in sorted(checked.points):
                line = checked.m.graph[label][index]
                if 'icmp eq i8 ' in line:
                    mutants.append(body.replace(line, line.replace('icmp eq', 'icmp ne'), 1))
                    mutants.append(body.replace(line, re.sub(r', -?\d+$', ', 1', line), 1))
                elif line.startswith('br i1'):
                    condition, good, bad = checked.flow.branch(label)
                    mutants.append(body.replace(line, line.replace('label %' + good, 'label %' + bad), 1))
                    mutants.append(body.replace(line, line.replace('label %' + bad, 'label %' + good), 1))
                elif line.startswith('store i16 '):
                    for code in (0, checked.ok & 255):
                        mutants.append(body.replace(line, re.sub('store i16 ' + h.syntax.VALUE,
                                                                'store i16 ' + str(code), line), 1))
            # Each boundary is necessary even when the other five survive.
            for point in checked.guards:
                line = checked.m.graph[point[0]][point[1]]
                symbol, _ = h.syntax.call(line)
                mutants.append(body.replace(line, line.replace('@' + symbol, '@missing_checkpoint'), 1))
            for mutant in mutants:
                self.assertNotEqual(mutant, body)
                with self.subTest(target=case[1], mutation=count), self.assertRaises(ValueError):
                    validate(mutant)
                count += 1
        self.assertGreater(count, 100)
        print(f'Accelerated SHA-1 checkpoint placement/result: {count} defects rejected', flush=True)

    def checkpoint_callees(self):
        h = self.driver.hosted
        for case in self.cases:
            llvm = case[0]['brynja-legacy-hmac-std']
            defs, aliases = h.flow.definitions_and_aliases(llvm)
            names = h.model.demangle({n.strip('"') for n in re.findall(r'@("[^"]+"|[-\w.$]+)', llvm)})
            compiler = re.findall(r'!"rustc version ([\d.]+) ', llvm)[0]
            wanted = h.checkpoints.owner(case[1]) + '::sha1_compiled::worker::checkpoint'
            selected = [s for s in (*defs, *aliases) if names.get(s) == wanted]
            if selected:
                self.assertEqual(len(selected), 1)
                yield case, *h.flow.resolve(selected[0], defs, aliases), names, compiler

    def temporary_mutations(self, model, body, points):
        h = self.driver.hosted
        for label, index in sorted(points):
            line = model.graph[label][index]
            call = h.syntax.call(line)
            if call:
                symbol, args = call
                name = model.names.get(symbol, symbol)
                if symbol.startswith('llvm.lifetime.') or name == h.checkpoint_flow.DROP:
                    if 'invoke ' in line:
                        edge = model.graph[label][index + 1]
                        normal = re.match('to label %' + h.flow.LABEL, edge)[1]
                        yield body.replace(line, 'br label %' + normal, 1).replace(edge, '', 1)
                    else:
                        yield body.replace(line, '', 1)
                        yield body.replace(line, line + '\n' + line, 1)
                    yield body.replace(line, line.replace(args[-1], 'ptr %unbound'), 1)
                if symbol == 'llvm.memcpy.p0.p0.i64':
                    for arg in args[:2]:
                        yield body.replace(line, line.replace(arg, 'ptr %unbound', 1), 1)
                    width = int(args[2].split()[-1])
                    for size in (width - 1, width + 1):
                        yield body.replace(line, line.replace(args[2], 'i64 ' + str(size)), 1)
                if name == h.checkpoint_flow.START:
                    for arg in args:
                        yield body.replace(line, line.replace(arg, 'ptr %unbound', 1), 1)
            if 'load atomic ' in line:
                yield body.replace(line, line.replace(' acquire,', ' monotonic,'), 1)
                yield body.replace(line, re.sub('ptr ' + h.syntax.VALUE, 'ptr %unbound', line), 1)
            elif ' = load i8,' in line:
                yield body.replace(line, re.sub('ptr ' + h.syntax.VALUE, 'ptr %unbound', line), 1)
            if line.startswith('store i8 '):
                yield body.replace(line, re.sub('store i8 ' + h.syntax.VALUE, 'store i8 0', line), 1)
                yield body.replace(line, '', 1)
            if 'icmp eq i8' in line:
                yield body.replace(line, line.replace('icmp eq', 'icmp ne'), 1)
            if '= getelementptr' in line and re.search(r'i64 \d+$', line):
                yield body.replace(line, re.sub(r'i64 (\d+)$', lambda m: 'i64 ' + str(int(m[1]) + 1), line), 1)

    def test_accelerated_checkpoint_callee_paths_and_lifetimes(self):
        h, count, cases = self.driver.hosted, 0, 0
        for case, arguments, body, names, compiler in self.checkpoint_callees():
            model = h.authority.Transfer(body, names, compiler, 'sha1_compiled')
            h.checkpoint_flow.validate(arguments, body, names, compiler)
            renamed, signature = body, arguments
            for index, root in enumerate((*model.allocs, *(h.syntax.operand(arg) for arg in h.syntax.parameters(arguments)))):
                replacement = '%checkpoint_identity_' + str(index)
                renamed = re.sub(re.escape(root) + r'(?![-\w.])', replacement, renamed)
                signature = re.sub(re.escape(root) + r'(?![-\w.])', replacement, signature)
            h.checkpoint_flow.validate(signature, renamed, names, compiler)
            points = {(label, i) for label, rows in model.graph.items() for i in range(len(rows))}
            mutants = list(self.temporary_mutations(model, body, points))
            mutants.extend((body.replace('ret i8 ', 'call void @unexpected()\nret i8 '),
                            body.replace('[ 7,', '[ 6,'), body.replace(', i8 6', ', i8 0')))
            for mutant in mutants:
                self.assertNotEqual(mutant, body)
                with self.subTest(compiler=compiler, target=case[1], mutation=count), self.assertRaises(ValueError):
                    h.checkpoint_flow.validate(arguments, mutant, names, compiler)
                count += 1
            # Integration must validate the callee, not just worker call names.
            self.rejects(case, body, '[ 7,', '[ 6,')
            cases += 1
        self.assertEqual(cases, 4)
        self.assertGreater(count, 180)
        print(f'Accelerated SHA-1 checkpoint callees: {count} ownership/admission defects rejected', flush=True)

    def test_inlined_checkpoint_temporary_owner_provenance(self):
        h, count, starts = self.driver.hosted, 0, 0
        for case, identity, arguments, body, names, compiler in self.stream_workers():
            if identity != 'sha1_compiled':
                continue
            model, envelope = self.stream_model(arguments, body, names, compiler, identity)
            incoming = h.input_flow.check(model, arguments, envelope, case[3], compiler)
            transfer = h.authority.check(body, names, compiler, identity)
            records, points = h.checkpoint_inline.check(model, incoming, transfer, case[1])
            starts += len(records)
            mutants = list(self.temporary_mutations(model, body, points))
            for symbol, args, point in model.calls:
                if symbol == 'llvm.lifetime.start.p0' and point in points:
                    # Dominance alone is insufficient: a single hoisted begin
                    # cannot restart a temporary ended on each loop iteration.
                    line = model.graph[point[0]][point[1]]
                    root = model.pointer(h.syntax.operand(args[-1]))[0]
                    allocated = model.defs[root][1]
                    allocation = model.graph[allocated[0]][allocated[1]]
                    mutants.append(body.replace(line, '', 1).replace(allocation, allocation + '\n  ' + line, 1))
            for mutant in mutants:
                self.assertNotEqual(mutant, body)
                with self.subTest(compiler=compiler, target=case[1], mutation=count), self.assertRaises(ValueError):
                    altered = h.keyed.Admission(mutant, names, compiler, identity)
                    h.checkpoint_inline.check(altered, incoming, transfer, case[1])
                count += 1
        self.assertGreater(starts, 6)
        self.assertGreater(count, 250)
        print(f'Inlined SHA-1 checkpoints: {count} defects rejected across {starts} temporary streams', flush=True)

    def test_checkpoint_typed_probes_are_load_bearing(self):
        h, count = self.driver.hosted, 0
        for case in self.cases:
            llvm = case[0]['brynja-legacy-hmac-hosted-cleanup']
            defs, aliases = h.flow.definitions_and_aliases(llvm)
            names = h.model.demangle({n.strip('"') for n in re.findall(r'@("[^"]+"|[-\w.$]+)', llvm)})
            for symbol in (*defs, *aliases):
                if '::checkpoint::' not in names[symbol]:
                    continue
                signature, body = h.flow.resolve(symbol, defs, aliases)
                operation = names[symbol].rsplit('::', 1)[-1]
                before, after = {'accepted': ('i64 448, i1 false', 'i64 447, i1 false'),
                                 'rejected': ('i64 441', 'i64 440'),
                                 'discard': ('i64 8', 'i64 9')}[operation]
                self.assertIn(before, body)
                changed = dict(defs)
                changed[symbol] = signature, body.replace(before, after)
                with self.assertRaises(ValueError):
                    h.checkpoint_flow.probes((changed, aliases, names))
                self.rejects(case, body, before, after)
                count += 1
        self.assertEqual(count, 18)
