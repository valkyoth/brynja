"""Emitted input/iterator/tail mutations and compiling safe-Rust regressions."""
import re
import copy


class InputTests:
    def input_mutations(self, model, flow, body):
        d = self.driver
        mutations = []
        for point in sorted(flow.points):
            line = model.graph[point[0]][point[1]]
            alternatives = []
            if line.startswith('store '):
                alternatives = ['', line + '\n' + line,
                                re.sub(r'^(store (?:i8|i64)) ' + d.syntax.VALUE, r'\1 0', line)]
            elif ' = phi ' in line:
                values = re.findall(r'\[ (' + d.syntax.VALUE + '|null), %' + d.common.LABEL + r' \]', line)
                if len(values) == 2 and values[0][0] != values[1][0]:
                    alternatives = [line.replace('[ ' + values[0][0] + ',', '[ ' + values[1][0] + ',', 1),
                                    line.replace('[ ' + values[1][0] + ',', '[ ' + values[0][0] + ',', 1)]
            elif ' = icmp ' in line:
                alternatives = [line.replace('icmp eq', 'icmp ne') if 'icmp eq' in line else line.replace('icmp ne', 'icmp eq')]
            elif ' = getelementptr' in line:
                alternatives = [re.sub(r'i64 (\d+)$', lambda match: 'i64 ' + str(int(match[1]) + 1), line),
                                re.sub(r'i64 ' + d.syntax.VALUE + '$', 'i64 0', line)]
            elif '@llvm.umin.i64' in line:
                alternatives = [line.replace('i64 4096', 'i64 4095')]
            elif '@llvm.usub.sat.i64' in line:
                alternatives = [line.replace('i64 1)', 'i64 2)')]
            elif re.search(r' = (?:add|sub) ', line):
                alternatives = [line.replace(' = add ', ' = sub ') if ' = add ' in line else line.replace(' = sub ', ' = add ')]
            elif ' = sext i1 ' in line or ' = zext i1 ' in line:
                alternatives = [line.replace('sext', 'zext') if 'sext' in line else line.replace('zext', 'sext')]
            elif ' = and i1 ' in line or ' = or i1 ' in line:
                alternatives = [line.replace(' = and ', ' = or ') if ' = and ' in line else line.replace(' = or ', ' = and ')]
            elif line.startswith('br i1 '):
                edges = re.findall(r'label %' + d.common.LABEL, line)
                alternatives = [line.replace('label %' + edges[0], 'label %__temporary', 1).replace(
                    'label %' + edges[1], 'label %' + edges[0], 1).replace('label %__temporary', 'label %' + edges[1])]
            elif ' = select ' in line:
                alternatives = [line.replace('i1 true', 'i1 false'),
                                re.sub(r'i8 0', 'i8 1', line)]
            elif '@llvm.memcpy.' in line:
                alternatives = [line.replace('i64 22', 'i64 21')]
            for changed in alternatives:
                if changed != line:
                    mutations.append(body.replace(line, changed, 1))
        # Direct argument substitution is independent of iterator expressions.
        for symbol, args, point in model.calls:
            if point not in {flow.update, flow.tail.full[2], flow.tail.partial[2],
                             *(at for _, at, _ in model.terminals)}:
                continue
            line = model.graph[point[0]][point[1]]
            if point == flow.update:
                indexes = (1, 2)
            elif point in (flow.tail.full[2], flow.tail.partial[2]):
                indexes = range(1, len(args))
            else:
                indexes = (2 if len(args) == 5 else 1,)
            for index in indexes:
                replacement = 'ptr %unrelated_input' if args[index].startswith('ptr') else args[index].split()[0] + ' 0'
                mutations.append(body.replace(line, line.replace(args[index], replacement, 1), 1))
        return list(dict.fromkeys(mutations))

    def test_input_iterators_and_tail_provenance(self):
        d, count = self.driver, 0
        for target, (_, definitions, aliases, names, checked) in self.profiles.items():
            for arguments, body, identity, compiled in self.output_workers(definitions, aliases, names, checked, target):
                model = d.keyed.check(body, names, '1.99.1', identity, compiled)
                flow = d.input_flow.check(model, arguments)
                for mutant in self.input_mutations(model, flow, body):
                    with self.subTest(target=target, identity=identity, compiled=compiled, case=count):
                        with self.assertRaises(ValueError):
                            changed = d.keyed.Admission(mutant, names, '1.99.1', identity, compiled)
                            d.input_flow.check(changed, arguments)
                    count += 1
        self.assertGreater(count, 3000)
        print(f'Hosted input/tail provenance: {count} emitted mutations rejected', flush=True)

    def test_msrv_input_split_and_result_cases(self):
        d, count = self.driver, 0
        for target in d.TARGETS:
            llvm = d.emit(self.root / ('input-msrv-' + target), '1.90.0', target, 'abort')[1]
            definitions, aliases, names, checked = d.validate(llvm, target, '1.90.0', 'abort')
            for arguments, body, identity, compiled in self.output_workers(definitions, aliases, names, checked, target):
                model = d.keyed.check(body, names, '1.90.0', identity, compiled)
                flow = d.input_flow.check(model, arguments, '1.90.0')
                for mutant in self.input_mutations(model, flow, body):
                    with self.subTest(target=target, identity=identity, compiled=compiled, case=count):
                        with self.assertRaises(ValueError):
                            changed = d.keyed.Admission(mutant, names, '1.90.0', identity, compiled)
                            d.input_flow.check(changed, arguments, '1.90.0')
                    count += 1
        self.assertGreater(count, 3000)
        print(f'Hosted MSRV input/tail provenance: {count} emitted mutations rejected', flush=True)

    def test_nonempty_part_cannot_repeat_before_advance(self):
        d, count = self.driver, 0
        for target, (_, definitions, aliases, names, checked) in self.profiles.items():
            for arguments, body, identity, compiled in self.output_workers(definitions, aliases, names, checked, target):
                model = d.keyed.check(body, names, '1.99.1', identity, compiled)
                flow = d.input_flow.check(model, arguments)
                self.assertNotEqual(flow.update[0], flow.part_header)
                changed = copy.copy(flow)
                changed.m = copy.copy(model)
                changed.m.graph = {block: list(lines) for block, lines in model.graph.items()}
                lines = changed.m.graph[flow.update[0]]
                self.assertIn('invoke ', lines[flow.update[1]])
                normal = re.match('to label %' + d.common.LABEL, lines[flow.update[1] + 1])
                self.assertIsNotNone(normal)
                lines[flow.update[1] + 1] = lines[flow.update[1] + 1].replace(
                    'label %' + normal[1], 'label %' + flow.update[0], 1)
                # Directly exercise the path check, rather than crediting a
                # predecessor/dominance rejection in another verifier first.
                with self.assertRaisesRegex(ValueError, 'same input part updated more than once'):
                    changed.iteration()
                count += 1
        self.assertEqual(count, 72)
        print(f'Hosted input iteration: {count} repeated-update paths rejected', flush=True)

    def check_compiled_input_mutants(self, host, fixture, work):
        d = self.driver
        for target, directory in ((d.TARGETS[0], 'strict_hmac'), (d.TARGETS[2], 'macos_resident/hmac')):
            for compiled in (False, True):
                path = host / 'src' / directory / ('compiled/worker.rs' if compiled else 'worker.rs')
                original = path.read_text()
                variants = [original.replace('chunk.chunks(4096)', 'chunk.chunks(4095)'),
                            original.replace('.chain(core::iter::once(complete))', '.chain(core::iter::once(request.tail.bytes))'),
                            original.replace('request.tail.valid_bits == 8', 'request.tail.valid_bits == 7'),
                            original.replace('            request.tail.valid_bits\n', '            8\n'),
                            original.replace('state.update(part).map_err(Error::Mac)?;',
                                             'for _ in 0..request.tail.valid_bits { state.update(part).map_err(Error::Mac)?; }')]
                for case, mutant in enumerate(variants):
                    self.assertNotEqual(mutant, original)
                    try:
                        path.write_text(mutant)
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
                                # Require the input checker itself to reject each
                                # mutant, independently of earlier admission checks.
                                model = d.keyed.Admission(body, names, '1.99.1', identity, compiled)
                                with self.assertRaises(ValueError):
                                    d.input_flow.check(model, arguments)
                        with self.assertRaises(ValueError):
                            d.validate(llvm, target)
                    finally:
                        path.write_text(original)
                    d.validate(d.emit(work / target, '1.99.1', target, 'unwind', fixture / 'Cargo.toml')[1], target)
        print('Hosted input: twenty real compiled Rust mutants rejected; restored baselines pass', flush=True)

    def test_real_compiled_input_mutants(self):
        work = self.root / 'compiled-input-mutants'
        host, fixture = self.compiled_fixture(work)
        self.check_compiled_input_mutants(host, fixture, work)
