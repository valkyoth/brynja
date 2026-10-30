"""Hosted inlined accelerated consumers: byte handoffs, cleanup and real mutants."""
import copy
import re
import shutil
from unittest import mock


class CompiledCalleeTests:
    def compiled_consumers(self, profile, target, compiler='1.99.1', panic='unwind'):
        d = self.driver
        _, definitions, aliases, names, checked = profile
        for _, body, identity, compiled in self.output_workers(definitions, aliases, names, checked, target):
            if not compiled:
                continue
            model = d.keyed.check(body, names, compiler, identity, True)
            d.consumers.compiled(model, identity, definitions, aliases, compiler, panic)
            for _, point, _ in model.terminals:
                symbol = model.call_map[point][0]
                operation = 'verify_bits' if names[symbol].endswith('::verify_bits') else 'secret_bits'
                arguments, consumer = d.common.resolve(symbol, definitions, aliases)
                yield model, identity, symbol, arguments, consumer, operation, definitions, aliases

    def check_compiled_consumer_body(self, body, identity, operation, definitions, aliases,
                                    compiler='1.99.1', panic='unwind', route=15, present=True):
        d = self.driver
        d.consumers.compiled_scratch.check_body(body, operation, definitions, aliases)
        return d.consumers.prefix.check(body, identity, operation, definitions, aliases,
                                       compiler, panic, route, present)

    def compiled_consumer_mutations(self, profile, target, compiler='1.99.1'):
        d, count = self.driver, 0
        for model, identity, symbol, args, body, operation, definitions, aliases in self.compiled_consumers(
                profile, target, compiler):
            cuts = self.check_compiled_consumer_body(body, identity, operation, definitions, aliases, compiler)
            self.assertEqual(len(cuts), 1)
            label, index, root = next(iter(cuts))
            graph = d.common.blocks(body)
            allocs = re.findall('(' + d.syntax.VALUE + r') = alloca ', body)
            ptrs = d.syntax.pointers(body, (*allocs, '%self'))
            mutants = []
            for line in body.splitlines():
                call = d.syntax.call(line)
                if call and call[0] == 'llvm.memcpy.p0.p0.i64':
                    source = d.syntax.operand(call[1][1])
                    if ptrs.get(source, (source, 0))[0] == '%self':
                        extent = int(call[1][2].split()[-1])
                        mutants += [body.replace(line, '', 1),
                                    body.replace(line, line.replace(call[1][2], 'i64 ' + str(extent - 1)), 1),
                                    body.replace(line, line.replace(source + ',', '%input,'), 1)]
                if call and 'clear_owned_region' in call[0] and re.search(r'i64(?: noundef)? (64|1)\)', line):
                    mutants.append(body.replace(line, re.sub(r'(i64(?: noundef)? )(64|1)\)', r'\g<1>0)', line), 1))
            for line in graph[label][:index]:
                store = re.match(r'store i\d+ (' + d.syntax.VALUE + '), ptr (' + d.syntax.VALUE + '),', line)
                if store and ptrs.get(store[2], (store[2], 0))[0] == root:
                    mutants.append(body.replace(line, line.replace(store[1] + ',', '0,'), 1))
            for instruction in ('ret void', 'store ptr %self, ptr %escaped, align 8',
                                '%escaped = ptrtoint ptr %self to i64'):
                altered = copy.deepcopy(graph)
                altered[label].insert(index, instruction)
                mutants.append('\n'.join(name + ':\n' + '\n'.join(lines) for name, lines in altered.items()))
            for instruction in ('store i8 0, ptr %self, align 1',
                                'store ptr %self, ptr %escaped, align 8',
                                '%payload = load i8, ptr %self, align 1'):
                altered = copy.deepcopy(graph)
                altered[next(iter(altered))].insert(0, instruction)
                mutant = '\n'.join(name + ':\n' + '\n'.join(lines) for name, lines in altered.items())
                with self.assertRaises(ValueError):
                    self.check_compiled_consumer_body(mutant, identity, operation, definitions,
                                                      aliases, compiler, present=False)
                count += 1
            for mutant in mutants:
                self.assertNotEqual(mutant, body)
                with self.subTest(target=target, identity=identity, operation=operation), self.assertRaises(ValueError):
                    self.check_compiled_consumer_body(mutant, identity, operation, definitions, aliases, compiler)
                count += 1
            for changed in ((args.replace('%self', '%unrelated'), body), (args, 'start:\nret void\n')):
                with self.assertRaises(ValueError):
                    d.consumers.compiled(model, identity, {**definitions, symbol: changed}, aliases, compiler, 'unwind')
                count += 1
            with self.assertRaises(ValueError):
                d.consumers.compiled(model, identity, definitions, {**aliases, symbol: symbol}, compiler, 'unwind')
            count += 1
            changed = copy.copy(model)
            changed.names = {**model.names, symbol: 'unreviewed::' + model.names[symbol]}
            with self.assertRaises(ValueError):
                d.consumers.compiled(changed, identity, definitions, aliases, compiler, 'unwind')
            count += 1
            if operation == 'secret_bits':
                clear = [line for line in body.splitlines() if (call := d.syntax.call(line))
                         and 'clear_owned_region' in call[0] and '%output.0' in line]
                self.assertEqual(len(clear), 1)
                for replacement in ('', clear[0].replace('%output.0', '%input'),
                                    clear[0].replace('%output.1', '0')):
                    mutant = body.replace(clear[0], replacement, 1)
                    with self.assertRaises(ValueError):
                        self.check_compiled_consumer_body(mutant, identity, operation, definitions,
                                                          aliases, compiler, present=False)
                    count += 1
        return count

    def test_actual_compiled_consuming_handoffs_and_cleanup(self):
        count = sum(self.compiled_consumer_mutations(profile, target) for target, profile in self.profiles.items())
        self.assertGreater(count, 700)
        print(f'Hosted compiled consuming mutations: {count} rejected', flush=True)

    def test_msrv_compiled_consuming_handoffs_and_cleanup(self):
        d, count = self.driver, 0
        for target in d.TARGETS:
            llvm = d.emit(self.root / ('compiled-consumers-msrv-' + target), '1.90.0', target, 'unwind')[1]
            profile = (llvm, *d.validate(llvm, target, '1.90.0'))
            count += self.compiled_consumer_mutations(profile, target, '1.90.0')
        self.assertGreater(count, 700)
        print(f'MSRV hosted compiled consuming mutations: {count} rejected', flush=True)

    def test_compiled_handoff_continuation_guard_is_load_bearing(self):
        d = self.driver
        for target, profile in self.profiles.items():
            row = next(row for row in self.compiled_consumers(profile, target)
                       if row[1] == 'sha256' and row[5] == 'secret_bits')
            _, identity, _, _, body, operation, definitions, aliases = row
            cuts = self.check_compiled_consumer_body(body, identity, operation, definitions, aliases)
            label, index, _ = next(iter(cuts))
            graph = d.common.blocks(body)
            # The continuation must reject a moved source even though the
            # consuming interpreter now tracks the new private allocation.
            graph[label].insert(index, 'store ptr %self, ptr %escaped, align 8')
            mutant = '\n'.join(name + ':\n' + '\n'.join(lines) for name, lines in graph.items())
            with self.assertRaisesRegex(ValueError, 'reuses moved wrapper'):
                self.check_compiled_consumer_body(mutant, identity, operation, definitions, aliases)
            require = d.consumers.prefix.final.require
            def without_moved_guard(condition, message):
                if message != 'consuming body reuses moved wrapper storage/value':
                    require(condition, message)
            with mock.patch.object(d.consumers.prefix.final, 'require', side_effect=without_moved_guard):
                self.check_compiled_consumer_body(mutant, identity, operation, definitions, aliases)

    def test_real_compiling_accelerated_consumer_mutants(self):
        d, count = self.driver, 0
        work = self.root / 'compiled-accelerated-consumers'
        host, fixture = self.compiled_fixture(work)
        leaf = work / 'leaf'
        shutil.copytree(d.ROOT / 'crates/brynja-mac-hmac/src', leaf / 'src')
        manifest = (d.ROOT / 'crates/brynja-mac-hmac/Cargo.toml').read_text().split('[lints]')[0]
        for key, value in (('edition', '"2024"'), ('rust-version', '"1.90"'),
                           ('license', '"MIT OR Apache-2.0"'), ('repository', '"https://github.com/valkyoth/brynja"')):
            manifest = manifest.replace(key + '.workspace = true', key + ' = ' + value)
        manifest = re.sub(r'(brynja-[\w-]+)\.workspace = true', r'\1 = { workspace = true }', manifest)
        manifest = re.sub(r'(brynja-[\w-]+) = \{ workspace = true',
                          lambda m: m[1] + ' = { default-features = false, path = "'
                          + str(d.ROOT / 'crates' / m[1]) + '"', manifest)
        (leaf / 'Cargo.toml').write_text('[workspace]\n' + manifest)
        path = host / 'Cargo.toml'
        path.write_text(path.read_text().replace(str(d.ROOT / 'crates/brynja-mac-hmac'), str(leaf)))
        d.verifier.run(['cargo', '+1.99.1', 'generate-lockfile', '--offline', '--manifest-path',
                       str(fixture / 'Cargo.toml')], d.verifier.environment(work))
        source = leaf / 'src/engine.rs'
        original = source.read_text()
        mutants = (
            ('let mut inner_digest = Scratch::<64>::new();',
             'let mut inner_digest = core::mem::ManuallyDrop::new(Scratch::<64>::new());'),
            ('let mut difference = Scratch::<1>::new();',
             'let mut difference = core::mem::ManuallyDrop::new(Scratch::<1>::new());'),
            ('A::finish_outer(self.outer, digest, tag.prefix(A::TAG_BYTES)?, |digest| {',
             'if digest.len() == self.tag_bytes {\n'
             '                core::mem::forget(self.outer);\n'
             '                return Err(Error::SecretMemory);\n'
             '            }\n'
             '            A::finish_outer(self.outer, digest, tag.prefix(A::TAG_BYTES)?, |digest| {'),
        )
        for target in (d.TARGETS[0], d.TARGETS[2]):
            for old, new in mutants:
                self.assertEqual(original.count(old), 1)
                try:
                    source.write_text(original.replace(old, new, 1))
                    llvm = d.emit(work / target, '1.99.1', target, 'unwind', fixture / 'Cargo.toml')[1]
                    definitions, aliases = d.common.definitions_and_aliases(llvm)
                    names = d.lifecycle.demangle((*definitions, *aliases))
                    for identity in d.common.IDENTITIES:
                        algorithm = ('general::Sha512T<' + identity[7:] + '>' if identity.startswith('general')
                                     else 'algorithms::Sha' + identity[3:])
                        workers = [s for s in definitions if 'thread::enter' in names[s]
                                   and '::compiled::CompiledSession<brynja_mac_hmac::' + algorithm + '>' in names[s]]
                        self.assertEqual(len(workers), 1)
                        expected = ('accelerated finalizer exits with live/wrong owner'
                                    if 'core::mem::forget(self.outer)' in new else 'scratch')
                        with self.subTest(target=target, identity=identity, mutant=new):
                            # Isolate the consuming-body obligation: a source
                            # mutation may also change earlier admission codegen.
                            # Earlier rejection must not mask this cleanup check.
                            model = d.keyed.Admission(definitions[workers[0]][1], names,
                                                      '1.99.1', identity, True)
                            with self.assertRaisesRegex(ValueError, expected):
                                d.consumers.compiled(model, identity, definitions, aliases, '1.99.1', 'unwind')
                    with self.assertRaises(ValueError):
                        d.validate(llvm, target)
                    count += 1
                finally:
                    source.write_text(original)
            d.validate(d.emit(work / target, '1.99.1', target, 'unwind', fixture / 'Cargo.toml')[1], target)
        self.assertEqual(count, 6)
        print(f'Hosted compiled consumers: {count} compiling source mutants rejected for all 12 identities', flush=True)
