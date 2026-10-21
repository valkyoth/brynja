"""Real scalar hosted callees: transfers, split initialization and cleanup mutations."""
import copy
import re
import shutil
from unittest import mock


class ScalarCalleeTests:
    def scalar_models(self, profile, target, compiler='1.99.1'):
        d = self.driver
        _, definitions, aliases, names, checked = profile
        for _, body, identity, compiled in self.output_workers(definitions, aliases, names, checked, target):
            if not compiled:
                yield d.keyed.check(body, names, compiler, identity, False), identity, definitions, aliases

    def scalar_callee_mutations(self, profile, target, compiler='1.99.1', panic='unwind'):
        d, count = self.driver, 0
        for model, identity, definitions, aliases in self.scalar_models(profile, target, compiler):
            symbol = d.constructor.scalar(model, identity, definitions, aliases, panic)
            args, body = d.common.resolve(symbol, definitions, aliases)
            tag = next(line for line in body.splitlines() if 'store i64 %tag_bytes,' in line)
            pointer = d.syntax.operand(d.syntax.parameters(tag.strip()[6:])[1])
            mutants = [body.replace(tag, '', 1), body.replace(tag, tag.replace('%tag_bytes,', '16,'), 1)]
            for overwrite in (f'store i8 0, ptr {pointer}, align 1',
                              f'call void @llvm.memset.p0.i64(ptr {pointer}, i8 0, i64 8, i1 false)',
                              f'call void @llvm.memcpy.p0.p0.i64(ptr {pointer}, ptr %key.0, i64 8, i1 false)'):
                mutants.append(body.replace(tag, tag + '\n' + overwrite, 1))
            width = d.syntax.geometry(identity)[0]
            for line in body.splitlines():
                parsed = d.syntax.call(line)
                if parsed and parsed[0] == 'llvm.memcpy.p0.p0.i64' and parsed[1][2] in (
                        'i64 ' + str(width), 'i64 ' + str(width - 1), 'i64 ' + str(width * 2)):
                    mutants.append(body.replace(line, line.replace(parsed[1][2], 'i64 1'), 1))
                if parsed and parsed[0] == 'llvm.memset.p0.i64' and parsed[1][2] == 'i64 1039':
                    for replacement in ('', line.replace('i64 1039,', 'i64 1038,'),
                                        line.replace('i8 0,', 'i8 1,')):
                        mutants.append(body.replace(line, replacement, 1))
                if re.search(r'store i8 0, ptr %(?:hash|inner|outer),', line):
                    mutants.append(body.replace(line, '', 1))
                    mutants.append(body.replace(line, line.replace('i8 0,', 'i8 1,'), 1))
            for mutant in mutants:
                self.assertNotEqual(mutant, body)
                with self.subTest(target=target, identity=identity), self.assertRaises(ValueError):
                    d.constructor.scalar(model, identity, {**definitions, symbol: (args, mutant)}, aliases, panic)
                count += 1
            d.consumers.scalar(model, identity, definitions, aliases, panic)
            for _, point, _ in model.terminals:
                terminal = model.call_map[point][0]
                formals, finalizer = d.common.resolve(terminal, definitions, aliases)
                method = model.names[terminal].split('::')[-1]
                # Keep the complete graph and typed callee identity, but make
                # each actual scratch clear too short in turn.
                for line in finalizer.splitlines():
                    if 'clear_owned_region' in line and re.search(r'i64(?: noundef)? (?:64|1)\)', line):
                        altered = re.sub(r'(i64(?: noundef)? )(64|1)\)', r'\g<1>0)', line)
                        self.assertNotEqual(line, altered)
                        mutant = finalizer.replace(line, altered, 1)
                        with self.assertRaises(ValueError):
                            d.consumers.scalar(model, identity,
                                {**definitions, terminal: (formals, mutant)}, aliases, panic)
                        count += 1
                self.assertIn(method, ('secret', 'verify'))
                # A correct unrelated standalone definition is not evidence for
                # a missing, empty or incorrectly bound actual worker callee.
                for changed in ((formals, 'start:\nret void\n'),
                                (formals.replace('%self', '%unrelated'), finalizer)):
                    with self.assertRaises(ValueError):
                        d.consumers.scalar(model, identity, {**definitions, terminal: changed}, aliases, panic)
                    count += 1
                with self.assertRaises(ValueError):
                    d.consumers.scalar(model, identity, definitions, {**aliases, terminal: terminal}, panic)
                count += 1
            for changed in ((args.replace('%tag_bytes', '%unrelated'), body), (args, 'start:\nret void\n')):
                with self.assertRaises(ValueError):
                    d.constructor.scalar(model, identity, {**definitions, symbol: changed}, aliases, panic)
                count += 1
            for subject in ('constructor', 'consumer'):
                changed = copy.copy(model)
                changed.names = dict(model.names)
                chosen = symbol if subject == 'constructor' else model.call_map[model.terminals[0][1]][0]
                changed.names[chosen] = 'unreviewed::' + model.names[chosen]
                check = d.constructor.scalar if subject == 'constructor' else d.consumers.scalar
                with self.assertRaises(ValueError):
                    check(changed, identity, definitions, aliases, panic)
                count += 1
        return count

    def test_actual_scalar_constructor_and_consuming_callees(self):
        count = sum(self.scalar_callee_mutations(profile, target) for target, profile in self.profiles.items())
        self.assertGreater(count, 500)
        print(f'Hosted scalar constructor/consumer mutations: {count} rejected', flush=True)

    def test_msrv_scalar_constructor_and_consuming_callees(self):
        d, count = self.driver, 0
        for target in d.TARGETS:
            llvm = d.emit(self.root / ('scalar-msrv-' + target), '1.90.0', target, 'unwind')[1]
            profile = (llvm, *d.validate(llvm, target, '1.90.0'))
            count += self.scalar_callee_mutations(profile, target, '1.90.0')
        self.assertGreater(count, 500)
        print(f'MSRV hosted scalar constructor/consumer mutations: {count} rejected', flush=True)

    def test_split_scalar_initialization_and_tag_state(self):
        from hmac_engine_construct_state import State
        state = State()
        state.initializing.add('inner')
        for effect in (lambda: state.store(('inner', 1), 1, 0),
                       lambda: state.store(('inner', 0), 1, 1),
                       lambda: state.transfer(('other', 0), ('inner', 0), 1040),
                       lambda: state.transfer(('inner', 0), ('other', 0), 1040),
                       lambda: state.complete(('inner', 0), 1040)):
            with self.assertRaises(ValueError):
                effect()
        state.store(('inner', 0), 1, 0)
        self.assertEqual(state.born, set())  # Only the checked constructor dispatch creates owners.
        self.assertNotEqual(state.key(), State().key())
        state.end('inner')
        self.assertFalse(state.initializing)
        for offset in range(8):
            state.tag_fields = {('result', 8)}
            state.store(('result', 8 + offset), 1, 0)
            self.assertFalse(state.tag_fields)
        for extent in (-1, 1 << 64, True):
            with self.assertRaises(ValueError):
                state.forget_tags(('result', 0), extent)

    def test_scalar_tag_and_partial_owner_cannot_escape(self):
        d = self.driver
        for target, profile in self.profiles.items():
            for model, identity, definitions, aliases in self.scalar_models(profile, target):
                if identity not in ('sha256', 'sha3_224'):
                    continue
                symbol = d.constructor.scalar(model, identity, definitions, aliases, 'unwind')
                args, original = d.common.resolve(symbol, definitions, aliases)
                if identity == 'sha3_224' and not re.search(r'store i8 0, ptr %inner,', original):
                    # Linux Arm currently uses the equivalent whole-owner fill.
                    # Establish that its split form passes before mutating the
                    # interval between the two initialization instructions.
                    whole = [line for line in original.splitlines() if (call := d.syntax.call(line))
                             and call[0] == 'llvm.memset.p0.i64'
                             and d.syntax.operand(call[1][0]) == '%inner' and call[1][2] == 'i64 1040']
                    self.assertEqual(len(whole), 1)
                    original = original.replace(whole[0],
                        '%split_inner = getelementptr inbounds i8, ptr %inner, i64 1\n'
                        'call void @llvm.memset.p0.i64(ptr %split_inner, i8 0, i64 1039, i1 false)\n'
                        'store i8 0, ptr %inner, align 1', 1)
                    d.constructor.scalar(model, identity,
                        {**definitions, symbol: (args, original)}, aliases, 'unwind')
                graph = d.common.blocks(original)
                clear = next(call[0] for lines in graph.values() for line in lines
                             if (call := d.syntax.call(line)) and 'clear_owned_region' in call[0])
                if identity == 'sha256':
                    lines = next(lines for lines in graph.values() if any('store i64 %tag_bytes,' in s for s in lines))
                    store = next(line for line in lines if 'store i64 %tag_bytes,' in line)
                    pointer = d.syntax.operand(d.syntax.parameters(store[6:])[1])
                    gep = next(line for line in lines if line.startswith(pointer + ' = '))
                    lines.remove(gep)
                    lines.remove(store)
                    # Before owner copies exist, only tag provenance protects
                    # this returned field from an intervening helper write.
                    lines[:0] = [gep, store, f'call i8 @{clear}(ptr {pointer}, i64 8)']
                else:
                    lines = next(lines for lines in graph.values() if any('ptr %inner, align 1' in s for s in lines))
                    index = next(i for i, line in enumerate(lines) if 'store i8 0, ptr %inner,' in line)
                    lines.insert(index, f'call i8 @{clear}(ptr %inner, i64 1040)')
                mutant = '\n'.join(label + ':\n' + '\n'.join(lines) for label, lines in graph.items())
                with self.assertRaisesRegex(ValueError, 'passed to auxiliary'):
                    d.constructor.scalar(model, identity, {**definitions, symbol: (args, mutant)}, aliases, 'unwind')
                require = d.constructor.scalar_construct.require
                def omit_escape_guard(condition, message):
                    if message != 'constructor owner storage passed to auxiliary':
                        require(condition, message)
                with mock.patch.object(d.constructor.scalar_construct, 'require', side_effect=omit_escape_guard):
                    d.constructor.scalar(model, identity, {**definitions, symbol: (args, mutant)}, aliases, 'unwind')

    def test_real_compiling_scalar_callee_mutants(self):
        d, count = self.driver, 0
        work = self.root / 'compiled-scalar-callees'
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
        path = leaf / 'src/engine.rs'
        original = path.read_text()
        mutants = (
            ('            tag_bytes,\n        })', '            tag_bytes: 16,\n        })', 'constructor'),
            ('            inner,\n            outer,', '            inner: outer,\n            outer: inner,', 'constructor'),
            ('let mut inner_digest = Scratch::<64>::new();',
             'let mut inner_digest = core::mem::ManuallyDrop::new(Scratch::<64>::new());', 'consumer'),
            ('let mut difference = Scratch::<1>::new();',
             'let mut difference = core::mem::ManuallyDrop::new(Scratch::<1>::new());', 'consumer'),
        )
        for target in (d.TARGETS[0], d.TARGETS[2]):
            for old, new, subject in mutants:
                self.assertEqual(original.count(old), 1)
                try:
                    path.write_text(original.replace(old, new, 1))
                    llvm = d.emit(work / target, '1.99.1', target, 'unwind', fixture / 'Cargo.toml')[1]
                    definitions, aliases = d.common.definitions_and_aliases(llvm)
                    names = d.lifecycle.demangle((*definitions, *aliases))
                    models = []
                    for identity in d.common.IDENTITIES:
                        algorithm = ('general::Sha512T<' + identity[7:] + '>' if identity.startswith('general')
                                     else 'algorithms::Sha' + identity[3:])
                        workers = [s for s in definitions if 'thread::enter' in names[s]
                                   and '::Session<brynja_mac_hmac::' + algorithm + '>' in names[s]]
                        self.assertEqual(len(workers), 1)
                        model = d.keyed.check(definitions[workers[0]][1], names, '1.99.1', identity, False)
                        models.append((model, identity))
                    self.assertEqual(len(models), 12)
                    check = d.constructor.scalar if subject == 'constructor' else d.consumers.scalar
                    for model, identity in models:
                        with self.subTest(target=target, identity=identity, mutant=new), self.assertRaises(ValueError):
                            check(model, identity, definitions, aliases, 'unwind')
                    count += 1
                finally:
                    path.write_text(original)
            d.validate(d.emit(work / target, '1.99.1', target, 'unwind', fixture / 'Cargo.toml')[1], target)
        self.assertEqual(count, 8)
        print(f'Hosted scalar callees: {count} compiling source mutants rejected for all 12 identities', flush=True)
