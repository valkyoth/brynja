"""Actual hosted constructor bodies, helper identity and compiling leaf mutants."""
import re
import shutil
from unittest import mock

from hmac_execution_construct_tests import ConstructTests


class ConstructorTests:
    def constructors(self, profile, target, compiler='1.99.1'):
        d = self.driver
        llvm, definitions, aliases, names, checked = profile
        types = d.constructor.construct.iterator.array_types(llvm, 'static')
        for _, body, identity, compiled in self.output_workers(definitions, aliases, names, checked, target):
            if compiled:
                model = d.keyed.check(body, names, compiler, identity, True)
                symbol, constructor = d.callee_admission.resolve(model, identity, definitions, aliases)
                yield identity, symbol, constructor, definitions, aliases, types

    def check_constructor_body(self, body, identity, definitions, aliases, types, compiler='1.99.1',
                               panic='unwind', long_key=True):
        d = self.driver
        d.constructor.scratch.check_body(body, 'construct_static', definitions, aliases)
        d.constructor.construct.check(body, identity, definitions, aliases, compiler, panic,
                                      0, long_key, types, profile='static', dynamic_tag=True)

    def constructor_mutations(self, body, identity):
        d = self.driver
        shape = d.constructor.construct.cleanup.layout(identity, 'static')
        roles = d.constructor.construct.layout.roles(body, 'static')
        mutants = []
        tag = [line for line in body.splitlines() if 'store i64 %tag_bytes,' in line]
        self.assertEqual(len(tag), 1)
        pointer = d.syntax.operand(d.syntax.parameters(tag[0].strip()[6:])[1])
        mutants += [body.replace(tag[0], '', 1),
                    body.replace(tag[0], tag[0].replace('%tag_bytes,', '1,'), 1),
                    body.replace(tag[0], tag[0].replace('%tag_bytes,', '%key.1,'), 1),
                    body.replace(tag[0], tag[0].replace('ptr ' + pointer, 'ptr %_0'), 1)]
        for overwrite in ('store i8 0, ptr ' + pointer + ', align 1',
                          'call void @llvm.memset.p0.i64(ptr ' + pointer + ', i8 0, i64 8, i1 false)',
                          'call void @llvm.memcpy.p0.p0.i64(ptr ' + pointer + ', ptr %key.0, i64 8, i1 false)'):
            mutants.append(body.replace(tag[0], tag[0] + '\n' + overwrite, 1))
        for line in body.splitlines():
            call = d.syntax.call(line)
            if not call:
                continue
            symbol, args = call
            if symbol == 'llvm.memcpy.p0.p0.i64' and re.fullmatch(r'i64 ' + str(shape.stride), args[2]):
                mutants.append(body.replace(line, line.replace(args[2], 'i64 1'), 1))
            if d.constructor.construct.contracts.update_adapter(symbol) or d.constructor.construct.final.contracts.update(symbol):
                if d.syntax.operand(args[0]) == roles['inner']:
                    mutants.append(body.replace(line, line.replace(roles['inner'], roles['outer']), 1))
            if 'Flatten' in symbol and ('drop_glue' in symbol or 'drop_in_place' in symbol):
                # Preserve the original control-flow edges when changing an
                # invoke. The actual helper body is tested separately below.
                mutants.append(body.replace(line, line.replace(args[0], 'ptr %_0'), 1))
        self.assertGreater(len(mutants), 10)
        return mutants

    def constructor_profile_mutations(self, target, profile, compiler='1.99.1', panic='unwind'):
        count = 0
        for identity, symbol, original, definitions, aliases, types in self.constructors(profile, target, compiler):
            body = '\n'.join(label + ':\n' + '\n'.join(lines)
                             for label, lines in self.driver.common.blocks(original).items())
            self.check_constructor_body(body, identity, definitions, aliases, types, compiler, panic)
            for case, mutant in enumerate(self.constructor_mutations(body, identity)):
                self.assertNotEqual(mutant, body)
                with self.subTest(target=target, compiler=compiler, identity=identity, case=case), self.assertRaises(ValueError):
                    self.check_constructor_body(mutant, identity, definitions, aliases, types, compiler, panic)
                count += 1
            iterator = {call[0] for line in body.splitlines() if (call := self.driver.syntax.call(line))
                        and 'Flatten' in call[0] and ('drop_glue' in call[0] or 'drop_in_place' in call[0])}
            self.assertEqual(len(iterator), 1)
            helper = iterator.pop()
            args, nested = self.driver.common.resolve(helper, definitions, aliases)
            # A plausible body/extent does not authorize a different iterator
            # population or drop operation, on either compiler's v0 spelling.
            for fake in (helper.replace('EKj3_', 'EKj4_'),
                         helper.replace('9drop_glue', '9fake_glue').replace('13drop_in_place', '13fake_in_place')):
                self.assertNotEqual(fake, helper)
                with self.assertRaises(ValueError):
                    self.check_constructor_body(body.replace(helper, fake), identity,
                        {**definitions, fake: (args, nested)}, aliases, types, compiler, panic)
                count += 1
            for altered, links in (({**definitions, helper: (args, 'start:\nret void\n')}, aliases),
                                   (definitions, {**aliases, helper: helper})):
                with self.assertRaises(ValueError):
                    self.check_constructor_body(body, identity, altered, links, types, compiler, panic)
                count += 1
        return count

    def test_hosted_constructor_transfers_and_tag_provenance(self):
        count = sum(self.constructor_profile_mutations(target, profile) for target, profile in self.profiles.items())
        self.assertGreater(count, 400)
        print(f'Hosted constructor transfer/tag/helper mutations: {count} rejected', flush=True)

    def test_msrv_hosted_constructor_transfers_and_tag_provenance(self):
        d, count = self.driver, 0
        for target in d.TARGETS:
            llvm = d.emit(self.root / ('constructor-msrv-' + target), '1.90.0', target, 'unwind')[1]
            profile = llvm, *d.validate(llvm, target, '1.90.0', 'unwind')
            count += self.constructor_profile_mutations(target, profile, '1.90.0')
        self.assertGreater(count, 400)
        print(f'Hosted MSRV constructor transfer/tag/helper mutations: {count} rejected', flush=True)

    def test_exact_constructor_helper_contexts(self):
        d, count = self.driver, 0
        for target, profile in self.profiles.items():
            for identity, _, body, definitions, aliases, types in self.constructors(profile, target):
                for line in body.splitlines():
                    call = d.syntax.call(line)
                    if not call or not call[0].endswith('34brynja_hmac_hosted_cleanup_fixture'):
                        continue
                    symbol = call[0]
                    if not ('Flatten' in symbol or d.constructor.construct.contracts.update_adapter(symbol)
                            or d.constructor.construct.final.contracts.adapter(symbol)):
                        continue
                    for suffix in ('33brynja_hmac_hosted_cleanup_fixture', '34brynja_hmac_hosted_cleanup_impostor',
                                   '29brynja_hmac_execution_cleanup_extra'):
                        fake = symbol.removesuffix('34brynja_hmac_hosted_cleanup_fixture') + suffix
                        altered = {**definitions, fake: d.common.resolve(symbol, definitions, aliases)}
                        with self.assertRaises(ValueError):
                            self.check_constructor_body(body.replace(symbol, fake), identity, altered, aliases, types)
                        count += 1
        self.assertGreater(count, 100)
        print(f'Hosted constructor unknown-context mutations: {count} rejected', flush=True)

    def test_dynamic_tag_partial_overwrites(self):
        c = self.driver.constructor.construct
        state = c.model.State(c.admission.State(), {})
        address = ('%_0', 64)
        for offset in range(8):
            state.tag_fields = {address}
            state.store(('%_0', 64 + offset), 1, 0)
            self.assertFalse(state.tag_fields)
        for offset in (56, 72):
            state.tag_fields = {address}
            state.store(('%_0', offset), 8, 0)
            self.assertEqual(state.tag_fields, {address})
        for offset in (57, 63, 64, 71):
            state.tag_fields = {address}
            state.transfer(('%_0', offset), ('%other', 0), 8)
            self.assertFalse(state.tag_fields)
        for size in (-1, 1 << 64, None):
            for action in (lambda: state.forget_tags(address, size),
                           lambda: state.transfer(address, ('%other', 0), size)):
                with self.assertRaises(ValueError):
                    action()
        for dynamic, profile in ((True, 'runtime'), (1, 'static'), ('yes', 'static')):
            with self.assertRaises(ValueError):
                c.check('', 'sha256', {}, {}, dynamic_tag=dynamic, profile=profile)

    def test_dynamic_tag_cannot_escape_before_returned_owners(self):
        d = self.driver
        for target, profile in self.profiles.items():
            identity, _, original, definitions, aliases, types = next(
                row for row in self.constructors(profile, target) if row[0] == 'sha256')
            graph = d.common.blocks(original)
            lines = next(lines for lines in graph.values() if any('store i64 %tag_bytes,' in line for line in lines))
            store = next(line for line in lines if 'store i64 %tag_bytes,' in line)
            pointer = d.syntax.operand(d.syntax.parameters(store[6:])[1])
            gep = next(line for line in lines if line.startswith(pointer + ' = '))
            clear = next(call[0] for block in graph.values() for line in block
                         if (call := d.syntax.call(line)) and d.constructor.construct.contracts.non_unwinding(call[0]))
            lines.remove(gep)
            lines.remove(store)
            lines[:0] = [gep, store, f'call i8 @{clear}(ptr {pointer}, i64 8)']
            mutant = '\n'.join(label + ':\n' + '\n'.join(block) for label, block in graph.items())
            with self.assertRaisesRegex(ValueError, 'tag field escapes'):
                self.check_constructor_body(mutant, identity, definitions, aliases, types)
            # This new guard is load-bearing even before the output root has
            # acquired either cryptographic owner (the older owner-escape check
            # alone cannot detect this metadata-only write).
            require = d.constructor.construct.require
            def without_tag_guard(condition, message):
                if message != 'constructor tag field escapes to auxiliary':
                    require(condition, message)
            with mock.patch.object(d.constructor.construct, 'require', side_effect=without_tag_guard):
                self.check_constructor_body(mutant, identity, definitions, aliases, types)
            for instruction, error in ((f'store ptr {pointer}, ptr %escaped, align 8', 'tag pointer escape'),
                                       (f'%escaped = ptrtoint ptr {pointer} to i64', 'tag pointer operation')):
                altered = mutant.replace(f'call i8 @{clear}(ptr {pointer}, i64 8)', instruction)
                with self.assertRaisesRegex(ValueError, error):
                    self.check_constructor_body(altered, identity, definitions, aliases, types)

    def test_real_compiled_hosted_constructor_mutants(self):
        d, count = self.driver, 0
        work = self.root / 'compiled-hosted-constructor'
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
        mutants = ConstructTests.construct_mutants(leaf) + [(leaf / 'src/engine.rs',
            '            tag_bytes,\n        })', '            tag_bytes: 1,\n        })')]
        for target in (d.TARGETS[0], d.TARGETS[2]):
            for path, old, new in mutants:
                original = path.read_text()
                self.assertEqual(original.count(old), 1)
                try:
                    path.write_text(original.replace(old, new, 1))
                    # Successful compilation is a prerequisite for rejection.
                    llvm = d.emit(work / target, '1.99.1', target, 'unwind', fixture / 'Cargo.toml')[1]
                    definitions, aliases = d.common.definitions_and_aliases(llvm)
                    names = d.lifecycle.demangle((*definitions, *aliases))
                    constructors = [s for s, name in names.items() if name.startswith('<brynja_mac_hmac::execution::Hmac<')
                                    and name.endswith('>>::create')]
                    self.assertEqual(len(constructors), 12)
                    types = d.constructor.construct.iterator.array_types(llvm, 'static')
                    for identity in d.common.IDENTITIES:
                        algorithm = ('general::Sha512T<' + identity[7:] + '>' if identity.startswith('general')
                                     else 'algorithms::Sha' + identity[3:])
                        symbol = next(s for s in constructors if names[s] ==
                                      '<brynja_mac_hmac::execution::Hmac<brynja_mac_hmac::' + algorithm + '>>::create')
                        with self.subTest(target=target, identity=identity, mutant=new), self.assertRaises(ValueError):
                            self.check_constructor_body(d.common.resolve(symbol, definitions, aliases)[1],
                                                        identity, definitions, aliases, types)
                    count += 1
                finally:
                    path.write_text(original)
            d.validate(d.emit(work / target, '1.99.1', target, 'unwind', fixture / 'Cargo.toml')[1], target)
        self.assertEqual(count, 10)
        print(f'Hosted constructor: {count} compiling source mutants rejected for all 12 identities', flush=True)
