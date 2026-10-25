"""Actual worker tag-copy and compiled output-corruption regressions."""
from pathlib import Path
import difflib
import re

from legacy_hmac_hosted_compiled_fixture import prepare


class Md5TagCopyTests:
    def copy_model(self, case, arguments, body, names, compiler):
        h = self.driver.hosted
        model, health, boundaries = self.md5_check(arguments, body, names, compiler, case[1])
        envelope = h.envelope.check(arguments, body, names, 'md5_compiled')
        transports = h.md5_result_transport.check(model, health, case[1])
        return h.md5_tag_copy.Copies(model, envelope, boundaries, transports, compiler)

    def test_md5_tag_copy_masks_lengths_and_errors(self):
        h, count = self.driver.hosted, 0
        for case, arguments, body, names, compiler in self.md5_models():
            checked = self.copy_model(case, arguments, body, names, compiler).validate()
            self.assertEqual(checked.observed_copies, checked.copies)
            renamed = body
            for index, root in enumerate((checked.tags, checked.env['loads'][16][1])):
                renamed = re.sub(re.escape(root) + r'(?![-\w.])', '%copy_storage_' + str(index), renamed)
            self.copy_model(case, arguments, renamed, names, compiler).validate()
            count += 1
        self.assertEqual(count, 5)
        typed_count = 0
        for case in self.cases:
            llvm = case[0]['brynja-legacy-hmac-hosted-cleanup']
            compiler, = re.findall(r'!"rustc version ([\d.]+) ', llvm)
            population = self.report_population(llvm)
            h.md5_tag_copy.typed(population, compiler)
            for name in ('success', 'empty', 'overflow', 'capacity', 'incomplete'):
                symbol, = [s for s in (*population[0], *population[1]) if population[2].get(s) ==
                           'brynja_legacy_hmac_hosted_cleanup::tag_copy::' + name]
                _, body = h.md5_tag_copy.layout.flow.resolve(symbol, population[0], population[1])
                changed = re.sub(r'ret i8 -?\d+', 'ret i8 7', body)
                while symbol in population[1]:
                    symbol = population[1][symbol]
                definitions = dict(population[0])
                definitions[symbol] = (definitions[symbol][0], changed)
                with self.assertRaises(ValueError):
                    h.md5_tag_copy.typed((definitions, population[1], population[2]), compiler)
                typed_count += 1
        self.assertEqual(typed_count, 30)
        print('MD5 tag copies: five emitted profiles, 256 masks x seven lengths; boundary/four-error cases and 30 typed status mutants pass', flush=True)

    def test_md5_tag_copy_operand_guard_and_effect_mutations(self):
        h, count = self.driver.hosted, 0
        for case, arguments, body, names, compiler in self.md5_models():
            check = self.copy_model(case, arguments, body, names, compiler).validate()
            mutants = []
            for block, index in sorted(check.points):
                line = check.m.graph[block][index]
                call = h.syntax.call(line)
                if ' = getelementptr' in line:
                    mutants.append(body.replace(line, re.sub(r'i64 (\d+)$',
                        lambda m: 'i64 ' + str(int(m[1]) + 1), line), 1))
                elif ' = load ' in line:
                    mutants.append(body.replace(line, re.sub(r'ptr %[-\w.]+', 'ptr %unbound', line), 1))
                elif ' = trunc ' in line:
                    mutants.append(body.replace(line, re.sub(r'trunc(?: nuw)? i8 %[-\w.]+', 'trunc i8 %unbound', line), 1))
                elif ' = icmp ' in line:
                    # Some inlined null/bounds predicates are redundant under
                    # the admitted 128-byte owner premise. Test binding rather
                    # than claiming their inversion necessarily changes output.
                    mutants.append(body.replace(line, re.sub(r'(icmp \w+ \w+ )[^,]+',
                        r'\1%unbound', line), 1))
                    if 'icmp eq i8 ' in line:
                        mutants.append(body.replace(line, line.replace('icmp eq i8', 'icmp ne i8'), 1))
                elif line.startswith('br i1 '):
                    mutants.append(body.replace(line, re.sub(r'br i1 [^,]+', 'br i1 %unbound', line), 1))
                elif ' = select ' in line:
                    mutants.append(body.replace(line, re.sub(r'select i1 %[-\w.]+', 'select i1 %unbound', line), 1))
                if call and names.get(call[0]) in (h.md5_tag_copy.COPY, h.md5_tag_copy.EXPOSE, h.md5_tag_copy.DROP):
                    for arg in call[1]:
                        mutants.append(body.replace(line, line.replace(arg, arg.split()[0] + ' %unbound'), 1))
                    mutants.append(body.replace(line, 'call void @unreviewed()\n  ' + line, 1))
            # Exercise every slot plus mixed/full masks, both destination-bound
            # branches, overflow guards and each copy-error continuation.
            for mutant in mutants:
                self.assertNotEqual(mutant, body)
                delta = '\n'.join(difflib.unified_diff(body.splitlines(), mutant.splitlines(), n=1))
                with self.subTest(target=case[1], mutation=count, delta=delta), self.assertRaises(ValueError):
                    changed = self.copy_model(case, arguments, mutant, names, compiler)
                    for mask in (0, 85, 170, 255, *(1 << lane for lane in range(8))):
                        for length in (0, 10, 16, 17, 128, 2 ** 64 - 1):
                            changed.run(mask, length)
                    for lane in range(8):
                        for error in range(4):
                            changed.run(255, 10, lane, error)
                count += 1
        self.assertGreater(count, 500)
        print(f'MD5 tag copies: {count} operand/guard/lane/effect mutations rejected', flush=True)

    def test_compiled_md5_tag_copy_defects(self):
        d, h = self.driver, self.driver.hosted
        work = Path(self.directory.name) / 'md5-tag-copy-mutants'
        leaf, fixture = prepare(d, work)
        count = 0
        for target, directory in ((d.TARGETS[0], 'strict_execution'), (d.TARGETS[2], 'macos_resident')):
            def emit():
                return d.emit(work / target, '1.99.1', target, 'unwind', True,
                              fixture / 'Cargo.toml', leaf / 'Cargo.toml')
            h.validate(emit(), target, 'unwind')
            path = leaf / 'src' / directory / 'md5_compiled/worker.rs'
            original = path.read_text()
            copy = 'brynja_core::copy_secret_region(destination, tag).map_err(|_| Error::Invariant)?;'
            edits = (
                ('output.as_chunks_mut::<16>().0.iter_mut().enumerate()',
                 'output.as_chunks_mut::<16>().0.iter_mut().rev().enumerate()'),
                ('output.as_chunks_mut::<16>().0.iter_mut().enumerate()',
                 'output.as_chunks_mut::<16>().0.iter_mut().enumerate().take(7)'),
                ('row.get_mut(..parameters.bytes)', 'row.get_mut(..1)'),
                ('tags.expose(lane)', 'tags.expose(0)'),
                (copy, 'let _ = brynja_core::copy_secret_region(destination, tag);'),
                (copy, 'brynja_core::copy_secret_region(destination, &tag[..0]).map_err(|_| Error::Invariant)?;'),
                (copy, 'brynja_core::copy_secret_region(destination, tag).map_err(|_| Error::Cancelled)?;'),
            )
            for before, after in edits:
                self.assertIn(before, original)
                try:
                    path.write_text(original.replace(before, after, 1))
                    artifacts = emit()
                    with self.subTest(target=target, mutation=count), self.assertRaises(ValueError):
                        h.validate(artifacts, target, 'unwind')
                finally:
                    path.write_text(original)
                count += 1
            h.validate(emit(), target, 'unwind')
        self.assertEqual(count, 14)
        print('MD5 tag copies: 14 compiled Rust defects rejected; restored baselines pass', flush=True)
