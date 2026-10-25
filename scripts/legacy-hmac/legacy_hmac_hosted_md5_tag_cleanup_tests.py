"""Returned-tag destruction mutations on actual hosted worker artifacts."""
import difflib
from pathlib import Path
import re

from legacy_hmac_hosted_compiled_fixture import prepare


class Md5TagCleanupTests:
    def cleanup_model(self, case, arguments, body, names, compiler, read_sites=None):
        copies = self.copy_model(case, arguments, body, names, compiler)
        if read_sites is None:
            copies.validate()
        else:
            # Focus these mutations on the new checker without repeatedly
            # executing all 1,906 copy scenarios. Only identical, independently
            # accepted read instructions retain their premise. Production
            # composition and the compiled mutants always run both checkers.
            copies.points = {(block, index) for block, rows in copies.m.graph.items()
                             for index, line in enumerate(rows) if (block, line) in read_sites}
        return self.driver.hosted.md5_tag_cleanup.check(copies, case[3])

    def test_md5_tag_cleanup_paths_and_mutations(self):
        h, count, unwind = self.driver.hosted, 0, 0
        for case, arguments, body, names, compiler in self.md5_models():
            checked = self.cleanup_model(case, arguments, body, names, compiler)
            self.assertTrue(checked.drops and checked.ends and checked.handoffs)
            read_sites = {(block, checked.m.graph[block][index]) for block, index in checked.c.points}
            mutants = []
            for point in sorted(checked.drops):
                line = checked.m.graph[point[0]][point[1]]
                symbol, args = h.syntax.call(line)
                mutants.append(body.replace(line, line.replace('@' + symbol, '@missing_drop'), 1))
                mutants.append(body.replace(line, line.replace(args[0], 'ptr %wrong_owner'), 1))
                mutants.append(body.replace(line, 'call void @' + symbol + '(' + args[0] + ')\n  ' + line, 1))
            for point in sorted(checked.ends):
                line = checked.m.graph[point[0]][point[1]]
                mutants.append(body.replace(line, '', 1))
                mutants.append(body.replace(line, line + '\n  ' + line, 1))
                mutants.append(body.replace(line, line.replace(checked.owner, '%wrong_owner'), 1))
            for kind, point in sorted(checked.handoffs):
                line = checked.m.graph[point[0]][point[1]]
                if kind == 'unwind':
                    _, args = h.syntax.call(line)
                    mutants.append(body.replace(line, line.replace(args[0], 'ptr ' + checked.owner), 1))
                for extra in (
                    'call void @unreviewed()',
                    'store i8 0, ptr ' + checked.owner,
                    'store i8 0, ptr %unbound',
                    'fence seq_cst',
                    '%late_tag = load i8, ptr ' + checked.owner + ', align 1',
                    '%late_read = load i8, ptr %unbound, align 1',
                    'call void @llvm.lifetime.start.p0(ptr nonnull ' + checked.owner + ')',
                    'call void @llvm.memcpy.p0.p0.i64(ptr %unbound, ptr %unbound2, i64 1, i1 false)',
                ):
                    mutants.append(body.replace(line, extra + '\n  ' + line, 1))
            for point in sorted(checked.points):
                line = checked.m.graph[point[0]][point[1]]
                if line.startswith('to label ') and point[1] > 0:
                    prior = checked.m.graph[point[0]][point[1] - 1]
                    call = h.syntax.call(prior)
                    if call and (point[0], point[1] - 1) in checked.live_calls:
                        # A direct panic handoff must not bypass the live owner.
                        handoffs = {p[0] for k, p in checked.handoffs if k == 'unwind'}
                        catches = [block for block, rows in checked.m.graph.items()
                                   if any(' = landingpad ' in row for row in rows)
                                   and any(rows[-1] == 'br label %' + target for target in handoffs)]
                        if catches:
                            self.assertEqual(len(catches), 1)
                            replacement = re.sub(r'unwind label %[-\w.$]+', 'unwind label %' + catches[0], line)
                            if replacement != line:
                                mutants.append(body.replace(line, replacement, 1))
            for mutant in mutants:
                self.assertNotEqual(mutant, body)
                delta = '\n'.join(difflib.unified_diff(body.splitlines(), mutant.splitlines(), n=1))
                with self.subTest(target=case[1], mutation=count, delta=delta), self.assertRaises(ValueError):
                    self.cleanup_model(case, arguments, mutant, names, compiler, read_sites)
                count += 1
            # These faults must pass the earlier copy checker, demonstrating
            # that exceptional destruction is a new, load-bearing obligation.
            for point, routes in checked.routes.items():
                if routes != {True}:
                    continue
                line = checked.m.graph[point[0]][point[1]]
                symbol, _ = h.syntax.call(line)
                mutant = body.replace(line, line.replace('@' + symbol, '@missing_unwind_drop'), 1)
                copies = self.copy_model(case, arguments, mutant, names, compiler).validate()
                with self.assertRaises(ValueError):
                    h.md5_tag_cleanup.check(copies, case[3])
                unwind += 1
            renamed = re.sub(re.escape(checked.owner) + r'(?![-\w.])', '%returned_tag_owner', body)
            self.cleanup_model(case, arguments, renamed, names, compiler)
        self.assertGreater(count, 75)
        self.assertEqual(unwind, 3)
        print(f'MD5 returned-tag cleanup: {count} dispatch/lifetime/escape/edge defects and {unwind} independent unwind defects rejected', flush=True)

    def test_compiled_md5_tag_cleanup_defects(self):
        d, h = self.driver, self.driver.hosted
        work = Path(self.directory.name) / 'md5-tag-cleanup-mutants'
        leaf, fixture = prepare(d, work)
        count = 0
        for target, directory in ((d.TARGETS[0], 'strict_execution'), (d.TARGETS[2], 'macos_resident')):
            def emit():
                return d.emit(work / target, '1.99.1', target, 'unwind', True,
                              fixture / 'Cargo.toml', leaf / 'Cargo.toml')
            h.validate(emit(), target, 'unwind')
            path = leaf / 'src' / directory / 'md5_compiled/worker.rs'
            original = path.read_text()
            moved = 'let (tags, actual) = result?;'
            report = moved + '\n        report(actual, &parameters, active)?;'
            checkpoint = report + '\n        checkpoint(&owner, cancel)?;'
            copy = 'brynja_core::copy_secret_region(destination, tag).map_err(|_| Error::Invariant)?;'
            edits = (
                ('        None\n', '        core::mem::forget(tags);\n        None\n'),
                (moved, moved + '\n        let tags = core::mem::ManuallyDrop::new(tags);'),
                (report, moved + '\n        if let Err(error) = report(actual, &parameters, active) { core::mem::forget(tags); return Err(error); }'),
                (checkpoint, report + '\n        if let Err(error) = checkpoint(&owner, cancel) { core::mem::forget(tags); return Err(error); }'),
                (copy, 'if brynja_core::copy_secret_region(destination, tag).is_err() { core::mem::forget(tags); return Err(Error::Invariant); }'),
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
        self.assertEqual(count, 10)
        print('MD5 returned-tag cleanup: 10 compiled Rust defects rejected; restored baselines pass', flush=True)
