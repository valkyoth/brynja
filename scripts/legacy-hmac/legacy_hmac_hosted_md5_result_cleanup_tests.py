"""Pending Result cleanup: ownership, discriminants and compiled failures."""
import difflib
from pathlib import Path
import re

from legacy_hmac_hosted_compiled_fixture import prepare


class Md5ResultCleanupTests:
    def pending_model(self, case, arguments, body, names, compiler, read_sites=None):
        h = self.driver.hosted
        m, health, boundaries = self.md5_check(arguments, body, names, compiler, case[1])
        env = h.envelope.check(arguments, body, names, 'md5_compiled')
        transfers = h.md5_result_transport.check(m, health, case[1])
        copies = h.md5_tag_copy.Copies(m, env, boundaries, transfers, compiler)
        if read_sites is None:
            copies.validate()
        else:
            copies.points = {(b, i) for b, rows in m.graph.items() for i, line in enumerate(rows)
                             if (b, line) in read_sites}
        post = h.md5_tag_cleanup.check(copies, case[3])
        return h.md5_result_cleanup.ResultCleanup(copies, post, health, case[3])

    def test_md5_pending_result_cleanup_mutations(self):
        h, count, scenarios, independent = self.driver.hosted, 0, 0, 0
        for case, arguments, body, names, compiler in self.md5_models():
            checked = self.pending_model(case, arguments, body, names, compiler).validate()
            scenarios += len(checked.outcomes)
            reads = {(b, checked.m.graph[b][i]) for b, i in checked.c.points}
            mutants = []
            for point in sorted(checked.drops):
                line = checked.m.graph[point[0]][point[1]]
                symbol, args = h.syntax.call(line)
                missing = body.replace(line, line.replace('@' + symbol, '@missing_pending_drop'), 1)
                # All preceding checks, including post-transfer cleanup, still
                # pass: this omission is caught by the new pending-owner check.
                candidate = self.pending_model(case, arguments, missing, names, compiler, reads)
                with self.assertRaises(ValueError):
                    candidate.validate()
                independent += 1
                mutants.extend((missing,
                    body.replace(line, line.replace(args[0], 'ptr %wrong_region'), 1),
                    body.replace(line, 'call void @' + symbol + '(' + args[0] + ')\n  ' + line, 1)))
            for point in sorted(checked.points):
                line = checked.m.graph[point[0]][point[1]]
                if ' = load i8, ptr ' in line and any((p := checked.address(v)) and p[0] == checked.root
                                                    for v in re.findall(h.md5_result_cleanup.V, line)):
                    mutants.append(body.replace(line, line.replace('load i8', 'load i16'), 1))
                    if point not in checked.auth.points:
                        mutants.append(body.replace(line, '%opaque_result = ptrtoint ptr ' + checked.root
                                                    + ' to i64\n  ' + line, 1))
                if ' = icmp eq i8 ' in line:
                    mutants.append(body.replace(line, line.replace('icmp eq i8', 'icmp ne i8'), 1))
                if line.startswith('br i1 '):
                    for target in re.findall('label %' + h.flow.LABEL, line):
                        mutants.append(body.replace(line, 'br label %' + target, 1))
            ends = set(checked.ends)
            for symbol, args, point in checked.m.calls:
                if symbol == 'llvm.lifetime.end.p0' and checked.address(h.syntax.operand(args[-1])) == (checked.root, 0):
                    ends.add(point)
            for point in sorted(ends):
                line = checked.m.graph[point[0]][point[1]]
                mutants.extend((body.replace(line, '', 1), body.replace(line, line + '\n  ' + line, 1),
                                body.replace(line, line.replace(checked.root, '%different_result'), 1),
                                body.replace(line, line.replace(checked.root, checked.auth.destination), 1)))
            anchor = checked.m.graph[checked.health[0]][checked.health[1]]
            for effect in ('call void @escape(ptr ' + checked.root + ')',
                           'store i8 2, ptr ' + checked.root,
                           'call void @llvm.lifetime.end.p0(ptr nonnull ' + checked.root + ')'):
                mutants.append(body.replace(anchor, effect + '\n  ' + anchor, 1))
            # Pending and moved owner identities must not escape via the
            # panic handoff or an extra post-transfer operation.
            for kind, point in checked.post.handoffs:
                line = checked.m.graph[point[0]][point[1]]
                if kind == 'unwind':
                    _, args = h.syntax.call(line)
                    mutants.append(body.replace(line, line.replace(args[0], 'ptr ' + checked.root), 1))
                for effect in ('%late_result = load i8, ptr ' + checked.root + ', align 8',
                               'call void @escape(ptr ' + checked.root + ')'):
                    mutants.append(body.replace(line, effect + '\n  ' + line, 1))
            for mutant in mutants:
                self.assertNotEqual(mutant, body)
                delta = '\n'.join(difflib.unified_diff(body.splitlines(), mutant.splitlines(), n=1))
                with self.subTest(target=case[1], mutation=count, delta=delta), self.assertRaises(ValueError):
                    self.pending_model(case, arguments, mutant, names, compiler, reads).validate()
                count += 1
            renamed = re.sub(re.escape(checked.root) + r'(?![-\w.])', '%pending_result', body)
            self.pending_model(case, arguments, renamed, names, compiler).validate()
        self.assertEqual(scenarios, 54)
        self.assertEqual(independent, 8)
        self.assertGreater(count, 75)
        print(f'MD5 pending Result: {scenarios} ownership/health outcomes; {count} mutations and {independent} independent missing-drop defects rejected', flush=True)

    def test_compiled_md5_pending_result_defects(self):
        d, h = self.driver, self.driver.hosted
        work = Path(self.directory.name) / 'md5-pending-result-mutants'
        leaf, fixture = prepare(d, work)
        count = 0
        for target, directory in ((d.TARGETS[0], 'strict_execution'), (d.TARGETS[2], 'macos_resident')):
            def emit():
                return d.emit(work / target, '1.99.1', target, 'unwind', True,
                              fixture / 'Cargo.toml', leaf / 'Cargo.toml')
            h.validate(emit(), target, 'unwind')
            path = leaf / 'src' / directory / 'md5_compiled/worker.rs'
            original = path.read_text()
            before = 'healthy(&owner)?;\n        let (tags, actual) = result?;'
            edits = (
                'if let Err(error) = healthy(&owner) { core::mem::forget(result); return Err(error); }\n        let (tags, actual) = result?;',
                'let pending = core::mem::ManuallyDrop::new(result);\n        healthy(&owner)?;\n        let (tags, actual) = core::mem::ManuallyDrop::into_inner(pending)?;',
                'let (tags, actual) = result?;\n        healthy(&owner)?;',
            )
            self.assertEqual(original.count(before), 1)
            for after in edits:
                try:
                    path.write_text(original.replace(before, after, 1))
                    artifacts = emit()
                    with self.subTest(target=target, mutation=count), self.assertRaises(ValueError):
                        h.validate(artifacts, target, 'unwind')
                finally:
                    path.write_text(original)
                count += 1
            h.validate(emit(), target, 'unwind')
        self.assertEqual(count, 6)
        print('MD5 pending Result: six compiled Rust defects rejected; restored baselines pass', flush=True)
