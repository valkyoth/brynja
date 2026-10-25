"""MD5 health/checkpoint regressions on genuine optimized compiler output."""
import re
import difflib
from types import SimpleNamespace


class Md5CheckpointTests:
    def md5_models(self):
        h = self.driver.hosted
        for case, identity, worker, population, _ in self.hosts():
            if identity != 'md5_compiled':
                continue
            arguments, body = h.flow.resolve(worker, *population[:2])
            names = population[2]
            if not any('::for_compiled_target' in name and '@' + symbol + '(' in body
                       for symbol, name in names.items()):
                continue
            compiler = re.findall(r'!"rustc version ([\d.]+) ', case[0]['brynja-legacy-hmac-std'])[0]
            yield case, arguments, body, names, compiler

    def md5_check(self, arguments, body, names, compiler, target):
        h = self.driver.hosted
        # Retain independently validated constructor/selector premises.
        model = h.keyed.check(body, names, compiler, 'md5_compiled')
        transfer = h.authority.check(body, names, compiler, 'md5_compiled')
        envelope = h.envelope.check(arguments, body, names, 'md5_compiled')
        health = h.md5_health.check(model, transfer, envelope, compiler)
        boundaries = h.md5_boundaries.check(model, transfer, envelope, compiler, target, health)
        return model, health, boundaries

    def test_md5_checkpoint_callee_provenance(self):
        h, count, cases = self.driver.hosted, 0, 0
        for case, _, _, _, compiler in self.md5_models():
            llvm = case[0]['brynja-legacy-hmac-std']
            definitions, aliases = h.flow.definitions_and_aliases(llvm)
            names = h.model.demangle({n.strip('"') for n in re.findall(r'@("[^"]+"|[-\w.$]+)', llvm)})
            wanted = h.checkpoints.owner(case[1]) + '::md5_compiled::worker::checkpoint'
            selected = [s for s in (*definitions, *aliases) if names.get(s) == wanted]
            self.assertEqual(len(selected), 1)
            arguments, body = h.flow.resolve(selected[0], definitions, aliases)
            h.md5_checkpoint.validate(arguments, body, names, compiler)
            model = h.authority.Transfer(body, names, compiler, 'md5_compiled')
            points = {(b, i) for b, rows in model.graph.items() for i in range(len(rows))}
            mutants = list(self.temporary_mutations(model, body, points))
            for line, _, args, name in self.calls(body, names):
                if name == h.md5_checkpoint.NEW:
                    for arg in args:
                        mutants.append(body.replace(line, line.replace(arg, 'ptr %unbound', 1), 1))
            mutants.extend((body.replace('{ i8 7, i8 poison }', '{ i8 6, i8 poison }'),
                            body.replace(', i8 6', ', i8 0'),
                            re.sub(r'(insertvalue \{ i8, i8 \} %[-\w.]+, i8 )%[-\w.]+(, 1)', r'\g<1>0\2', body),
                            body.replace('ret { i8, i8 } ', 'call void @unexpected()\nret { i8, i8 } ')))
            for mutant in mutants:
                self.assertNotEqual(mutant, body)
                with self.subTest(compiler=compiler, target=case[1], mutation=count), self.assertRaises(ValueError):
                    h.md5_checkpoint.validate(arguments, mutant, names, compiler)
                count += 1
            # Semantics, not a textual fingerprint of SSA identities.
            signature, renamed = arguments, body
            for i, root in enumerate((*model.allocs, *(h.syntax.operand(a) for a in h.syntax.parameters(arguments)))):
                signature = re.sub(re.escape(root) + r'(?![-\w.])', '%md5_identity_' + str(i), signature)
                renamed = re.sub(re.escape(root) + r'(?![-\w.])', '%md5_identity_' + str(i), renamed)
            h.md5_checkpoint.validate(signature, renamed, names, compiler)
            self.rejects(case, body, '{ i8 7, i8 poison }', '{ i8 6, i8 poison }')
            cases += 1
        self.assertEqual(cases, 5)
        self.assertEqual(count, 111)
        print(f'MD5 checkpoint callees: {count} provenance/status/lifetime defects rejected', flush=True)

    def test_md5_health_and_checkpoint_boundaries(self):
        h, count = self.driver.hosted, 0
        for case, arguments, body, names, compiler in self.md5_models():
            model, health, boundaries = self.md5_check(arguments, body, names, compiler, case[1])
            points = health[3] | boundaries[0]
            mutants = list(self.temporary_mutations(model, body, points))
            for block, index in sorted(points):
                line = model.graph[block][index]
                call = h.syntax.call(line)
                if call and (names.get(call[0]) == h.md5_checkpoint.NEW
                             or names.get(call[0], '').endswith('::md5_compiled::worker::checkpoint')):
                    mutants.append(body.replace(line, line.replace('@' + call[0], '@missing_health'), 1))
                    for arg in call[1]:
                        mutants.append(body.replace(line, line.replace(arg, 'ptr %unbound', 1), 1))
                if call and call[0] == 'llvm.lifetime.start.p0':
                    root = model.pointer(h.syntax.operand(call[1][-1]))[0]
                    allocated = model.defs[root][1]
                    allocation = model.graph[allocated[0]][allocated[1]]
                    mutants.append(body.replace(line, '', 1).replace(allocation, allocation + '\n  ' + line, 1))
                if line.startswith('br i1 '):
                    labels = re.findall('label %' + h.flow.LABEL, line)
                    self.assertEqual(len(labels), 2)
                    for old, new in (labels, labels[::-1]):
                        mutants.append(body.replace(line, line.replace('label %' + old, 'label %' + new), 1))
                if line.startswith('store i16 '):
                    for value in (0, 7, 255):
                        mutants.append(body.replace(line, re.sub(r'store i16 %[-\w.]+', 'store i16 ' + str(value), line), 1))
            # Payload is preserved symbolically even if all low-byte tags stay
            # unchanged. Corrupt just one rejected health payload at a time.
            for _, _, (_, _, error) in health[0]:
                phi = next(line for rows in model.graph.values() for line in rows
                           if ' = phi i8 ' in line and '[ ' + error + ', %' in line)
                mutants.append(body.replace(phi, phi.replace('[ ' + error + ', %', '[ 0, %'), 1))
            for mutant in mutants:
                self.assertTrue(mutant != body, 'unchanged mutation ' + str(count))
                delta = [line for line in difflib.unified_diff(body.splitlines(), mutant.splitlines())
                         if line.startswith(('+', '-')) and not line.startswith(('+++', '---'))]
                with self.subTest(compiler=compiler, target=case[1], mutation=count, delta=delta), self.assertRaises(ValueError):
                    self.md5_check(arguments, mutant, names, compiler, case[1])
                count += 1
        self.assertGreater(count, 200)
        print(f'MD5 inlined health/admission/result: {count} defects rejected', flush=True)

    def test_md5_status_bit_identity_and_cycle_rejection(self):
        from legacy_hmac_hosted_md5_status import ERROR, evaluate, literal, value, walk
        known = {'%error': ERROR, '%tag': literal(7, 16)}
        known['%wide'] = evaluate('zext i8 %error to i16', known, {}, '')
        known['%upper'] = evaluate('shl nuw i16 %wide, 8', known, {}, '')
        for operation in ('or disjoint', 'add nuw nsw'):
            self.assertEqual(evaluate(operation + ' i16 %upper, %tag', known, {}, ''), literal(7, 8) + ERROR)
        self.assertIsNone(evaluate('add i16 %tag, %tag', known, {}, ''))
        self.assertEqual(value('%unknown', known, 8), (None,) * 8)
        graph = {'start': ['%wide = zext i8 %error to i16', '%upper = shl nuw i16 %wide, 8',
                           '%result = or disjoint i16 %upper, 7', 'store i16 %result, ptr %out, align 1', 'ret ptr null']}
        env = {'loads': {32: (None, '%out')}, 'result': ('start', 3)}
        walk(SimpleNamespace(graph=graph), env, 'start', '', {'%error': ERROR}, 7, ERROR)
        for changed in ('%wide = zext i8 0 to i16', '%wide = zext i8 undef to i16'):
            with self.assertRaises(ValueError):
                walk(SimpleNamespace(graph={'start': [changed, *graph['start'][1:]]}), env,
                     'start', '', {'%error': ERROR}, 7, ERROR)
        # A valid exit does not excuse a second path looping forever.
        looping = dict(graph, loop=['br i1 %unknown, label %loop, label %start'])
        with self.assertRaises(ValueError):
            walk(SimpleNamespace(graph=looping), env, 'loop', '', {'%error': ERROR}, 7, ERROR)
        with self.assertRaises(ValueError):
            self.driver.hosted.md5_health.mandatory(SimpleNamespace(graph=looping), ('loop', 0), ('start', 0))
