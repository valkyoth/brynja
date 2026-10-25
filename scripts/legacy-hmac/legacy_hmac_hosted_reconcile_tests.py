"""Crossed projections and premature borrowed-local lifetime regressions."""
import copy
from pathlib import Path
import re
from unittest.mock import patch

from legacy_hmac_hosted_compiled_fixture import prepare
from legacy_hmac_hosted_prearm_tests import replace_point


class ReconcileTests:
    def reconciliation_rows(self):
        h = self.driver.hosted
        for case in self.cases:
            _, leaf, compiler = self.batch_populations(case)
            for identity, (symbol, worker, population, body) in case[2].items():
                signature, _ = h.flow.resolve(symbol, *population[:2])
                worker_signature, worker_body = h.flow.resolve(worker, *population[:2])
                names = population[2]
                prefix = h.prearm.check(signature, body, names, leaf, case[1], identity, compiler)
                native = h.launch.Launch(signature, body, names, case[1], identity, h.profile(case[1])[1])
                record = h.capture.check(signature, body, names, case[1], identity)
                joined = h.transaction.check(record, compiler, *h.profile(case[1]))
                worker_envelope = h.envelope.check(worker_signature, worker_body, names, identity)
                yield case, dict(prefix=prefix, native=native, record=record, joined=joined, worker=worker,
                                worker_signature=worker_signature, worker_body=worker_body, worker_envelope=worker_envelope)

    def test_projection_reconciliation(self):
        h, count, profiles = self.driver.hosted, 0, 0
        for _, row in self.reconciliation_rows():
            prefix, record, joined = row['prefix'], row['record'], row['joined']
            result = h.reconcile.check(**row)
            self.assertEqual(result['borrowed_locals'], len(record.borrowed))
            self.assertGreater(result['captured_fields_read'], 0)
            variants = []
            for field, value in (('signature', prefix.signature + ' '), ('body', prefix.body + '\n'),
                                 ('identity', 'wrong'), ('target', 'wrong'), ('compiler', 'wrong'),
                                 ('scenarios', 0), ('boundaries', frozenset()), ('points', frozenset())):
                variants.append({**row, 'prefix': prefix._replace(**{field: value})})
            variants.append({**row, 'prefix': prefix._replace(boundaries=frozenset({record.create[0]}),
                                                            points=prefix.points | {record.create[0]})})
            for component, field, value in (
                    ('native', 'job', '%wrong'), ('native', 'create', ('wrong', 0)),
                    ('native', 'names', {}), ('native', 'graph', {}),
                    ('native', 'allocs', {}), ('joined', 'r', copy.copy(record)),
                    ('joined', 'flags', (0, 1)), ('joined', 'scenarios', 0),
                    ('joined', 'initial', [record.create[0]]),
                    ('record', 'signature', 'wrong'), ('record', 'body', record.body + '\n')):
                component_copy = copy.copy(row[component])
                setattr(component_copy, field, value)
                variants.append({**row, component: component_copy})
            if record.identity.endswith('_compiled'):
                altered = copy.copy(joined)
                altered.quarantine = [(record.create[0], '1')]
                variants.append({**row, 'joined': altered})
            env = row['worker_envelope']
            variants += [{**row, 'worker': 'another_callback'},
                         {**row, 'worker_signature': 'wrong'}, {**row, 'worker_body': row['worker_body'] + '\n'},
                         {**row, 'worker_envelope': {**env, 'binding': ()}},
                         {**row, 'worker_envelope': {**env, 'loads': {}}},
                         {**row, 'worker_envelope': {**env, 'loads': {**env['loads'], 999: (('x', 0), '%wrong')}}}]
            for variant in variants:
                with self.subTest(identity=record.identity, target=record.target, mutation=count), self.assertRaises(ValueError):
                    h.reconcile.check(**variant)
                count += 1
            profiles += 1
        self.assertEqual(profiles, 24)
        print(f'Hosted reconciliation: {profiles} profiles, {count} crossed/missing projection mutations rejected', flush=True)

    def test_borrowed_lifetime_reconciliation(self):
        h, count, after_join, frame = self.driver.hosted, 0, 0, 0
        for _, row in self.reconciliation_rows():
            original, joined = row['record'], row['joined']
            body = original.body
            ptrs = h.syntax.pointers(body, original.allocs)
            for root in sorted(original.borrowed):
                uses = [(point, rhs) for token, (rhs, point) in original.defs.items()
                        if (load := re.match(r'load (?:i8|ptr|i64), ptr (' + h.syntax.VALUE + '),', rhs))
                        and ptrs.get(load[1], (None,))[0] == root]
                starts = [(label, index, line) for label, lines in original.graph.items()
                          for index, line in enumerate(lines) if (call := h.syntax.call(line))
                          and call[0] == 'llvm.lifetime.start.p0' and h.syntax.operand(call[1][-1]) == root]
                if not starts:
                    frame += 1
                # The join itself uses every borrowed local indirectly, even
                # if its ordinary-host pointer is not loaded afterward.
                join = next(point for point, (name, _) in joined.calls.items()
                            if name in ('pthread_join', joined.resource + '::thread::join'))
                sites = {join, *(point for point, _ in uses if original.before(join, point))}
                for point in sites:
                    line = original.graph[point[0]][point[1]]
                    end = f'call void @llvm.lifetime.end.p0(i64 {original.allocs[root]}, ptr {root})'
                    changed = replace_point(body, *point, line, end + '\n  ' + line)
                    record = h.capture.Record(original.signature, changed, original.names, original.target, original.identity)
                    record.borrowed = original.borrowed
                    model = copy.copy(joined)
                    model.r = record
                    model.calls = {(label, index): (record.names.get(c[0], c[0]), c[1])
                                   for label, lines in record.graph.items() for index, text in enumerate(lines)
                                   if (c := h.syntax.call(text))}
                    with self.subTest(root=root, target=record.target, point=point), self.assertRaises(ValueError):
                        h.reconcile.borrowed_lifetimes(record, model)
                    count += 1
                    after_join += int(point != join)
            # A removed start but retained end must not acquire whole-frame
            # lifetime by accident. Exact-point editing avoids duplicate calls.
            for label, lines in original.graph.items():
                for index, line in enumerate(lines):
                    call = h.syntax.call(line)
                    if call and call[0] == 'llvm.lifetime.start.p0' and h.syntax.operand(call[1][-1]) in original.borrowed:
                        changed = replace_point(body, label, index, line, '')
                        record = h.capture.Record(original.signature, changed, original.names, original.target, original.identity)
                        record.borrowed = original.borrowed
                        model = copy.copy(joined)
                        model.calls = {(b, i): (record.names.get(c[0], c[0]), c[1])
                                       for b, rows in record.graph.items() for i, text in enumerate(rows)
                                       if (c := h.syntax.call(text))}
                        with self.assertRaises(ValueError):
                            h.reconcile.borrowed_lifetimes(record, model)
                        count += 1
        self.assertGreater(after_join, 0)
        self.assertGreater(frame, 0)
        print(f'Borrowed lifetime reconciliation: {count} defects rejected, {after_join} after-join use cases; '
              f'{frame} frame-lifetime baselines accepted', flush=True)

    def test_reconciliation_output_is_atomic(self):
        h = self.driver.hosted
        case = self.cases[0]
        output = {}
        h.validate(case[0], case[1], case[3], output)
        self.assertEqual(set(output), {'sha1', 'md5', 'sha1_compiled', 'md5_compiled'})
        with self.assertRaises(ValueError):
            h.validate(case[0], case[1], case[3], output)
        calls, output = [], {}
        real = h.reconcile.check
        def fail_last(*args):
            calls.append(args[2].identity)
            if args[2].identity == 'md5_compiled':
                raise ValueError('last projection failed')
            return real(*args)
        with patch.object(h.reconcile, 'check', side_effect=fail_last), self.assertRaises(ValueError):
            h.validate(case[0], case[1], case[3], output)
        self.assertEqual(len(calls), 4)
        self.assertEqual(output, {})

    def test_ordinary_setup_error_paths(self):
        h, profiles, scenarios, rejected = self.driver.hosted, 0, 0, 0
        for _, row in self.reconciliation_rows():
            original, model = row['record'], row['joined']
            if model.compiled:
                continue
            boundary, = row['prefix'].boundaries
            model.points.clear()
            scenarios += h.reconcile.preentry.check(model, boundary)
            profiles += 1
            changes = []
            for point in model.points:
                line = original.graph[point[0]][point[1]]
                call = h.syntax.call(line)
                if call and original.names.get(call[0]) in (model.clear, model.drop):
                    changes.append((point, line, line.replace('@' + call[0], '@missing_cleanup')))
                if line.startswith('ret i16 '):
                    changes.append((point, line, 'ret i16 0'))
            self.assertTrue(changes)
            for point, before, after in changes:
                changed = replace_point(original.body, *point, before, after)
                # Branch indices before a replaced line remain unchanged.
                with self.subTest(identity=original.identity, target=original.target, point=point), self.assertRaises(ValueError):
                    record = h.capture.check(original.signature, changed, original.names, original.target, original.identity)
                    altered = h.transaction.Transaction(record, model.compiler, *h.profile(record.target))
                    h.reconcile.preentry.check(altered, boundary)
                rejected += 1
        self.assertEqual(profiles, 12)
        self.assertGreaterEqual(scenarios, 72)
        print(f'Ordinary setup errors: {profiles} profiles, {scenarios} outcomes, {rejected} cleanup/status mutations rejected', flush=True)

    def test_compiled_ordinary_setup_cleanup_defect(self):
        d, h = self.driver, self.driver.hosted
        work = Path(self.directory.name) / 'ordinary-setup-mutant'
        leaf, fixture = prepare(d, work)
        for target, directory in ((d.TARGETS[0], 'strict_execution'), (d.TARGETS[2], 'macos_resident')):
            path = leaf / 'src' / directory / 'mod.rs'
            original = path.read_text()
            before = '})?;\n        let result = result?;'
            self.assertIn(before, original)
            changed = original.replace('self.stack.run(|| {', 'let launched = self.stack.run(|| {', 1)
            changed = changed.replace(before, '});\n        if let Err(error) = launched {\n'
                '            core::mem::forget(buffers);\n            return Err(error.into());\n        }\n'
                '        let result = result?;', 1)
            def emit():
                return d.emit(work / target, '1.99.1', target, 'unwind', True,
                              fixture / 'Cargo.toml', leaf / 'Cargo.toml')
            try:
                path.write_text(changed)
                artifacts = emit()
                with self.assertRaises(ValueError):
                    h.validate(artifacts, target, 'unwind')
            finally:
                path.write_text(original)
            h.validate(emit(), target, 'unwind')
        print('Ordinary setup cleanup: two compiled forgotten-guard defects rejected; restored baselines pass', flush=True)

    def test_compiled_batch_width_probe_defect(self):
        d, h = self.driver, self.driver.hosted
        work = Path(self.directory.name) / 'reconcile-probe-mutant'
        leaf, fixture = prepare(d, work)
        path = fixture / 'src/admission.rs'
        original = path.read_text()
        before = 'pub fn batch_width(value: &Md5BatchSession) -> usize {\n    value.tag_bytes()'
        self.assertIn(before, original)
        for target in (d.TARGETS[0], d.TARGETS[2]):
            def emit():
                return d.emit(work / target, '1.99.1', target, 'unwind', True,
                              fixture / 'Cargo.toml', leaf / 'Cargo.toml')
            try:
                path.write_text(original.replace(before, before + '.saturating_add(1)'))
                with self.assertRaises(ValueError):
                    h.validate(emit(), target, 'unwind')
            finally:
                path.write_text(original)
            h.validate(emit(), target, 'unwind')
        print('MD5 batch typed width: two compiled defects rejected; restored baselines pass', flush=True)
