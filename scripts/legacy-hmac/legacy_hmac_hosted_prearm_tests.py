"""Boundary and compiler-defect regressions for real request admission paths."""
from pathlib import Path
import re
from unittest.mock import patch

from legacy_hmac_hosted_compiled_fixture import prepare


def replace_point(body, label, index, before, after):
    """Mutate the witnessed instruction, not an identical earlier cleanup call."""
    lines, active, ordinal = body.splitlines(), False, 0
    for position, raw in enumerate(lines):
        line = raw.split(';', 1)[0].strip()
        if line == label + ':':
            active = True
            continue
        if not active or not line:
            continue
        if ordinal == index:
            if line != before:
                raise ValueError('mutation point does not match instruction')
            lines[position] = raw.replace(before, after, 1)
            return '\n'.join(lines)
        ordinal += 1
    raise ValueError('mutation point missing')


class PrearmTests:
    def admission_rows(self):
        h = self.driver.hosted
        for case in self.cases:
            _, leaf, compiler = self.batch_populations(case)
            for identity, (symbol, _, population, body) in case[2].items():
                signature, _ = h.flow.resolve(symbol, *population[:2])
                owner = h.profile(case[1])[0]
                wanted = (owner + ('::md5_compiled' if identity == 'md5_compiled' else '') + '::types::validate',
                          '<' + owner + '::types::Cancellation>::check')
                callees = {name: h.flow.resolve(s, *leaf[:2]) for name in wanted for s in (*leaf[0], *leaf[1])
                           if leaf[2].get(s) == name}
                names = {**leaf[2], **population[2]}
                requests = h.prearm.cases.batch() if identity == 'md5_compiled' else h.prearm.cases.scalar(identity)
                yield case, identity, compiler, signature, body, names, callees, requests

    def test_prearm_request_policy_and_artifact_defects(self):
        h, profiles, outcomes, rejected, captures = self.driver.hosted, 0, 0, 0, 0
        for case, identity, compiler, signature, body, names, callees, requests in self.admission_rows():
            def model(text=body, functions=callees):
                return h.prearm.Admission(signature, text, names, functions, case[1], identity, compiler)
            baseline = model()
            witnesses = {}
            for request in requests:
                baseline.points, baseline.callee_points = set(), set()
                baseline.run(request)
                for point in baseline.points:
                    witnesses.setdefault((None, *point), []).append((request, baseline.uses))
                for point in baseline.callee_points:
                    witnesses.setdefault(point, []).append((request, baseline.callee_uses[point[0]]))
            profiles += 1
            outcomes += len(requests)
            mutants = {}
            for (callee, label, index), samples in witnesses.items():
                original = body if callee is None else callees[callee][1]
                line = h.flow.blocks(original)[label][index]
                changes = []
                if 'getelementptr' in line:
                    # Hoisted addresses consumed only after worker entry belong
                    # to the launch/capture projection, not this prefix.
                    samples = [(request, uses) for request, uses in samples if line.split(' = ', 1)[0] in uses]
                    changed = re.sub(r'i64 (\d+)(?=,|$)', lambda m: 'i64 ' + str(int(m[1]) + 1), line)
                    if changed != line:
                        changes.append(changed)
                if 'icmp ugt ' in line:
                    changes.append(line.replace('icmp ugt ', 'icmp uge '))
                if 'icmp eq ' in line:
                    changes.append(line.replace('icmp eq ', 'icmp ne '))
                if '= load atomic i8' in line:
                    changes += [line.replace(' acquire,', ' monotonic,'), line.replace('ptr %cancel', 'ptr %wrong')]
                if line.startswith('store i8 1,'):
                    changes.append(line.replace('store i8 1,', 'store i8 0,'))
                if call := h.syntax.call(line):
                    if names.get(call[0], '').endswith(('>::clear', '::validate', '>::check', '>::drop')):
                        changes.append(line.replace('@' + call[0], '@unreviewed_admission_call'))
                if line.startswith('ret i16 '):
                    changes.append('ret i16 0')
                for changed in changes:
                    if changed != line and samples:
                        mutant = replace_point(original, label, index, line, changed)
                        mutants.setdefault((callee, mutant), []).extend(request for request, _ in samples)
            for (callee, mutant), samples in mutants.items():
                functions = dict(callees)
                if callee is not None:
                    functions[callee] = (callees[callee][0], mutant)
                altered = model(mutant if callee is None else body, functions)
                original = body if callee is None else callees[callee][1]
                delta = [(a, b) for a, b in zip(original.splitlines(), mutant.splitlines()) if a != b]
                with self.subTest(target=case[1], identity=identity, callee=callee, mutation=rejected, delta=delta):
                    try:
                        for request in dict.fromkeys(samples):
                            altered.run(request)
                    except ValueError:
                        pass
                    else:
                        # Some pre-entry loads initialize a captured field
                        # used only by the worker. Reconcile these with the
                        # existing independent capture-provenance projection.
                        with self.assertRaises(ValueError):
                            h.capture.check(signature, mutant if callee is None else body, names, case[1], identity)
                        captures += 1
                rejected += 1
        self.assertEqual(profiles, 24)
        self.assertGreater(outcomes, 20000)
        self.assertGreater(rejected, 400)
        print(f'Legacy pre-arm admission: {profiles} profiles, {outcomes} outcomes, {rejected} artifact defects rejected '
              f'({captures} by composed capture provenance)', flush=True)

    def test_prearm_typed_layout_probes(self):
        h, count = self.driver.hosted, 0
        for case in self.cases:
            fixture, _, _ = self.batch_populations(case)
            definitions, aliases, names = fixture
            h.prearm_layout.validate(fixture)
            for name in h.prearm_layout.FIELDS:
                wanted = 'brynja_legacy_hmac_hosted_cleanup::admission::' + name
                symbol = next(s for s in (*definitions, *aliases) if names.get(s) == wanted)
                with self.assertRaises(ValueError):
                    h.prearm_layout.validate((definitions, aliases, {**names, symbol: 'missing'}))
                with self.assertRaises(ValueError):
                    h.prearm_layout.validate((definitions, {**aliases, 'extra': symbol}, {**names, 'extra': wanted}))
                signature, body = h.flow.resolve(symbol, definitions, aliases)
                changed = re.sub(r'= load (?:i8|i64|i128),', '= load i32,', body, count=1)
                self.assertNotEqual(changed, body)
                resolved = symbol
                while resolved in aliases:
                    resolved = aliases[resolved]
                with self.assertRaises(ValueError):
                    h.prearm_layout.validate(({**definitions, resolved: (signature, changed)}, aliases, names))
                count += 3
        print(f'Pre-arm typed layout: {count} missing/duplicate/load-width probe mutations rejected', flush=True)

    def test_prearm_projection_cache_and_walker(self):
        h = self.driver.hosted
        duplicated = 'entry:\n call void @clear()\n br label %later\nlater:\n call void @clear()\n ret i16 0'
        selected = replace_point(duplicated, 'later', 0, 'call void @clear()', 'call void @wrong()')
        self.assertEqual(selected, duplicated.replace('later:\n call void @clear()', 'later:\n call void @wrong()'))
        with self.assertRaises(ValueError):
            replace_point(duplicated, 'later', 0, 'ret i16 0', 'ret i16 1')
        case, identity, compiler, signature, body, names, callees, _ = next(self.admission_rows())
        arguments = (signature, body, tuple(sorted(names.items())), tuple((n, *v) for n, v in callees.items()),
                     case[1], identity, compiler)
        expected = h.prearm._check(*arguments)
        with patch.object(h.prearm.Admission, 'run', side_effect=ValueError('must recheck changed projection')):
            self.assertEqual(h.prearm._check(*arguments), expected)
            replacements = (signature + ' ', body + '\n', tuple(sorted({**names, 'new': 'name'}.items())),
                            tuple((n, a, b + '\n') for n, a, b in arguments[3]),
                            'other-target', 'md5' if identity != 'md5' else 'sha1', '1.99.1' if compiler == '1.90.0' else '1.90.0')
            for index, replacement in enumerate(replacements):
                changed = list(arguments)
                changed[index] = replacement
                with self.assertRaises(ValueError):
                    h.prearm._check(*changed)
        f = h.prearm.flow
        def read(*_):
            self.fail('arithmetic read memory')
        loop = '''entry:
 br label %loop
loop:
 %a = phi i64 [ 1, %entry ], [ %b, %again ]
 %b = phi i64 [ 2, %entry ], [ %a, %again ]
 %n = phi i64 [ 0, %entry ], [ %next, %again ]
 %next = add i64 %n, 1
 %done = icmp eq i64 %next, 2
 br i1 %done, label %exit, label %again
again:
 br label %loop
exit:
 %result = trunc i64 %a to i16
 ret i16 %result'''
        self.assertEqual(f.run(loop, {}, read, read, read, lambda *_: False)[1], 2)
        for expression in ('add nuw i8 255, 1', 'sub nuw i8 0, 1', 'mul nuw i8 128, 2',
                           'add nsw i8 127, 1', 'sub nsw i8 -128, 1', 'mul nsw i8 64, 2',
                           'zext nneg i8 128 to i128'):
            with self.assertRaises(ValueError):
                f.expression(expression, int, None)
        model = h.prearm.Admission(signature, body, names, callees, case[1], identity, compiler)
        model.run(h.prearm.cases.scalar(identity)[0])
        root = 'local:%overlap_regression'
        model.allocs[root] = 32
        model.write((root, 16), 'i8', 0)
        model.write((root, 0), 'ptr', ('self', 184))
        model.write((root, 16), 'i64', 1)
        with self.assertRaises(ValueError):
            model.read((root, 16), 'i8')
        self.assertEqual(model.read((root, 0), 'ptr'), ('self', 184))
        model.write((root, 17), 'i8', 0)
        with self.assertRaises(ValueError):
            model.read((root, 16), 'i64')
        for offset in (-1, 25):
            with self.assertRaises(ValueError):
                model.write((root, offset), 'i64', 0)

    def test_compiled_prearm_defects(self):
        d, h = self.driver, self.driver.hosted
        work = Path(self.directory.name) / 'prearm-mutants'
        leaf, fixture = prepare(d, work)
        count = 0
        for target, directory in ((d.TARGETS[0], 'strict_execution'), (d.TARGETS[2], 'macos_resident')):
            def emit():
                return d.emit(work / target, '1.99.1', target, 'unwind', True,
                              fixture / 'Cargo.toml', leaf / 'Cargo.toml')
            edits = [('mod.rs', 'cancel.check()?;', '/* missing initial cancellation */'),
                     ('mod.rs', 'keep: false,', 'keep: true,'),
                     ('sha1_compiled.rs', 'if self.quarantined {', 'if false {'),
                     ('types.rs', 'request.key.len() > limits.max_key_bytes', 'false'),
                     ('types.rs', 'request.chunks.len() > limits.max_chunks', 'false'),
                     ('types.rs', 'if bits > limits.max_message_bits {', 'if false {'),
                     ('types.rs', 'value.len() != bytes', 'value.len() != value.len()'),
                     ('md5_compiled.rs', 'cancel.check()?;', '/* missing batch cancellation */'),
                     ('md5_compiled.rs', 'if self.quarantined {', 'if false {'),
                     ('md5_compiled/types.rs', 'group.iter().all(Option::is_some)', 'group.iter().any(Option::is_some)'),
                     ('md5_compiled/types.rs', 'input.key.len() > limits.max_key_bytes', 'false'),
                     ('md5_compiled/types.rs', 'candidate.len() == bytes', 'candidate.len() == candidate.len()')]
            for file, before, after in edits:
                path = leaf / 'src' / directory / file
                original = path.read_text()
                self.assertIn(before, original)
                try:
                    path.write_text(original.replace(before, after, 1))
                    artifacts = emit()
                    with self.subTest(target=target, mutant=count), self.assertRaises(ValueError):
                        h.validate(artifacts, target, 'unwind')
                finally:
                    path.write_text(original)
                count += 1
            h.validate(emit(), target, 'unwind')
        print(f'Pre-arm admission: {count} compiled defects rejected; restored baselines pass', flush=True)
