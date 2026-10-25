"""Mutate real report transports, layouts and storage lifetimes."""
import difflib
from pathlib import Path
import re

from legacy_hmac_hosted_compiled_fixture import prepare


class Md5ResultTests:
    def test_md5_result_typed_projections(self):
        h, count = self.driver.hosted, 0
        for case in self.cases:
            population = self.report_population(case[0]['brynja-legacy-hmac-hosted-cleanup'])
            h.md5_result_layout.validate(population)
            for symbol, (arguments, body) in population[0].items():
                if '::report_result::' not in population[2].get(symbol, ''):
                    continue
                mutants = [body.replace('icmp eq i8', 'icmp ne i8'),
                           body.replace(', 2\n', ', 1\n'),
                           re.sub(r'ret ptr %[-\w.]+', 'ret ptr null', body)]
                for line in body.splitlines():
                    if 'getelementptr' in line:
                        mutants.append(body.replace(line, re.sub(r'i64 (\d+)',
                            lambda m: 'i64 ' + str(int(m[1]) + 8), line), 1))
                for mutant in mutants:
                    self.assertNotEqual(mutant, body)
                    altered = dict(case[0])
                    altered['brynja-legacy-hmac-hosted-cleanup'] = altered['brynja-legacy-hmac-hosted-cleanup'].replace(body, mutant, 1)
                    with self.subTest(target=case[1], mutation=count), self.assertRaises(ValueError):
                        h.validate(altered, case[1], case[3])
                    count += 1
        self.assertEqual(count, 54)
        print('MD5 typed Result projections: 54 layout/admission substitutions rejected', flush=True)

    def test_md5_result_bytes_lifetimes_and_errors(self):
        h, count = self.driver.hosted, 0
        for case, arguments, body, names, compiler in self.md5_models():
            def validate(candidate):
                model, health, _ = self.md5_check(arguments, candidate, names, compiler, case[1])
                return model, h.md5_result_transport.check(model, health, case[1])
            model, checks = validate(body)
            points = set().union(*(item.points for item in checks))
            mutants = []
            for block, index in sorted(points):
                line = model.graph[block][index]
                if ' = getelementptr' in line:
                    mutants.append(body.replace(line, re.sub(r'i64 (\d+)$',
                        lambda m: 'i64 ' + str(int(m[1]) + 1), line), 1))
                elif ' = load i8' in line:
                    mutants.append(body.replace(line, line.replace('load i8', 'load i16'), 1))
                elif line.startswith('store i8 '):
                    mutants.append(body.replace(line, re.sub(r'store i8 (%[-\w.]+|\d+)', 'store i8 255', line), 1))
                elif ' = phi i8 ' in line:
                    mutants.append(body.replace(line, re.sub(r'\[ %[-\w.]+,', '[ 0,', line, count=1), 1))
                elif ' = icmp eq i8 ' in line:
                    mutants.append(body.replace(line, line.replace('icmp eq', 'icmp ne'), 1))
                elif line.startswith('br i1 '):
                    _, good = re.findall('label %' + h.flow.LABEL, line)
                    mutants.append(body.replace(line, 'br label %' + good, 1))
                call = h.syntax.call(line)
                if call and call[0] == 'llvm.memcpy.p0.p0.i64':
                    args = call[1]
                    for arg in args[:2]:
                        mutants.append(body.replace(line, line.replace(arg, 'ptr %unknown'), 1))
                    for size in (0, int(args[2].split()[-1]) - 1, int(args[2].split()[-1]) + 1):
                        mutants.append(body.replace(line, line.replace(args[2], 'i64 ' + str(size)), 1))
                    mutants.append(body.replace(line, '', 1))
                elif call and call[0].startswith('llvm.lifetime.'):
                    # Mapped authentication storage has separate post-report
                    # tag/drop paths. Their end completeness is not claimed by
                    # this report-transfer check; early ends and duplicate ends
                    # are checked, as are the complete verification temporaries.
                    root = model.pointer(h.syntax.operand(call[1][-1]))[0]
                    mapped_auth = any(root in item.roots and model.allocs[root] == 120
                                      and root != item.source for item in checks)
                    if not (mapped_auth and call[0] == 'llvm.lifetime.end.p0'):
                        mutants.append(body.replace(line, '', 1))
                    mutants.append(body.replace(line, line + '\n  ' + line, 1))
            for item in checks:
                report_line = model.graph[item.report[0]][item.report[1]]
                for root in item.roots:
                    # Hidden pointer escape and unknown writes must not be
                    # dismissed as unrelated to the transport.
                    for effect in ('store ptr ' + root + ', ptr %escape, align 8',
                                   'store i8 0, ptr ' + root + ', align 1',
                                   'call void @escape(ptr ' + root + ')'):
                        mutants.append(body.replace(report_line, effect + '\n  ' + report_line, 1))
                mutants.append(body.replace(report_line, report_line.replace(item.destination, item.source), 1))
            for mutant in mutants:
                self.assertNotEqual(mutant, body)
                delta = list(difflib.unified_diff(body.splitlines(), mutant.splitlines()))
                with self.subTest(target=case[1], compiler=compiler, mutation=count, delta=delta), self.assertRaises(ValueError):
                    validate(mutant)
                count += 1
            # SSA naming is not evidence; a consistent renaming still passes.
            renamed, signature = body, arguments
            for index, value in enumerate(model.allocs):
                token = '%result_storage_' + str(index)
                renamed = re.sub(re.escape(value) + r'(?![-\w.])', token, renamed)
                signature = re.sub(re.escape(value) + r'(?![-\w.])', token, signature)
            h.md5_result_transport.check(*self.md5_check(signature, renamed, names, compiler, case[1])[:2], case[1])
        self.assertGreater(count, 400)
        print(f'MD5 report Result transport: {count} byte/guard/lifetime/escape defects rejected', flush=True)

    def test_compiled_md5_report_transport_defects(self):
        d, h = self.driver, self.driver.hosted
        work = Path(self.directory.name) / 'md5-result-mutants'
        leaf, fixture = prepare(d, work)
        count = 0
        for target, directory in ((d.TARGETS[0], 'strict_execution'), (d.TARGETS[2], 'macos_resident')):
            def emit():
                return d.emit(work / target, '1.99.1', target, 'unwind', True,
                              fixture / 'Cargo.toml', leaf / 'Cargo.toml')
            h.validate(emit(), target, 'unwind')
            path = leaf / 'src' / directory / 'md5_compiled/worker.rs'
            original = path.read_text()
            marker = 'report(actual, &parameters, active)?;'
            offsets = [i for i in range(len(original)) if original.startswith(marker, i)]
            self.assertEqual(len(offsets), 2)
            for at in offsets:
                for edit in ('actual.vector_width = parameters.backend.lane_width();',
                             'actual.backend = parameters.backend;',
                             'actual.inner.active_lanes = active;',
                             'actual.normalization.vector_blocks = 0;',
                             'actual.outer = actual.inner;',
                             'core::mem::swap(&mut actual.inner, &mut actual.outer);'):
                    mutant = original[:at] + 'let mut actual = actual; ' + edit + '\n' + original[at:]
                    try:
                        path.write_text(mutant)
                        artifacts = emit()
                        with self.subTest(target=target, mutation=count), self.assertRaises(ValueError):
                            h.validate(artifacts, target, 'unwind')
                    finally:
                        path.write_text(original)
                    count += 1
            h.validate(emit(), target, 'unwind')
        self.assertEqual(count, 24)
        print('MD5 report transport: 24 compiled Rust defects rejected; restored baselines pass', flush=True)
