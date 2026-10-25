"""Real typed/emitted/compiled MD5 lane provenance regressions."""
from pathlib import Path
import re

from legacy_hmac_hosted_compiled_fixture import prepare


class Md5LaneTests:
    def test_md5_lane_typed_geometry(self):
        h, count = self.driver.hosted, 0
        for case in self.cases:
            population = self.report_population(case[0]['brynja-legacy-hmac-hosted-cleanup'])
            h.md5_lane_layout.validate(population)
            for symbol, (_, body) in population[0].items():
                if '::lane::' not in population[2].get(symbol, ''):
                    continue
                mutants = []
                for line in body.splitlines():
                    if 'getelementptr' in line:
                        mutants.append(body.replace(line, re.sub(r'i64 (\d+)',
                            lambda m: 'i64 ' + str(int(m[1]) + 8), line), 1))
                    elif ' = load ' in line:
                        mutants.append(body.replace(line, re.sub(r'ptr %[-\w.]+', 'ptr %unbound', line), 1))
                    elif 'icmp ne ptr' in line:
                        mutants.append(body.replace(line, line.replace('icmp ne', 'icmp eq'), 1))
                    elif 'icmp eq ptr' in line:
                        mutants.append(body.replace(line, line.replace('icmp eq', 'icmp ne'), 1))
                    elif 'llvm.mem' in line:
                        mutants.append(body.replace(line, line.replace('i64 384', 'i64 336').replace('i64 32', 'i64 24'), 1))
                for mutant in mutants:
                    self.assertNotEqual(mutant, body)
                    altered = dict(case[0])
                    altered['brynja-legacy-hmac-hosted-cleanup'] = altered['brynja-legacy-hmac-hosted-cleanup'].replace(body, mutant, 1)
                    with self.subTest(target=case[1], mutation=count), self.assertRaises(ValueError):
                        h.validate(altered, case[1], case[3])
                    count += 1
        self.assertGreater(count, 90)
        print(f'MD5 typed lane geometry: {count} field/descriptor/niche substitutions rejected', flush=True)

    def test_md5_lane_slots_payloads_and_rejections(self):
        h, count = self.driver.hosted, 0
        for case, arguments, body, names, compiler in self.md5_models():
            def validate(candidate):
                model = h.keyed.check(candidate, names, compiler, 'md5_compiled')
                transfer = h.authority.check(candidate, names, compiler, 'md5_compiled')
                envelope = h.envelope.check(arguments, candidate, names, 'md5_compiled')
                health = h.md5_health.check(model, transfer, envelope, compiler)
                return model, h.md5_lanes.check(model, transfer, envelope, health)
            model, lanes = validate(body)
            self.assertEqual(len(lanes.reads), 8)
            mutants = []
            for block, index in sorted(lanes.points):
                line = model.graph[block][index]
                if ' = getelementptr' in line:
                    mutants.append(body.replace(line, re.sub(r'i64 (\d+)$',
                        lambda m: 'i64 ' + str(int(m[1]) + 8), line), 1))
                elif ' = load ' in line:
                    mutants.append(body.replace(line, re.sub(r'ptr %[-\w.]+', 'ptr %unbound', line), 1))
                elif line.startswith('store '):
                    mutants.append(body.replace(line, re.sub(r'(store (?:ptr|i\d+) )(%[-\w.]+)', r'\g<1>%unbound', line), 1))
                elif line.startswith('br i1 '):
                    for target in re.findall('label %' + h.flow.LABEL, line):
                        mutants.append(body.replace(line, 'br label %' + target, 1))
                elif 'icmp eq ptr' in line:
                    mutants.append(body.replace(line, line.replace('icmp eq', 'icmp ne'), 1))
                call = h.syntax.call(line)
                if call and call[0].startswith('llvm.mem'):
                    for arg in call[1][:2]:
                        if arg.startswith('ptr '):
                            mutants.append(body.replace(line, line.replace(arg, 'ptr %unbound'), 1))
                    mutants.append(body.replace(line, re.sub(r'i64 (\d+), i1 false',
                        lambda m: 'i64 ' + str(int(m[1]) - 1) + ', i1 false', line), 1))
                    mutants.append(body.replace(line, '', 1))
                elif call and call[0].startswith('llvm.lifetime.'):
                    # Whole-array end completeness after use is part of the
                    # separate cleanup review; early/duplicate ends are checked.
                    if not (call[0] == 'llvm.lifetime.end.p0'
                            and h.syntax.operand(call[1][-1]) == lanes.lanes):
                        mutants.append(body.replace(line, '', 1))
                    mutants.append(body.replace(line, line + '\n  ' + line, 1))
                elif call and names.get(call[0]) == h.md5_lanes.BITS:
                    for arg in call[1]:
                        mutants.append(body.replace(line, line.replace(arg, arg.split()[0] + ' %unbound'), 1))
            for index, key, length, message, message_length, bits, site in lanes.reads:
                call = model.graph[site[0]][site[1]]
                mutants.append(body.replace(call, call.replace(message, key), 1))
                mutants.append(body.replace(call, call.replace(message_length, length), 1))
                # Duplicate the preceding slot's message for each later lane.
                if index:
                    mutants.append(body.replace(call, call.replace(message, lanes.reads[index - 1][3]), 1))
            use = model.consumers[0][1]
            line = model.graph[use[0]][use[1]]
            for root in (lanes.lanes, lanes.result, lanes.scratch):
                mutants.append(body.replace(line, 'call void @escape(ptr ' + root + ')\n  ' + line, 1))
            for block in (lanes.start[0], lanes.reads[0][-1][0], lanes.fills[-1]):
                mutants.append(body + '\nextra_reentry:\n  br label %' + block + '\n')
            for mutant in mutants:
                self.assertNotEqual(mutant, body, 'unchanged mutation ' + str(count))
                with self.subTest(target=case[1], compiler=compiler, mutation=count), self.assertRaises(ValueError):
                    validate(mutant)
                count += 1
        self.assertGreater(count, 1500)
        print(f'MD5 lane chain/payloads: {count} slot/byte/lifetime/admission defects rejected', flush=True)

    def test_compiled_md5_lane_defects(self):
        d, h = self.driver, self.driver.hosted
        work = Path(self.directory.name) / 'md5-lane-mutants'
        leaf, fixture = prepare(d, work)
        count = 0
        for target, directory in ((d.TARGETS[0], 'strict_execution'), (d.TARGETS[2], 'macos_resident')):
            def emit():
                return d.emit(work / target, '1.99.1', target, 'unwind', True,
                              fixture / 'Cargo.toml', leaf / 'Cargo.toml')
            h.validate(emit(), target, 'unwind')
            path = leaf / 'src' / directory / 'md5_compiled/worker.rs'
            original = path.read_text()
            edits = (
                ('lanes.iter_mut().zip(inputs)', 'lanes.iter_mut().zip(inputs).take(7)'),
                ('lanes.iter_mut().zip(inputs)', 'lanes.iter_mut().zip(inputs).skip(1)'),
                ('lanes.iter_mut().zip(inputs)', 'lanes.iter_mut().zip(inputs.iter().rev())'),
                ('input.key,', 'input.message.bytes,'),
                ('BitString::new(input.message.bytes, input.message.valid_bits)', 'BitString::new(input.key, input.message.valid_bits)'),
                ('input.message.valid_bits)', '8)'),
                ('Error::InvalidBits', 'Error::Invariant'),
                ('if let Some(input) = input {', 'if let Some(input) = input.filter(|v| !v.key.is_empty()) {'),
            )
            for before, after in edits:
                self.assertIn(before, original)
                # Borrowed Option filtering needs as_ref(), without copying an input.
                after = after.replace('input.filter(', 'input.as_ref().filter(')
                try:
                    path.write_text(original.replace(before, after, 1))
                    artifacts = emit()
                    with self.subTest(target=target, mutation=count), self.assertRaises(ValueError):
                        h.validate(artifacts, target, 'unwind')
                finally:
                    path.write_text(original)
                count += 1
            h.validate(emit(), target, 'unwind')
        self.assertEqual(count, 16)
        print('MD5 lanes: 16 compiled Rust defects rejected; restored baselines pass', flush=True)
