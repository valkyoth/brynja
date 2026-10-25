"""Actual host CFG admission/clear/quarantine defects, plus Rust mutations."""
import difflib
from pathlib import Path
import re

from legacy_hmac_hosted_compiled_fixture import prepare


class TransactionTests:
    def transaction_model(self, signature, body, names, target, identity, compiler):
        h = self.driver.hosted
        record = h.capture.check(signature, body, names, target, identity)
        return h.transaction.check(record, compiler, *h.profile(target))

    def test_host_output_quarantine_transactions(self):
        h, total, count, population = self.driver.hosted, 0, 0, 0
        for case, identity, _, package, body in self.hosts():
            symbol = case[2][identity][0]
            signature, _ = h.flow.resolve(symbol, *package[:2])
            compiler = re.findall(r'!"rustc version ([\d.]+) ', case[0]['brynja-legacy-hmac-std'])[0]
            model = self.transaction_model(signature, body, package[2], case[1], identity, compiler)
            total += model.scenarios
            population += 1
            mutants = set()
            for point in model.points | set(model.initial):
                line = model.r.graph[point[0]][point[1]]
                call = h.syntax.call(line)
                if call and package[2].get(call[0]) in (model.clear, model.drop):
                    mutants.add(body.replace(line, line.replace('@' + call[0], '@missing_clear'), 1))
                    mutants.add(body.replace(line, line.replace(call[1][0], 'ptr %wrong_buffer'), 1))
                    if 'invoke ' not in line:
                        mutants.add(body.replace(line, line + '\n  ' + line, 1))
                if line.startswith('store i8 '):
                    for val in (0, 1):
                        mutants.add(body.replace(line, re.sub(r'store i8 [^,]+', 'store i8 ' + str(val), line), 1))
                if ' = load atomic i8' in line:
                    mutants.add(body.replace(line, line.replace('%cancel', '%wrong_cancel'), 1))
                    mutants.add(body.replace(line, line.replace(' acquire,', ' monotonic,'), 1))
                if ' = icmp ' in line:
                    if 'icmp eq ' in line:
                        mutants.add(body.replace(line, line.replace('icmp eq ', 'icmp ne '), 1))
                    elif 'icmp ne ' in line:
                        mutants.add(body.replace(line, line.replace('icmp ne ', 'icmp eq '), 1))
                if line.startswith('ret i16 '):
                    mutants.add(body.replace(line, 'ret i16 ' + str(model.ok + 512), 1))
            for point, val in model.quarantine:
                line = model.r.graph[point[0]][point[1]]
                mutants.add(body.replace(line, line.replace('store i8 ' + val, 'store i8 ' + str(1 - int(val))), 1))
            mutants.discard(body)
            for mutant in sorted(mutants):
                delta = '\n'.join(difflib.unified_diff(body.splitlines(), mutant.splitlines(), n=1))
                with self.subTest(identity=identity, target=case[1], mutation=count, delta=delta), self.assertRaises(ValueError):
                    self.transaction_model(signature, mutant, package[2], case[1], identity, compiler)
                count += 1
            comparison = re.search(r'(%[-\w.]+) = icmp ne i8 [^\n]+, 2', body)
            if comparison:
                renamed = re.sub(re.escape(comparison[1]) + r'(?![-\w.])', '%transaction_predicate', body)
                self.transaction_model(signature, renamed, package[2], case[1], identity, compiler)
        self.assertEqual(population, 24)
        self.assertGreater(total, 3000)
        self.assertGreater(count, 250)
        print(f'Legacy host transactions: {population} profiles, {total} outcomes, {count} mutations rejected', flush=True)

    def test_compiled_host_transaction_defects(self):
        d, h = self.driver, self.driver.hosted
        work = Path(self.directory.name) / 'host-transaction-mutants'
        leaf, fixture = prepare(d, work)
        count = 0
        for target, directory in ((d.TARGETS[0], 'strict_execution'), (d.TARGETS[2], 'macos_resident')):
            def emit():
                return d.emit(work / target, '1.99.1', target, 'unwind', True,
                              fixture / 'Cargo.toml', leaf / 'Cargo.toml')
            for file in ('mod.rs', 'sha1_compiled.rs', 'md5_compiled.rs'):
                path = leaf / 'src' / directory / file
                original = path.read_text()
                keep = ('buffers.keep = !verifying;' if file == 'mod.rs' else
                        'guard.keep = !verifying;' if file == 'sha1_compiled.rs' else
                        'guard.keep = candidates.is_none();')
                edits = [(keep, keep.split('=')[0] + '= true;'),
                         ('self.inner.output.clear();' if file == 'sha1_compiled.rs' else 'self.output.clear();',
                          '/* defective forgotten-loan clearing */')]
                if file != 'mod.rs':
                    edits.append(('self.quarantined = true;', 'self.quarantined = false;'))
                    edits.append(('return Err(Error::Invariant);',
                                  'self.quarantined = false; return Err(Error::Invariant);'))
                for before, after in edits:
                    self.assertIn(before, original)
                    try:
                        path.write_text(original.replace(before, after))
                        artifacts = emit()
                        with self.subTest(target=target, file=file, mutation=count), self.assertRaises(ValueError):
                            h.validate(artifacts, target, 'unwind')
                    finally:
                        path.write_text(original)
                    count += 1
            h.validate(emit(), target, 'unwind')
        self.assertEqual(count, 20)
        print('Legacy host transactions: 20 compiled defects rejected; restored baselines pass', flush=True)
