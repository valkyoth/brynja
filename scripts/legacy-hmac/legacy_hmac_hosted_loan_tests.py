"""Ordinary legacy output construction and method regressions."""
import difflib
from pathlib import Path
import re

from legacy_hmac_hosted_compiled_fixture import prepare


class LoanTests:
    def loan_rows(self):
        h = self.driver.hosted
        for case in self.cases:
            llvm = case[0]['brynja-legacy-hmac-hosted-cleanup']
            definitions, aliases = h.flow.definitions_and_aliases(llvm)
            names = h.model.demangle({n.strip('"') for n in re.findall(r'@("[^"]+"|[-\w.$]+)', llvm)})
            compiler = re.findall(r'!"rustc version ([\d.]+) ', llvm)[0]
            for identity in ('sha1', 'md5', 'sha1_compiled'):
                for operation in h.loans.METHODS:
                    wanted = 'brynja_legacy_hmac_hosted_cleanup::' + identity + '::' + operation
                    selected, = [s for s in (*definitions, *aliases) if names.get(s) == wanted]
                    signature, body = h.flow.resolve(selected, definitions, aliases)
                    yield case, compiler, identity, operation, signature, body, names

    def test_ordinary_loan_methods(self):
        h, count, scenarios, population = self.driver.hosted, 0, 0, 0
        for case, compiler, identity, operation, signature, body, names in self.loan_rows():
            def check(text):
                return h.loans.method(signature, text, names, case[1], compiler, case[3], identity, operation)
            reached, total = check(body)
            h.loans.method(signature.replace('%output', '%borrowed_output'),
                           body.replace('%output', '%borrowed_output'), names,
                           case[1], compiler, case[3], identity, operation)
            scenarios += total
            population += 1
            mutants = set()
            graph = h.flow.blocks(body)
            for block in reached:
                for line in graph[block]:
                    call = h.syntax.call(line)
                    if '= getelementptr' in line:
                        mutants.add(body.replace(line, re.sub(r'i64 (-?\d+)', lambda m: 'i64 ' + str(int(m[1]) + 1), line), 1))
                    if '= icmp eq ' in line:
                        mutants.add(body.replace(line, line.replace('icmp eq ', 'icmp ne '), 1))
                    if call and (names.get(call[0], '').endswith(('>::clear', '>::as_bytes'))
                                 or call[0] == 'llvm.memcpy.p0.p0.i64'):
                        mutants.add(body.replace(line, line.replace('@' + call[0], '@unreviewed_loan_call'), 1))
                        for arg in call[1]:
                            if arg.startswith('ptr '):
                                mutants.add(body.replace(line, line.replace(arg, 'ptr %unrelated'), 1))
                        if call[0] == 'llvm.memcpy.p0.p0.i64':
                            mutants.add(body.replace(line, line.replace(call[1][2], 'i64 0'), 1))
                        if 'invoke ' not in line:
                            mutants.add(body.replace(line, '', 1))
                    if line.startswith('ret ') and line != 'ret void':
                        mutants.add(body.replace(line, 'ret void', 1))
            first = next(iter(graph)) + ':'
            mutants.add(body.replace(first, first + '\n  call void @unexpected_effect()', 1))
            mutants.discard(body)
            for mutant in sorted(mutants):
                delta = '\n'.join(difflib.unified_diff(body.splitlines(), mutant.splitlines(), n=1))
                with self.subTest(target=case[1], identity=identity, method=operation, mutant=count, delta=delta), self.assertRaises(ValueError):
                    check(mutant)
                count += 1
        self.assertEqual(population, 54)
        self.assertGreater(count, 300)
        print(f'Ordinary legacy output loans: {population} methods, {scenarios} outcomes, {count} mutations rejected', flush=True)

    def test_ordinary_loan_factories(self):
        h, count, scenarios, population = self.driver.hosted, 0, 0, 0
        for case, identity, _, package, _ in self.hosts():
            if identity == 'md5_compiled':
                continue
            compiler = re.findall(r'!"rustc version ([\d.]+) ', case[0]['brynja-legacy-hmac-std'])[0]
            definitions, aliases, names = package
            executor = names[case[2][identity][0]]
            wanted = (executor.removesuffix('execute') + 'compute' if identity.endswith('_compiled') else
                      'brynja_legacy_hmac_hosted_cleanup::' + identity + '::compute')
            selected, = [s for s in (*definitions, *aliases) if names.get(s) == wanted]
            signature, body = h.flow.resolve(selected, definitions, aliases)
            def check(text):
                return h.loans.creation(signature, text, names, case[1], compiler, identity, executor)
            scenarios += check(body)
            population += 1
            mutants = set()
            for line in body.splitlines():
                if '= getelementptr' in line:
                    mutants.add(body.replace(line, re.sub(r'i64 (\d+)', lambda m: 'i64 ' + str(int(m[1]) + 1), line), 1))
                if line.strip().startswith('store '):
                    mutants.add(body.replace(line, '', 1))
                if '= icmp eq ' in line:
                    mutants.add(body.replace(line, line.replace('icmp eq ', 'icmp ne '), 1))
                call = h.syntax.call(line)
                if call and names.get(call[0]) == executor:
                    for arg in call[1]:
                        if arg.startswith('ptr '):
                            mutants.add(body.replace(line, line.replace(arg, 'ptr %different_owner'), 1))
            for mutant in sorted(mutants):
                self.assertNotEqual(mutant, body)
                with self.subTest(target=case[1], identity=identity, mutant=count), self.assertRaises(ValueError):
                    check(mutant)
                count += 1
        self.assertEqual(population, 18)
        print(f'Ordinary legacy loan factories: {population} profiles, {scenarios} outcomes, {count} mutations rejected', flush=True)

    def test_ordinary_loan_probe_population(self):
        h = self.driver.hosted
        for case in self.cases:
            llvm = case[0]['brynja-legacy-hmac-hosted-cleanup']
            definitions, aliases = h.flow.definitions_and_aliases(llvm)
            names = h.model.demangle({n.strip('"') for n in re.findall(r'@("[^"]+"|[-\w.$]+)', llvm)})
            compiler = re.findall(r'!"rustc version ([\d.]+) ', llvm)[0]
            symbol = next(s for s in (*definitions, *aliases)
                          if names.get(s) == 'brynja_legacy_hmac_hosted_cleanup::sha1::output_clear')
            with self.assertRaises(ValueError):
                h.loans.validate((definitions, aliases, {**names, symbol: 'unreviewed_probe'}), case[1], compiler, case[3])
            with self.assertRaises(ValueError):
                h.loans.validate((definitions, {**aliases, 'extra_probe': symbol},
                                  {**names, 'extra_probe': names[symbol]}), case[1], compiler, case[3])

    def test_compiled_ordinary_loan_defects(self):
        d, h = self.driver, self.driver.hosted
        work = Path(self.directory.name) / 'ordinary-loan-mutants'
        leaf, fixture = prepare(d, work)
        count = 0
        for target, directory in ((d.TARGETS[0], 'strict_execution'), (d.TARGETS[2], 'macos_resident')):
            def emit():
                return d.emit(work / target, '1.99.1', target, 'unwind', True,
                              fixture / 'Cargo.toml', leaf / 'Cargo.toml')
            edits = [('mod.rs', 'storage: &mut self.output,', 'storage: &mut self.staging,'),
                     ('mod.rs', 'self.storage.clear();', 'let _ = self.storage.as_bytes();'),
                     ('mod.rs', 'self.storage.as_bytes()\n', '&self.storage.as_bytes()[..1]\n'),
                     ('mod.rs', 'output.copy_from_slice(self.expose());', 'output.fill(0);'),
                     ('mod.rs', 'output.copy_from_slice(self.expose());',
                      'output.copy_from_slice(self.expose()); core::mem::forget(self);'),
                     ('sha1_compiled.rs', 'storage: &mut self.inner.output,', 'storage: &mut self.inner.staging,')]
            for file, before, after in edits:
                path = leaf / 'src' / directory / file
                original = path.read_text()
                self.assertEqual(original.count(before), 1)
                try:
                    path.write_text(original.replace(before, after, 1))
                    artifacts = emit()
                    with self.subTest(target=target, mutation=count), self.assertRaises(ValueError):
                        h.validate(artifacts, target, 'unwind')
                finally:
                    path.write_text(original)
                count += 1
            h.validate(emit(), target, 'unwind')
        self.assertEqual(count, 12)
        print('Ordinary legacy loans: 12 compiled defects rejected; restored baselines pass', flush=True)
