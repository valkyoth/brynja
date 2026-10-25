"""Public decision/payload conversion and compiled forwarding regressions."""
from pathlib import Path
import re

from legacy_hmac_hosted_compiled_fixture import prepare
from legacy_hmac_hosted_prearm_tests import replace_point


class VerifyTests:
    def verification_rows(self):
        h = self.driver.hosted
        for case in self.cases:
            fixture, leaf, compiler = self.batch_populations(case)
            for identity, (symbol, _, population, _) in case[2].items():
                executor = population[2][symbol]
                name = 'brynja_legacy_hmac_hosted_cleanup::' + identity + '::verify'
                args, body = h.batch_loans.selected(fixture, name)
                if identity.endswith('_compiled'):
                    public = executor.removesuffix('execute') + 'verify'
                    yield case, compiler, identity, args, body, fixture[2], public, True
                    args, body = h.batch_loans.selected(leaf, public)
                yield case, compiler, identity, args, body, leaf[2] if identity.endswith('_compiled') else fixture[2], executor, False

    def test_public_verification_results(self):
        h, profiles, outcomes, rejected = self.driver.hosted, 0, 0, 0
        for case, compiler, identity, args, body, names, executor, forward in self.verification_rows():
            def check(text):
                return h.verification.check(args, text, names, case[1], compiler, identity, executor, forward)
            outcomes += check(body)
            profiles += 1
            mutants = set()
            for block, lines in h.flow.blocks(body).items():
                for index, line in enumerate(lines):
                    changes = []
                    if line.startswith('ret i16 '):
                        changes += ['ret i16 0', 'ret i16 511', 'ret i16 8']
                    if 'icmp eq ' in line:
                        changes.append(line.replace('icmp eq ', 'icmp ne '))
                    if 'icmp ne ' in line:
                        changes.append(line.replace('icmp ne ', 'icmp eq '))
                    if call := h.syntax.call(line):
                        if names.get(call[0]) == executor:
                            changes.append(line.replace('@' + call[0], '@wrong_verifier'))
                            changes.append(line.replace(call[1][0], 'ptr %wrong_session', 1))
                    for changed in changes:
                        if changed != line:
                            mutants.add(replace_point(body, block, index, line, changed))
            for mutant in mutants:
                with self.subTest(identity=identity, target=case[1], forwarded=forward), self.assertRaises(ValueError):
                    check(mutant)
                rejected += 1
        self.assertEqual(profiles, 36)
        self.assertGreater(outcomes, 70000)
        print(f'Public verification: {profiles} profiles, {outcomes} outcomes, {rejected} result/dispatch mutations rejected', flush=True)

    def test_public_verification_typed_and_padding(self):
        h, rejected = self.driver.hosted, 0
        for case in self.cases:
            fixture, _, compiler = self.batch_populations(case)
            definitions, aliases, names = fixture
            h.verification.typed(fixture, compiler)
            for name in ('accepted_tag', 'rejected_tag', 'invalid_result'):
                symbol = next(s for s in (*definitions, *aliases)
                              if names.get(s) == 'brynja_legacy_hmac_hosted_cleanup::verification::' + name)
                with self.assertRaises(ValueError):
                    h.verification.typed((definitions, aliases, {**names, symbol: 'missing'}), compiler)
                args, body = h.flow.resolve(symbol, definitions, aliases)
                root = symbol
                while root in aliases:
                    root = aliases[root]
                changed = re.sub(r'ret i16 \d+', 'ret i16 9', body)
                with self.assertRaises(ValueError):
                    h.verification.typed(({**definitions, root: (args, changed)}, aliases, names), compiler)
                rejected += 2
        case, compiler, identity, args, _, names, executor, _ = next(self.verification_rows())
        symbol = next(s for s, name in names.items() if name == executor)
        parameters = h.syntax.parameters(args)
        operands = ', '.join(arg.split()[0] + ' ' + arg.split()[-1] for arg in parameters)
        good = f'entry:\n %provided = call i16 @{symbol}({operands})\n ret i16 %provided'
        h.verification.check(args, good, names, case[1], compiler, identity, executor, True)
        ok = 255 if compiler == '1.99.1' else 10
        bad = good.replace('ret i16 %provided', f'%bad = icmp eq i16 %provided, {3 | (255 << 8)}\n'
                           f' %answer = select i1 %bad, i16 {ok | 256}, i16 %provided\n ret i16 %answer')
        with self.assertRaises(ValueError):
            h.verification.check(args, bad, names, case[1], compiler, identity, executor, True)
        print(f'Public verification ABI: {rejected} typed-probe mutations and unit-padding decision corruption rejected', flush=True)

    def test_compiled_public_verification_defects(self):
        d, h = self.driver, self.driver.hosted
        work = Path(self.directory.name) / 'public-verification-mutants'
        leaf, fixture = prepare(d, work)
        count = 0
        for target, directory in ((d.TARGETS[0], 'strict_execution'), (d.TARGETS[2], 'macos_resident')):
            def emit():
                return d.emit(work / target, '1.99.1', target, 'unwind', True,
                              fixture / 'Cargo.toml', leaf / 'Cargo.toml')
            for file in ('mod.rs', 'sha1_compiled.rs', 'md5_compiled.rs'):
                path = leaf / 'src' / directory / file
                original = path.read_text()
                before = '.ok_or(Error::Invariant)'
                self.assertIn(before, original)
                try:
                    path.write_text(original.replace(before, '.map(|_| true).ok_or(Error::Invariant)', 1))
                    artifacts = emit()
                    with self.assertRaises(ValueError):
                        h.validate(artifacts, target, 'unwind')
                finally:
                    path.write_text(original)
                count += 1
            h.validate(emit(), target, 'unwind')
        print(f'Public verification: {count} compiled forced-true defects rejected; restored baselines pass', flush=True)
