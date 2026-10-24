#!/usr/bin/env python3
"""Regressions against real emitted caller bodies and independent ABI probes."""
import importlib.util
from pathlib import Path
import re
import unittest

spec = importlib.util.spec_from_file_location('driver', Path(__file__).with_name('check-legacy-hmac-md5-cleanup.py'))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
i, c = driver.initialization, driver.candidates


class Callers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = driver.runner.cargo_environment.private_directory(driver.ROOT)
        cls.addClassCleanup(cls.directory.cleanup)
        cls.cases = []
        for compiler, target, panic, simd in (
                ('1.90.0', 'x86_64-unknown-linux-gnu', 'unwind', True),
                ('1.90.0', 'x86_64-unknown-linux-gnu', 'abort', False),
                ('1.99.1', 'x86_64-unknown-linux-gnu', 'unwind', True),
                ('1.99.1', 'x86_64-unknown-linux-gnu', 'abort', False),
                ('1.99.1', 'aarch64-unknown-linux-gnu', 'abort', False),
                ('1.99.1', 'aarch64-apple-darwin', 'unwind', True)):
            artifacts = driver.emit(Path(cls.directory.name) / (compiler + target + panic), compiler, target, panic, simd)
            fixture, llvm = artifacts[0][1], artifacts[1][1]
            init = i.validate(fixture, llvm)
            candidate = c.validate(fixture, llvm)
            cls.cases.append((fixture, llvm, init, candidate))

    def rejects(self, check, before, after):
        self.assertIn(before, check.body)
        self.assertNotEqual(before, after)
        signature = check.signature if hasattr(check, 'signature') else self.signature
        with self.subTest(before=before, after=after), self.assertRaises(ValueError):
            type(check)(signature, check.body.replace(before, after, 1)).run()

    def initializations(self):
        for _, llvm, check, _ in self.cases:
            definitions, aliases = i.flow.definitions_and_aliases(llvm)
            self.signature = i.r.phases.rows.method(definitions, aliases, 'authenticate_secret')[1][0]
            yield check

    def test_begin_destination_extent_and_discriminant(self):
        for check in self.initializations():
            label, index, _, _ = check.begin
            begin = check.graph[label][index]
            self.rejects(check, begin, begin.replace('i64 noundef 128', 'i64 noundef 127'))
            self.rejects(check, begin, begin.replace(check.destination + ',', check.result + ','))
            self.rejects(check, begin, 'call void @unreviewed()\n' + begin)
            guard = check.graph[label][index + 2]
            self.rejects(check, guard, re.sub(r'i8 %[-\w.]+', 'i8 0', guard))

    def test_every_move_must_preserve_full_exclusive_owner(self):
        for check in self.initializations():
            for (label, index), (source, dest) in check.moves.items():
                line = check.graph[label][index]
                self.rejects(check, line, line.replace('i64 24,', 'i64 23,'))
                self.rejects(check, line, '')
                self.rejects(check, line, line + '\n' + line)
                args = i.syntax.call(line)[1]
                self.rejects(check, line, line.replace(args[1], args[0]))

    def test_early_expiry_and_alias_escape_reject(self):
        for check in self.initializations():
            first = next(site for site, (source, _) in check.moves.items() if source == (check.result, 8))
            line = check.graph[first[0]][first[1]]
            self.rejects(check, line, 'call void @llvm.lifetime.end.p0(i64 32, ptr ' + check.result + ')\n' + line)
            self.rejects(check, line, line + '\ncall void @unreviewed(ptr ' + check.owner + ')')
            self.rejects(check, line, line + '\nstore i8 0, ptr ' + check.owner + ', align 1')

    def test_each_normal_and_unwind_drop_is_required(self):
        for check in self.initializations():
            for (label, index), (effect, _) in check.effects.items():
                if effect != 'drop':
                    continue
                line = check.graph[label][index]
                self.rejects(check, line, line.replace(check.owner + ')', check.result + ')'))
                if 'invoke ' in line:
                    continuation = check.graph[label][index + 1]
                    target = re.search('to label %' + i.flow.LABEL, continuation)[1]
                    original = re.search(re.escape(line) + r'\s+' + re.escape(continuation), check.body)[0]
                    self.rejects(check, original, 'br label %' + target)
                else:
                    self.rejects(check, line, '')

    def test_drop_flag_reversal_is_detected(self):
        for check in self.initializations():
            drops = {site[0] for site, (effect, _) in check.effects.items() if effect == 'drop'}
            count = 0
            for label, lines in check.graph.items():
                branch = re.fullmatch(rf'br i1 ({i.VALUE}), label %{i.flow.LABEL}, label %{i.flow.LABEL}', lines[-1])
                if branch and branch[1] in check.flags and branch[2] in drops and branch[2] not in (
                        i.r.phases.handoff.reachable(check.graph, branch[3])):
                    changed = f'br i1 {branch[1]}, label %{branch[3]}, label %{branch[2]}'
                    self.rejects(check, lines[-1], changed)
                    count += 1
            self.assertGreater(count, 0)

    def test_all_eight_lane_checks_are_load_bearing(self):
        for _, _, _, check in self.cases:
            lengths = [line.strip() for line in check.body.splitlines() if 'icmp eq i64 %_26.1' in line]
            self.assertEqual(len(lengths), 8)
            for line in lengths:
                self.rejects(check, line, line.replace('icmp eq', 'icmp ne'))
                lhs = re.search(r'icmp eq i64 (%[-\w.]+),', line)[1]
                self.rejects(check, line, line.replace(lhs + ',', '%_21,'))
            input_checks = [line.strip() for line in check.body.splitlines() if re.match(r'\s*%\.not1(?:\.[0-7])? = icmp eq ptr', line)]
            self.assertEqual(len(input_checks), 8)
            for line in input_checks:
                self.rejects(check, line, line.replace('icmp eq', 'icmp ne'))

    def test_missing_candidate_and_extra_candidate_are_rejected(self):
        for _, _, _, check in self.cases:
            candidates = [line.strip() for line in check.body.splitlines() if re.match(r'\s*%\.not2(?:\.[0-7])? = icmp ne ptr', line)]
            self.assertEqual(len(candidates), 8)
            for line in candidates:
                self.rejects(check, line, line.replace('icmp ne', 'icmp eq'))
            selects = [line.strip() for line in check.body.splitlines() if 'select i1 %.not2' in line]
            self.assertEqual(len(selects), 8)
            for line in selects:
                self.rejects(check, line, line.replace('i1 false', 'i1 true'))

    def test_preflight_cannot_read_payload_or_invoke_callbacks(self):
        for _, _, _, check in self.cases:
            first = next(line.strip() for line in check.body.splitlines() if f'load ptr, ptr {check.inputs},' in line)
            result = re.match(r'(%[-\w.]+) =', first)[1]
            self.rejects(check, first, first + '\n%payload = load i64, ptr ' + result + ', align 8')
            self.rejects(check, first, first + '\ncall void @unreviewed(ptr ' + check.control + ')')
            self.rejects(check, 'store i8 1, ptr ' + check.output + ', align 8',
                         'store i8 0, ptr ' + check.output + ', align 8')

    def test_independent_abi_probes_detect_layout_changes(self):
        for fixture, _, _, _ in self.cases:
            definitions, aliases = i.flow.definitions_and_aliases(fixture)
            for name, validator in (('candidate_pair', c.probes), ('verify_tag_error', c.probes),
                                     ('initialization_success', i.probes), ('initialization_error', i.probes)):
                body = i.r.n.pads.descriptors.admission.probe(definitions, aliases, name)
                store = next(line for line in body.splitlines() if 'store ' in line or 'llvm.memcpy.' in line)
                changed = body.replace(store, '', 1)
                with self.subTest(probe=name), self.assertRaises(ValueError):
                    validator(fixture.replace(body, changed))

    def test_boolean_engine_against_independent_truth_tables(self):
        bdd = c.Decisions()
        for order in ((0, 1, 2), (0, 3, 23), (23, 5, 0)):
            a, b, d = [bdd.variable(v) for v in order]
            formulas = [(bdd.conjunction(a, b), lambda x: x[0] and x[1]),
                        (bdd.disjunction(a, b), lambda x: x[0] or x[1]),
                        (bdd.negate(a), lambda x: not x[0]),
                        (bdd.disjunction(bdd.conjunction(bdd.negate(a), bdd.negate(b)),
                                         bdd.conjunction(a, bdd.conjunction(b, d))),
                         lambda x: (not x[0] and not x[1]) or (x[0] and x[1] and x[2]))]
            for bits in range(8):
                assignment = [bool(bits & (1 << j)) for j in range(3)]
                mapping = dict(zip(order, assignment))
                for node, reference in formulas:
                    while node >= 2:
                        var, low, high = bdd.nodes[node]
                        node = high if mapping[var] else low
                    self.assertEqual(bool(node), reference(assignment))
        bdd.negate.cache_clear(); bdd.conjunction.cache_clear()


if __name__ == '__main__':
    unittest.main()
