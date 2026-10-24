#!/usr/bin/env python3
"""Actual compiled outer-result, truncation and returned-counter regressions."""
import importlib.util
from pathlib import Path
import re
import unittest

spec = importlib.util.spec_from_file_location('driver', Path(__file__).with_name('check-legacy-hmac-md5-cleanup.py'))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
outer, truncation, returned = driver.outer_result, driver.truncation, driver.report_return
flow, syntax, phases = outer.flow, outer.syntax, outer.phases


class OutputPath(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = driver.runner.cargo_environment.private_directory(driver.ROOT)
        cls.addClassCleanup(cls.directory.cleanup)
        cls.cases, cls.fixtures = [], []
        for compiler, target, panic, simd in (('1.90.0', 'x86_64-unknown-linux-gnu', 'unwind', True),
                                              ('1.99.1', 'x86_64-unknown-linux-gnu', 'unwind', True),
                                              ('1.99.1', 'aarch64-unknown-linux-gnu', 'unwind', True),
                                              ('1.99.1', 'x86_64-unknown-linux-gnu', 'abort', False)):
            artifacts = driver.emit(Path(cls.directory.name) / (compiler + target + panic), compiler, target, panic, simd)
            fixture, llvm = artifacts[0][1], artifacts[1][1]
            cls.fixtures.append(fixture)
            tags, offsets = outer.layouts(fixture), returned.layout.validate(fixture)
            copy_ok = outer.n.pads.probes(fixture)
            definitions, aliases = flow.definitions_and_aliases(llvm)
            for operation in ('authenticate', 'authenticate_secret', 'verify'):
                signature, body = phases.rows.method(definitions, aliases, operation)[1]
                report = outer.Check(signature, body, llvm)
                rows = truncation.Check(signature, body, llvm, copy_ok)
                for backend in (0, 1):
                    report.run_report(255, backend)
                    report.run_report(15, backend)
                rows.run(255, 10); rows.run(255, 16); rows.run(0, 16)
                for lane in range(8):
                    rows.run(255, 10, lane)
                for tag in tags:
                    report.error(tag, None)
                cls.cases.append((signature, body, llvm, report, rows, offsets[operation]))

    def mutate(self, case, before, after, kind='outer', failure=None):
        signature, body, llvm, _, rows, base = case
        self.assertIn(before, body)
        self.assertNotEqual(before, after)
        changed = body.replace(before, after, 1)
        llvm = llvm.replace(body, changed, 1)
        with self.subTest(before=before, after=after), self.assertRaises(ValueError):
            if kind == 'truncation':
                check = truncation.Check(signature, changed, llvm, rows.copy_ok)
                for mask in (0, 1, 15, 240, 255):
                    if failure is not None and not mask & (1 << failure):
                        continue  # A failure can only be injected into an executed copy.
                    for count in (10, 16):
                        check.run(mask, count, failure)
            elif kind == 'return':
                for part, cls in (('inner', driver.inner_report.Check), ('outer', outer.Check)):
                    check = cls(signature, changed, llvm)
                    fields, _ = returned.fields(check, base, part)
                    for backend in (0, 1):
                        for mask in (0, 15, 240, 255):
                            returned.transported(check, fields, mask, backend)
            else:
                check = outer.Check(signature, changed, llvm)
                for backend in (0, 1):
                    for mask in (0, 15, 240, 255):
                        check.run_report(mask, backend)
                        check.run_report(mask, backend, width=0)
                        check.run_report(mask, backend, active=9)
                        check.run_report(mask, backend, vector=0)
                        check.run_report(mask, backend, reported_backend=1 - backend)

    def lines(self, check):
        return [check.graph[label][index] for label, index in sorted(check.visited)]

    def test_outer_owner_pointer_length_and_report_predicates(self):
        for case in self.cases:
            check = case[3]
            pointers = syntax.pointers(check.body, (check.owner,))
            for line in self.lines(check):
                store = re.fullmatch(r'store (ptr|i64) (%[-\w.]+), ptr (%[-\w.]+), align 8(?:, !.*)?', line)
                if store and pointers.get(store[3], (None,))[0] == check.owner:
                    self.mutate(case, line, line.replace(store[1] + ' ' + store[2] + ',', store[1] + (' null,' if store[1] == 'ptr' else ' 0,')))
                if ' = icmp ' in line:
                    self.mutate(case, line, re.sub(r'icmp (eq|ne|uge)', lambda m:
                                'icmp ' + {'eq': 'ne', 'ne': 'eq', 'uge': 'ugt'}[m[1]], line))

    def test_outer_lifetime_unknown_effect_and_unwind(self):
        for case in self.cases:
            check = case[3]
            line = next(line for line in self.lines(check) if 'br i1' in line and 'label %' + check.stop in line)
            for extra in (f'call void @llvm.lifetime.end.p0(i64 16, ptr {check.owner})',
                          'call void @unreviewed()'):
                self.mutate(case, line, extra + '\n' + line)
            if 'invoke ' in check.graph[check.site[0]][check.site[1]]:
                edge = check.graph[check.site[0]][check.site[1] + 1]
                unwind = re.search(r'unwind label %([-\w.]+)', edge)[1]
                self.mutate(case, edge, edge.replace('unwind label %' + unwind, 'unwind label %' + check.stop))

    def test_truncation_copy_source_destination_count_and_lane(self):
        for case in self.cases:
            check = case[4]
            lines = self.lines(check)
            line = next(line for line in lines if (c := syntax.call(line)) and phases.handoff.copy_region(c[0]))
            name, args = syntax.call(line)
            for index, replacement in ((0, check.owner), (2, check.truncated)):
                self.mutate(case, line, line.replace(syntax.operand(args[index]), replacement), 'truncation')
            self.mutate(case, line, line.replace(args[1], 'i64 noundef 9'), 'truncation')
            self.mutate(case, line, line.replace(name, name + '_fake'), 'truncation')
            geps = [line for line in lines if 'getelementptr' in line and '[16 x i8]' in line]
            self.assertGreaterEqual(len(geps), 2)
            for gep in geps:
                self.mutate(case, gep, re.sub(r'i64 %[-\w.]+$', 'i64 0', gep), 'truncation')

    def test_truncation_zero_tail_activity_and_failure(self):
        for case in self.cases:
            check = case[4]
            lines = self.lines(check)
            memset = next(line for line in lines if '@llvm.memset.' in line)
            self.mutate(case, memset, memset.replace('i64 128', 'i64 127'), 'truncation')
            activity = next(line for line in lines if 'icmp eq ptr' in line)
            self.mutate(case, activity, activity.replace('icmp eq ptr', 'icmp ne ptr'), 'truncation')
            copy = next(line for line in lines if (c := syntax.call(line)) and phases.handoff.copy_region(c[0]))
            result = copy.split(' = ')[0]
            compare = next(line for line in lines if f'icmp eq i8 {result},' in line)
            self.mutate(case, compare, compare.replace('icmp eq', 'icmp ne'), 'truncation', failure=0)

    def test_truncation_unwind_and_expired_storage(self):
        for case in self.cases:
            check = case[4]
            call = phases.one(check.body, lambda name, args: phases.handoff.copy_region(name) and
                              syntax.operand(args[0]) != syntax.operand(syntax.parameters(case[0])[3]), 'truncation copy')
            if 'invoke ' in check.graph[call[0]][call[1]]:
                edge = check.graph[call[0]][call[1] + 1]
                unwind = re.search(r'unwind label %([-\w.]+)', edge)[1]
                self.mutate(case, edge, edge.replace('unwind label %' + unwind, 'unwind label %' + check.stop[0]), 'truncation')
            self.mutate(case, check.graph[call[0]][call[1]],
                        f'call void @llvm.lifetime.end.p0(i64 128, ptr {check.truncated})\n' + check.graph[call[0]][call[1]], 'truncation')

    def test_return_counter_constants_swaps_and_overwrites(self):
        for case in self.cases:
            first = driver.inner_report.Check(*case[:3])
            inner_fields, _ = returned.fields(first, case[5], 'inner')
            for part, cls in (('inner', driver.inner_report.Check), ('outer', outer.Check)):
                check = cls(*case[:3])
                _, sites = returned.fields(check, case[5], part)
                for label, index in sites:
                    line = check.graph[label][index]
                    changed = re.sub(r'(store (?:i64|<2 x i64>)) %[-\w.]+,', r'\1 zeroinitializer,', line)
                    self.mutate(case, line, changed, 'return')
                    self.mutate(case, line, line + '\n' + line, 'return')
                    if part == 'outer':
                        fields, _ = returned.fields(check, case[5], part)
                        for offset, (dtype, name) in fields.items():
                            if offset and dtype == inner_fields[offset][0] and name in line:
                                self.mutate(case, line, line.replace(name, inner_fields[offset][1]), 'return')

    def test_return_output_escape_and_field_offset(self):
        for case in self.cases:
            check = outer.Check(*case[:3])
            _, sites = returned.fields(check, case[5], 'outer')
            label, index = next(iter(sites))
            line = check.graph[label][index]
            self.mutate(case, line, 'call void @unreviewed(ptr %_0)\n' + line, 'return')
            pointer = re.search(r', ptr (%[-\w.]+),', line)[1]
            gep = next(line for line in check.body.splitlines() if line.strip().startswith(pointer + ' ='))
            self.mutate(case, gep, re.sub(r'i64 \d+$', 'i64 0', gep), 'return')

    def test_independent_nested_result_and_return_layouts(self):
        for fixture in self.fixtures:
            definitions, aliases = flow.definitions_and_aliases(fixture)
            for name in ('outer_success', 'outer_inner_error', 'outer_scope_error'):
                body = driver.admission.probe(definitions, aliases, name)
                self.assertIn('i64 48' if 'error' in name else 'i64 16', body)
                changed = body.replace('i64 48' if 'error' in name else 'i64 16', 'i64 8', 1)
                with self.assertRaises(ValueError): outer.layouts(fixture.replace(body, changed, 1))
            for name in ('hmac_report', 'public_success', 'secret_success', 'verify_success'):
                body = driver.admission.probe(definitions, aliases, name)
                changed = body.replace('i64 24' if name == 'hmac_report' else 'i64 88', 'i64 16', 1)
                self.assertNotEqual(body, changed)
                with self.assertRaises(ValueError): returned.layout.validate(fixture.replace(body, changed, 1))

    def test_hoisted_inner_values_require_the_accepted_state(self):
        count = 0
        for case in self.cases:
            check = outer.Check(*case[:3])
            check.run_report(255, 0)
            pointers = syntax.pointers(check.body, (check.inner.result,))
            carried = [name for name in check.carried if (match := re.search(r'load i64, ptr (%[-\w.]+),', check.defs[name][1]))
                       and pointers.get(match[1], (None,))[0] == check.inner.result]
            if not carried:
                continue
            count += 1
            for name in carried:
                old = check.prior[name]
                check.prior[name] = outer.Bits.integer(0, 64)
                with self.assertRaises(ValueError): check.run_report(255, 0)
                check.prior[name] = old
            for name in carried:
                del check.prior[name]
            with self.assertRaises(ValueError): check.run_report(255, 0)
        self.assertGreaterEqual(count, 3)


if __name__ == '__main__':
    unittest.main()
