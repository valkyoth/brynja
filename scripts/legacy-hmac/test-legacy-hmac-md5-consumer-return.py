#!/usr/bin/env python3
"""Compiled consumer/output accessor provenance and adversarial regressions."""
import importlib.util
from pathlib import Path
import re
import unittest

spec = importlib.util.spec_from_file_location('driver', Path(__file__).with_name('check-legacy-hmac-md5-cleanup.py'))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
c, views = driver.consumer_return, driver.output_views
r = c.r


class Consumers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = driver.runner.cargo_environment.private_directory(driver.ROOT)
        cls.addClassCleanup(cls.directory.cleanup)
        cls.cases, cls.fixtures = [], []
        for compiler, target, panic, simd in (('1.90.0', 'x86_64-unknown-linux-gnu', 'unwind', True),
                                              ('1.90.0', 'x86_64-unknown-linux-gnu', 'abort', False),
                                              ('1.99.1', 'x86_64-unknown-linux-gnu', 'unwind', True),
                                              ('1.99.1', 'aarch64-apple-darwin', 'unwind', True),
                                              ('1.99.1', 'x86_64-unknown-linux-gnu', 'abort', False)):
            artifacts = driver.emit(Path(cls.directory.name) / (compiler + target + panic), compiler, target, panic, simd)
            fixture, llvm = artifacts[0][1], artifacts[1][1]
            cls.fixtures.append((fixture, llvm))
            for operation, (check, returned, call, base, niche) in zip(('authenticate', 'authenticate_secret', 'verify'), c.validate(fixture, llvm)):
                cls.cases.append((operation, fixture, llvm, check, returned, call, base, niche))

    def reject(self, case, before, after, mode='gate'):
        operation, fixture, llvm, original, _, _, base, niche = case
        self.assertIn(before, original.body)
        self.assertNotEqual(before, after)
        changed = original.body.replace(before, after, 1)
        with self.subTest(operation=operation, mode=mode, before=before), self.assertRaises(ValueError):
            check = r.inner.Check(original.signature, changed, llvm.replace(original.body, changed, 1))
            check.signature = original.signature
            returned = c.fields(check, base, niche)
            call = c.gate(check, operation, returned, r.n.pads.probes(fixture))
            if mode == 'region':
                c.region_transport(check, call, returned)
            elif mode == 'metadata':
                c.metadata(check, returned, operation == 'authenticate_secret')
            elif mode == 'destination':
                c.public_destination(check, call, returned)

    def test_consumer_gate_cannot_invert_or_ignore_result(self):
        for case in self.cases:
            operation, _, _, check, _, call, _, _ = case
            if operation == 'verify':
                continue
            normal, _ = r.n.results.continuation(check.graph, call)
            line = check.graph[normal[0]][-1]
            labels = re.findall('label %' + r.flow.LABEL, line)
            self.assertEqual(len(labels), 2)
            self.reject(case, line, line.replace('label %' + labels[0] + ', label %' + labels[1],
                                                'label %' + labels[1] + ', label %' + labels[0]))
            self.reject(case, line, re.sub(r'br i1 %[-\w.]+,', 'br i1 true,', line))

    def test_consumer_unwind_cannot_construct_success(self):
        for case in self.cases:
            _, _, _, check, returned, call, _, _ = case
            _, unwind = r.n.results.continuation(check.graph, call)
            if unwind:
                edge = check.graph[call[0]][call[1] + 1]
                success = returned[0][2][0]
                self.reject(case, edge, edge.replace('unwind label %' + unwind[0], 'unwind label %' + success))

    def test_decision_and_region_return_values_are_not_invented(self):
        for case in self.cases:
            operation, _, _, check, returned, _, _, _ = case
            if operation == 'authenticate':
                continue
            for offset in ((0,) if operation == 'verify' else (8, 16)):
                dtype, value, site = returned[offset]
                line = check.graph[site[0]][site[1]]
                self.reject(case, line, line.replace(dtype + ' ' + value + ',', dtype + (' null,' if dtype == 'ptr' else ' 0,')),
                            'gate' if operation == 'verify' else 'region')

    def test_region_expired_escaped_overwritten_or_rebound(self):
        for case in self.cases:
            if case[0] != 'authenticate_secret':
                continue
            _, _, _, check, _, call, _, _ = case
            root = r.syntax.operand(call[3][0])
            pointers = r.syntax.pointers(check.body, (root,))
            line = next(line for line in check.body.splitlines() if (match := re.search(r'load ptr, ptr (%[-\w.]+),', line))
                        and pointers.get(match[1]) == (root, 8))
            for prefix in (f'call void @llvm.lifetime.end.p0(i64 24, ptr {root})',
                           f'call void @unreviewed(ptr {root})', f'store i8 0, ptr {root}, align 1'):
                self.reject(case, line, prefix + '\n' + line, 'region')
            gep = next(line for line in check.body.splitlines() if 'ptr ' + root + ', i64 16' in line)
            self.reject(case, gep, gep.replace('i64 16', 'i64 8'), 'region')

    def test_all_activity_bytes_and_selected_length_are_bound(self):
        for case in self.cases:
            if case[0] == 'verify':
                continue
            _, _, _, check, returned, _, base, _ = case
            for offset in (0, base - 8):
                dtype, value, site = returned[offset]
                line = check.graph[site[0]][site[1]]
                self.reject(case, line, line.replace(dtype + ' ' + value + ',', dtype + ' 0,'), 'metadata')
            line = check.defs[returned[base - 8][1]][1]
            pointer = re.search(r'load i64, ptr (%[-\w.]+)', line)[1]
            gep = check.defs[pointer][1]
            self.reject(case, gep, gep.replace('i64 8', 'i64 0'), 'metadata')

    def test_public_destination_has_only_copy_and_return_uses(self):
        for case in self.cases:
            if case[0] != 'authenticate':
                continue
            _, _, _, check, returned, call, _, _ = case
            root = r.syntax.operand(r.syntax.parameters(check.signature)[3])
            line = check.graph[call[0]][call[1]]
            for extra in (f'store i8 0, ptr {root}, align 1', f'call void @unreviewed(ptr {root})',
                          f'%escaped_output = getelementptr inbounds i8, ptr {root}, i64 1'):
                self.reject(case, line, extra + '\n' + line, 'destination')
            site = returned[8][2]; line = check.graph[site[0]][site[1]]
            self.reject(case, line, line.replace('ptr ' + root + ',', 'ptr null,'), 'metadata')

    def test_region_abi_probes_bind_tag_pointer_and_length(self):
        for fixture, _ in self.fixtures:
            definitions, aliases = r.flow.definitions_and_aliases(fixture)
            for name, before, after in (('region_success', 'store i8 0,', 'store i8 1,'),
                                        ('region_success', 'ptr %region.0,', 'ptr null,'),
                                        ('region_success', 'i64 %region.1,', 'i64 0,'),
                                        ('region_error', 'store i8 1,', 'store i8 0,')):
                body = r.n.pads.descriptors.admission.probe(definitions, aliases, name)
                self.assertIn(before, body)
                symbols = [symbol for symbol in (*definitions, *aliases)
                           if re.search('30brynja_legacy_hmac_md5_cleanup' + str(len(name)) + name
                                        + r'(?:17h[0-9a-f]+E)?$', symbol)]
                self.assertEqual(len(symbols), 1)
                symbol = symbols[0]
                while symbol in aliases:
                    symbol = aliases[symbol]
                function = re.search(r'^define [^\n]*@"?' + re.escape(symbol)
                                     + r'"?\([^\n]*\)[^{]*\{\n.*?^\}', fixture, re.M | re.S)
                self.assertIsNotNone(function)
                changed = fixture[:function.start()] + function[0].replace(before, after, 1) + fixture[function.end():]
                changed_defs, changed_aliases = r.flow.definitions_and_aliases(changed)
                self.assertEqual(r.n.pads.descriptors.admission.probe(changed_defs, changed_aliases, name),
                                 body.replace(before, after, 1))
                with self.subTest(name=name, before=before), self.assertRaises(ValueError):
                    c.probes(changed)

    def test_accessor_layout_lane_and_limit_mutations(self):
        for fixture, llvm in self.fixtures:
            for secret in (False, True):
                body, root = views.body(fixture, llvm, secret)
                for before, after in (('i64 %lane, 8', 'i64 %lane, 7'),
                                      ('ptr ' + root + ', i64 %lane', 'ptr ' + root + ', i64 0'),
                                      ('ptr ' + root + ', i64 8', 'ptr ' + root + ', i64 0'),
                                      ('ptr ' + root + ', i64 ' + ('24' if secret else '16'),
                                       'ptr ' + root + ', i64 0')):
                    self.assertIn(before, body)
                    with self.assertRaises(ValueError):
                        changed = body.replace(before, after, 1)
                        for mask in (0, 1, 128, 255):
                            for lane in (0, 1, 7, 8):
                                for length in (10, 16, 17):
                                    views.run(changed, root, mask, lane, length, secret)


if __name__ == '__main__':
    unittest.main()
