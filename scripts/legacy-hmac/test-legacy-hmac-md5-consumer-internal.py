#!/usr/bin/env python3
"""Actual emitted consumer mutations; no synthetic PASS-marker evidence."""
import importlib.util
from pathlib import Path
import re
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('driver', Path(__file__).with_name('check-legacy-hmac-md5-cleanup.py'))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
c, secret = driver.comparison, driver.secret_consumer


class Consumers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = driver.runner.cargo_environment.private_directory(driver.ROOT)
        cls.addClassCleanup(cls.directory.cleanup)
        cls.cases = []
        for compiler, target, panic, simd in (('1.90.0', 'x86_64-unknown-linux-gnu', 'unwind', True),
                                              ('1.90.0', 'x86_64-unknown-linux-gnu', 'abort', False),
                                              ('1.99.1', 'x86_64-unknown-linux-gnu', 'unwind', True),
                                              ('1.99.1', 'aarch64-apple-darwin', 'unwind', True),
                                              ('1.99.1', 'aarch64-unknown-linux-gnu', 'abort', False),
                                              ('1.99.1', 'x86_64-unknown-linux-gnu', 'abort', False)):
            artifacts = driver.emit(Path(cls.directory.name) / (compiler + target + panic), compiler, target, panic, simd)
            fixture, llvm = artifacts[0][1], artifacts[1][1]
            secret_check = secret.validate(fixture, llvm, panic)
            comparison = c.validate(llvm, panic)
            cls.cases.append((fixture, llvm, panic, secret_check, comparison))

    def secret_rejects(self, case, before, after, scenario):
        original = case[3]
        self.assertIn(before, original.body)
        self.assertNotEqual(before, after)
        changed = original.body.replace(before, after, 1)
        with self.subTest(before=before, scenario=scenario), self.assertRaises(ValueError):
            definitions, aliases = c.flow.definitions_and_aliases(case[1])
            name = next(name for name in definitions if driver.handoff.closure(name, 'authenticate_secret'))
            check = secret.Check(definitions[name][0], changed, original.ok)
            secret.State(check, scenario).run()

    def comparison_rejects(self, case, before, after, failure=None):
        original = case[4]
        self.assertIn(before, original.body)
        self.assertNotEqual(before, after)
        changed = original.body.replace(before, after, 1)
        with self.subTest(before=before, failure=failure), self.assertRaises(ValueError):
            definitions, aliases = c.flow.definitions_and_aliases(case[1])
            name = next(name for name in definitions if driver.handoff.closure(name, 'verify'))
            check = c.Check(definitions[name][0], changed)
            c.State(check, 255, 16, failure).run()

    def test_write_inputs_and_capture_move_cannot_change(self):
        for case in self.cases:
            check = case[3]
            write = next(line for line in check.body.splitlines() if (call := c.syntax.call(line)) and secret.primitive(call[0], 'write'))
            for before, after in (('i64 noundef 128', 'i64 noundef 127'), (check.rows, check.capture),
                                  (check.capture + ',', check.result + ',')):
                self.secret_rejects(case, write, write.replace(before, after), 'success')
            move = next(line for line in check.body.splitlines() if '@llvm.memcpy.' in line)
            self.secret_rejects(case, move, move.replace('i64 24,', 'i64 16,'), 'success')
            self.secret_rejects(case, move, move.replace(check.capture + ',', check.result + ','), 'success')

    def test_write_failure_and_finish_discriminants_are_load_bearing(self):
        for case in self.cases:
            check = case[3]
            branch = next(line for line in check.body.splitlines() if 'icmp eq i8' in line)
            self.secret_rejects(case, branch, branch.replace('icmp eq', 'icmp ne'), 0)
            guard = next(line for line in check.body.splitlines() if 'trunc nuw i8' in line)
            self.secret_rejects(case, guard, re.sub(r'i8 %[-\w.]+', 'i8 0', guard), 'finish-error')
            finish = next(line for line in check.body.splitlines() if (call := c.syntax.call(line)) and secret.primitive(call[0], 'finish'))
            self.secret_rejects(case, finish, '', 'success')

    def test_initialization_drop_required_on_write_error_and_unwind(self):
        for case in self.cases:
            check = case[3]
            for line in check.body.splitlines():
                call = c.syntax.call(line)
                if not call or not secret.drop(call[0]):
                    continue
                scenario = 'write-unwind' if 'invoke' in line else 0
                self.secret_rejects(case, line, line.replace(call[0], call[0] + '_fake'), scenario)
                self.secret_rejects(case, line, line.replace(check.capture + ')', check.result + ')'), scenario)

    def test_secret_result_pointer_length_error_and_lifetime(self):
        for case in self.cases:
            check = case[3]
            for line in check.body.splitlines():
                store = re.search(r'store (ptr|i64) (%[-\w.]+),', line)
                if store:
                    self.secret_rejects(case, line, line.replace(store[2] + ',', ('null' if store[1] == 'ptr' else '0') + ','), 'success')
            self.secret_rejects(case, 'store i8 2,', 'store i8 3,', 0)
            load = next(line for line in check.body.splitlines() if 'load ptr,' in line)
            root = next(call[1][0].split()[-1] for line in check.body.splitlines()
                        if (call := c.syntax.call(line)) and secret.primitive(call[0], 'finish'))
            self.secret_rejects(case, load, f'call void @llvm.lifetime.end.p0(i64 24, ptr {root})\n' + load, 'success')
            self.secret_rejects(case, load, f'%bad_address = getelementptr inbounds i8, ptr {root}, i64 25\n' + load, 'success')

    def test_each_comparison_lane_and_byte_pointer_is_bound(self):
        for case in self.cases:
            check = case[4]
            calls = [line for line in check.body.splitlines() if (call := c.syntax.call(line))
                     and c.model.primitive(call[0], 'accumulate_secret_byte_difference')]
            self.assertEqual(len(calls), 8)
            for line in calls:
                _, args = c.syntax.call(line)
                for index in (0, 1, 2):
                    old = c.syntax.operand(args[index])
                    other = check.rows if index == 0 else check.local
                    self.comparison_rejects(case, line, line.replace(old + ',', other + ',').replace(old + ')', other + ')'))

    def test_comparison_cannot_skip_bytes_or_reset_difference(self):
        for case in self.cases:
            check = case[4]
            limit = next(line for line in check.body.splitlines() if 'llvm.umin.i64' in line)
            self.comparison_rejects(case, limit, limit.replace('i64 16)', 'i64 15)'))
            store = 'store i8 0, ptr ' + check.local + ', align ' + check.alignment
            self.comparison_rejects(case, store, store.replace('i8 0', 'i8 1'))
            call = next(line for line in check.body.splitlines() if '33accumulate_secret_byte_difference' in line)
            self.comparison_rejects(case, call, store + '\n' + call)

    def test_comparison_clears_on_normal_and_unwind_returns(self):
        for case in self.cases:
            check = case[4]
            for line in check.body.splitlines():
                call = c.syntax.call(line)
                if call and c.model.primitive(call[0], 'clear_owned_region'):
                    failure = 0 if 'invoke ' in line else None
                    self.comparison_rejects(case, line, line.replace('i64 noundef 1)', 'i64 noundef 0)'), failure)
            result = next(line for line in check.body.splitlines() if line.strip().startswith('ret i8 '))
            self.comparison_rejects(case, result, 'ret i8 1')

    def test_unknown_effects_and_secret_decision_branches_reject(self):
        for case in self.cases:
            check = case[4]
            call = next(line for line in check.body.splitlines() if '33accumulate_secret_byte_difference' in line)
            self.comparison_rejects(case, call, 'call void @unreviewed()\n' + call)
            self.comparison_rejects(case, call, f'%bad_address = getelementptr inbounds i8, ptr {check.rows}, i64 129\n' + call)
            result = next(line for line in check.body.splitlines() if line.strip().startswith('ret i8 '))
            value = result.split()[-1]
            self.comparison_rejects(case, result, f'%bad = icmp eq i8 {value}, 0\n' + result)

    def test_all_primitive_pins_reject_changes(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            for name in c.PINS:
                path = root / name; path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((driver.ROOT / name).read_bytes())
            c.validate_source(root)
            for name in c.PINS:
                path = root / name; before = path.read_bytes()
                path.write_bytes(before + b'\n')
                with self.subTest(name=name), self.assertRaises(ValueError):
                    c.validate_source(root)
                path.write_bytes(before)

    def test_core_result_and_error_conversion_probes_are_not_assumed(self):
        for fixture, *_ in self.cases:
            definitions, aliases = c.flow.definitions_and_aliases(fixture)
            for name, before, after in (
                    ('core_region_success', 'store i8 0,', 'store i8 1,'),
                    ('core_region_success', 'ptr %region.0,', 'ptr null,'),
                    ('core_region_success', 'i64 %region.1,', 'i64 0,'),
                    ('core_region_error', 'store i8 1,', 'store i8 0,'),
                    ('region_memory_error', 'store i8 2,', 'store i8 3,')):
                names = [symbol for symbol in (*definitions, *aliases)
                         if re.search('30brynja_legacy_hmac_md5_cleanup' + str(len(name)) + name
                                      + r'(?:17h[0-9a-f]+E)?$', symbol)]
                self.assertEqual(len(names), 1)
                symbol = names[0]
                while symbol in aliases:
                    symbol = aliases[symbol]
                function = re.search(r'^define [^\n]*@"?' + re.escape(symbol)
                                     + r'"?\([^\n]*\)[^{]*\{\n.*?^\}', fixture, re.M | re.S)
                self.assertIsNotNone(function)
                self.assertIn(before, function[0])
                changed = fixture[:function.start()] + function[0].replace(before, after, 1) + fixture[function.end():]
                with self.subTest(name=name, before=before), self.assertRaises(ValueError):
                    secret.probes(changed)


if __name__ == '__main__':
    unittest.main()
