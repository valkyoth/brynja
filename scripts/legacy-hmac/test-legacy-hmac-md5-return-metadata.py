#!/usr/bin/env python3
"""Real emitted normalization/report-metadata transport and rejection tests."""
import importlib.util
from pathlib import Path
import re
import unittest

spec = importlib.util.spec_from_file_location('driver', Path(__file__).with_name('check-legacy-hmac-md5-cleanup.py'))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
normal, header = driver.normalization_return, driver.return_header
r, output = header.r, header.output


class ReturnMetadata(unittest.TestCase):
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
            cls.fixtures.append(fixture)
            offsets = header.probes(fixture)
            definitions, aliases = r.flow.definitions_and_aliases(llvm)
            for operation, (base, niche) in offsets.items():
                signature, body = r.phases.rows.method(definitions, aliases, operation)[1]
                copy = normal.Check(body, base)
                check = r.inner.Check(signature, body, llvm)
                fields = header.fields(check, base, niche)
                for backend in (0, 1):
                    for mask in (0, 15, 240, 255):
                        header.transported(check, fields, mask, backend)
                check.signature = signature
                driver.return_paths.walk(check, base, niche)
                cls.cases.append((signature, body, llvm, base, copy, niche))

    def reject(self, case, before, after, kind='normal'):
        signature, body, llvm, base, _, niche = case
        self.assertIn(before, body)
        self.assertNotEqual(before, after)
        changed = body.replace(before, after, 1)
        with self.subTest(kind=kind, before=before, after=after), self.assertRaises(ValueError):
            if kind == 'normal':
                normal.Check(changed, base)
            elif kind == 'paths':
                check = r.inner.Check(signature, changed, llvm.replace(body, changed, 1))
                check.signature = signature
                driver.return_paths.walk(check, base, niche)
            else:
                check = r.inner.Check(signature, changed, llvm.replace(body, changed, 1))
                fields = header.fields(check, base, niche)
                for backend in (0, 1):
                    for mask in (0, 15, 240, 255):
                        header.transported(check, fields, mask, backend)

    def test_normalization_copy_size_source_and_duplicate(self):
        for case in self.cases:
            check = case[4]
            for site, _, _, _ in check.chain:
                line = check.graph[site[0]][site[1]]
                self.reject(case, line, line.replace('i64 24,', 'i64 23,'))
                self.reject(case, line, line + '\n' + line)
                args = r.syntax.call(line)[1]
                source = r.syntax.operand(args[1])
                self.reject(case, line, line.replace(args[1], args[1].replace(source, check.root)))

    def test_normalization_unbound_alias_or_write(self):
        for case in self.cases:
            check = case[4]
            for site, dest, source, _ in check.chain:
                line = check.graph[site[0]][site[1]]
                for root in {dest[0], source[0]}:
                    self.reject(case, line, 'call void @unreviewed(ptr ' + root + ')\n' + line)
                    if root != '%_0':
                        self.reject(case, line, 'store i8 0, ptr ' + root + ', align 1\n' + line)
                args = r.syntax.call(line)[1]
                self.reject(case, line, line + '\nstore i8 0, ptr ' + r.syntax.operand(args[0]) + ', align 1')

    def test_lifetime_missing_repeated_expired(self):
        for case in self.cases:
            check = case[4]
            for root, sites in check.starts.items():
                site = sites[0]; line = check.graph[site[0]][site[1]]
                self.reject(case, line, '')
                self.reject(case, line, line + '\n' + line)
            for site, _, source, _ in check.chain:
                line = check.graph[site[0]][site[1]]
                end = f'call void @llvm.lifetime.end.p0(i64 {check.allocs[source[0]]}, ptr {source[0]})'
                self.reject(case, line, end + '\n' + line)

    def test_normalization_guard_and_unwind(self):
        for case in self.cases:
            check = case[4]
            normal_site, unwind = r.n.results.continuation(check.graph, check.pad)
            label, _ = normal_site
            line = check.graph[label][-1]
            edges = re.findall('label %' + r.flow.LABEL, line)
            self.assertEqual(len(edges), 2)
            self.reject(case, line, line.replace('label %' + edges[0] + ', label %' + edges[1],
                                                'label %' + edges[1] + ', label %' + edges[0]))
            if unwind:
                edge = check.graph[check.pad[0]][check.pad[1] + 1]
                self.reject(case, edge, edge.replace('unwind label %' + unwind[0],
                                                     'unwind label %' + check.chain[0][0][0]))

    def test_return_header_backend_width_and_overwrite(self):
        for case in self.cases:
            check = r.inner.Check(*case[:3])
            base = case[3]
            for site, offset, _, dtype, name in output.writes(case[1]):
                if offset not in (base, base + 80) or dtype == 'copy' or name == '2':
                    continue
                line = check.graph[site[0]][site[1]]
                self.reject(case, line, line.replace(dtype + ' ' + name + ',', dtype + ' 0,'), 'header')
                self.reject(case, line, line + '\n' + line, 'header')
                self.reject(case, line, 'call void @unreviewed(ptr %_0)\n' + line, 'header')

    def test_success_header_cannot_become_error_or_disappear(self):
        for case in self.cases:
            check = r.inner.Check(*case[:3])
            for site, offset, _, dtype, name in output.writes(case[1]):
                if offset == case[3] + 80 and dtype == 'i8' and name != '2':
                    line = check.graph[site[0]][site[1]]
                    self.reject(case, line, line.replace('i8 ' + name + ',', 'i8 2,'), 'header')
                    self.reject(case, line, '', 'header')

    def test_abi_error_probe_niche_and_payload(self):
        for fixture in self.fixtures:
            definitions, aliases = r.flow.definitions_and_aliases(fixture)
            for name in ('public_error', 'secret_error', 'verify_error'):
                body = r.n.pads.descriptors.admission.probe(definitions, aliases, name)
                for before, after in (('store i8 2,', 'store i8 1,'), ('store i8 %error,', 'store i8 0,')):
                    self.assertIn(before, body)
                    with self.assertRaises(ValueError):
                        header.probes(fixture.replace(body, body.replace(before, after), 1))

    def test_every_success_return_requires_complete_report(self):
        for case in self.cases:
            check = r.inner.Check(*case[:3])
            for site, offset, _, _, _ in output.writes(case[1]):
                if offset in (case[3], case[3] + 8, case[3] + 32, case[3] + 56):
                    line = check.graph[site[0]][site[1]]
                    self.reject(case, line, '', 'paths')

    def test_early_returns_and_missing_error_tag_reject(self):
        for case in self.cases:
            check = r.inner.Check(*case[:3])
            success, errors = driver.return_paths.classify(check, case[3], case[5])[1:]
            site = min(errors)
            line = check.graph[site[0]][site[1]]
            self.reject(case, line, '', 'paths')
            self.reject(case, line, 'ret void\nunbound_return_tail:\n' + line, 'paths')
            # Preserve a syntactically valid block, but bypass all construction.
            start = next(iter(check.graph))
            self.reject(case, start + ':', start + ':\nret void\nunused_entry:', 'paths')

    def test_success_niche_activity_cannot_be_constant(self):
        for case in self.cases:
            if case[5] != 0:
                continue
            check = r.inner.Check(*case[:3])
            site = driver.return_paths.classify(check, case[3], case[5])[1]
            line = check.graph[site[0]][site[1]]
            changed = re.sub(r'store i64 %[-\w.]+,', 'store i64 0,', line)
            self.reject(case, line, changed, 'paths')

    def test_width_truncation_rejects_wrapping_and_poison(self):
        for flags, limit in (('', 256), (' nuw', 256), (' nuw nsw', 128)):
            expression = 'trunc' + flags + ' i64 %width to i8'
            for value in (0, 4, 8, limit - 1):
                self.assertEqual(header.narrowed(r.Bits.integer(value, 64), expression), r.Bits.integer(value, 8))
            for value in (limit, 264, (1 << 64) - 1):
                with self.assertRaises(ValueError):
                    header.narrowed(r.Bits.integer(value, 64), expression)
            with self.assertRaises(ValueError):
                header.narrowed(r.Bits.unknown(64), expression)

    def test_non_report_output_write_must_stay_in_result(self):
        for case in self.cases:
            if case[3] == 8:
                continue  # Verification has no pointer/length output prefix.
            line = next(line for line in case[1].splitlines()
                        if re.search(r'getelementptr inbounds(?: nuw)? i8, ptr %_0, i64 8$', line))
            self.reject(case, line, line.replace('i64 8', 'i64 4096'), 'paths')


if __name__ == '__main__':
    unittest.main()
