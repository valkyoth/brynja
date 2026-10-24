#!/usr/bin/env python3
"""Actual compiler-artifact mutations for success teardown and quarantine."""
import importlib.util
from pathlib import Path
import re
import unittest

spec = importlib.util.spec_from_file_location('driver', Path(__file__).with_name('check-legacy-hmac-md5-cleanup.py'))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
t, q = driver.teardown, driver.quarantine


class Teardown(unittest.TestCase):
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
            teardowns = t.validate(fixture, llvm, panic)
            quarantines = q.validate(fixture, llvm, panic)
            cls.cases.append((fixture, llvm, panic, teardowns, quarantines))

    def rejects(self, case, check, before, after, module, label=None):
        self.assertTrue(before in check.body, before)
        self.assertNotEqual(before, after)
        fragment = check.body
        if label is not None:
            start = re.search(r'^' + re.escape(label) + ':', check.body, re.M).start()
            ends = [match.start() for match in re.finditer(r'^' + t.flow.LABEL + ':', check.body, re.M)
                    if match.start() > start]
            fragment = check.body[start:min(ends) if ends else len(check.body)]
        self.assertIn(before, fragment)
        changed = check.body.replace(fragment, fragment.replace(before, after, 1), 1)
        self.assertTrue(check.body in case[1])
        with self.subTest(before=before, after=after), self.assertRaises(ValueError):
            module.validate(case[0], case[1].replace(check.body, changed, 1), case[2])

    def suffix(self, check, start):
        pending, seen = [start], set()
        while pending:
            label, index = pending.pop()
            if label in seen:
                continue
            seen.add(label)
            for n, line in enumerate(check.graph[label][index:], index):
                call = t.syntax.call(line)
                if call:
                    yield label, n, line, call
                    if 'invoke ' in line:
                        normal, _ = t.r.n.results.continuation(check.graph, (label, n, *call))
                        pending.append(normal)
                        break
                direct = re.fullmatch('br label %' + t.flow.LABEL, line)
                if direct:
                    pending.append((direct[1], 0))

    def test_all_seven_cleanup_calls_are_required_and_bound(self):
        for case in self.cases:
            for check, operation, fields, site, start in case[3]:
                count = 0
                for label, index, line, (symbol, args) in self.suffix(check, start):
                    if symbol.startswith('llvm.'):
                        continue
                    count += 1
                    self.rejects(case, check, line, line.replace(symbol, symbol + '_unreviewed'), t, label)
                    if 'invoke ' in line:
                        continuation = check.graph[label][index + 1]
                        old = re.search(re.escape(line) + r'\s+' + re.escape(continuation), check.body)[0]
                        dest = re.search('to label %' + t.flow.LABEL, continuation)[1]
                        self.rejects(case, check, old, 'br label %' + dest, t, label)
                    else:
                        self.rejects(case, check, line, '', t, label)
                self.assertEqual(count, 7)

    def test_cleanup_extent_and_owner_retargeting(self):
        for case in self.cases:
            for check, _, _, _, start in case[3]:
                for label, _, line, (symbol, args) in self.suffix(check, start):
                    if t.model.primitive(symbol, 'clear_owned_region'):
                        size = int(args[1].split()[-1])
                        self.rejects(case, check, line, line.replace(args[1], 'i64 noundef ' + str(size - 1)), t, label)
                    elif t.contracts.region_drop(symbol):
                        root = t.syntax.operand(args[0])
                        self.rejects(case, check, line, line.replace(root, '%_0'), t, label)

    def test_no_callback_write_or_early_expiry_after_consumer(self):
        for case in self.cases:
            for check, _, _, _, start in case[3]:
                line = check.graph[start[0]][start[1]]
                self.rejects(case, check, line, 'call void @unreviewed()\n' + line, t, start[0])
                self.rejects(case, check, line, 'store i8 0, ptr %self, align 1\n' + line, t, start[0])
                cleanup = next(item for item in self.suffix(check, start) if t.model.primitive(item[3][0], 'clear_owned_region'))
                root = t.syntax.operand(cleanup[3][1][0])
                self.rejects(case, check, cleanup[2], 'call void @llvm.lifetime.end.p0(ptr ' + root + ')\n' + cleanup[2], t, cleanup[0])

    def test_returned_secret_owner_cannot_escape_or_be_destroyed(self):
        for case in self.cases:
            check, _, fields, _, _ = next(item for item in case[3] if item[1] == 'authenticate_secret')
            for offset in (8, 16):
                _, name, site = fields[offset]
                line = check.graph[site[0]][site[1]]
                call = f'call void @unreviewed({"ptr" if offset == 8 else "i64"} {name})'
                self.rejects(case, check, line, call + '\n' + line, t, site[0])

    def test_every_revocation_cell_is_load_bearing(self):
        for case in self.cases:
            for check in case[4]:
                for label, lines in check.graph.items():
                    for line in lines:
                        store = re.fullmatch(r'store i8 ([01]), ptr (%[-\w.]+),.*', line)
                        if store and check.ptrs.get(store[2]) in ((check.executor, 16), (check.executor, 8)):
                            self.rejects(case, check, line, line.replace('store i8 ' + store[1], 'store i8 ' + str(1 - int(store[1]))), q, label)

    def test_error_classifier_cannot_preserve_integrity_errors(self):
        for case in self.cases:
            for check in case[4]:
                lines = check.graph[check.entry]
                add = next((line for line in lines if ' = add nsw i8 ' in line), None)
                if add:
                    self.rejects(case, check, add, add.replace(', -5', ', -4'), q, check.entry)
                    compare = next(line for line in lines if 'icmp ult i8' in line)
                    self.rejects(case, check, compare, compare.replace('icmp ult', 'icmp eq'), q, check.entry)
                else:
                    case_line = next(line for line in lines if line.startswith('i8 0,'))
                    self.rejects(case, check, case_line, case_line.replace('i8 0,', 'i8 2,'), q, check.entry)

    def test_classifier_and_returned_error_cannot_diverge(self):
        for case in self.cases:
            for check in case[4]:
                count = 0
                for site, offset, size, dtype, name in check.writes:
                    if (offset, size, dtype) != (check.payload, 1, 'i8'):
                        continue
                    # Pre-initialization/admission failures are outside Operation.
                    if site[0] not in t.r.phases.handoff.reachable(check.graph, check.workspace[0]):
                        continue
                    # The same union offset also holds a successful verify
                    # decision; that is checked by the consumer projection.
                    if (check.entry not in t.r.phases.handoff.reachable(check.graph, site[0])
                            and site[0] not in t.r.phases.handoff.reachable(check.graph, check.entry)):
                        continue
                    line = check.graph[site[0]][site[1]]
                    self.rejects(case, check, line, line.replace('store i8 ' + name + ',',
                                 'store i8 ' + ('3' if name != '3' else '2') + ','), q, site[0])
                    count += 1
                self.assertGreater(count, 0)

    def test_authority_presence_and_unwind_suffix_cannot_change(self):
        for case in self.cases:
            for check in case[4]:
                for site in check.stores:
                    for line in check.graph[site[0]]:
                        if 'icmp eq i8' in line:
                            self.rejects(case, check, line, line.replace(', 2', ', 1'), q, site[0])
                for site in check.unwind:
                    line = check.graph[site[0]][site[1]]
                    self.rejects(case, check, line, '', q, site[0])

    def test_independent_error_and_revoke_probes(self):
        for fixture, _, _, _, _ in self.cases:
            definitions, aliases = q.flow.definitions_and_aliases(fixture)
            probe = q.r.n.pads.descriptors.admission.probe
            errors = probe(definitions, aliases, 'error_order')
            changed = re.sub(r'ret i64 \d+', 'ret i64 0', errors)
            with self.assertRaises(ValueError):
                q.probes(fixture.replace(errors, changed))
            revoke = probe(definitions, aliases, 'revoke')
            with self.assertRaises(ValueError):
                q.probes(fixture.replace(revoke, revoke.replace('store i8 1,', 'store i8 0,')))

    def test_unwind_edge_cannot_bypass_revocation(self):
        for case in self.cases:
            if case[2] != 'unwind':
                continue
            for check in case[4]:
                reachable = t.r.phases.handoff.reachable(check.graph, check.workspace[0])
                label = next(label for label in reachable if any('invoke ' in line for line in check.graph[label]))
                edge = next(line for line in check.graph[label] if line.startswith('to label '))
                changed = re.sub(r'unwind label %' + t.flow.LABEL, 'unwind label %bypass_quarantine', edge)
                changed += '\nbypass_quarantine:\n  %bypass_lpad = landingpad { ptr, i32 }\n  cleanup\n  resume { ptr, i32 } %bypass_lpad'
                self.rejects(case, check, edge, changed, q, label)

    def test_inlined_cleanup_cannot_change_lane_or_lifetime(self):
        count = 0
        for case in self.cases:
            for check in case[4]:
                for line in check.graph[check.entry]:
                    call = t.syntax.call(line)
                    if call and t.r.phases.rows.shared.owner_drop(call[0], 'md5'):
                        root = t.syntax.operand(call[1][0])
                        self.rejects(case, check, line, line.replace(root, check.output), q, check.entry)
                        workspace = t.r.phases.owner(check.allocs, 'workspace', 912)
                        self.rejects(case, check, line, 'call void @llvm.lifetime.end.p0(i64 912, ptr '
                                     + workspace + ')\n' + line, q, check.entry)
                        count += 1
        self.assertGreater(count, 0)

    def test_byte_origins_require_matching_phi_predecessors(self):
        body = '%a = phi i8 [ 2, %left ], [ 4, %right ]\n%b = phi ptr [ inttoptr (i64 2 to ptr), %left ], [ inttoptr (i64 4 to ptr), %right ]'
        good = q.Bytes(body)
        self.assertEqual(good.origin('%a'), good.origin('%b'))
        bad = q.Bytes(body.replace('i64 2 to ptr), %left', 'i64 2 to ptr), %right').replace('i64 4 to ptr), %right', 'i64 4 to ptr), %left'))
        self.assertNotEqual(bad.origin('%a'), bad.origin('%b'))

    def test_error_domain_cannot_silently_expand(self):
        source = (t.contracts.ROOT / 'crates/brynja-legacy-hmac/src/lib.rs').read_text()
        q.error_domain(source)
        for changed in (source.replace('Cancelled,', 'Cancelled, NewFailure,'),
                        source.replace('Cancelled,', 'Cancelled(u8),'),
                        source.replace('Cancelled,', 'Renamed,'),
                        source.replace('Cancelled,', 'Cancelled = 9,')):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                q.error_domain(changed)


if __name__ == '__main__':
    unittest.main()
