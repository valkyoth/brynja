"""Real-Git mutations for exact test decomposition; no synthetic CPU claims."""
import contextlib
import io as output
import json
import os
import re
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import native_evidence_approval as approval
import native_review_io as io
import native_test_reuse as tests
import native_unchanged as reuse
from native_review_families import Family
from native_review_tests import init_repository, commit, write


class NativeTestReuseTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='brynja-native-test-reuse-')
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        init_repository(self.root)
        self.family = 'kmac-execution'
        self.register = 'scripts/kmac/kmac_reviewed_hashes.py'
        self.parent = 'crates/example/src/lib.rs'
        self.test = 'crates/example/src/tests.rs'
        self.code = 'crates/example/src/kernel.rs'
        self.driver = 'scripts/kmac/native-fixture.py'
        parent = 'mod kernel;\n#[cfg(test)]\nmod tests;\n'
        old, new = '#[test] fn matrix() {}\n', '#[test] fn matrix() { assert!(true); }\n'
        self.pair = (io.sha(old.encode()), io.sha(new.encode()))
        for name, raw in ((self.parent, parent), (self.test, old),
                          (self.code, 'pub fn kernel() {}\n'),
                          (self.driver, 'COMMANDS = ["native accelerated tests"]\n')):
            write(self.root, name, raw)
        pin = f'REVIEWED_HASHES = {{"{self.test}": "{self.pair[0]}"}}\n'
        write(self.root, self.register, pin)
        self.names = {self.parent, self.test, self.code, self.register, self.driver}
        self.capture = commit(self.root)
        self.captured = self.sources()
        self.artifact = 'assurance/native-fixture/record.json'
        write(self.root, self.artifact, {'commit': self.capture, 'cpu': 'synthetic',
                                       'sources': self.captured, 'results': {'test': 'fixture'}})
        self.index = approval.INDEXES[self.family]
        write(self.root, self.index, {'capture_commit': self.capture, 'lanes': {'lane': {
            'artifact': self.artifact, 'sha256': io.sha(io.read(self.root, self.artifact)),
            'reviewed': True, 'cpu': 'synthetic'}}})
        anchor = commit(self.root)
        write(self.root, approval.REVIEW, {
            'schema': 1, 'purpose': 'native-observation-integrity', 'status': 'owner-approved',
            'reviewed_commit': anchor, 'families': [self.family], 'validation_changes': {}})
        commit(self.root)
        self.external = io.sha(io.read(self.root, approval.REVIEW))
        write(self.root, self.test, new)
        write(self.root, self.register, pin.replace(*self.pair))
        commit(self.root)
        rows = ((self.test, self.parent, io.sha(parent.encode()), *self.pair),)
        for patcher in (patch.object(tests, 'CAPTURE', self.capture),
                        patch.object(tests, 'FAMILIES', {self.family: (self.register, '"', rows)}),
                        patch.dict(os.environ, {approval.ENVIRONMENT: self.external})):
            patcher.start()
            self.addCleanup(patcher.stop)

    def sources(self):
        return {name: io.sha((self.root / name).read_bytes()) for name in self.names}

    def validate(self):
        # Use real historical-record/approval/source validators. Only the
        # algorithm-specific result parser is synthetic, never real evidence.
        adapter = Family.__new__(Family)
        adapter.name, adapter.root = self.family, self.root
        adapter.module = SimpleNamespace(INDEX=self.index, LANES={'lane': None},
                                        record_check=lambda *args: None)
        adapter.sources = self.sources
        adapter.digest = lambda name, raw: io.sha(raw)
        with contextlib.redirect_stdout(output.StringIO()) as stream:
            reuse.validate_family(adapter, io.git(self.root, 'rev-parse', 'HEAD').decode().strip())
        return stream.getvalue()

    def mutate(self, name, raw):
        path = self.root / name
        before = path.read_bytes() if path.exists() else None
        write(self.root, name, raw)
        commit(self.root)
        try:
            with self.assertRaises(ValueError):
                self.validate()
        finally:
            if before is None:
                path.unlink()
            else:
                path.write_bytes(before)
            commit(self.root)

    def test_exact_delta_reuses_only_original_observations(self):
        message = self.validate()
        self.assertIn('original native test population only, NOT a run of changed tests', message)
        write(self.root, 'docs/note.md', 'unrelated documentation')
        commit(self.root)
        self.validate()

    def test_unknown_family_and_capture_do_not_gain_exception(self):
        for family, capture in (('md5-hardened', self.capture), (self.family, 'f' * 40)):
            self.assertEqual(tests.changes(self.root, capture, 'unused', {}, {}, family), {})
        with patch.object(tests, 'CAPTURE', 'f' * 40), self.assertRaises(ValueError):
            self.validate()

    def test_test_changes_and_parent_gate_changes_reject(self):
        self.validate()
        for name in (self.test, self.parent):
            raw = (self.root / name).read_text()
            for changed in (raw + '\n// unreviewed\n', raw.replace('\n', '\r\n')):
                with self.subTest(name=name, change=changed):
                    self.mutate(name, changed)
        self.mutate(self.parent, 'mod kernel;\nmod tests; // #[cfg(test)]\n')

    def test_raw_before_and_after_pins_are_both_required(self):
        register, quote, rows = tests.FAMILIES[self.family]
        for field in (2, 3, 4):
            row = list(rows[0])
            row[field] = '0' * 64
            with patch.dict(tests.FAMILIES, {self.family: (register, quote, (tuple(row),))}):
                with self.assertRaises(ValueError):
                    self.validate()

    def test_capture_and_current_closures_require_tests_and_parents(self):
        for name in (self.test, self.parent, self.register):
            for side in ('current', 'captured'):
                current, captured = self.sources(), dict(self.captured)
                (current if side == 'current' else captured).pop(name)
                with self.subTest(name=name, side=side), self.assertRaises(ValueError):
                    tests.changes(self.root, self.capture,
                                  io.git(self.root, 'rev-parse', 'HEAD').decode().strip(),
                                  current, captured, self.family)

    def test_executable_register_other_pins_duplicates_and_crlf_reject(self):
        raw = (self.root / self.register).read_text()
        for changed in (raw + 'print("bypass")\n', raw + 'OTHER = "pin"\n', raw + raw,
                        raw.replace('\n', '\r\n'), raw.replace(self.pair[1], '0' * 64)):
            self.mutate(self.register, changed)

    def test_production_orphan_build_and_configuration_changes_reject(self):
        self.mutate(self.code, 'pub fn kernel() { /* changed */ }\n')
        for name in ('crates/example/src/orphan.rs', 'crates/example/build.rs',
                     'crates/example/Cargo.toml', '.cargo/config.toml', 'rust-toolchain.toml'):
            self.mutate(name, '# unreviewed input\n')

    def test_deleted_test_rejects(self):
        (self.root / self.test).unlink()
        commit(self.root)
        with self.assertRaises((OSError, ValueError)):
            self.validate()

    def test_changed_capture_commands_do_not_gain_test_exception(self):
        self.mutate(self.driver, 'COMMANDS = ["portable smoke only"]\n')

    def test_external_approval_cannot_be_replaced_by_review_pins(self):
        for pin in ('', '0' * 64):
            with patch.dict(os.environ, {approval.ENVIRONMENT: pin}):
                with self.assertRaisesRegex(ValueError, 'approval'):
                    self.validate()
        doc = json.loads(io.read(self.root, approval.REVIEW))
        doc['status'] = 'pending-owner-review'
        write(self.root, approval.REVIEW, doc)
        commit(self.root)
        with patch.dict(os.environ, {approval.ENVIRONMENT: io.sha(io.read(self.root, approval.REVIEW))}):
            with self.assertRaisesRegex(ValueError, 'pending/invalid'):
                self.validate()

    def test_rehashed_forged_cpu_and_markers_reject_before_test_exception(self):
        record = json.loads(io.read(self.root, self.artifact))
        record.update(cpu='FORGED CPU - no command executed', results={'test': 'forged PASS'})
        write(self.root, self.artifact, record)
        index = json.loads(io.read(self.root, self.index))
        index['lanes']['lane'].update(cpu=record['cpu'], sha256=io.sha(io.read(self.root, self.artifact)))
        write(self.root, self.index, index)
        commit(self.root)
        with patch.object(tests, 'changes', side_effect=AssertionError('must not reach source exception')):
            with self.assertRaisesRegex(ValueError, 'approved native index/artifact changed'):
                self.validate()

    def test_overlapping_external_validation_review_rejects(self):
        doc = json.loads(io.read(self.root, approval.REVIEW))
        head = io.git(self.root, 'rev-parse', 'HEAD').decode().strip()
        doc['validation_changes'] = {self.family: {self.register: {
            'before': io.sha(io.raw_blob(self.root, self.capture, self.register)),
            'after': io.sha(io.raw_blob(self.root, head, self.register))}}}
        write(self.root, approval.REVIEW, doc)
        commit(self.root)
        with patch.dict(os.environ, {approval.ENVIRONMENT: io.sha(io.read(self.root, approval.REVIEW))}):
            with self.assertRaisesRegex(ValueError, 'overlapping'):
                self.validate()


class RealTestDecompositionPins(unittest.TestCase):
    # This is a historical exact-delta fixture, not approval of today's checkout.
    # Later documentation pins must not turn its positive control into a failure.
    reviewed = '24695de45cc1763b93cac648f222e0952035c2fd'

    def changes_at(self, family, revision):
        register, _, rows = tests.FAMILIES[family]
        names = {register} | {name for row in rows for name in row[:2]}
        before = {name: io.sha(io.raw_blob(io.ROOT, tests.CAPTURE, name)) for name in names}
        after = {name: io.sha(io.raw_blob(io.ROOT, revision, name)) for name in names}
        return tests.changes(io.ROOT, tests.CAPTURE, revision, after, before, family)

    def test_all_four_committed_revisions_and_declaring_parents(self):
        count = 0
        for family, (register, _, rows) in tests.FAMILIES.items():
            changes = self.changes_at(family, self.reviewed)
            self.assertEqual(set(changes), {register} | {row[0] for row in rows})
            count += len(rows)
        self.assertEqual(count, 4)

    def test_later_readme_pins_do_not_gain_test_only_approval(self):
        # Real documentation-only follow-up: the test modules and parents stayed
        # identical, but the register also changed two README pins. The narrow
        # test-only proof must still reject that distinct delta.
        later = '5902fbe88b66a6098e721f52a472611ae3921a74'
        family = 'parallelhash-execution'
        register, _, rows = tests.FAMILIES[family]
        for name in {name for row in rows for name in row[:2]}:
            self.assertEqual(io.raw_blob(io.ROOT, self.reviewed, name),
                             io.raw_blob(io.ROOT, later, name))
        self.assertNotEqual(io.raw_blob(io.ROOT, self.reviewed, register),
                            io.raw_blob(io.ROOT, later, register))
        with self.assertRaisesRegex(ValueError, 'test review cannot change executable policy or other pins'):
            self.changes_at(family, later)

    def test_exact_readme_supplement_preserves_all_executable_examples(self):
        for family, crates in tests.READMES.items():
            names = {f'crates/{crate}/README.md' for crate in crates}
            before = {n: io.sha(io.raw_blob(io.ROOT, tests.CAPTURE, n)) for n in names}
            after = {n: io.sha(io.raw_blob(io.ROOT, tests.README_AFTER, n)) for n in names}
            result = tests.readme_changes(io.ROOT, tests.CAPTURE, tests.README_AFTER,
                                         after, before, family)
            self.assertEqual(set(result), names)
            for name in names:
                old = io.raw_blob(io.ROOT, tests.README_BEFORE, name)
                new = io.raw_blob(io.ROOT, tests.README_AFTER, name)
                fences = rb'(?ms)^```[^\n]*\n.*?^```[^\n]*$'
                self.assertEqual(re.findall(fences, old), re.findall(fences, new))
                self.assertEqual(result[name], {'before': before[name], 'after': after[name]})
                self.assertEqual(io.sha(old), before[name])
            self.assertEqual(tests.readme_changes(io.ROOT, 'f' * 40, tests.README_AFTER,
                                                 after, before, family), {})

    def test_readme_changes_and_combined_pin_policy_remain_bounded(self):
        family = 'parallelhash-execution'
        register, _, rows = tests.FAMILIES[family]
        names = {register} | {n for row in rows for n in row[:2]} | {
            f'crates/{crate}/README.md' for crate in tests.READMES[family]}
        before = {n: io.sha(io.raw_blob(io.ROOT, tests.CAPTURE, n)) for n in names}
        after = {n: io.sha(io.raw_blob(io.ROOT, tests.README_AFTER, n)) for n in names}
        result = tests.changes(io.ROOT, tests.CAPTURE, tests.README_AFTER, after, before,
                               family, include_readmes=True)
        self.assertEqual(len(result), 5)  # two tests, two READMEs, one exact pin module
        raw_blob = io.raw_blob
        candidate = 'e' * 40
        def mutate(name, suffix):
            def changed(root, revision, path):
                data = raw_blob(root, tests.README_AFTER if revision == candidate else revision, path)
                return data + suffix if revision == candidate and path == name else data
            return changed
        for name in names:
            with self.subTest(path=name), patch.object(io, 'raw_blob', side_effect=mutate(name, b'\r\n')):
                # Tree identity is held constant so raw-byte checking, not a
                # missing fixture commit, must reject this mutation.
                with patch.object(io, 'tree', return_value=io.tree(io.ROOT, tests.README_AFTER)):
                    with self.assertRaises(ValueError):
                        tests.changes(io.ROOT, tests.CAPTURE, candidate, after, before,
                                      family, include_readmes=True)
