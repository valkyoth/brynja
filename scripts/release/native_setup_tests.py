"""Synthetic review mutations: no test fixture qualifies native execution."""
import copy
from contextlib import ExitStack
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import native_review_io as io
import native_setup_review as setup
from native_review_tests import NativeReviewTests, write, commit, CODE, TEST

ADDED = 'crates/example/src/setup.rs'


class SetupReviewTests(unittest.TestCase):
    def setUp(self):
        NativeReviewTests.setUp(self)
        self.base = self.reviewed
        self.captured = {n: io.sha(io.historical(self.root, self.capture, n))
                         for n in (CODE, TEST)}
        write(self.root, ADDED, 'pub fn new_setup() {}\n')
        self.source = commit(self.root)
        self.current = {n: io.sha(io.read(self.root, n)) for n in (CODE, TEST, ADDED)}
        self.supplement = {
            'schema': 1, 'base_commit': self.base, 'source_commit': self.source,
            'disposition': 'accepted-unchanged-paths-with-separate-setup-tests',
            'families': setup.FAMILIES,
            'changes': setup.changes(self.root, self.base, self.source, self.current),
            'compiler': 'host: x86_64-unknown-linux-gnu\nrelease: 1.98.1\n', 'checks': [],
        }
        for i, command in enumerate(setup.COMMANDS):
            if i < 3:
                output = ''.join('test module::' + n + ' ... ok\n' for n in setup.TESTS)
                output += 'test result: ok. 7 passed; 0 failed; 0 ignored;\n'
            else:
                output = ''.join(f'test TypeSetup (line {n}) - compile fail ... ok\n'
                                 for n in range(20))
                output += 'test result: ok. 10 passed; 0 failed; 0 ignored;\n' * 2
            name = f'security/native-reuse/v0.24.50-setup-{i:02d}.log'
            write(self.root, name, output)
            self.supplement['checks'].append({'command': command, 'exit_code': 0,
                'log': name, 'sha256': io.sha(output.encode())})
        self.seal()

    def seal(self):
        write(self.root, setup.REVIEW, self.supplement)
        self.pin = io.sha(io.read(self.root, setup.REVIEW))
        self.head = commit(self.root)

    def validate(self):
        adapter = SimpleNamespace(digest=lambda name, raw: io.sha(raw))
        with ExitStack() as stack:
            for name, value in (('BASE', self.base), ('SOURCE', self.source),
                                ('REVIEW_SHA256', self.pin)):
                stack.enter_context(patch.object(setup, name, value))
            inactive = stack.enter_context(patch.object(setup, 'inactive'))
            setup.validate(self.root, 'kmac-execution', self.doc, adapter,
                           self.current, self.captured, self.head)
            inactive.assert_called_once_with(self.root, 'kmac-execution')

    def test_exact_review_and_later_unrelated_docs_pass(self):
        self.validate()
        write(self.root, 'docs/extra.md', 'documentation only')
        self.head = commit(self.root)
        self.validate()

    def test_old_or_new_code_and_orphan_build_changes_reject(self):
        for name in (CODE, TEST, ADDED, 'crates/example/src/orphan.rs',
                     'crates/example/build.rs', 'crates/example/Cargo.toml',
                     '.cargo/config.toml', 'rust-toolchain.toml', 'Cargo.toml'):
            with self.subTest(name=name):
                path = self.root / name
                before = path.read_bytes() if path.exists() else None
                write(self.root, name, 'unreviewed implementation')
                self.head = commit(self.root)
                with self.assertRaises(ValueError):
                    self.validate()
                if before is None:
                    path.unlink()
                else:
                    path.write_bytes(before)
                self.head = commit(self.root)

    def test_removed_input_rejects(self):
        (self.root / ADDED).unlink()
        self.head = commit(self.root)
        with self.assertRaises(ValueError):
            self.validate()

    def test_uncommitted_review_and_rehashed_log_reject(self):
        self.supplement['checks'][0]['sha256'] = '0' * 64
        write(self.root, setup.REVIEW, self.supplement)
        with self.assertRaises(ValueError):
            self.validate()
        self.head = commit(self.root)
        with self.assertRaisesRegex(ValueError, 'exact accepted review'):
            self.validate()

    def test_resealing_cannot_change_scope_or_skip_checks(self):
        original = copy.deepcopy(self.supplement)
        for key, value in (('schema', True), ('base_commit', '0'*40),
                           ('source_commit', 'f'*40), ('families', {}), ('changes', {}),
                           ('disposition', 'pending'), ('checks', []), ('compiler', 'wrong')):
            with self.subTest(key=key):
                self.supplement = {**original, key: value}
                self.seal()
                with self.assertRaises((ValueError, KeyError)):
                    self.validate()

    def test_resealing_cannot_hide_failed_or_different_commands(self):
        original = copy.deepcopy(self.supplement)
        for key, value in (('command', ['true']), ('exit_code', 1), ('exit_code', False),
                           ('log', '../outside'), ('sha256', '0'*64)):
            with self.subTest(key=key):
                self.supplement = copy.deepcopy(original)
                self.supplement['checks'][0][key] = value
                self.seal()
                with self.assertRaises(ValueError):
                    self.validate()

    def test_partial_failed_and_changed_test_logs_reject(self):
        original = copy.deepcopy(self.supplement)
        for i, output in ((0, ''), (0, '0 failed\n'),
                          (0, 'test module::fragmented_domains_match_contiguous_at_all_bit_offsets ... ok\n0 failed'),
                          (3, 'test result: ok. 0 passed; 0 failed;'),
                          (3, 'test result: FAILED. 0 failed;')):
            with self.subTest(index=i, output=output):
                self.supplement = copy.deepcopy(original)
                name = self.supplement['checks'][i]['log']
                before = io.read(self.root, name)
                write(self.root, name, output)
                self.supplement['checks'][i]['sha256'] = io.sha(output.encode())
                self.seal()
                with self.assertRaises(ValueError):
                    self.validate()
                (self.root / name).write_bytes(before)

    def test_original_capture_delta_still_checked(self):
        self.doc['changes'] = {}
        with self.assertRaises(ValueError):
            self.validate()

    def test_feature_graph_rejects_activation_ambiguity_and_foreign_origin(self):
        package = {'id': 'cpu', 'name': 'brynja-crypto-cpu-std',
                   'manifest_path': str(self.root / 'crates/brynja-crypto-cpu-std/Cargo.toml')}
        graph = {'packages': [package], 'resolve': {'nodes': [{'id': 'cpu', 'features': ['runtime-execution']}]}}
        setup.feature_graph(self.root, 'kmac-execution', graph)
        setup.feature_graph(self.root, 'parallelhash-execution', {'packages': []})
        mutations = [dict(graph, packages=[]), dict(graph, packages=[package, package]),
                     dict(graph, packages=[dict(package, manifest_path='/tmp/foreign/Cargo.toml')]),
                     dict(graph, resolve={'nodes': []}),
                     dict(graph, resolve={'nodes': [{'id': 'cpu', 'features': ['strict-sha2']}]})]
        for changed in mutations:
            with self.assertRaises(ValueError):
                setup.feature_graph(self.root, 'kmac-execution', changed)
        with self.assertRaises(ValueError):
            setup.feature_graph(self.root, 'parallelhash-execution', graph)

    def test_metadata_errors_do_not_grant_reuse(self):
        import subprocess
        with patch.object(setup.subprocess, 'run', side_effect=subprocess.TimeoutExpired('cargo', 60)):
            with self.assertRaises(subprocess.TimeoutExpired):
                setup.inactive(self.root, 'kmac-execution')

    def test_entrypoint_keeps_original_records_receipt_and_supplement_mandatory(self):
        import native_review_carry_forward as entry
        import native_review_checks as checks
        write(self.root, entry.REVIEW, self.doc)
        self.head = commit(self.root)
        adapter = SimpleNamespace(sources=lambda: self.current,
                                  records=lambda *args: (self.captured, 3))
        with patch.object(entry, 'Family', return_value=adapter), \
             patch.object(setup, 'validate') as supplement, \
             patch.object(checks, 'validate_receipt') as receipt:
            entry.validate('kmac-execution', self.root)
            supplement.assert_called_once()
            receipt.assert_called_once()
            supplement.side_effect = ValueError('supplement rejected')
            with self.assertRaisesRegex(ValueError, 'supplement rejected'):
                entry.validate('kmac-execution', self.root)
            supplement.side_effect = None
            receipt.side_effect = ValueError('original receipt rejected')
            with self.assertRaisesRegex(ValueError, 'original receipt rejected'):
                entry.validate('kmac-execution', self.root)
        adapter.records = lambda *args: (_ for _ in ()).throw(ValueError('original records rejected'))
        with patch.object(entry, 'Family', return_value=adapter), \
             patch.object(setup, 'validate') as supplement:
            with self.assertRaisesRegex(ValueError, 'original records rejected'):
                entry.validate('kmac-execution', self.root)
            supplement.assert_not_called()


if __name__ == '__main__':
    unittest.main()
