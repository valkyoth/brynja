"""Real Git mutations for the explicit native test/tooling review boundary."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import native_review_io as io
import native_review_carry_forward as review
import native_review_checks as checks
from native_review_families import Family

CODE = 'crates/example/src/lib.rs'
TEST = 'crates/example/src/tests.rs'
MARKER = '#[cfg(test)]\nmod tests;'


def write(root, name, value):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value if isinstance(value, str) else json.dumps(value))


def commit(root):
    io.git(root, 'add', '.')
    io.git(root, '-c', 'commit.gpgsign=false', 'commit', '--allow-empty', '-qm', 'review test')
    return io.git(root, 'rev-parse', 'HEAD').decode().strip()


class NativeReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='brynja-native-review-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        io.git(self.root, 'init', '-q')
        io.git(self.root, 'config', 'user.name', 'Test')
        io.git(self.root, 'config', 'user.email', 'test@example.invalid')
        write(self.root, CODE, 'pub fn implementation() {}\n' + MARKER + '\n')
        write(self.root, TEST, '#[test] fn native_matrix() {}\n')
        write(self.root, 'Cargo.toml', '[workspace]\n')
        write(self.root, 'Cargo.lock', 'version = 4\n')
        write(self.root, 'rust-toolchain.toml', '[toolchain]\nchannel = "1.98.1"\n')
        self.capture = commit(self.root)
        write(self.root, TEST, '#[test] fn native_matrix() { assert!(true); }\n')
        self.reviewed = commit(self.root)
        self.doc = {'schema': 1, 'capture_commit': self.capture,
                    'reviewed_commit': self.reviewed,
                    'owner_review': 'accepted-test-tooling-equivalence',
                    'changes': {TEST: {'before': io.sha(io.historical(self.root, self.capture, TEST)),
                                      'after': io.sha(io.read(self.root, TEST)),
                                      'disposition': 'test-only', 'production_prefix': None}},
                    'verification': checks.REPORT}

    def validate(self, head=None):
        review.schema(self.doc)
        review.check_changes(self.root, self.doc)
        review.check_protected(self.root, self.doc, head or self.reviewed)

    def test_explicit_test_delta_and_subsequent_documentation_pass(self):
        self.validate()
        write(self.root, 'docs/note.md', 'metadata-only follow-up')
        self.validate(commit(self.root))

    def test_production_build_guards_and_new_orphan_sources_fail(self):
        for name in (CODE, TEST, 'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml',
                     '.cargo/config.toml', 'crates/example/build.rs',
                     'crates/example/src/new_kernel.rs', 'assurance/new/src/main.rs'):
            with self.subTest(name=name):
                path = self.root / name
                original = path.read_bytes() if path.exists() else None
                write(self.root, name, 'unreviewed change')
                with self.assertRaisesRegex(ValueError, 'implementation/build'):
                    self.validate(commit(self.root))
                if original is None:
                    path.unlink()
                else:
                    path.write_bytes(original)
                commit(self.root)

    def test_module_guard_removal_and_deleted_input_fail(self):
        write(self.root, CODE, 'pub fn implementation() {}\nmod tests;\n')
        with self.assertRaises(ValueError):
            self.validate(commit(self.root))
        (self.root / TEST).unlink()
        with self.assertRaises(ValueError):
            self.validate(commit(self.root))

    def test_original_unreviewed_production_change_is_not_a_test_delta(self):
        write(self.root, CODE, 'pub fn changed() {}\n' + MARKER)
        self.doc['reviewed_commit'] = commit(self.root)
        with self.assertRaisesRegex(ValueError, 'original implementation'):
            self.validate(self.doc['reviewed_commit'])

    def test_exact_digests_and_review_schema(self):
        for path, value in (('before', '0' * 64), ('after', '0' * 64),
                            ('disposition', 'ignore-any-test')):
            altered = copy.deepcopy(self.doc)
            altered['changes'][TEST][path] = value
            with self.assertRaises(ValueError):
                review.schema(altered)
                review.check_changes(self.root, altered)
        for key, value in (('schema', True), ('owner_review', 'pending'),
                           ('reviewed_commit', 'HEAD'), ('capture_commit', 'HEAD~1'),
                           ('changes', {}), ('verification', '../outside')):
            altered = copy.deepcopy(self.doc)
            altered[key] = value
            with self.assertRaises(ValueError):
                review.schema(altered)

    def test_mixed_module_prefix_must_be_unique_and_byte_identical(self):
        name = 'crates/example/src/mixed.rs'
        marker = '#[cfg(test)]\nmod tests {'
        write(self.root, name, 'pub fn code() {}\n' + marker + '\n}\n')
        old = commit(self.root)
        before = io.read(self.root, name)
        for prefix in ('pub fn code() {}\n', 'pub fn changed() {}\n',
                       marker + '\n}\npub fn code() {}\n'):
            write(self.root, name, prefix + marker + '\n#[test] fn t() {}\n}\n')
            new = commit(self.root)
            doc = {'capture_commit': old, 'reviewed_commit': new, 'changes': {
                name: {'before': io.sha(before), 'after': io.sha(io.read(self.root, name)),
                       'disposition': 'test-module', 'production_prefix': marker}}}
            if prefix == 'pub fn code() {}\n':
                review.check_changes(self.root, doc)
            else:
                with self.assertRaisesRegex(ValueError, 'production prefix'):
                    review.check_changes(self.root, doc)

    def test_closure_rejects_additions_removals_and_unreviewed_tooling(self):
        captured = {CODE: io.sha(io.historical(self.root, self.capture, CODE)),
                    TEST: self.doc['changes'][TEST]['before']}
        current = {CODE: captured[CODE], TEST: self.doc['changes'][TEST]['after']}
        digest = lambda name, raw: io.sha(raw)
        review.check_closure(self.root, self.doc, current, captured, digest)
        for changed in ({CODE: current[CODE]}, {**current, 'scripts/new.py': '0'*64},
                        {**current, TEST: '0'*64}):
            with self.assertRaises(ValueError):
                review.check_closure(self.root, self.doc, changed, captured, digest)
        with self.assertRaisesRegex(ValueError, 'missing exact review'):
            review.check_closure(self.root, {**self.doc, 'changes': {}}, current, captured, digest)

    def test_dirty_untracked_symlink_and_duplicate_json_reject(self):
        write(self.root, 'untracked.rs', 'not committed')
        with self.assertRaisesRegex(ValueError, 'clean committed'):
            io.clean(self.root)
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            io.document('{"schema":1,"schema":1}')
        for name in ('../file', '/tmp/file', 'a/../b', 'a\\b', 'a//b'):
            with self.assertRaises(ValueError):
                io.relative(name)

    def test_symlink_input_is_rejected(self):
        try:
            (self.root / 'link').symlink_to(self.root / TEST)
        except OSError as error:
            self.skipTest('host does not permit symlink fixtures: ' + str(error))
        with self.assertRaisesRegex(ValueError, 'symlinked'):
            io.read(self.root, 'link')
        with self.assertRaisesRegex(ValueError, 'symlinked output'):
            checks.write_generated(self.root, 'link', b'overwrite')

    def test_failed_current_command_cannot_create_success_receipt(self):
        write(self.root, review.REVIEW, self.doc)
        compiler = 'release: 1.98.1\nhost: x86_64-unknown-linux-gnu'
        for result in (subprocess.CompletedProcess(['test'], 1, b'failed'),
                       subprocess.TimeoutExpired(['test'], 1)):
            with patch.object(io, 'ROOT', self.root), \
                 patch.object(review, 'check_protected'), \
                 patch.object(checks, 'inputs', return_value='bound'), \
                 patch.object(io, 'git', return_value=self.reviewed.encode()), \
                 patch.object(review, 'check_changes'), \
                 patch.object(checks.subprocess, 'check_output', return_value=compiler), \
                 patch.object(checks.subprocess, 'run') as run:
                if isinstance(result, Exception):
                    run.side_effect = result
                else:
                    run.return_value = result
                with self.assertRaises((ValueError, subprocess.TimeoutExpired)):
                    checks.main()
                self.assertFalse((self.root / checks.REPORT).exists())

    def test_receipt_failure_partial_drift_and_log_tampering_reject(self):
        raw = json.dumps(self.doc).encode()
        command = ['cargo', 'test']
        log = 'security/native-reuse/v0.24.49-check-00.log'
        write(self.root, log, 'test result: ok. 1 passed; 0 failed\n')
        report = {'schema': 1, 'review_sha256': io.sha(raw), 'inputs': 'bound-inputs',
                  'compiler': 'release: 1.98.1\nhost: x86_64-unknown-linux-gnu',
                  'environment': checks.SELECTORS,
                  'checks': [{'command': command, 'exit_code': 0, 'log': log,
                              'sha256': io.sha(io.read(self.root, log))}]}
        def validate(value):
            write(self.root, checks.REPORT, value)
            head = commit(self.root)
            with patch.object(checks, 'inputs', return_value='bound-inputs'), \
                 patch.object(checks, 'COMMANDS', [command]):
                checks.validate_receipt(self.root, self.doc, raw, head)
        validate(report)
        for key, value in (('checks', []), ('inputs', 'stale'), ('review_sha256', '0'*64),
                           ('schema', True), ('environment', {}), ('compiler', 'wrong')):
            with self.assertRaises(ValueError):
                validate({**report, key: value})
        for key, value in (('command', ['true']), ('exit_code', 1), ('exit_code', False),
                           ('log', '../escape'), ('sha256', '0'*64)):
            altered = copy.deepcopy(report)
            altered['checks'][0][key] = value
            with self.assertRaises(ValueError):
                validate(altered)
        write(self.root, log, 'altered output')
        with self.assertRaises(ValueError):
            validate(report)

    def test_historical_artifacts_cannot_be_relabelled_or_rehashed(self):
        from types import SimpleNamespace
        name = 'assurance/test/lane.json'
        record = {'commit': self.capture, 'cpu': 'reviewed CPU', 'sources': {}}
        write(self.root, name, record)
        index = {'capture_commit': self.capture, 'lanes': {'lane': {
            'artifact': name, 'sha256': io.sha(io.read(self.root, name)),
            'cpu': 'reviewed CPU', 'reviewed': True}}}
        index_name = 'security/test-index.json'
        write(self.root, index_name, index)
        approved = commit(self.root)
        adapter = Family.__new__(Family)
        adapter.root, adapter.name = self.root, 'keccak-hardened'
        adapter.module = SimpleNamespace(INDEX=index_name, LANES={'lane': None},
                                        record_check=lambda *args: None)
        doc = {**self.doc, 'reviewed_commit': approved}
        self.assertEqual(adapter.records(doc, approved), ({}, 1))
        for key, value in (('cpu', 'forged'), ('commit', '0'*40), ('sources', {CODE: '0'*64})):
            write(self.root, name, {**record, key: value})
            altered = copy.deepcopy(index)
            altered['lanes']['lane']['sha256'] = io.sha(io.read(self.root, name))
            write(self.root, index_name, altered)
            with self.assertRaisesRegex(ValueError, 'original reviewed'):
                adapter.records(doc, commit(self.root))
        write(self.root, index_name, {**index, 'lanes': {}})
        with self.assertRaises(ValueError):
            adapter.records(doc, commit(self.root))

    def test_gate_cannot_pass_when_exact_and_reviewed_checks_fail(self):
        gate = (io.ROOT / 'scripts/tag_gate.sh').read_text()
        start = gate.index('if\npython3 scripts/sha1/check-sha1-hardened-native.py')
        end = gate.index('\nscripts/checks.sh', start)
        section = gate[start:end]
        families = ('sha1-hardened', 'md5-execution', 'md5-hardened',
                    'keccak-hardened', 'kmac-execution', 'tuplehash-execution',
                    'parallelhash-execution')
        for rejected in (*families, None):
            lines = ['set -e']
            for line in section.splitlines():
                if line.lstrip().startswith('python3 '):
                    fallback = 'native_review_carry_forward.py' in line
                    success = fallback and ('--family ' + str(rejected)) not in line
                    lines.append(('true' if success else 'false') +
                                 (' ||' if line.rstrip().endswith('||') else ''))
                else:
                    lines.append(line)
            result = subprocess.run(['bash', '-c', '\n'.join(lines)], check=False)
            self.assertEqual(result.returncode == 0, rejected is None)
        for family in families:
            self.assertEqual(section.count('native_review_carry_forward.py --family ' + family + '\n'), 1)
