#!/usr/bin/env python3
"""Real Git evidence-substitution tests; synthetic data never qualifies a CPU."""
import copy
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import native_evidence_approval as approval
import native_review_carry_forward as carry
import native_review_io as io
import native_review_tests as fixtures
import native_unchanged
from native_review_families import Family


def approve_fixture(root, families):
    """Test-only owner decision, kept distinct from the candidate mutation."""
    anchor = io.git(root, 'rev-parse', 'HEAD').decode().strip()
    document = {'schema': 1, 'purpose': 'native-observation-integrity',
                'status': 'owner-approved', 'reviewed_commit': anchor,
                'families': families, 'validation_changes': {}}
    fixtures.write(root, approval.REVIEW, document)
    fixtures.commit(root)
    return io.sha(io.read(root, approval.REVIEW))


class ApprovalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='brynja-native-approval-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        fixtures.init_repository(self.root)
        self.source = 'crates/example/src/lib.rs'
        fixtures.write(self.root, self.source, 'pub fn unchanged() {}\n')
        self.capture = fixtures.commit(self.root)
        self.sources = {self.source: io.sha(io.read(self.root, self.source))}
        self.artifact = 'assurance/kmac-execution-native/lane.json'
        self.record = {'commit': self.capture, 'cpu': 'TEST CPU', 'sources': self.sources,
                       'results': {'package': 'synthetic fixture, not real execution'}}
        fixtures.write(self.root, self.artifact, self.record)
        self.index_name = approval.INDEXES['kmac-execution']
        self.index = {'capture_commit': self.capture, 'lanes': {'lane': {
            'artifact': self.artifact, 'sha256': io.sha(io.read(self.root, self.artifact)),
            'reviewed': True, 'cpu': self.record['cpu']}}}
        fixtures.write(self.root, self.index_name, self.index)
        self.anchor = fixtures.commit(self.root)
        self.pin = approve_fixture(self.root, ['kmac-execution'])
        environment = patch.dict(os.environ, {approval.ENVIRONMENT: self.pin})
        environment.start()
        self.addCleanup(environment.stop)

    def validate(self):
        return approval.validate('kmac-execution', self.root)

    def test_approved_snapshot_and_later_documentation_pass(self):
        self.assertEqual(self.validate(), {'capture_commit': self.capture,
                                          'reviewed_commit': self.anchor,
                                          'validation_changes': {}})
        fixtures.write(self.root, 'docs/note.md', 'only documentation')
        fixtures.commit(self.root)
        self.validate()

    def test_sha1_and_sha2_index_formats(self):
        for family in ('sha1-hardened', 'sha2-hardened'):
            record = copy.deepcopy(self.record)
            if family == 'sha2-hardened':
                record['capture_commit'] = record.pop('commit')
            name = f'assurance/test/{family}.json'
            fixtures.write(self.root, name, record)
            descriptor = {'path' if family == 'sha1-hardened' else 'artifact': name,
                          'sha256': io.sha(io.read(self.root, name))}
            fixtures.write(self.root, approval.INDEXES[family], {
                'captures' if family == 'sha1-hardened' else 'lanes': {'lane': descriptor}})
            fixtures.commit(self.root)
            pin = approve_fixture(self.root, [family])
            with self.subTest(family=family), patch.dict(os.environ, {approval.ENVIRONMENT: pin}):
                self.assertEqual(approval.validate(family, self.root)['capture_commit'], self.capture)

    def test_forged_markers_cpu_and_rehashed_index_reject(self):
        forged = copy.deepcopy(self.record)
        forged['cpu'] = 'FORGED CPU - no command executed'
        forged['results'] = {'package': 'handcrafted PASS markers'}
        fixtures.write(self.root, self.artifact, forged)
        index = copy.deepcopy(self.index)
        index['lanes']['lane'].update(cpu=forged['cpu'],
                                     sha256=io.sha(io.read(self.root, self.artifact)))
        fixtures.write(self.root, self.index_name, index)
        fixtures.commit(self.root)
        with self.assertRaisesRegex(ValueError, 'approved native index/artifact changed'):
            self.validate()
        with patch.object(carry, 'Family') as family:
            with self.assertRaisesRegex(ValueError, 'approved native index/artifact changed'):
                carry.validate('kmac-execution', self.root)
            family.assert_not_called()  # No legacy fallback after failed approval.

    def test_artifact_only_even_whitespace_rejects(self):
        path = self.root / self.artifact
        path.write_bytes(path.read_bytes() + b'\n')
        fixtures.commit(self.root)
        with self.assertRaisesRegex(ValueError, 'approved native index/artifact changed'):
            self.validate()

    def test_missing_invalid_and_wrong_trusted_pin_reject(self):
        for value in ('', 'HEAD', 'f' * 64, self.pin.upper()):
            with self.subTest(value=value), patch.dict(os.environ, {approval.ENVIRONMENT: value}):
                with self.assertRaises(ValueError):
                    self.validate()

    def test_candidate_cannot_self_approve_or_retarget_review(self):
        doc = json.loads(io.read(self.root, approval.REVIEW))
        for key, value in (('reviewed_commit', self.capture), ('families', ['sha2-hardened']),
                           ('status', 'pending-owner-review')):
            fixtures.write(self.root, approval.REVIEW, {**doc, key: value})
            fixtures.commit(self.root)
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'approval digest mismatch'):
                self.validate()

    def test_pinned_pending_malformed_and_unapproved_family_reject(self):
        doc = json.loads(io.read(self.root, approval.REVIEW))
        for key, value in (('schema', True), ('purpose', 'any-output'),
                           ('status', 'pending-owner-review'), ('reviewed_commit', 'HEAD'),
                           ('families', []), ('families', ['kmac-execution'] * 2),
                           ('families', ['sha2-hardened']), ('families', ['unknown'])):
            fixtures.write(self.root, approval.REVIEW, {**doc, key: value})
            fixtures.commit(self.root)
            pin = io.sha(io.read(self.root, approval.REVIEW))
            with self.subTest(key=key, value=value), patch.dict(os.environ, {approval.ENVIRONMENT: pin}):
                with self.assertRaises(ValueError):
                    self.validate()

    def test_head_snapshot_and_nonancestor_reject(self):
        head = io.git(self.root, 'rev-parse', 'HEAD').decode().strip()
        doc = json.loads(io.read(self.root, approval.REVIEW))
        for anchor in (head, 'f' * 40):
            raw = json.dumps({**doc, 'reviewed_commit': anchor}).encode()
            with patch.object(io, 'committed', return_value=raw), \
                 patch.dict(os.environ, {approval.ENVIRONMENT: io.sha(raw)}):
                with self.assertRaises((ValueError, __import__('subprocess').CalledProcessError)):
                    approval.receipt(self.root, head)

    def test_unchanged_reuse_compares_against_approved_commit_not_head(self):
        adapter = Family.__new__(Family)
        adapter.root, adapter.name = self.root, 'kmac-execution'
        adapter.module = SimpleNamespace(INDEX=self.index_name, LANES={'lane': None},
                                        record_check=lambda *args: None)
        adapter.sources = lambda: {self.source: io.sha(io.read(self.root, self.source))}
        adapter.digest = lambda name, raw: io.sha(raw)
        head = io.git(self.root, 'rev-parse', 'HEAD').decode().strip()
        with patch.object(adapter, 'records', wraps=adapter.records) as records:
            native_unchanged.validate_family(adapter, head)
            self.assertEqual(records.call_args.args[0]['reviewed_commit'], self.anchor)
            self.assertNotEqual(self.anchor, head)
        fixtures.write(self.root, self.source, 'pub fn changed() {}\n')
        head = fixtures.commit(self.root)
        with self.assertRaisesRegex(ValueError, 'implementation/fixture/tool changed'):
            native_unchanged.validate_family(adapter, head)

    def test_explicit_validation_review_binds_both_versions_and_not_rust(self):
        name = 'scripts/check-result.py'
        fixtures.write(self.root, name, 'print("old validator")\n')
        capture = fixtures.commit(self.root)
        captured = {name: io.sha(io.read(self.root, name))}
        fixtures.write(self.root, name, 'print("reviewed validator")\n')
        head = fixtures.commit(self.root)
        current = {name: io.sha(io.read(self.root, name))}
        changes = {name: {'before': captured[name], 'after': current[name]}}
        digest = lambda name, raw: io.sha(raw)
        with self.assertRaisesRegex(ValueError, 'implementation/fixture/tool changed'):
            native_unchanged.validate_inputs(self.root, capture, head, current, captured, digest)
        native_unchanged.validate_inputs(self.root, capture, head, current, captured, digest, changes)
        for key in ('before', 'after'):
            forged = copy.deepcopy(changes)
            forged[name][key] = '0' * 64
            with self.assertRaisesRegex(ValueError, 'reviewed validation bytes changed'):
                native_unchanged.validate_inputs(self.root, capture, head, current, captured, digest, forged)
        doc = json.loads(io.read(self.root, approval.REVIEW))
        for path in (self.source, 'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml',
                     'assurance/fixture/src/main.rs', 'scripts/../crates/code.rs'):
            invalid = {**doc, 'validation_changes': {'kmac-execution': {path: changes[name]}}}
            fixtures.write(self.root, approval.REVIEW, invalid)
            fixtures.commit(self.root)
            with self.subTest(path=path), patch.dict(os.environ, {
                    approval.ENVIRONMENT: io.sha(io.read(self.root, approval.REVIEW))}):
                with self.assertRaises(ValueError):
                    self.validate()

    def test_validation_pairs_bind_raw_committed_line_endings(self):
        name = 'scripts/check-result.py'
        io.git(self.root, 'config', 'core.autocrlf', 'false')
        for before_crlf in (False, True):
            old = b'print("old validator")\n'
            new = b'print("reviewed validator")\n'
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(old.replace(b'\n', b'\r\n') if before_crlf else old)
            capture = fixtures.commit(self.root)
            path.write_bytes(new if before_crlf else new.replace(b'\n', b'\r\n'))
            head = fixtures.commit(self.root)
            captured, current = {name: io.sha(old)}, {name: io.sha(new)}
            digest = lambda name, raw: io.sha(io.normalized(raw))
            changes = {name: {'before': io.sha(old), 'after': io.sha(new)}}
            with self.assertRaisesRegex(ValueError, 'reviewed validation bytes changed'):
                native_unchanged.validate_inputs(self.root, capture, head, current, captured, digest, changes)
            changes[name] = {key: io.sha(io.raw_blob(self.root, rev, name))
                             for key, rev in (('before', capture), ('after', head))}
            native_unchanged.validate_inputs(self.root, capture, head, current, captured, digest, changes)

    def test_raw_blob_reports_missing_and_rejects_nonregular_or_oversized_inputs(self):
        with self.assertRaisesRegex(ValueError, 'missing/nonregular Git input: missing.py'):
            io.raw_blob(self.root, self.capture, 'missing.py')
        with patch.object(io, 'LIMIT', 1):
            with self.assertRaisesRegex(ValueError, 'oversized Git object'):
                io.raw_blob(self.root, self.capture, self.source)
        (self.root / 'symlink.py').symlink_to(self.source)
        head = fixtures.commit(self.root)
        with self.assertRaisesRegex(ValueError, 'missing/nonregular Git input'):
            io.raw_blob(self.root, head, 'symlink.py')


ENTRYPOINTS = {
    'sha2/check-sha2-hardened-native-evidence.py': ('hardened_native_evidence', 'sha2-hardened'),
    'sha1/check-sha1-hardened-native.py': ('hardened_native', 'sha1-hardened'),
    'md5/check-md5-execution-native.py': ('md5_execution_native', 'md5-execution'),
    'md5/check-md5-hardened-native.py': ('md5_hardened_native', 'md5-hardened'),
    'sha3/check-keccak-hardened-native.py': ('keccak_hardened_native', 'keccak-hardened'),
    'kmac/check-kmac-execution-native.py': ('kmac_execution_native', 'kmac-execution'),
    'tuplehash/check-tuplehash-execution-native.py': ('tuplehash_execution_native', 'tuplehash-execution'),
    'parallelhash/check-parallelhash-execution-native.py': ('parallelhash_execution_native', 'parallelhash-execution'),
}


class EntrypointTests(unittest.TestCase):
    def probe(self, name, module, family, source):
        path = io.ROOT / 'scripts' / name
        consumer = Mock()
        stub = SimpleNamespace(validate=consumer, policy=SimpleNamespace(ROOT=io.ROOT))
        with patch.dict('sys.modules', {module: stub}), patch('sys.argv', [str(path)]), \
             patch.object(approval, 'validate', side_effect=ValueError('approval denied')) as guard:
            with self.assertRaisesRegex(ValueError, 'approval denied'):
                exec(compile(source, str(path), 'exec'), {'__name__': '__main__', '__file__': str(path)})
            guard.assert_called_once_with(family)
            consumer.assert_not_called()

    def test_all_direct_commands_reject_before_result_validation(self):
        for name, (module, family) in ENTRYPOINTS.items():
            with self.subTest(name=name):
                self.probe(name, module, family, (io.ROOT / 'scripts' / name).read_text())

    def test_missing_guard_mutants_are_detected(self):
        for name, (module, family) in ENTRYPOINTS.items():
            source = (io.ROOT / 'scripts' / name).read_text()
            mutant = source.replace(f"    approve('{family}')\n", '')
            self.assertNotEqual(mutant, source)
            with self.subTest(name=name), self.assertRaises((AssertionError, AttributeError)):
                self.probe(name, module, family, mutant)

    def test_gate_preflight_precedes_all_fallbacks(self):
        gate = (io.ROOT / 'scripts/tag_gate.sh').read_text()
        command = 'python3 scripts/release/native_evidence_approval.py\n'
        self.assertEqual(gate.count(command), 1)
        self.assertLess(gate.index(command), gate.index('if python3 scripts/sha2/'))


if __name__ == '__main__':
    unittest.main()
