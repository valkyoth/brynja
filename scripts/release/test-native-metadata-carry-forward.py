#!/usr/bin/env python3
"""Real Git/object regression tests; synthetic records never qualify hardware."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import native_metadata_carry_forward as review

spec = importlib.util.spec_from_file_location('native_fixture', review.ROOT /
    'scripts/tuplehash/test-tuplehash-execution-native.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
CODE = 'crates/brynja-hash-tuple/src/test-only.rs'


def git(root, *args):
    return subprocess.check_output(['git', '-c', 'commit.gpgsign=false', *args],
                                   cwd=root, stderr=subprocess.DEVNULL)


def write(root, name, value):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value if isinstance(value, str) else json.dumps(value))


def commit(root):
    git(root, 'add', '.')
    git(root, 'commit', '--allow-empty', '-qm', 'test fixture')
    return git(root, 'rev-parse', 'HEAD').decode().strip()


def sources(root):
    return {name: review.evidence.shared.source_digest(name, (root / name).read_bytes())
            for name in (CODE, review.REVIEW)}


class CarryForwardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='brynja-native-metadata-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        git(self.root, 'init', '-q')
        git(self.root, 'config', 'user.name', 'Test')
        git(self.root, 'config', 'user.email', 'test@example.invalid')
        old = '[dependencies]\nbrynja = { version = "=0.24.39", default-features = false }\n'
        write(self.root, review.FIXTURE, old)
        write(self.root, review.FACADE, '[package]\nversion = "0.24.39"\n')
        write(self.root, CODE, 'test-only unchanged native input')
        h = review.evidence.hashlib.sha256(old.encode()).hexdigest()
        write(self.root, review.REVIEW, 'REVIEWED_HASHES = {"' + review.FIXTURE + '": "' + h + '"}\n')
        capture = commit(self.root)
        captured = sources(self.root)
        index = {'schema': 1, 'capture_commit': capture, 'lanes': {}}
        for lane in review.evidence.LANES:
            record = fixture.record(lane)
            record.update(commit=capture, sources=captured)
            name = 'assurance/tuplehash-execution-native/' + lane + '.json'
            write(self.root, name, record)
            index['lanes'][lane] = {'artifact': name, 'cpu': record['cpu'], 'reviewed': True,
                'sha256': review.evidence.hashlib.sha256((self.root / name).read_bytes()).hexdigest()}
        write(self.root, review.evidence.INDEX, index)
        new = old.replace('0.24.39', '0.24.40')
        write(self.root, review.FIXTURE, new)
        write(self.root, review.FACADE, '[package]\nversion = "0.24.40"\n')
        write(self.root, review.REVIEW, (self.root / review.REVIEW).read_text().replace(
            h, review.evidence.hashlib.sha256(new.encode()).hexdigest()))
        commit(self.root)

    def validate(self):
        with patch.object(review.evidence, 'sources', side_effect=sources), contextlib.redirect_stdout(io.StringIO()):
            review.validate(self.root)

    def test_exact_version_change_preserves_original_records(self):
        self.validate()

    def test_code_capture_fixture_and_artifact_mutations_fail(self):
        paths = (CODE, review.REVIEW, review.FIXTURE, review.FACADE,
                 'assurance/tuplehash-execution-native/linux-x86_64.json')
        for name in paths:
            with self.subTest(name=name):
                path = self.root / name
                original = path.read_bytes()
                changed = (original.replace(b'0.24.40', b'0.24.41') if name == review.FACADE
                           else original + b'\n# unexpected change\n')
                path.write_bytes(changed)
                commit(self.root)
                with self.assertRaises((ValueError, KeyError, TypeError)):
                    self.validate()
                path.write_bytes(original)
                commit(self.root)

    def test_valid_metadata_tampering_is_rejected(self):
        path = self.root / review.evidence.INDEX
        original = json.loads(path.read_text())
        mutations = []
        for key, value in [('schema', True), ('capture_commit', 'f' * 40), ('lanes', {})]:
            item = copy.deepcopy(original)
            item[key] = value
            mutations.append(item)
        for key, value in [('reviewed', False), ('cpu', 'forged'), ('sha256', '0' * 64),
                           ('artifact', '../outside.json')]:
            item = copy.deepcopy(original)
            item['lanes']['linux-x86_64'][key] = value
            mutations.append(item)
        for item in mutations:
            write(self.root, review.evidence.INDEX, item)
            commit(self.root)
            with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                self.validate()
        write(self.root, review.evidence.INDEX, original)
        commit(self.root)
        self.validate()

    def test_dirty_input_rejected(self):
        write(self.root, CODE, 'changed without commit')
        with self.assertRaises(ValueError):
            self.validate()

    def test_other_fixture_settings_rejected_even_with_matching_review_pin(self):
        path = self.root / review.FIXTURE
        before = path.read_bytes()
        after = before.replace(b'default-features = false', b'default-features = true')
        path.write_bytes(after)
        pins = self.root / review.REVIEW
        pins.write_text(pins.read_text().replace(review.evidence.hashlib.sha256(before).hexdigest(),
                                               review.evidence.hashlib.sha256(after).hexdigest()))
        commit(self.root)
        with self.assertRaises(ValueError):
            self.validate()

    def test_artifact_rehash_cannot_forge_results_or_compiler(self):
        index_path = self.root / review.evidence.INDEX
        original_index = json.loads(index_path.read_text())
        row = original_index['lanes']['linux-x86_64']
        artifact = self.root / row['artifact']
        original = json.loads(artifact.read_text())
        for key, value in [('compiler', 'wrong'), ('sources', {}), ('commit', 'a' * 40),
                           ('results', {}), ('native_attestation', 'QEMU')]:
            changed = copy.deepcopy(original)
            changed[key] = value
            write(self.root, row['artifact'], changed)
            index = copy.deepcopy(original_index)
            index['lanes']['linux-x86_64']['sha256'] = review.evidence.hashlib.sha256(artifact.read_bytes()).hexdigest()
            write(self.root, review.evidence.INDEX, index)
            commit(self.root)
            with self.assertRaises(ValueError):
                self.validate()

    def test_gate_runs_strict_validation_then_bounded_fallback(self):
        gate = (review.ROOT / 'scripts/tag_gate.sh').read_text()
        self.assertIn('if\npython3 scripts/tuplehash/check-tuplehash-execution-native.py\nthen\n'
                      '    :\nelse\n    python3 scripts/release/native_metadata_carry_forward.py\nfi', gate)
        checks = (review.ROOT / 'scripts/checks.sh').read_text()
        self.assertIn('python3 scripts/release/test-native-metadata-carry-forward.py\n', checks)


if __name__ == '__main__':
    unittest.main()
