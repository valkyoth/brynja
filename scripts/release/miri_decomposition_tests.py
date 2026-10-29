"""Real-Git source proof and fail-closed mutations for exact task decomposition."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import miri_decomposition_reuse as proof
import verification_carry_forward as carry
import verification_plan as plans
from miri_coverage_tests import entry


class MiriDecompositionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.git('init', '-q')
        for path in ('Cargo.lock', 'rust-toolchain.toml', 'assurance/policy.toml'):
            self.write(path, (plans.ROOT / path).read_bytes())
        self.write('release-crates.toml', b'[release]\nversion="0.25.2"\nstage="public"\nverification="full"\n')
        self.pairs = {}
        for path in proof.REVISIONS:
            before, after = (path + ':old\n').encode(), (path + ':reviewed\n').encode()
            self.write(path, before)
            self.pairs[path] = tuple(hashlib.sha256(raw).hexdigest() for raw in (before, after))
        self.git('add', '.')
        self.git('commit', '-qm', 'baseline')
        self.base = self.git('rev-parse', 'HEAD').decode().strip()
        for path in proof.REVISIONS:
            self.write(path, (path + ':reviewed\n').encode())
        pins = patch.object(proof, 'REVISIONS', self.pairs)
        pins.start()
        self.addCleanup(pins.stop)
        environment = patch.dict(os.environ, {}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)

    def git(self, *args):
        return subprocess.check_output(['git', '-c', 'user.name=Test', '-c',
            'user.email=test@example.invalid', '-c', 'commit.gpgsign=false', *args],
            cwd=self.root, stderr=subprocess.DEVNULL)

    def write(self, path, raw):
        destination = self.root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)

    def prove(self):
        return proof.prove(self.root, self.base, plans.changed_paths(self.root, self.base))

    def test_only_exact_runner_catalog_change_allows_unchanged_families(self):
        self.assertEqual(self.prove(), set(plans.scope.GROUPS))
        self.assertEqual(proof.prove(self.root, self.base, []), set())
        path = next(iter(self.pairs))
        self.write(path, (path + ':unreviewed\n').encode())
        self.assertEqual(self.prove(), set())

    def test_missing_and_changed_line_endings_do_not_match_reviewed_runner(self):
        path = next(iter(self.pairs))
        self.write(path, (path + ':reviewed\r\n').encode())
        self.assertEqual(self.prove(), set())
        (self.root / path).unlink()
        self.assertEqual(self.prove(), set())

    def test_changed_tests_invalidate_their_family_and_consumers(self):
        for path, expected in (
            ('crates/brynja-mac-kmac/src/setup/tests.rs', {'kmac'}),
            ('crates/brynja-hash-tuple/src/hardened_in_place/tests.rs', {'tuplehash'}),
            ('crates/brynja-hash-parallel/src/hardened_in_place/tests.rs', {'parallelhash'}),
            ('crates/brynja-hash-sha3/src/lib.rs', {'sha3', 'kmac', 'tuplehash', 'parallelhash', 'hmac'}),
            ('crates/brynja-legacy-md5/src/lib.rs', {'md5', 'legacy', 'legacy_hmac'}),
        ):
            with self.subTest(path=path):
                self.write(path, b'changed implementation or tests\n')
                self.assertEqual(self.prove(), set(plans.scope.GROUPS) - expected)
                (self.root / path).unlink()

    def test_unknown_shared_driver_build_input_and_bad_lock_fail_closed(self):
        for path, raw in (
            ('scripts/zeroization/new-runner.py', b'unreviewed\n'),
            ('assurance/new-fixture/src/lib.rs', b'changed\n'),
            ('.cargo/config.toml', b'[build]\nrustflags=["--cfg", "unreviewed"]\n'),
            ('build.rs', b'fn main() {}\n'),
        ):
            with self.subTest(path=path):
                self.write(path, raw)
                self.assertEqual(self.prove(), set())
                (self.root / path).unlink()
        self.write('Cargo.lock', b'not a valid graph')
        self.assertEqual(self.prove(), set())

    def test_environment_override_prevents_source_exception(self):
        for key in ('MIRIFLAGS', 'BRYNJA_MIRI_CASE', 'RUSTFLAGS', 'RUSTC_WRAPPER'):
            with patch.dict(os.environ, {key: 'unreviewed'}), self.subTest(key=key):
                self.assertEqual(self.prove(), set())

    def test_verifier_or_compiler_policy_change_cannot_use_old_installed_tools(self):
        # Normal source scope can ignore verifier-only metadata. This exception
        # must not: an old installed Miri may still match the old tool receipt.
        for path in proof.POLICY_INPUTS:
            destination = self.root / path
            original = destination.read_bytes() if destination.exists() else None
            with self.subTest(path=path):
                self.write(path, (original or b'') + b'\n# policy changed\n')
                self.assertEqual(self.prove(), set())
                if original is None:
                    destination.unlink()
                else:
                    destination.write_bytes(original)

    def test_review_only_docs_do_not_hide_a_source_mutation(self):
        self.write('docs/note.md', b'documented\n')
        self.write('scripts/release/new-test.py', b'# current baseline review\n')
        self.assertEqual(self.prove(), set(plans.scope.GROUPS))
        self.write('crates/brynja-core/src/lib.rs', b'changed\n')
        self.assertNotIn('md5', self.prove())

    def test_exception_still_needs_matching_coverage_tools_and_same_checkpoint(self):
        task = entry(group='md5')
        context = {'plan': {'groups': list(plans.scope.GROUPS),
                           'verifiers': {'miri': list(plans.scope.GROUPS)},
                           'full_phases': ['miri'],
                           'evidence': {'changed_paths': list(self.pairs)}},
                   'manifest': {'commands': [task]}, 'public_checkpoint': False,
                   'coverage_roots': (plans.ROOT, plans.ROOT),
                   'miri_decomposition_groups': self.prove()}
        self.assertTrue(carry.disposition(task, context).startswith('reuse:'))
        for delta in ({'manifest': {'commands': []}}, {'public_checkpoint': True},
                      {'tool_drift': {'miri': ['different']}}, {'miri_decomposition_groups': set()},
                      {'coverage_roots': None}):
            with self.subTest(delta=delta):
                self.assertTrue(carry.disposition(task, {**context, **delta}).startswith('run:'))
        self.write('crates/brynja-legacy-md5/src/lib.rs', b'changed\n')
        context['miri_decomposition_groups'] = self.prove()
        self.assertTrue(carry.disposition(task, context).startswith('run:'))


class ReviewedMiriDecompositionTests(unittest.TestCase):
    def test_current_reviewed_endpoints_match_raw_files(self):
        for path, (_, expected) in proof.REVISIONS.items():
            self.assertEqual(hashlib.sha256((plans.ROOT / path).read_bytes()).hexdigest(), expected, path)
