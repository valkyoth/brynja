#!/usr/bin/env python3
"""Offline regressions for latest compatibility versus pinned native compiler."""
import io
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import rust_freshness as policy

MATRIX = 'scripts/ci/check-rust-version-matrix.sh'
FILES = (
    MATRIX, 'rust-toolchain.toml', 'assurance/zeroization-matrix.toml',
    'assurance/constant-time-matrix.toml', '.github/workflows/qualification.yml',
    'scripts/checks.sh', 'scripts/tag_gate.sh', 'scripts/zeroization/check-tag-miri.sh',
    'scripts/release/verification_plan.py', 'scripts/release/run-verification.py',
)
MANIFEST = b'manifest-version = "2"\n[pkg.rust]\nversion = "1.99.1 (abcd1234 2026-10-01)"\n'


class FreshnessTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='brynja-rust-freshness-')
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        for name in FILES:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(policy.ROOT / name, path)

    def replace(self, name, old, new):
        path = self.root / name
        original = path.read_text()
        self.assertIn(old, original)
        path.write_text(original.replace(old, new, 1))
        return original

    def test_current_pinned_compiler_has_complete_coverage(self):
        self.assertEqual(policy.coverage(self.root, '1.99.1'), '1.99.1')
        self.assertEqual(policy.latest(MANIFEST), '1.99.1')

    def test_latest_equal_to_pinned_is_still_valid(self):
        # No special exemption depends on the versions being different.
        self.assertEqual(policy.coverage(self.root, '1.99.1'), '1.99.1')

    def test_older_stable_cannot_satisfy_current_default(self):
        with self.assertRaisesRegex(ValueError, 'newer than current stable'):
            policy.coverage(self.root, '1.98.1')

    def test_future_stable_missing_from_matrix_rejects(self):
        with self.assertRaisesRegex(ValueError, 'must cover latest'):
            policy.coverage(self.root, '1.100.0')

    def test_default_newer_than_stable_and_floating_pin_reject(self):
        for value in ('1.100.0', 'stable', 'nightly', '1.99', '01.99.1'):
            with self.subTest(value=value):
                original = self.replace('rust-toolchain.toml', '1.99.1', value)
                with self.assertRaises(ValueError):
                    policy.coverage(self.root, '1.99.1')
                (self.root / 'rust-toolchain.toml').write_text(original)

    def test_missing_duplicate_and_disagreeing_coverage_rejects(self):
        cases = [(MATRIX, ' 1.99.1)', ')'), (MATRIX, ' 1.98.1 ', ' '),
                 (MATRIX, ' 1.99.1)', ' 1.99.1 1.99.1)'),
                 (MATRIX, 'toolchains=(', '# toolchains=(')]
        for family in ('zeroization', 'constant-time'):
            path = f'assurance/{family}-matrix.toml'
            cases.extend([(path, '  "1.99.1",\n', ''),
                          (path, '  "1.99.1",\n', '  "1.99.1",\n  "1.99.1",\n'),
                          (path, 'target_compiler = "1.99.1"', 'target_compiler = "1.98.1"')])
        for name, old, new in cases:
            with self.subTest(name=name, new=new):
                original = self.replace(name, old, new)
                with self.assertRaises((ValueError, RuntimeError)):
                    policy.coverage(self.root, '1.99.1')
                (self.root / name).write_text(original)

    def test_declared_but_unexecuted_latest_compiler_rejects(self):
        original = self.replace(MATRIX, 'cargo "+$toolchain" check --workspace --all-features',
                                'cargo "+1.98.1" check --workspace --all-features')
        with self.assertRaisesRegex(ValueError, 'not executable'):
            policy.coverage(self.root, '1.99.1')
        (self.root / MATRIX).write_text(original)

    def test_ci_codegen_and_tag_bindings_remain_required(self):
        cases = [('.github/workflows/qualification.yml', ', 1.99.1]', ']')]
        for family in ('zeroization', 'constant-time'):
            cases.append(('.github/workflows/qualification.yml',
                          f'scripts/{family}/check-{family}-codegen.sh', 'scripts/omitted.sh'))
        for command in ('scripts/ci/check-rust-version-matrix.sh', 'scripts/ci/check_latest_tools.sh'):
            cases.append(('scripts/tag_gate.sh', command, 'true'))
        for name, old, new in cases:
            with self.subTest(old=old):
                original = self.replace(name, old, new)
                with self.assertRaises((ValueError, RuntimeError)):
                    policy.coverage(self.root, '1.99.1')
                (self.root / name).write_text(original)

    def test_bad_empty_prerelease_duplicate_and_oversized_manifests_reject(self):
        for raw in (b'', b'<html>outage</html>', b'x' * (policy.LIMIT + 1),
                    MANIFEST.replace(b'"2"', b'"1"'),
                    MANIFEST.replace(b'1.99.1', b'1.99.1-beta.1'),
                    MANIFEST.replace(b'1.99.1', b'01.99.1'),
                    MANIFEST + b'version = "1.98.1 (abcd 2026-09-01)"\n'):
            with self.subTest(prefix=raw[:50]):
                with self.assertRaises((ValueError, KeyError)):
                    policy.latest(raw)

    def test_fetch_is_bounded_and_network_failure_never_reuses_old_value(self):
        with patch.object(policy.urllib.request, 'urlopen', return_value=io.BytesIO(MANIFEST)) as opened:
            self.assertEqual(policy.fetch(policy.URL), '1.99.1')
            opened.assert_called_once_with(policy.URL, timeout=30)
        for error in (OSError('offline'), TimeoutError('timed out')):
            with patch.object(policy.urllib.request, 'urlopen', side_effect=error):
                with self.assertRaises(OSError):
                    policy.fetch(policy.URL)
        with patch.object(policy.urllib.request, 'urlopen',
                          return_value=io.BytesIO(b'x' * (policy.LIMIT + 1))):
            with self.assertRaisesRegex(ValueError, 'oversized'):
                policy.fetch(policy.URL)

    def test_shell_calls_real_checker_and_stops_on_failure(self):
        driver = (policy.ROOT / 'scripts/ci/check_latest_tools.sh').read_text()
        prefix = driver.split('for tool in cargo-deny cargo-audit cargo-sbom;', 1)[0]
        self.assertEqual(prefix.count('python3 scripts/repository/rust_freshness.py'), 1)
        executable = self.root / 'python3'
        executable.write_text('#!/bin/sh\ntest "$1" = scripts/repository/rust_freshness.py || exit 99\nexit 17\n')
        executable.chmod(0o755)
        env = dict(os.environ, PATH=str(self.root) + os.pathsep + os.environ['PATH'])
        result = subprocess.run(['sh', '-c', prefix], cwd=self.root, env=env,
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 17, result.stderr)
        self.assertIn('scripts/ci/install-ci-tools.sh --verify-only', driver)
        self.assertIn('python3 scripts/assurance/check-assurance.py --network', driver)
        self.assertIn('# BEGIN ACTION PIN CHECK', driver)


if __name__ == '__main__':
    unittest.main()
