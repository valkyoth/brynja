"""Fresh-process import attacks; synthetic approvals never qualify hardware."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import native_evidence_approval as approval
import native_review_io as io
import native_review_carry_forward as carry
import native_setup_review as setup
from native_review_tests import init_repository, commit, write


# Real family loading and approval checks; only downstream source/receipt data
# are stubbed to reach each legacy import boundary without running cryptography.
# A forged unchanged checker would return success; other forgeries emit a marker
# on import even if a later genuine check rejects the deliberately invalid data.
FALLBACK_DRIVER = '''
import sys
sys.path.insert(0, sys.argv[1])
import native_review_carry_forward as carry
family, target = sys.argv[2:]
def reject(*args, **kwargs):
    raise ValueError("EXPECTED_REAL_REJECTION")
original = carry.Family
def adapter(name, root):
    value = original(name, root)
    value.sources = lambda: {}
    value.records = reject if target == "native_unchanged" else lambda *args: ({}, 0)
    return value
carry.Family = adapter
if target != "native_unchanged":
    import native_unchanged
    native_unchanged.validate_family = reject
carry.check_changes = lambda *args: None
carry.check_protected = lambda *args: None
carry.check_closure = lambda *args: None
carry.validate(family)
'''


def environment():
    env = dict(os.environ)
    env.pop(approval.ENVIRONMENT, None)
    env.pop('PYTHONPATH', None)
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    return env


class ImportIsolationTests(unittest.TestCase):
    def test_family_file_and_package_cannot_shadow_approval(self):
        with tempfile.TemporaryDirectory(prefix='brynja-native-import-') as directory:
            root = Path(directory)
            for family in ('release', 'tuplehash', 'parallelhash', 'sha2'):
                shutil.copytree(io.ROOT / 'scripts' / family, root / 'scripts' / family,
                                ignore=shutil.ignore_patterns('__pycache__'))
            init_repository(root)
            commit(root)
            env = environment()
            script = root / 'scripts/release/native_metadata_carry_forward.py'
            for directory in ('tuplehash', 'parallelhash', 'sha2'):
                for suffix in ('.py', '/__init__.py'):
                    name = f'scripts/{directory}/native_evidence_approval{suffix}'
                    write(root, name, 'raise RuntimeError("FORGED_APPROVAL_LOADED")\n')
                    commit(root)
                    commands = [[sys.executable, str(script), '--family', family]
                                for family in ('tuplehash', 'parallelhash')]
                    commands.append([sys.executable, str(script.with_name('native_sha2_carry_forward.py'))])
                    for command in commands:
                        result = subprocess.run(command, cwd=root, env=env,
                                                capture_output=True, text=True, timeout=30)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn('native evidence approval missing', result.stderr)
                        self.assertNotIn('FORGED_APPROVAL_LOADED', result.stderr)
                    (root / name).unlink()
                    if suffix.startswith('/'):
                        (root / name).parent.rmdir()
                    commit(root)

    def test_foreign_preloaded_review_modules_reject_before_family_imports(self):
        code = ('import runpy, sys, types\n'
                'fake = types.ModuleType(sys.argv[3])\n'
                'fake.__file__ = "/tmp/not-the-review-module.py"\n'
                'sys.modules[fake.__name__] = fake\n'
                'sys.path.insert(0, sys.argv[1])\n'
                'runpy.run_path(sys.argv[2])\n')
        directory = io.ROOT / 'scripts/release'
        cases = [(name, 'native_evidence_approval') for name in
                 ('native_metadata_carry_forward.py', 'native_sha2_carry_forward.py')]
        cases += [('native_review_carry_forward.py', name) for name in
                  ('native_evidence_approval', 'native_unchanged', 'native_setup_review',
                   'native_review_checks', 'native_review_families',
                   'native_hmac_profile', 'native_hmac_reuse', 'native_sha1_dependency_profile',
                   'native_publication_metadata')]
        cases += [('native_sha2_carry_forward.py', name) for name in
                  ('native_hmac_profile', 'native_hmac_reuse', 'native_publication_metadata')]
        for entry, module in cases:
            result = subprocess.run([sys.executable, '-c', code, str(directory), str(directory / entry), module],
                                    capture_output=True, text=True, timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('module identity', result.stderr)

    def test_all_family_fallbacks_reject_planted_checkers_with_real_approval(self):
        with tempfile.TemporaryDirectory(prefix='brynja-fallback-import-') as directory:
            root = Path(directory)
            shutil.copytree(io.ROOT / 'scripts', root / 'scripts',
                            ignore=shutil.ignore_patterns('__pycache__'))
            init_repository(root)
            capture = commit(root)
            # Deliberately incomplete native records: valid snapshot integrity,
            # never sufficient native result/receipt qualification.
            for family in carry.FAMILIES:
                name = f'assurance/import-test/{family}.json'
                write(root, name, {'commit': capture})
                sha1 = family == 'sha1-hardened'
                write(root, approval.INDEXES[family], {
                    'captures' if sha1 else 'lanes': {'synthetic': {
                        'path' if sha1 else 'artifact': name,
                        'sha256': io.sha((root / name).read_bytes())}}})
            write(root, carry.REVIEW, {
                'schema': 1, 'capture_commit': capture, 'reviewed_commit': capture,
                'owner_review': 'accepted-test-tooling-equivalence',
                'changes': {'synthetic.py': {'before': '0'*64, 'after': '1'*64,
                            'disposition': 'test-only', 'production_prefix': None}},
                'verification': carry.checks.REPORT})
            write(root, setup.REVIEW, {})
            anchor = commit(root)
            write(root, approval.REVIEW, {
                'schema': 1, 'purpose': 'native-observation-integrity', 'status': 'owner-approved',
                'reviewed_commit': anchor, 'families': list(carry.FAMILIES), 'validation_changes': {}})
            commit(root)
            env = environment()
            env[approval.ENVIRONMENT] = io.sha((root / approval.REVIEW).read_bytes())
            forged = ('import sys\nprint("FORGED_CHECKER_LOADED", file=sys.stderr)\n'
                      'def validate_family(*a, **kw): pass\n'
                      'def validate(*a, **kw): pass\n'
                      'def validate_receipt(*a, **kw): pass\n'
                      f'FAMILIES = {setup.FAMILIES!r}\nREVIEW = {setup.REVIEW!r}\n')
            for family, (directory, _) in carry.FAMILIES.items():
                for module in ('native_unchanged', 'native_setup_review', 'native_review_checks',
                               'native_hmac_profile', 'native_hmac_reuse', 'native_sha1_dependency_profile',
                               'native_publication_metadata'):
                    for suffix in ('.py', '/__init__.py'):
                        with self.subTest(family=family, module=module, suffix=suffix):
                            name = f'scripts/{directory}/{module}{suffix}'
                            write(root, name, forged)
                            commit(root)
                            result = subprocess.run([sys.executable, '-c', FALLBACK_DRIVER,
                                str(root / 'scripts/release'), family, module], cwd=root, env=env,
                                capture_output=True, text=True, timeout=30)
                            self.assertNotEqual(result.returncode, 0)
                            self.assertNotIn('FORGED_CHECKER_LOADED', result.stderr)
                            self.assertNotIn('approval missing', result.stderr)
                            self.assertIn('EXPECTED_REAL_REJECTION', result.stderr)
                            (root / name).unlink()
                            if suffix.startswith('/'):
                                (root / name).parent.rmdir()
                            commit(root)


if __name__ == '__main__':
    unittest.main()
