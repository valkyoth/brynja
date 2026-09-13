"""Reject broadened deferrals and exercise the real committed-report shell gate."""
import copy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

import internal_deferral as policy


def main():
    count = 0
    with tempfile.TemporaryDirectory(prefix='brynja-internal-deferral-') as tmp:
        root = Path(tmp)
        names = set(policy.md5_execution_policy.paths()) | set(policy.md5_execution_policy.GATES)
        names.update((policy.md5_execution_policy.REVIEW, policy.RECORD, 'rust-toolchain.toml',
                      'release-crates.toml', 'security/pentest/v0.24.43.md',
                      'scripts/release/internal_deferral.py',
                      'scripts/release/validate-release-readiness.sh'))
        for name in names:
            destination = root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(policy.ROOT / name, destination)
        policy.validate(root)

        def rejects():
            try:
                policy.validate(root)
            except (ValueError, KeyError, TypeError, OSError):
                return
            raise AssertionError('broadened internal deferral accepted')

        for key in policy.EXPECTED:
            for missing in (True, False):
                changed = copy.deepcopy(policy.EXPECTED)
                if missing:
                    del changed[key]
                else:
                    changed[key] = True if key == 'schema' else 'unauthorized'
                (root / policy.RECORD).write_text(json.dumps(changed))
                rejects()
                count += 1
        (root / policy.RECORD).write_text(json.dumps(policy.EXPECTED))

        report = root / 'security/pentest/v0.24.43.md'
        original_report = report.read_text()
        for key, value in policy.FIELDS.items():
            line = key + ': ' + value
            for replacement in ('', key + ': unauthorized', line + '\n' + line):
                report.write_text(original_report.replace(line, replacement, 1))
                rejects()
                count += 1
        report.write_text(original_report)

        mutations = (
            ('release-crates.toml', 'stage = "internal"', 'stage = "public"'),
            ('release-crates.toml', 'version = "0.24.43"', 'version = "0.24.44"'),
            ('release-crates.toml', 'milestone = "0.24.43"', 'milestone = "0.24.44"'),
            ('release-crates.toml', 'exceptional = true', 'exceptional = false'),
            ('release-crates.toml', 'publish = false', 'publish = true'),
            ('release-crates.toml', 'publish = false', 'publish = 0'),
            ('rust-toolchain.toml', '1.98.1', '1.90.0'),
            (policy.md5_execution_policy.REVIEW, '"schema": 1', '"schema": 2'),
            ('crates/brynja-legacy-md5/src/batch/execution.rs', 'owner.commit_public(output);',
             'let _ = output;'),
        )
        for name, before, after in mutations:
            path = root / name
            original = path.read_text()
            assert before in original
            path.write_text(original.replace(before, after, 1))
            rejects()
            path.write_text(original)
            count += 1
        for version, publish in (('v0.24.44', ''), ('v0.25.2', ''),
                                 (policy.VERSION, policy.VERSION)):
            try:
                policy.validate(root, version, publish)
            except ValueError:
                count += 1
            else:
                raise AssertionError('another release or publication context accepted')

        def git(*args):
            subprocess.run(['git', '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null',
                            *args], cwd=root, check=True, capture_output=True, timeout=30)

        git('init', '-q')
        git('config', 'user.name', 'Deferral fixture')
        git('config', 'user.email', 'deferral@example.invalid')
        # Prevent Python import caches from appearing as untracked candidate data.
        (root / '.gitignore').write_text('__pycache__/\n')

        def commit():
            with report.open('a') as stream:
                stream.write('\nFixture review updated.\n')
            git('add', '.')
            git('commit', '-qm', 'test(release): exercise internal deferral')

        def gate(passed, *arguments):
            result = subprocess.run(['bash', 'scripts/release/validate-release-readiness.sh',
                                     *arguments, policy.VERSION], cwd=root, text=True,
                                    capture_output=True, timeout=30)
            assert (result.returncode == 0) == passed, result.stdout + result.stderr
            if passed:
                assert 'one finding remains open' in result.stdout
                assert 'PASS pentest report' not in result.stdout

        commit()
        gate(True)
        gate(True, '--allow-pending')
        plan_path = root / 'release-crates.toml'
        original_plan = plan_path.read_text()
        plan_path.write_text(original_plan.replace('stage = "internal"', 'stage = "public"'))
        commit()
        gate(False)
        plan_path.write_text(original_plan)
        report.write_text(original_report.replace('Open-Findings: 1', 'Open-Findings: 2'))
        commit()
        gate(False)
        report.write_text(original_report.replace('Retest: PASS WITH DEFERRAL', 'Retest: FAIL'))
        commit()
        gate(False)
    print(f'Internal MD5 deferral rejects {count} identity, scope, approval, publication and source regressions')
    print('Committed-report gate: two explicit-deferral passes and three nonwaivable rejection cases passed')


if __name__ == '__main__':
    main()
