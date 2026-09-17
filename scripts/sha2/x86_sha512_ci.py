"""Offline fail-closed installer and separate SDE workflow regressions."""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / 'scripts/ci/install-sde.sh'
WORKFLOW = ROOT / '.github/workflows/dedicated-sha512.yml'


def validate(installer, workflow):
    for token in ('BRYNJA_ACCEPT_INTEL_SDE_LICENSE', 'sha256sum --check --status',
                  '94e97d623fec54385686e1e7ba65ebc9941748c05ee451423948334892bf2b50',
                  "--proto '=https' --proto-redir '=https'", '--no-same-owner --no-same-permissions'):
        if token not in installer:
            raise ValueError('SDE installer contract missing: ' + token)
    for token in ('push:', 'pull_request:', 'paths:', "github.repository == 'valkyoth/brynja'",
                  "BRYNJA_ACCEPT_INTEL_SDE_LICENSE: '1'", 'contents: read', 'timeout-minutes: 25',
                  '1.90.0 1.98.1 nightly-2026-09-11',
                  'python3 scripts/sha2/check-x86-sha512.py --sde "$sde_executable" --asan'):
        if token not in workflow:
            raise ValueError('SDE workflow contract missing: ' + token)


def regressions():
    installer, workflow = INSTALLER.read_text(), WORKFLOW.read_text()
    validate(installer, workflow)
    for old in ('BRYNJA_ACCEPT_INTEL_SDE_LICENSE', 'sha256sum --check --status',
                '94e97d623fec54385686e1e7ba65ebc9941748c05ee451423948334892bf2b50'):
        try:
            validate(installer.replace(old, 'removed'), workflow)
        except ValueError:
            pass
        else:
            raise AssertionError('installer policy mutant escaped')
    for old in ('--asan', "github.repository == 'valkyoth/brynja'", 'contents: read'):
        try:
            validate(installer, workflow.replace(old, 'removed'))
        except ValueError:
            pass
        else:
            raise AssertionError('workflow policy mutant escaped')
    with tempfile.TemporaryDirectory(prefix='brynja-sde-install-tests-') as directory:
        root = Path(directory)
        tools = root / 'bin'
        tools.mkdir()
        for name, body in {
            'uname': 'case "$1" in -s) echo Linux;; -m) echo x86_64;; esac',
            'curl': 'echo curl >> "$PROBE_LOG"; exit "$CURL_EXIT"',
            'sha256sum': 'echo checksum >> "$PROBE_LOG"; cat >/dev/null; exit "$HASH_EXIT"',
            'tar': '''echo extract >> "$PROBE_LOG"
while test "$1" != --directory; do shift; done
shift
mkdir -p "$1/sde-external-10.13.1-2026-07-28-lin"
touch "$1/sde-external-10.13.1-2026-07-28-lin/sde64"
chmod +x "$1/sde-external-10.13.1-2026-07-28-lin/sde64"''',
        }.items():
            path = tools / name
            path.write_text('#!/bin/sh\nset -eu\n' + body + '\n')
            path.chmod(0o700)
        log = root / 'calls'
        for acceptance, curl_exit, hash_exit, expected in (
            ('0', '0', '0', []), ('1', '22', '0', ['curl']),
            ('1', '0', '1', ['curl', 'checksum']),
            ('1', '0', '0', ['curl', 'checksum', 'extract']),
        ):
            log.write_text('')
            env = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ['PATH'],
                       TMPDIR=directory, PROBE_LOG=str(log),
                       BRYNJA_ACCEPT_INTEL_SDE_LICENSE=acceptance,
                       CURL_EXIT=curl_exit, HASH_EXIT=hash_exit)
            result = subprocess.run(['sh', str(INSTALLER)], env=env, text=True,
                                    capture_output=True, timeout=10)
            assert log.read_text().splitlines() == expected
            assert (result.returncode == 0) == (len(expected) == 3)
            if result.returncode == 0:
                assert Path(result.stdout.strip()).is_file()
    print('SDE installer: four execution cases and six installer/workflow regressions PASS')


if __name__ == '__main__':
    regressions()
