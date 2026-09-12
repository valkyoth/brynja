#!/usr/bin/env python3
"""Capture orchestration rejects missing routes, coverage and dirty snapshots."""
import argparse
import importlib.util
import json
import tempfile
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('capture',
    Path(__file__).with_name('capture-sha1-execution-native.py'))
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)


def campaign(root, change=None):
    args = argparse.Namespace(attest_native=True, output=root/'result.json', lane='intel-x86_64')
    (root/'source.rs').write_text('reviewed source')
    calls = []

    def run(command, env=None):
        calls.append(command)
        if command == ['git', 'status', '--porcelain']:
            return ' M source.rs' if change == 'dirty' else ''
        if command == ['git', 'rev-parse', 'HEAD']:
            count = sum(c == command for c in calls)
            return '2'*40 if change == 'commit-drift' and count > 1 else '1'*40
        if command[0] == 'rustc':
            return 'rustc 1.98.1; native x86_64'
        if command[0] == 'python3':
            assert env['RUSTFLAGS'] == '-C target-feature=+sse2,+sha'
            if change == 'source-drift':
                (root/'source.rs').write_text('changed source')
            return 'Independent operational SHA-1 corpus: ' + ('1134' if change == 'oracle' else '1135')
        assert '--offline' in command and '--locked' in command
        assert 'brynja_sha1_cpu_evidence' not in env.get('RUSTFLAGS', '')
        if 'runtime-execution' in command:
            assert 'RUSTFLAGS' not in env
            return 'SHA1_HOSTED_OPERATIONAL: ' + ('Some(Aarch64Sha1)' if change == 'hosted' else 'None')
        if '--lib' in command:
            result = 'test result: ok. 4 passed\nSHA1_OPERATIONAL: legacy-x86-sha1; normal build; public only'
            if change == 'static': result = result.replace('legacy-x86-sha1', 'portable')
            if change == 'coverage': result = result.replace('4 passed', '0 passed')
            return result
        assert 'RUSTFLAGS' not in env
        return 'test result: ok. 4 passed'

    if change == 'attestation': args.attest_native = False
    if change == 'overwrite': args.output.write_text('existing evidence')
    with patch.object(capture.policy, 'ROOT', root), patch.object(capture.policy, 'BOUND', ['source.rs']), \
         patch.object(capture.policy, 'validate'), patch.object(capture.native, 'run', side_effect=run), \
         patch.object(capture.native, 'host', return_value=('GenuineIntel', '+sse2,+sha')):
        capture.capture(args)
    record = json.loads(args.output.read_text())
    assert record['profile'] == 'ordinary-public-only'
    assert record['independent_review'] is False and record['fips_validated'] is False
    assert record['hardened'] == 'portable-only'


def main():
    with tempfile.TemporaryDirectory(prefix='brynja-sha1-execution-capture-') as temporary:
        root = Path(temporary)
        campaign(root)
        (root/'result.json').unlink()
        for change in ('dirty', 'commit-drift', 'source-drift', 'static', 'hosted', 'coverage', 'oracle', 'attestation', 'overwrite'):
            try:
                campaign(root, change)
            except ValueError:
                pass
            else:
                raise AssertionError('accepted capture regression: '+change)
            if (root/'result.json').exists():
                assert change == 'overwrite'
                assert (root/'result.json').read_text() == 'existing evidence'
                (root/'result.json').unlink()
    print('Operational SHA-1 capture: positive control and nine fail-closed regressions passed')


if __name__ == '__main__': main()
