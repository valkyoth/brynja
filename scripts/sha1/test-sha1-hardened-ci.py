#!/usr/bin/env python3
"""Require real kernel markers and prove missing feature flags fail tests."""
import importlib.util
import contextlib
import io
import platform
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch
import hardened_native as native

spec = importlib.util.spec_from_file_location('ci', Path(__file__).with_name('check-sha1-hardened-ci.py'))
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)


def main():
    for arch, kernel in (('x86_64', 'legacy-x86-sha1'), ('aarch64', 'legacy-aarch64-sha1')):
        good = f'HARDENED_SHA1_EXECUTION: {kernel}; blocks=512\nSHA1_HARDENED_OPERATIONAL: {kernel}; actual hardened startup and digest passed\ntest result: ok. 4 passed; 0 failed;'
        for bad in (None, 'missing-host', '', good.replace('512', '0'), good.replace('4 passed', '0 passed'), good.replace('OPERATIONAL', 'SKIPPED')):
            def run(command, env):
                assert env['BRYNJA_REQUIRE_HARDENED_SHA1'] == '1'
                assert env['RUSTFLAGS'] == '-C target-feature='+features
                assert '--lib' in command and '--test' in command and 'hardened_execution' in command
                return good if bad is None else bad
            features = '+sse2,+sha' if arch=='x86_64' else '+neon,+sha2'
            with patch.object(sys, 'argv', ['ci', arch]), patch.object(ci.platform, 'system', return_value='Linux'), \
                 patch.object(ci.platform, 'machine', return_value=arch), patch.object(ci.Path, 'read_text', return_value='AuthenticAMD'), \
                 patch.object(native.host, 'host', return_value=('CI', features)) as host, \
                 patch.object(native.host, 'run', side_effect=run) as execute, contextlib.redirect_stdout(io.StringIO()):
                if bad == 'missing-host': host.side_effect = ValueError('missing features')
                try: ci.main()
                except ValueError:
                    assert bad is not None
                    if bad == 'missing-host': execute.assert_not_called()
                else: assert bad is None
    compiled = 0
    machine = platform.machine().lower()
    disabled = '-sha' if machine in ('x86_64', 'amd64') else '-sha2' if machine in ('aarch64', 'arm64') else None
    if disabled is not None:
        with tempfile.TemporaryDirectory(prefix='brynja-sha1-required-negative-') as temporary:
            env = native.clean_environment()
            env.update(CARGO_TARGET_DIR=temporary, RUSTFLAGS='-C target-cpu=generic -C target-feature='+disabled,
                       BRYNJA_REQUIRE_HARDENED_SHA1='1')
            for target, case in ((['--lib'], 'native_hardened_kernel_matches_512_arbitrary_compressions'),
                                 (['--test', 'hardened_execution'], 'required_route_executes_without_candidate_admission')):
                command = ['cargo', 'test', '--locked', '--offline', '-p', 'brynja-legacy-sha1', '--features', 'hardened-execution', *target, case]
                result = subprocess.run(command, cwd=native.policy.ROOT, env=env, text=True, capture_output=True, timeout=180)
                if result.returncode == 0 or 'test result: FAILED' not in result.stdout or 'has no compiled CPU feature bundle' not in result.stdout:
                    raise AssertionError('missing-flags test passed or failed for the wrong reason: '+result.stdout+result.stderr)
                compiled += 1
    print(f'Hardened SHA-1 CI: two-architecture driver model, 10 orchestration negatives, {compiled} missing-flags compiled rejections passed')


if __name__ == '__main__': main()
