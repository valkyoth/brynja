#!/usr/bin/env python3
"""Exercise native selection, forced sanitizer options and non-vacuous results."""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
from unittest.mock import patch

PATH = Path(__file__).with_name('check-hardened-batch-asan.py')
spec = importlib.util.spec_from_file_location('hardened_asan', PATH)
asan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(asan)


def rejected(action):
    try:
        action()
    except (RuntimeError, ValueError, subprocess.TimeoutExpired):
        return
    raise AssertionError('invalid execution accepted')


def exercise(module):
    assert len(module.SUITES) == 6
    for machine, cpu, flags, kernel in (
            ('x86_64', 'flags : avx avx2\nflags : avx2 avx', '+avx,+avx2', 'Avx2'),
            ('aarch64', 'Features : asimd\nFeatures : asimd aes', '+neon', 'Neon')):
        with patch.object(module.platform, 'system', return_value='Linux'), \
             patch.object(module.platform, 'machine', return_value=machine), \
             patch.object(module.Path, 'read_text', return_value=cpu):
            assert module.native_host() == (flags, kernel, machine + '-unknown-linux-gnu')
            for invalid in ('', cpu + '\n' + cpu.split(':')[0] + ': missing'):
                with patch.object(module.Path, 'read_text', return_value=invalid):
                    rejected(module.native_host)
        for ambient in ({}, {'ASAN_OPTIONS': 'detect_leaks=0:exitcode=0',
                             'LSAN_OPTIONS': 'exitcode=0:suppressions=untrusted',
                             'RUSTFLAGS': '-C panic=abort', 'RUSTC_WRAPPER': 'untrusted',
                             'CARGO_BUILD_TARGET': 'wasm32-unknown-unknown',
                             'CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER': 'untrusted',
                             'CARGO_ENCODED_RUSTFLAGS': '-Copt-level=0'}):
            with patch.dict(os.environ, ambient, clear=True):
                env = module.environment(flags, '/tmp/example-target')
            assert env['ASAN_OPTIONS'] == 'detect_leaks=1:halt_on_error=1:exitcode=1'
            assert env['LSAN_OPTIONS'] == 'exitcode=23'
            assert env['RUSTFLAGS'] == '-Zsanitizer=address -C target-feature=' + flags
            assert env['CARGO_TARGET_DIR'] == '/tmp/example-target'
            assert all(env['BRYNJA_REQUIRE_' + name] == '1' for name in module.REQUIRED)
            assert not any(key in env for key in ambient if key not in ('ASAN_OPTIONS', 'LSAN_OPTIONS', 'RUSTFLAGS'))
        for package, _, _, tests in module.SUITES:
            good = '\n'.join('test ' + name + ' ... ok' for name in tests)
            marker = '\nHARDENED_KECCAK_BATCH_NATIVE: ' + kernel + '; pairs=1024'
            good += marker if package == 'brynja-crypto-cpu' else ''
            result = subprocess.CompletedProcess([], 0, good, '')
            module.validate(result, package, tests, kernel)
            for status, stderr in ((23, 'ERROR: LeakSanitizer'), (1, 'ptrace denied'),
                                   (1, 'ERROR: AddressSanitizer'), (0, 'ERROR: LeakSanitizer')):
                bad = subprocess.CompletedProcess([], status, good, stderr)
                rejected(lambda: module.validate(bad, package, tests, kernel))
            for missing in tests:
                bad = subprocess.CompletedProcess([], 0, good.replace('test ' + missing + ' ... ok', ''), '')
                rejected(lambda: module.validate(bad, package, tests, kernel))
            if package == 'brynja-crypto-cpu':
                bad = subprocess.CompletedProcess([], 0, good.replace(marker, ''), '')
                rejected(lambda: module.validate(bad, package, tests, kernel))
    with patch.object(module.platform, 'system', return_value='Darwin'):
        rejected(module.native_host)
    with patch.object(module.platform, 'system', return_value='Linux'), \
         patch.object(module.platform, 'machine', return_value='riscv64'):
        rejected(module.native_host)


def orchestration():
    def child(command, **kwargs):
        suite = asan.SUITES[calls[0]]
        package, features, selection, tests = suite
        assert command == ['cargo', '+nightly-2026-09-11', 'test', '--locked', '--offline',
                           '-p', package, '--features', features, '--target', 'x86_64-unknown-linux-gnu',
                           '--lib', selection, '--', '--show-output']
        assert kwargs['cwd'] == asan.ROOT and kwargs['timeout'] == 900
        assert kwargs['env']['ASAN_OPTIONS'].startswith('detect_leaks=1:')
        calls[0] += 1
        output = '\n'.join('test ' + name + ' ... ok' for name in tests)
        output += '\nHARDENED_KECCAK_BATCH_NATIVE: Avx2; pairs=1024'
        return subprocess.CompletedProcess(command, 0, output, '')
    calls = [0]
    captured = io.StringIO()
    with patch.object(asan, 'native_host', return_value=('+avx,+avx2', 'Avx2', 'x86_64-unknown-linux-gnu')), \
         patch.object(asan.subprocess, 'run', side_effect=child), contextlib.redirect_stdout(captured):
        asan.main()
    assert calls[0] == 6 and 'six layers; Avx2' in captured.getvalue()
    captured = io.StringIO()
    with patch.object(asan, 'native_host', return_value=('+avx,+avx2', 'Avx2', 'x86_64-unknown-linux-gnu')), \
         patch.object(asan.subprocess, 'run', side_effect=subprocess.TimeoutExpired('cargo', 900)), \
         contextlib.redirect_stdout(captured):
        rejected(asan.main)
    assert 'PASS' not in captured.getvalue()


def main():
    exercise(asan)
    orchestration()
    source = PATH.read_text()
    mutations = (
        ('detect_leaks=1:halt_on_error=1:exitcode=1', 'detect_leaks=0:halt_on_error=1:exitcode=1'),
        ('detect_leaks=1:halt_on_error=1:exitcode=1', 'detect_leaks=1:halt_on_error=0:exitcode=0'),
        ("env['LSAN_OPTIONS'] = 'exitcode=23'", "env['LSAN_OPTIONS'] = 'exitcode=0'"),
        ("env['BRYNJA_REQUIRE_' + name] = '1'", 'pass'),
        ('if result.returncode != 0:', 'if False:'),
        ("if 'test ' + test + ' ... ok' not in lines:", 'if False:'),
        ("if package == 'brynja-crypto-cpu' and (", 'if False and ('),
    )
    for old, new in mutations:
        assert source.count(old) == 1
        mutant = type('Module', (), {})()
        namespace = {'__file__': str(PATH.resolve()), '__name__': 'asan_mutant'}
        exec(compile(source.replace(old, new), str(PATH), 'exec'), namespace)
        mutant.__dict__.update(namespace)
        try:
            exercise(mutant)
        except (AssertionError, KeyError):
            pass
        else:
            raise AssertionError('surviving enforcement mutation: ' + old)
    print('Hardened batch sanitizer host/environment/results/orchestration checks: PASS; 7 mutants rejected')


if __name__ == '__main__':
    main()
