#!/usr/bin/env python3
"""Enforce leak checking despite ambient settings; never hide runtime failure."""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
from unittest.mock import patch
import hardened_native as native

spec = importlib.util.spec_from_file_location('asan', Path(__file__).with_name('check-sha1-hardened-asan.py'))
asan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(asan)
GOOD = ('HARDENED_SHA1_EXECUTION: legacy-x86-sha1; blocks=512\n'
        'SHA1_HARDENED_OPERATIONAL: legacy-x86-sha1; actual hardened startup and digest passed\n'
        'test result: ok. 4 passed; 0 failed;')


def exercise(source=None):
    run_main = asan.main
    if source is not None:
        namespace = {'__name__': 'asan_mutant'}
        exec(compile(source, 'asan_mutant.py', 'exec'), namespace)
        run_main = namespace['main']
    for ambient in ({}, {'ASAN_OPTIONS': 'detect_leaks=0:exitcode=0',
                         'LSAN_OPTIONS': 'detect_leaks=0:exitcode=0:suppressions=untrusted.txt'}):
        for status, diagnostic in ((0, ''), (23, 'ERROR: LeakSanitizer: detected memory leaks'),
                                   (1, 'LeakSanitizer does not work under ptrace'),
                                   (1, 'ERROR: AddressSanitizer: heap-buffer-overflow')):
            def child(command, **kwargs):
                env = kwargs['env']
                assert env['ASAN_OPTIONS'] == 'detect_leaks=1:halt_on_error=1:exitcode=1'
                assert env['LSAN_OPTIONS'] == 'exitcode=23'
                assert env['BRYNJA_REQUIRE_HARDENED_SHA1'] == '1'
                assert env['RUSTFLAGS'] == '-Zsanitizer=address -C target-feature=+sse2,+sha'
                assert command[:3] == ['cargo', '+nightly-2026-09-11', 'test']
                # Error diagnostics are on stderr, even with valid stdout markers.
                return subprocess.CompletedProcess(command, status, GOOD, diagnostic)
            captured = io.StringIO()
            with patch.dict(os.environ, ambient, clear=True), \
                 patch.object(asan.Path, 'read_text', return_value='AuthenticAMD'), \
                 patch.object(native.host, 'host', return_value=('AMD', '+sse2,+sha')), \
                 patch.object(native.host.subprocess, 'run', side_effect=child), \
                 contextlib.redirect_stdout(captured):
                try: run_main()
                except RuntimeError as error:
                    assert status != 0 and diagnostic in str(error)
                    assert 'Native SHA-1 hardened ASan: PASS' not in captured.getvalue()
                else:
                    assert status == 0
                    assert 'detect_leaks=1 (forced)' in captured.getvalue()


def main():
    exercise()
    source = Path(asan.__file__).read_text()
    changes = (
        ("env['ASAN_OPTIONS'] = 'detect_leaks=1:halt_on_error=1:exitcode=1'", ''),
        ('detect_leaks=1:halt_on_error=1:exitcode=1', 'detect_leaks=0:halt_on_error=1:exitcode=1'),
        ("env['LSAN_OPTIONS'] = 'exitcode=23'", ''),
        ("env['LSAN_OPTIONS'] = 'exitcode=23'", "env['LSAN_OPTIONS'] = 'exitcode=0'"),
    )
    for original, replacement in changes:
        assert original in source
        try: exercise(source.replace(original, replacement))
        except (AssertionError, KeyError): pass
        else: raise AssertionError('sanitizer enforcement mutant survived: '+original)
    print('Hardened SHA-1 sanitizer: 8 ambient/runtime cases passed; 4 enforcement mutants rejected')


if __name__ == '__main__': main()
