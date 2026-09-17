"""Fast failure-path checks for the optional SDE execution driver."""
import contextlib
import importlib.util
import io
from pathlib import Path
import subprocess
from unittest.mock import patch


def regressions():
    path = Path(__file__).with_name('check-x86-sha512.py')
    spec = importlib.util.spec_from_file_location('x86_sha512_driver', path)
    driver = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(driver)
    markers = ('named=240; general=4590', 'wide=Static(X86Sha512)')
    positive = '\n'.join(markers)
    cases = ((1, positive), (-4, positive), (0, ''),
             (0, markers[0]), (0, markers[1]),
             (0, positive.replace('X86Sha512', 'ArmSha512')),
             (0, positive.replace('4590', '4589')))
    with contextlib.redirect_stdout(io.StringIO()):
        for code, output in ((0, positive), *cases):
            result = subprocess.CompletedProcess(['probe'], code, stdout=output)
            with patch.object(driver.subprocess, 'run', return_value=result) as execute:
                try:
                    actual = driver.run(['probe'], {}, markers)
                except RuntimeError:
                    assert (code, output) in cases
                else:
                    assert (code, output) == (0, positive) and actual == positive
                assert execute.call_args.kwargs['timeout'] == 600
        with patch.object(driver.subprocess, 'run',
                          side_effect=subprocess.TimeoutExpired(['probe'], 600)):
            try:
                driver.run(['probe'], {}, markers)
            except subprocess.TimeoutExpired:
                pass
            else:
                raise AssertionError('timeout was silently accepted')
        hostile = {'ASAN_OPTIONS': 'detect_leaks=0:exitcode=0', 'LSAN_OPTIONS': 'exitcode=0',
                   'RUSTFLAGS': '-C target-feature=-sha512'}
        with patch.object(driver, 'run') as execute:
            driver.sanitizer(hostile)
            assert execute.call_count == 2
            for call in execute.call_args_list:
                command, env, expected = call.args
                assert '+nightly-2026-09-11' in command
                assert env['ASAN_OPTIONS'] == 'detect_leaks=1:halt_on_error=1:exitcode=1'
                assert env['LSAN_OPTIONS'] == 'exitcode=23'
                assert env['RUSTFLAGS'] == '-Zsanitizer=address -C target-feature=+sha512,+avx2,+avx'
                assert any('X86Sha512' in marker or 'DEDICATED_X86_SHA512' in marker for marker in expected)
        assert hostile['LSAN_OPTIONS'] == 'exitcode=0'
    print('Dedicated SHA512 driver rejects seven exit/coverage/route regressions and timeout')
    print('Dedicated SHA512 sanitizer overrides hostile ambient disable/exit settings')


if __name__ == '__main__':
    regressions()
