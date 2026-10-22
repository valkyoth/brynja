"""Fast failure-path checks for the optional SDE execution driver."""
import contextlib
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
from types import SimpleNamespace
from unittest.mock import patch


def hardened_output_regressions(driver):
    scratch = 'test hardened_execution::tests::scratch_regions_clear_on_explicit_wipe_and_unwind ...'
    kernel = 'test hardened_execution::tests::hardened_kernel_matches_ordinary_and_clears_every_operation ...'
    marker = 'HARDENED_KERNEL_EXECUTION: X86Sha512; blocks=512'
    summary = 'test result: ok. 2 passed; 0 failed; 0 ignored;'
    expected = (scratch, kernel, marker, summary)
    assert driver.HARDENED_MARKERS == expected
    serial = f'{scratch} ok\n{kernel}\n{marker}\nok\n{summary} 29 filtered out;\n'
    # Reproduce CI: the other worker prints while libtest is reporting scratch.
    interleaved = f'{scratch}\n{marker}\nok\n{kernel} ok\n{summary} 29 filtered out;\n'
    rejected = [(1, interleaved), (-4, interleaved), (23, interleaved), (0, '')]
    rejected += [(0, interleaved.replace(token, '')) for token in expected]
    rejected += [(0, interleaved.replace(summary, replacement)) for replacement in (
        'test result: ok. 0 passed; 0 failed; 2 ignored;',
        'test result: ok. 1 passed; 0 failed; 1 ignored;',
        'test result: ok. 3 passed; 0 failed; 0 ignored;',
        'test result: FAILED. 1 passed; 1 failed; 0 ignored;')]
    rejected += [(0, interleaved.replace('X86Sha512', 'ArmSha512')),
                 (0, interleaved.replace('blocks=512', 'blocks=511'))]
    with contextlib.redirect_stdout(io.StringIO()):
        for code, output in ((0, serial), (0, interleaved), *rejected):
            result = subprocess.CompletedProcess(['probe'], code, stdout=output)
            with patch.object(driver.subprocess, 'run', return_value=result):
                try:
                    actual = driver.run(['probe'], {}, driver.HARDENED_MARKERS)
                except RuntimeError:
                    assert (code, output) in rejected
                else:
                    assert (code, output) in ((0, serial), (0, interleaved))
                    assert actual == output
        with tempfile.TemporaryDirectory(prefix='brynja-sde-driver-test-') as directory:
            sde = Path(directory)/'sde64'
            sde.write_text('synthetic driver test; never executed\n')
            sde.chmod(0o700)
            assembly = ('vsha512msg1 %ymm1, %ymm0\nvsha512msg2 %ymm1, %ymm0\n'
                        'vsha512rnds2 %ymm2, %ymm1, %ymm0\ncompress_sha512 BRYNJA_SECRET_BEGIN\n')
            with patch.object(sys, 'argv', [str(driver.__file__), '--sde', str(sde)]), \
                    patch.object(driver, 'run') as execute, \
                    patch.object(Path, 'glob', return_value=[SimpleNamespace(read_text=lambda: assembly)]), \
                    patch.object(driver.x86_sha512_package, 'check'):
                driver.main()
            calls = [call for call in execute.call_args_list if 'hardened_execution::tests' in call.args[0]]
            assert len(calls) == 4
            assert sum('--release' in call.args[0] for call in calls) == 2
            for call in calls:
                assert call.args[2] == expected
    print(f'Dedicated SHA512 output: serial/interleaved PASS; {len(rejected)} exit/population/identity regressions rejected')


def regressions():
    path = Path(__file__).with_name('check-x86-sha512.py')
    spec = importlib.util.spec_from_file_location('x86_sha512_driver', path)
    driver = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(driver)
    hardened_output_regressions(driver)
    ordinary = driver.x86_sha512_package.helper('check-sha2-execution')
    root = path.resolve().parents[2]
    inherited = tomllib.loads((root / 'Cargo.toml').read_text())['workspace']['dependencies']
    def require_path_closure(names):
        for name in names:
            manifest = tomllib.loads((root / 'crates' / name / 'Cargo.toml').read_text())
            for section in ('dependencies', 'dev-dependencies', 'build-dependencies'):
                for target, dependency in manifest.get(section, {}).items():
                    if dependency.get('workspace'):
                        dependency = inherited[target]
                    if 'path' in dependency and target not in names:
                        raise ValueError('missing packaged path dependency: ' + target)
    require_path_closure(ordinary.PACKAGES)
    for omitted in ('brynja-mac-kmac', 'brynja-hash-tuple'):
        try:
            require_path_closure(tuple(name for name in ordinary.PACKAGES if name != omitted))
        except ValueError as error:
            assert omitted in str(error)
        else:
            raise AssertionError('missing optional manifest was accepted')
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
        for output in (None, b'compiler progress\xff', 'running sanitizer'):
            log = io.StringIO()
            with contextlib.redirect_stdout(log), patch.object(driver.subprocess, 'run',
                    side_effect=subprocess.TimeoutExpired(['probe'], 600, output=output)):
                try:
                    driver.run(['probe'], {}, markers)
                except subprocess.TimeoutExpired:
                    pass
                else:
                    raise AssertionError('timeout was silently accepted')
            expected = output.decode('utf-8', errors='replace') if isinstance(output, bytes) else output or ''
            assert 'TIMEOUT:' in log.getvalue() and expected in log.getvalue()
        hostile = {'ASAN_OPTIONS': 'detect_leaks=0:exitcode=0', 'LSAN_OPTIONS': 'exitcode=0',
                   'RUSTFLAGS': '-C target-feature=-sha512'}
        with patch.object(driver, 'run') as execute:
            driver.sanitizer(hostile)
            assert execute.call_count == 3
            assert execute.call_args_list[0].args[0][-1] == '--no-run'
            for call in execute.call_args_list:
                command, env, *expected = call.args
                assert '+nightly-2026-09-11' in command
                assert env['ASAN_OPTIONS'] == 'detect_leaks=1:halt_on_error=1:exitcode=1'
                assert env['LSAN_OPTIONS'] == 'exitcode=23'
                assert env['RUSTFLAGS'] == '-Zsanitizer=address -C target-feature=+sha512,+avx2,+avx'
                if expected:
                    assert any('X86Sha512' in marker or 'DEDICATED_X86_SHA512' in marker for marker in expected[0])
                if 'hardened_execution::tests' in command:
                    assert expected == [driver.HARDENED_MARKERS]
        assert hostile['LSAN_OPTIONS'] == 'exitcode=0'
    print('Dedicated SHA512 driver rejects seven exit/coverage/route regressions and timeout')
    print('Dedicated SHA512 sanitizer overrides hostile ambient disable/exit settings')
    print('Dedicated SHA512 packager rejects both missing optional dependency manifests')


if __name__ == '__main__':
    regressions()
