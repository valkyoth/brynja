#!/usr/bin/env python3
"""Check oracle completion/routes/thread coverage and compiled fixture regressions."""
import argparse
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile

spec = importlib.util.spec_from_file_location('parallel_oracle_driver', Path(__file__).with_name('check-parallelhash-batch-oracle.py'))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


def result(mode, workers, stdout='01\n', count=1, status=0, calls=None, observed=None):
    if calls is None:
        calls = 0 if mode == 'portable' else 6
    if observed is None:
        observed = workers
    marker = (f'PARALLELHASH_BATCH_ORACLE: cases={count}; vector_calls={calls}; workers={workers}; '
              f'max_thread_width={observed}; profiles=public,secret; cleanup=drop,scratch')
    return subprocess.CompletedProcess([], status, stdout, marker)


def selection():
    # Exact ceil(bit_length / block_bits), including just-over-group boundaries.
    cases = [('parallel128', b'', 0, b'', bits, block, 8, b'')
             for block in (1, 7, 136) for bits in (0, 1, 8, block * 32 - 1, block * 32, block * 32 + 1, block * 64)]
    assert driver.select(cases, 'portable') == cases
    assert driver.select(cases, 'prefer') == cases
    expected = [case for case in cases if case[4] in (case[5] * 32 - 1, case[5] * 32, case[5] * 64)]
    assert driver.select(cases, 'required') == expected


def compiled(lane):
    env = driver.environment(driver.native.host(lane)[1])
    message = bytes(range(12))
    expected = [driver.oracle.parallel_hash(168, driver.oracle.oracle.byte_bits(message), 1, [], 256, False).hex()]
    data = f'parallel128 0 - 96 {message.hex()} 1 256\n'
    with tempfile.TemporaryDirectory(prefix='brynja-parallel-batch-mutants-') as temporary:
        root = Path(temporary)
        fixture = root / 'fixture'
        shutil.copytree(driver.FIXTURE, fixture, ignore=shutil.ignore_patterns('target'))
        manifest = fixture / 'Cargo.toml'
        manifest.write_text(manifest.read_text().replace('../../crates/', str(driver.ROOT / 'crates') + '/'))
        env['CARGO_TARGET_DIR'] = str(root / 'target')
        binary = root / 'target/release/brynja-parallelhash-batch-oracle-fixture'
        source = fixture / 'src/main.rs'
        original = source.read_text()

        def execute():
            driver.run(['cargo', '+1.98.1', 'build', '--locked', '--offline', '--release'], fixture, env)
            return subprocess.run([str(binary), 'required', '3'], env=env, input=data,
                                  text=True, capture_output=True, timeout=60)

        driver.validate(execute(), expected, 'required', 3)
        cases = (
            ('drop(owned);', 'core::mem::forget(owned);', 'secret Drop/canary cleanup'),
            ('"{byte:02x}"', '"{:02x}", byte ^ 1', None),
            ('"required" => (Preference::Require, Mode::Require)',
             '"required" => (Preference::Portable, Mode::Portable)', None),
            ('let mut total_vector = 0_u64;', 'let mut total_vector = u64::MAX;', 'vector counter overflow'),
            ('        workers,\n', '        workers: 1,\n', 'leaf/group/thread/route accounting'),
            ('if scratch.iter().any(|byte| *byte != 0) || public.last() != Some(&0xa5) {',
             'scratch[0] = 1;\n        if scratch.iter().any(|byte| *byte != 0) || public.last() != Some(&0xa5) {', 'scratch/canary cleanup'),
        )
        try:
            for before, after, diagnostic in cases:
                if original.count(before) != 1:
                    raise AssertionError('compiled mutation anchor drift: ' + before)
                source.write_text(original.replace(before, after))
                actual = execute()  # Compilation failure is never evidence of runtime rejection.
                if diagnostic:
                    if actual.returncode == 0 or actual.stdout or diagnostic not in actual.stderr or 'panicked' in actual.stderr:
                        raise AssertionError('compiled mutant did not fail cleanly: ' + before)
                else:
                    if actual.returncode:
                        raise AssertionError('output/route mutant failed before comparison')
                    try:
                        driver.validate(actual, expected, 'required', 3)
                    except ValueError:
                        pass
                    else:
                        raise AssertionError('compiled mutant survived: ' + before)
                source.write_text(original)
                driver.validate(execute(), expected, 'required', 3)
        finally:
            source.write_text(original)
    print('Threaded ParallelHash fixture: six compiled cleanup/output/route/counter/worker mutants rejected; restored source passed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lane', choices=driver.native.LANES)
    args = parser.parse_args()
    selection()
    rejected = 0
    for mode in ('portable', 'prefer', 'required'):
        for workers in (1, 2, 3):
            good = result(mode, workers)
            expected = ['01']
            driver.validate(good, expected, mode, workers)
            cases = [result(mode, workers, stdout=''), result(mode, workers, stdout='00\n'),
                     result(mode, workers, count=0), result(mode, workers, count=2),
                     result(mode, workers, status=1), result(mode, workers, observed=0),
                     result(mode, workers, observed=workers + 1),
                     result(mode, workers, calls=1 if mode == 'portable' else 0)]
            for marker in ('', good.stderr + '\n' + good.stderr,
                           good.stderr.replace('profiles=public,secret', 'profiles=public'),
                           good.stderr.replace('cleanup=drop,scratch', 'cleanup=drop'),
                           good.stderr.replace(f'workers={workers};', 'workers=0;')):
                cases.append(subprocess.CompletedProcess([], 0, good.stdout, marker))
            for bad in cases:
                try:
                    driver.validate(bad, expected, mode, workers)
                except ValueError:
                    rejected += 1
                else:
                    raise AssertionError('invalid threaded oracle result accepted')
    print(f'Threaded ParallelHash result checker: {rejected} regressions rejected; required-group selection passed')
    if args.lane:
        compiled(args.lane)


if __name__ == '__main__':
    main()
