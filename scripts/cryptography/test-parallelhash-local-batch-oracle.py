#!/usr/bin/env python3
"""Reject incomplete local oracle results and compiled fixture regressions."""
import argparse
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile

spec = importlib.util.spec_from_file_location('parallel_local_driver', Path(__file__).with_name('check-parallelhash-local-batch-oracle.py'))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
common = driver.common


def result(mode, layout, stdout='01\n', count=1, status=0, calls=None):
    if calls is None:
        calls = 0 if mode == 'portable' else 6
    marker = (f'PARALLELHASH_LOCAL_ORACLE: cases={count}; vector_calls={calls}; layout={layout}; '
              'profiles=public,secret; cleanup=drop,scratch,stream')
    return subprocess.CompletedProcess([], status, stdout, marker)


def compiled(lane):
    env = common.environment(common.native.host(lane)[1])
    message = bytes(range(12))
    cases = []
    for algorithm, rate, xof in (('parallel128', 168, False), ('parallel256', 136, False),
                                 ('parallelxof128', 168, True), ('parallelxof256', 136, True)):
        expected = common.oracle.parallel_hash(rate, common.oracle.oracle.byte_bits(message), 1, [], 256, xof)
        cases.append((algorithm, b'', 0, message, 96, 1, 256, expected))
    expected = [case[-1].hex() for case in cases]
    data = common.encode(cases)
    with tempfile.TemporaryDirectory(prefix='brynja-parallel-local-mutants-') as temporary:
        root = Path(temporary)
        fixture = root / 'fixture'
        shutil.copytree(common.FIXTURE, fixture, ignore=shutil.ignore_patterns('target'))
        manifest = fixture / 'Cargo.toml'
        manifest.write_text(manifest.read_text().replace('../../crates/', str(common.ROOT / 'crates') + '/'))
        env['CARGO_TARGET_DIR'] = str(root / 'target')
        binary = root / 'target/release/local'
        source = fixture / 'src/bin/local.rs'
        original = source.read_text()

        def build():
            common.run(['cargo', '+1.98.1', 'build', '--locked', '--offline', '--release', '--bin', 'local'], fixture, env)

        def execute(layout, input_data=data):
            return subprocess.run([str(binary), 'required', layout], env=env, input=input_data,
                                  text=True, capture_output=True, timeout=60)

        def restored():
            source.write_text(original)
            build()
            for layout in driver.LAYOUTS:
                driver.validate(execute(layout), expected, 'required', layout)

        restored()
        mutations = (
            ('drop(owned);', 'core::mem::forget(owned);', 3, driver.LAYOUTS, 'Drop/canary cleanup'),
            ('"{byte:02x}"', '"{:02x}", byte ^ 1', 1, driver.LAYOUTS, None),
            ('"required" => batch::Mode::Require', '"required" => batch::Mode::Portable', 1, driver.LAYOUTS, None),
            ('let mut total_vector = 0_u64;', 'let mut total_vector = u64::MAX;', 1, driver.LAYOUTS, 'vector counter overflow'),
            ('if storage.iter().any(|byte| *byte != 0) {',
             'storage[0] = 1;\n    if storage.iter().any(|byte| *byte != 0) {', 1,
             driver.LAYOUTS[1:], 'stream pending storage cleanup'),
            ('check(stream.update(part, &mut control))?;', 'let _ = part;', 1,
             ('stream-byte', 'stream-block'), 'stream prefix accounting'),
        )
        rejected = 0
        try:
            for before, after, occurrences, layouts, diagnostic in mutations:
                if original.count(before) != occurrences:
                    raise AssertionError('compiled mutation anchor drift: ' + before)
                source.write_text(original.replace(before, after))
                build()  # A compilation error never counts as runtime rejection.
                for layout in layouts:
                    # Separate processes prevent an early fixed-output rejection
                    # from hiding untested XOF cleanup paths.
                    for case in cases:
                        actual = execute(layout, common.encode([case]))
                        if diagnostic:
                            if actual.returncode == 0 or actual.stdout or diagnostic not in actual.stderr or 'panicked' in actual.stderr:
                                raise AssertionError('compiled mutant did not fail cleanly: ' + before + '/' + layout)
                        else:
                            if actual.returncode:
                                raise AssertionError('output/route mutant failed before comparison')
                            try:
                                driver.validate(actual, [case[-1].hex()], 'required', layout)
                            except ValueError:
                                pass
                            else:
                                raise AssertionError('compiled mutant survived: ' + before + '/' + layout)
                        rejected += 1
                restored()
        finally:
            source.write_text(original)
    print(f'Local ParallelHash fixture: six compiled mutations rejected across {rejected} identity/layout executions; restored source passed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lane', choices=common.native.LANES)
    args = parser.parse_args()
    rejected = 0
    for mode in ('portable', 'prefer', 'required'):
        for layout in driver.LAYOUTS:
            good = result(mode, layout)
            driver.validate(good, ['01'], mode, layout)
            bad_results = [result(mode, layout, stdout=''), result(mode, layout, stdout='00\n'),
                           result(mode, layout, count=0), result(mode, layout, count=2),
                           result(mode, layout, status=1), result(mode, 'invalid'),
                           result(mode, layout, calls=1 if mode == 'portable' else 0)]
            for marker in ('', good.stderr + '\n' + good.stderr,
                           good.stderr.replace('profiles=public,secret', 'profiles=public'),
                           good.stderr.replace('cleanup=drop,scratch,stream', 'cleanup=drop,scratch')):
                bad_results.append(subprocess.CompletedProcess([], 0, good.stdout, marker))
            for bad in bad_results:
                try:
                    driver.validate(bad, ['01'], mode, layout)
                except ValueError:
                    rejected += 1
                else:
                    raise AssertionError('invalid local oracle result accepted')
    print(f'Local ParallelHash result checker: {rejected} regressions rejected')
    if args.lane:
        compiled(args.lane)


if __name__ == '__main__':
    main()
