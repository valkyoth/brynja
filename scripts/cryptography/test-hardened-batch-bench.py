#!/usr/bin/env python3
"""Exercise benchmark coverage/routes and compiled timing-fixture regressions."""
import argparse
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile

spec = importlib.util.spec_from_file_location('hardened_bench_driver', Path(__file__).with_name('check-hardened-batch-bench.py'))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
common = driver.common


def synthetic(mode, arm):
    lines = []
    for key in sorted(driver.cases()):
        family, name, length, lanes, shape = key
        calls = driver.expected_calls(key, mode, arm)
        calls = 7 if calls is None else calls
        kernel = ('Neon' if arm else 'Avx2') if calls else 'None'
        lines.append(f'HARDENED_BATCH_BENCH: family={family}; algorithm={name}; bytes={length}; '
                     f'lanes={lanes}; shape={shape}; mode={mode}; samples=7; portable_ns=10; '
                     f'selected_ns=20; vector_calls={calls}; kernel={kernel}')
    return '\n'.join(lines + [driver.MARKER]) + '\n'


def validation_tests():
    rejected = 0
    for mode in ('portable', 'prefer'):
        for arm in (False, True):
            text = synthetic(mode, arm)
            result = lambda value, status=0: subprocess.CompletedProcess([], status, value, '')
            # Slower results MUST pass and remain visible, never filtered out.
            assert driver.validate(result(text), mode, arm) == 640
            assert driver.validate(result(text.replace('selected_ns=20', 'selected_ns=5')), mode, arm) == 0
            lines = text.splitlines()
            variants = [('', 0), (text, 1), ('\n'.join(lines[1:]) + '\n', 0),
                        ('\n'.join([lines[0]] + lines) + '\n', 0)]
            for before, after in (('samples=7', 'samples=6'), ('portable_ns=10', 'portable_ns=0'),
                                  ('selected_ns=20', 'selected_ns=0'), ('shape=balanced', 'shape=unknown'),
                                  ('algorithm=cshake128', 'algorithm=unknown'), ('lanes=1', 'lanes=9'),
                                  (f'mode={mode}', 'mode=invalid'), ('threshold=1', 'threshold=2'),
                                  ('timing=digest,validate,drop', 'timing=digest'),
                                  ('independent_review=NO', 'independent_review=YES'),
                                  ('vector_calls=0', 'vector_calls=7'), ('kernel=None', 'kernel=Avx2')):
                variants.append((text.replace(before, after, 1), 0))
            if mode == 'prefer':
                variants += [(text.replace('kernel=Neon' if arm else 'kernel=Avx2', 'kernel=None'), 0),
                             (text.replace('vector_calls=7;', 'vector_calls=0;', 1), 0)]
            for changed, status in variants:
                try:
                    driver.validate(result(changed, status), mode, arm)
                except ValueError:
                    rejected += 1
                else:
                    raise AssertionError('benchmark result regression survived')
    print(f'Hardened benchmark validator: {rejected} regressions rejected; slower results retained')


def compiled(lane):
    features = common.native.host(lane)[1]
    env = common.environment(features)
    with tempfile.TemporaryDirectory(prefix='brynja-hardened-bench-mutants-') as temporary:
        root = Path(temporary)
        fixture = root / 'fixture'
        shutil.copytree(driver.FIXTURE, fixture, ignore=shutil.ignore_patterns('target'))
        manifest = fixture / 'Cargo.toml'
        manifest.write_text(manifest.read_text().replace('../../crates/', str(common.ROOT / 'crates') + '/'))
        env['CARGO_TARGET_DIR'] = str(root / 'target')
        binary = root / 'target/release/brynja-hardened-batch-bench'

        def execute():
            common.run(['cargo', '+1.98.1', 'build', '--release', '--locked', '--offline'], fixture, env)
            return subprocess.run([str(binary), 'prefer'], env=env, text=True, capture_output=True, timeout=120)

        driver.validate(execute(), 'prefer', features == '+neon')
        mutations = (
            ('sha2.rs', 'drop(owned);', 'core::mem::forget(owned);', 'secret Drop/inactive/canary cleanup'),
            ('keccak.rs', 'drop(owned);', 'core::mem::forget(owned);', 'secret Drop/inactive/canary cleanup'),
            ('common.rs', 'let mut calls = 0_u64;', 'let mut calls = u64::MAX;', 'benchmark vector counter overflow'),
            ('sha2.rs', 'Mode::Prefer', 'Mode::Portable', None),
            ('keccak.rs', 'if staging.iter().any(|byte| *byte != 0)',
             'staging[0] = 1;\n                        if staging.iter().any(|byte| *byte != 0)', 'benchmark staging cleanup'),
            ('common.rs', 'black_box(actual) != expected', 'black_box(actual) == expected', 'timed digest output mismatch'),
        )
        for filename, before, after, diagnostic in mutations:
            source = fixture / 'src' / filename
            original = source.read_text()
            if original.count(before) != 1:
                raise AssertionError('mutation anchor drift: ' + before)
            try:
                source.write_text(original.replace(before, after))
                actual = execute()  # Build failure is not a runtime rejection.
                if diagnostic:
                    if not actual.returncode or diagnostic not in actual.stderr or 'panicked' in actual.stderr:
                        raise AssertionError('fixture mutation did not fail cleanly: ' + before)
                else:
                    if actual.returncode:
                        raise AssertionError('route mutant failed before result validation')
                    try:
                        driver.validate(actual, 'prefer', features == '+neon')
                    except ValueError:
                        pass
                    else:
                        raise AssertionError('false route accepted')
            finally:
                source.write_text(original)
            driver.validate(execute(), 'prefer', features == '+neon')
    print('Hardened benchmark fixture: six compiled regressions rejected; restored source passed')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lane', choices=common.native.LANES)
    args = parser.parse_args()
    validation_tests()
    if args.lane:
        compiled(args.lane)
