#!/usr/bin/env python3
"""Regression checks for threaded benchmark coverage, accounting and cleanup."""
import argparse
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile

spec = importlib.util.spec_from_file_location('parallel_bench_driver', Path(__file__).with_name('check-parallelhash-batch-bench.py'))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
common = driver.common


def synthetic(mode, arm):
    lines = []
    for key in sorted(driver.cases()):
        name, size, block, workers = key
        groups, threads, accelerated, calls = driver.accounting(key, mode, arm)
        bits = driver.ALGORITHMS[name][1]
        kernel = ('Neon' if arm else 'Avx2') if mode == 'prefer' else 'None'
        lines.append(f'PARALLELHASH_BATCH_BENCH: algorithm={name}; bytes={size}; block={block}; '
                     f'workers={workers}; output_bits={bits}; mode={mode}; selected_kernel={kernel}; '
                     f'samples=7; scheduled_ns=10; threaded_ns=20; groups={groups}; '
                     f'thread_width={threads}; accelerated_leaves={accelerated}; vector_calls={calls}')
    return '\n'.join(lines + [driver.MARKER]) + '\n'


def validation_tests():
    # Independently calculated edge cases for empty, short, full and tail groups.
    for arm in (False, True):
        assert driver.accounting(('parallel128', 0, 64, 4), 'prefer', arm) == (0, 0, 0, 0)
        assert driver.accounting(('parallel128', 65, 64, 4), 'prefer', arm) == (1, 1, 2 if arm else 0, 7 if arm else 0)
        assert driver.accounting(('parallel128', 4096, 1024, 4), 'prefer', arm) == (1, 1, 4, 98 if arm else 49)
        assert driver.accounting(('parallel256', 4096, 1024, 4), 'prefer', arm) == (1, 1, 4, 112 if arm else 56)
        assert driver.accounting(('parallelxof256', 16387, 64, 4), 'prefer', arm) == (65, 4, 256, 896 if arm else 448)
    rejected = 0
    for mode in ('portable', 'prefer'):
        for arm in (False, True):
            text = synthetic(mode, arm)
            result = lambda value, status=0: subprocess.CompletedProcess([], status, value, '')
            assert driver.validate(result(text), mode, arm) == 96  # Retain slower results.
            assert driver.validate(result(text.replace('threaded_ns=20', 'threaded_ns=5')), mode, arm) == 0
            lines = text.splitlines()
            variants = [('', 0), (text, 1), ('\n'.join(lines[1:]) + '\n', 0),
                        ('\n'.join([lines[0]] + lines) + '\n', 0)]
            for before, after in (('samples=7', 'samples=6'), ('scheduled_ns=10', 'scheduled_ns=0'),
                                  ('threaded_ns=20', 'threaded_ns=0'), ('groups=0', 'groups=1'),
                                  ('thread_width=0', 'thread_width=1'), ('accelerated_leaves=0', 'accelerated_leaves=1'),
                                  ('vector_calls=0', 'vector_calls=7'), ('workers=1', 'workers=3'),
                                  ('output_bits=256', 'output_bits=255'), ('block=64', 'block=63'),
                                  (f'mode={mode}', 'mode=invalid'), ('threshold=1', 'threshold=2'),
                                  ('root=portable', 'root=accelerated'), ('timing=hash,threads,validate,drop', 'timing=hash'),
                                  ('independent_review=NO', 'independent_review=YES'),
                                  ('selected_kernel=' + (('Neon' if arm else 'Avx2') if mode == 'prefer' else 'None'), 'selected_kernel=invalid')):
                variants.append((text.replace(before, after, 1), 0))
            for changed, status in variants:
                try:
                    driver.validate(result(changed, status), mode, arm)
                except ValueError:
                    rejected += 1
                else:
                    raise AssertionError('threaded benchmark result regression survived')
    print(f'ParallelHash benchmark validator: {rejected} regressions rejected; group boundaries and slower results checked')


def compiled(lane):
    features = common.native.host(lane)[1]
    env = common.environment(features)
    with tempfile.TemporaryDirectory(prefix='brynja-parallel-bench-mutants-') as temporary:
        root = Path(temporary)
        fixture = root / 'fixture'
        shutil.copytree(common.FIXTURE, fixture, ignore=shutil.ignore_patterns('target'))
        manifest = fixture / 'Cargo.toml'
        manifest.write_text(manifest.read_text().replace('../../crates/', str(common.ROOT / 'crates') + '/'))
        env['CARGO_TARGET_DIR'] = str(root / 'target')
        binary = root / 'target/release/benchmark'
        source = fixture / 'src/bin/benchmark.rs'
        original = source.read_text()

        def execute():
            common.run(['cargo', '+1.98.1', 'build', '--release', '--locked', '--offline', '--bin', 'benchmark'], fixture, env)
            return subprocess.run([str(binary), 'prefer'], env=env, text=True, capture_output=True, timeout=120)

        driver.validate(execute(), 'prefer', features == '+neon')
        mutations = (
            ('drop(owned);\n        let elapsed', 'core::mem::forget(owned);\n        let elapsed', 'benchmark secret Drop/canary cleanup'),
            ('let mut calls = 0_u64;', 'let mut calls = u64::MAX;', 'benchmark vector counter overflow'),
            ('let mode = args[0].as_str();', 'let mode = "portable";', None),
            ('workers,\n                        max_leaves:', 'workers: 1,\n                        max_leaves:', 'benchmark leaf/group/thread/route accounting'),
            ('cleanup(&self.output, size)?;', 'self.output[size] = 0;\n        cleanup(&self.output, size)?;', 'benchmark secret Drop/canary cleanup'),
            ('black_box(owned.expose()) != self.expected', 'black_box(owned.expose()) == self.expected', 'benchmark output mismatch'),
        )
        for before, after, diagnostic in mutations:
            if original.count(before) != 1:
                raise AssertionError('mutation anchor drift: ' + before)
            try:
                source.write_text(original.replace(before, after))
                actual = execute()  # Build failure is not runtime evidence.
                if diagnostic:
                    if not actual.returncode or diagnostic not in actual.stderr or 'panicked' in actual.stderr:
                        raise AssertionError('fixture mutation did not fail cleanly: ' + before)
                else:
                    if actual.returncode:
                        raise AssertionError('portable route mutant failed before result validation')
                    try:
                        driver.validate(actual, 'prefer', features == '+neon')
                    except ValueError:
                        pass
                    else:
                        raise AssertionError('false route accepted')
            finally:
                source.write_text(original)
            driver.validate(execute(), 'prefer', features == '+neon')
    print('ParallelHash benchmark fixture: six compiled regressions rejected; restored source passed')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lane', choices=common.native.LANES)
    args = parser.parse_args()
    validation_tests()
    if args.lane:
        compiled(args.lane)
