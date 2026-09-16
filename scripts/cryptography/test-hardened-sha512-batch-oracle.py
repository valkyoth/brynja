#!/usr/bin/env python3
"""Reject incomplete oracle outputs, wrong identities, failed runs and false routes."""
import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

spec = importlib.util.spec_from_file_location('hardened_oracle', Path(__file__).with_name('check-hardened-sha512-batch-oracle.py'))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


def result(mode, stdout='01;-;02;03\n', count=1, status=0, calls=None):
    if calls is None:
        calls = 0 if mode == 'portable' else 3
    marker = (f'HARDENED_SHA512_BATCH: batches={count}; vector_calls={calls}; '
              'profiles=secret,declassified,public; cleanup=drop,declassify')
    return subprocess.CompletedProcess([], status, stdout, marker)


def compiled(lane):
    features = driver.native.host(lane)[1]
    env = dict(os.environ)
    for key in tuple(env):
        if key.startswith(('CARGO_', 'RUST', 'BRYNJA_REQUIRE_')) and key not in ('CARGO_HOME', 'RUSTUP_HOME'):
            env.pop(key)
    env['RUSTFLAGS'] = '-C target-feature=' + features
    messages = [bytes([lane]) * 128 for lane in range(4)]
    data = ';'.join('sha512:1024:' + message.hex() for message in messages) + '\n'
    expected = [';'.join(hashlib.sha512(message).hexdigest() for message in messages)]
    with tempfile.TemporaryDirectory(prefix='brynja-hardened-sha512-mutants-') as temporary:
        root = Path(temporary)
        fixture = root / 'fixture'
        shutil.copytree(driver.FIXTURE, fixture, ignore=shutil.ignore_patterns('target'))
        manifest = fixture / 'Cargo.toml'
        manifest.write_text(manifest.read_text().replace('../../crates/', str(driver.ROOT / 'crates') + '/'))
        env['CARGO_TARGET_DIR'] = str(root / 'target')
        binary = root / 'target/release/brynja-hardened-sha512-batch-fixture'
        source = fixture / 'src/main.rs'
        original = source.read_text()

        def run():
            driver.oracle.run(['cargo', '+1.98.1', 'build', '--locked', '--offline', '--release'], fixture, env)
            return subprocess.run([str(binary), 'required'], env=env, input=data, text=True,
                                  capture_output=True, timeout=60)

        driver.validate(run(), expected, 'required')
        cases = (
            ('drop(owned);', 'core::mem::forget(owned);', 'Drop cleanup'),
            ('"{byte:02x}"', '"{:02x}", byte ^ 1', None),
            ('"required" => Mode::Require', '"required" => Mode::Portable', None),
            ('let mut total_vector = 0_u64;', 'let mut total_vector = u64::MAX;', 'vector counter overflow'),
        )
        try:
            for before, after, diagnostic in cases:
                if original.count(before) != 1:
                    raise AssertionError('compiled mutation anchor drift: ' + before)
                source.write_text(original.replace(before, after))
                result = run()  # A failed build is never accepted as mutant rejection.
                if diagnostic is not None:
                    if result.returncode == 0 or result.stdout or diagnostic not in result.stderr or 'panicked at' in result.stderr:
                        raise AssertionError('mutant did not reject cleanly: ' + before)
                else:
                    if result.returncode != 0:
                        raise AssertionError('output/route mutant failed before comparison')
                    try:
                        driver.validate(result, expected, 'required')
                    except ValueError:
                        pass
                    else:
                        raise AssertionError('compiled mutant survived: ' + before)
                source.write_text(original)
                driver.validate(run(), expected, 'required')
        finally:
            source.write_text(original)
    print('Hardened SHA-512 batch fixture: four compiled cleanup/output/route/counter mutants rejected; restored source passed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lane', choices=driver.native.LANES, help='also run compiled regressions on a matching SIMD host')
    args = parser.parse_args()
    rejected = 0
    for mode in ('portable', 'prefer', 'required'):
        good = result(mode)
        expected = good.stdout.splitlines()
        driver.validate(good, expected, mode)
        cases = [result(mode, stdout=''), result(mode, stdout='00;-;02;03\n'),
                 result(mode, stdout='01;02;-;03\n'), result(mode, count=0),
                 result(mode, count=2), result(mode, status=1),
                 result(mode, calls=1 if mode == 'portable' else 0)]
        for marker in ('', good.stderr + '\n' + good.stderr,
                       good.stderr.replace('profiles=secret,declassified,public', 'profiles=public'),
                       good.stderr.replace('cleanup=drop,declassify', 'cleanup=drop')):
            cases.append(subprocess.CompletedProcess([], 0, good.stdout, marker))
        for bad in cases:
            try:
                driver.validate(bad, expected, mode)
            except ValueError:
                rejected += 1
            else:
                raise AssertionError('invalid oracle result accepted')
    print(f'Hardened SHA-512 batch oracle result checker: {rejected} regressions rejected')
    if args.lane:
        compiled(args.lane)


if __name__ == '__main__':
    main()
