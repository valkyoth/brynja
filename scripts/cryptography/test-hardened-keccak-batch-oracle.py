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
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('hardened_oracle', Path(__file__).with_name('check-hardened-keccak-batch-oracle.py'))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


def result(mode, stdout='01;-;02;03\n', count=1, status=0, calls=None):
    if calls is None:
        calls = 0 if mode == 'portable' else 3
    marker = (f'HARDENED_KECCAK_BATCH: batches={count}; vector_calls={calls}; '
              'profiles=secret,declassified,public; cleanup=drop,declassify,staging')
    return subprocess.CompletedProcess([], status, stdout, marker)


def compiled(lane):
    features = driver.native.host(lane)[1]
    env = dict(os.environ)
    for key in tuple(env):
        if key.startswith(('CARGO_', 'RUST', 'BRYNJA_REQUIRE_')) and key not in ('CARGO_HOME', 'RUSTUP_HOME'):
            env.pop(key)
    env['RUSTFLAGS'] = '-C target-feature=' + features
    messages = [bytes([slot]) * 136 for slot in range(4)]
    data = ';'.join('sha3-256 1088 0 0 256 ' + message.hex() + ' - -' for message in messages) + '\n'
    expected = [';'.join(hashlib.sha3_256(message).hexdigest() for message in messages)]
    with tempfile.TemporaryDirectory(prefix='brynja-hardened-keccak-mutants-') as temporary:
        root = Path(temporary)
        fixture = root / 'fixture'
        shutil.copytree(driver.FIXTURE, fixture, ignore=shutil.ignore_patterns('target'))
        manifest = fixture / 'Cargo.toml'
        manifest.write_text(manifest.read_text().replace('../../crates/', str(driver.ROOT / 'crates') + '/'))
        env['CARGO_TARGET_DIR'] = str(root / 'target')
        binary = root / 'target/release/brynja-hardened-keccak-batch-fixture'
        source = fixture / 'src/main.rs'
        original = source.read_text()

        def run():
            driver.run(['cargo', '+1.98.1', 'build', '--locked', '--offline', '--release'], fixture, env)
            return subprocess.run([str(binary), 'required'], env=env, input=data, text=True,
                                  capture_output=True, timeout=60)

        driver.validate(run(), expected, 'required')
        cases = (
            ('drop(owned);', 'core::mem::forget(owned);', 'Drop/staging cleanup'),
            ('"{byte:02x}"', '"{:02x}", byte ^ 1', None),
            ('"required" => Mode::Require', '"required" => Mode::Portable', None),
            ('let mut total_vector = 0_u64;', 'let mut total_vector = u64::MAX;', 'vector counter overflow'),
            ('if direct != public || staging.iter().any(|byte| *byte != 0) {',
             'staging[0] = 1;\n        if direct != public || staging.iter().any(|byte| *byte != 0) {', 'public output/staging mismatch'),
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
    print('Hardened Keccak batch fixture: five compiled cleanup/staging/output/route/counter mutants rejected; restored source passed')


def sparse_corpus():
    # Empty active outputs are different from absent slots, including mask zero.
    lines = [';'.join(f'request-{case}-{slot}' for slot in range(4)) for case in range(256)]
    expected = [';'.join('' if slot == 0 else f'answer-{case}-{slot}' for slot in range(4))
                for case in range(256)]
    with patch.object(driver.oracle, 'corpus', return_value=('\n'.join(lines) + '\n', expected)):
        requests, outputs = driver.corpus()
    assert len(requests) == len(outputs) == 272
    assert requests[:256] == lines and outputs[:256] == expected
    for mask in range(16):
        for slot in range(4):
            active = bool(mask & (1 << slot))
            assert requests[256 + mask].split(';')[slot] == (lines[mask].split(';')[slot] if active else '-')
            assert outputs[256 + mask].split(';')[slot] == (expected[mask].split(';')[slot] if active else '-')
    with patch.object(driver.oracle, 'corpus', return_value=('\n'.join(lines[:-1]) + '\n', expected)):
        try:
            driver.corpus()
        except ValueError:
            pass
        else:
            raise AssertionError('truncated base corpus accepted')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lane', choices=driver.native.LANES, help='also run compiled regressions on a matching SIMD host')
    args = parser.parse_args()
    sparse_corpus()
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
                       good.stderr.replace('cleanup=drop,declassify,staging', 'cleanup=drop')):
            cases.append(subprocess.CompletedProcess([], 0, good.stdout, marker))
        for bad in cases:
            try:
                driver.validate(bad, expected, mode)
            except ValueError:
                rejected += 1
            else:
                raise AssertionError('invalid oracle result accepted')
    print(f'Hardened Keccak batch oracle result checker: {rejected} regressions rejected')
    if args.lane:
        compiled(args.lane)


if __name__ == '__main__':
    main()
