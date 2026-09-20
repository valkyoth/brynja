#!/usr/bin/env python3
"""Golden-vector, parser and compiled diagnostic-fixture regressions."""
import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile

import check_kmac_verify_callers as check


def parser_tests():
    count = 0
    for accelerated in (False, True):
        for target, kernel in (('x86_64-unknown-linux-gnu', 'X86Keccak'), ('aarch64-unknown-linux-musl', 'ArmKeccak')):
            route = kernel if accelerated else 'Portable'
            log = f'KMAC_VERIFY_ROUTE: {route}\ntest result: ok. 4 passed; 0 failed; 0 ignored;\n'
            log += ''.join(f'KMAC_VERIFY_RETURN: {name}; case={case}; observations=2; input_marker_cases=0; qualifies_cleanup=false\n'
                           for name in ('kmac128', 'kmac256') for case in range(7 if accelerated else 6))
            check.observations(log, accelerated, target)
            for mutant in (log.replace(route, 'WrongRoute'), log + f'KMAC_VERIFY_ROUTE: {route}\n',
                           log.replace('4 passed', '3 passed'), log.replace('qualifies_cleanup=false', 'qualifies_cleanup=true'),
                           log.replace('observations=2', 'observations=1'), log.replace('input_marker_cases=0', 'input_marker_cases=3'),
                           log[:log.rfind('KMAC_VERIFY_RETURN:')], log + log.splitlines()[-1] + '\n'):
                try:
                    check.observations(mutant, accelerated, target)
                except ValueError:
                    count += 1
                    continue
                raise AssertionError('invalid verification observation accepted')
    print(f'Verification parser: {count} malformed/missing/duplicate/overclaim regressions rejected', flush=True)


def mutations():
    check.audit.require_native_avx2(Path('/proc/cpuinfo').read_text())
    with tempfile.TemporaryDirectory(prefix='kmac-verify-mutants-') as temporary:
        root = Path(temporary)
        fixture = root / 'fixture'
        shutil.copytree(check.FIXTURE, fixture, ignore=shutil.ignore_patterns('target'))
        manifest = fixture / 'Cargo.toml'
        manifest.write_text(manifest.read_text().replace('../../../crates/', str(check.audit.ROOT / 'crates') + '/')
                            .replace('../caller-audit', str(check.audit.FIXTURE)))
        test = fixture / 'tests/audit.rs'
        test.write_text(test.read_text().replace('../../caller-audit/', str(check.audit.FIXTURE) + '/'))
        source = fixture / 'src/lib.rs'
        original = source.read_text()
        cases = [('state.update(&input[..135])?', 'state.update(&[])?'),
                 ('candidate[0] ^= 1;', 'candidate[0] ^= 0;'),
                 ('candidate[128] ^= 1;', 'candidate[128] ^= 0;'),
                 ('1026', '1027'), ('u8::from(!value.expose_public())', 'u8::from(value.expose_public())'),
                 ('owner.quarantine();', '/* missed revocation */')]
        count = 0
        for release in (False, True):
            env = check.audit.clean_environment()
            env['RUSTFLAGS'] = '-C target-feature=+avx2'
            env['CARGO_TARGET_DIR'] = str(root / 'target')
            command = ['cargo', '+1.98.1', 'test', '--locked', '--offline', '--manifest-path', str(manifest),
                       '--features', 'accelerated', '--test', 'audit', *(['--release'] if release else [])]
            check.observations(check.audit.run(command + ['--', '--nocapture'], env), True, 'x86_64-unknown-linux-gnu')
            for before, after in cases:
                if original.count(before) != 1:
                    raise ValueError('ambiguous verification fixture mutation: ' + before)
                try:
                    source.write_text(original.replace(before, after))
                    result = subprocess.run(command, cwd=check.audit.ROOT, env=env, text=True,
                                            capture_output=True, timeout=180, check=False)
                    if not result.returncode or 'test result: FAILED.' not in result.stdout:
                        raise ValueError('verification mutant did not compile and fail: ' + before + result.stderr[-1500:])
                    count += 1
                finally:
                    source.write_text(original)
        print(f'Compiled verification fixture regressions: {count} rejected in debug/release', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mutations', action='store_true')
    args = parser.parse_args()
    check.golden()
    parser_tests()
    if args.mutations:
        mutations()
