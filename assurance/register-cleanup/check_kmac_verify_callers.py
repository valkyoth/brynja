#!/usr/bin/env python3
"""Collect scoped KMAC verification diagnostics; never a release receipt."""
import argparse
import ast
import importlib.util
import json
from pathlib import Path
import platform
import re
import tempfile

import check_callers as audit

FIXTURE = Path(__file__).resolve().parent / 'kmac-verify'
PACKAGES = ('brynja_kmac_verify_caller', 'brynja_mac_kmac', 'brynja_hash_sha3',
            'brynja_crypto_cpu', 'brynja_core')


def sources():
    result = audit.sources()
    paths = [FIXTURE / 'Cargo.toml', FIXTURE / 'Cargo.lock', Path(__file__).resolve(),
             Path(__file__).with_name('test_kmac_verify_callers.py')]
    paths += list(FIXTURE.rglob('src/*.rs')) + list((FIXTURE / 'tests').rglob('*.rs'))
    result.update({str(path.relative_to(audit.ROOT)): audit.digest(path) for path in paths})
    return result


def golden():
    path = audit.ROOT / 'scripts/kmac/check-kmac-differential.py'
    spec = importlib.util.spec_from_file_location('kmac_verify_oracle', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.verify_oracle()
    bit = module.oracle.byte_bits
    expected = [[list(module.kmac(rate, bit(bytes([marker]) * 32),
                                 bit(bytes([marker]) * 135), [], 1027, False))
                 for marker in (0x36, 0xa7)] for rate in (168, 136)]
    actual = ast.literal_eval((FIXTURE / 'src/vectors.rs').read_text().split('=', 1)[1].strip().rstrip(';'))
    if actual != expected:
        raise ValueError('verification golden tags differ from independent oracle')


def observations(log, accelerated, target):
    route = ('ArmKeccak' if target.startswith('aarch64') else 'X86Keccak') if accelerated else 'Portable'
    if re.findall(r'^KMAC_VERIFY_ROUTE: (\w+)$', log, re.M) != [route]:
        raise ValueError('missing/wrong/ambiguous verification route')
    if len(re.findall(r'test result: ok\. 4 passed; 0 failed; 0 ignored;', log)) != 1:
        raise ValueError('verification tests did not all execute')
    rows = re.findall(r'^KMAC_VERIFY_RETURN: (kmac\d+); case=(\d+); observations=(\d+); '
                      r'input_marker_cases=(\d+); qualifies_cleanup=false$', log, re.M)
    expected = {(name, str(case)) for name in ('kmac128', 'kmac256')
                for case in range(7 if accelerated else 6)}
    if len(rows) != len(expected) or {(name, case) for name, case, _, _ in rows} != expected:
        raise ValueError('incomplete/duplicate verification observations')
    if any(count != '2' or not 0 <= int(matches) <= 2 for _, _, count, matches in rows):
        raise ValueError('invalid verification observation counts')
    return [dict(algorithm=name, case=int(case), observations=2, input_marker_cases=int(matches))
            for name, case, _, matches in rows]


def main(arm):
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise ValueError('development collector requires Linux x86-64')
    cpuinfo = Path('/proc/cpuinfo').read_text()
    audit.require_native_avx2(cpuinfo)
    golden()
    before = sources()
    directory = Path(tempfile.mkdtemp(prefix='kmac-verify-', dir=audit.ROOT / 'target'))
    rows = []
    for compiler in ('1.90.0', '1.98.1'):
        for target in ('x86_64-unknown-linux-gnu', *(('aarch64-unknown-linux-musl',) if arm else ())):
            for profile in ('debug', 'release'):
                for accelerated in (False, True):
                    mode = 'accelerated' if accelerated else 'portable'
                    build = directory / f'{compiler}-{target}-{profile}-{mode}'
                    env = audit.clean_environment()
                    env['CARGO_TARGET_DIR'] = str(build)
                    flags = ['--emit=mir,llvm-ir,asm,link']
                    if target.startswith('aarch64'):
                        flags += ['-C linker=rust-lld']
                        env['CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER'] = 'qemu-aarch64 -cpu max'
                    if accelerated:
                        flags += ['-C target-feature=' + ('+neon,+sha2,+sha3' if target.startswith('aarch64') else '+avx2')]
                    env['RUSTFLAGS'] = ' '.join(flags)
                    command = ['cargo', '+' + compiler, 'test', '--locked', '--offline',
                               '--manifest-path', str(FIXTURE / 'Cargo.toml'), '--target', target, '--test', 'audit']
                    if accelerated:
                        command += ['--features', 'accelerated']
                    if profile == 'release':
                        command += ['--release']
                    log = audit.run(command + ['--', '--nocapture', '--test-threads=1'], env)
                    (build / 'observations.log').write_text(log)
                    artifacts = {}
                    for package in PACKAGES:
                        for extension in ('mir', 'll', 's'):
                            paths = list((build / target / profile / 'deps').glob(package + '-*.' + extension))
                            if len(paths) != 1:
                                raise ValueError('missing/ambiguous verification artifact: ' + package)
                            artifacts[str(paths[0].relative_to(directory))] = audit.digest(paths[0])
                    rows.append(dict(compiler=audit.run(['rustc', '+' + compiler, '-vV'], env),
                                     target=target, profile=profile, mode=mode,
                                     execution='QEMU, not native' if target.startswith('aarch64') else 'native',
                                     observations=observations(log, accelerated, target), artifacts=artifacts,
                                     log_sha256=audit.digest(build / 'observations.log')))
                    print(f'KMAC verification caller: {compiler} {target} {profile} {mode}: PASS', flush=True)
    if before != sources():
        raise ValueError('verification inputs changed during collection')
    report = dict(schema=1, qualifies_register_cleanup=False, sources=before, records=rows,
                  native_cpuinfo=cpuinfo, scope='verification wrapper return; selected volatile registers only',
                  limitations=['Repeated markers only: no matches do not prove erasure',
                               'No stale stack, upper-vector, interruption or native Arm/Windows/Apple qualification',
                               'Emitted artifacts retained, not automatically proven free of secret residue'])
    destination = directory / 'observations.json'
    destination.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print('Development record: ' + str(destination), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arm', action='store_true', help='also execute under QEMU, not native Arm')
    main(parser.parse_args().arm)
