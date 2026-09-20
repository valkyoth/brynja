#!/usr/bin/env python3
"""Development diagnostics only: never qualify a release or accept residue."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / 'assurance/register-cleanup/caller-audit'
PACKAGES = ('brynja-core', 'brynja-hash-core', 'brynja-hash-sha2',
            'brynja-hash-sha3', 'brynja-legacy-sha1', 'brynja-legacy-md5')
ALGORITHMS = {'sha256', 'sha512', 'sha3', 'sha1', 'md5'}
HIGHER_PACKAGES = ('brynja-mac-kmac', 'brynja-hash-tuple', 'brynja-hash-parallel')
HIGHER_ALGORITHMS = {family + form + strength for family in ('kmac', 'tuple', 'parallel')
                     for form in ('', 'xof') for strength in ('128', '256')}
PROFILES = ('movable', 'scoped', 'higher', 'accelerated')
ACCELERATED_PACKAGES = (*HIGHER_PACKAGES, 'brynja-hash-sha3', 'brynja-crypto-cpu')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sources():
    paths = {ROOT / 'Cargo.toml', ROOT / 'Cargo.lock', Path(__file__).resolve(),
             Path(__file__).with_name('test_callers.py'),
             Path(__file__).with_name('check_higher_callers.py')}
    paths.update(ROOT / f'scripts/{family}/check-{family}-differential.py'
                 for family in ('kmac', 'tuplehash', 'parallelhash'))
    paths.update(ROOT / path for path in ('scripts/sha3/check-cshake-differential.py',
                                         'scripts/sha3/check-sha3-bit-differential.py'))
    for directory in [FIXTURE, *(ROOT / 'crates' / name for name in (*PACKAGES, *HIGHER_PACKAGES, 'brynja-crypto-cpu'))]:
        paths.add(directory / 'Cargo.toml')
        for subdirectory in ('src', 'tests'):
            paths.update((directory / subdirectory).rglob('*.rs'))
    paths.add(FIXTURE / 'Cargo.lock')
    return {str(path.relative_to(ROOT)): digest(path) for path in sorted(paths)}


def clean_environment():
    env = os.environ.copy()
    for key in list(env):
        if (key in {'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS',
                    'CARGO_ENCODED_RUSTDOCFLAGS', 'CARGO_BUILD_TARGET',
                    'CARGO_TARGET_DIR', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER',
                    'CARGO_BUILD_RUSTFLAGS', 'CARGO_BUILD_RUSTC',
                    'CARGO_BUILD_RUSTC_WRAPPER', 'CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER',
                    'RUSTC', 'RUSTDOC', 'RUST_TEST_THREADS'}
                or key.startswith(('CARGO_PROFILE_', 'CARGO_TARGET_'))):
            del env[key]
    return env


def run(command, env):
    result = subprocess.run(command, cwd=ROOT, env=env, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            timeout=180, check=False)
    if result.returncode:
        raise RuntimeError(f'development command failed: {command}\n{result.stdout[-6000:]}')
    return result.stdout


def observations(log, api_profile='movable', kernel=None):
    if api_profile not in PROFILES or re.findall(
            r'^CALLER_API_PROFILE: (\w+)$', log, re.MULTILINE) != [api_profile]:
        raise ValueError('missing, duplicate or wrong API profile')
    rows = re.findall(r'^CALLER_AUDIT: (\w+); cases=(\d+); input_marker_cases=(\d+); '
                      r'qualifies_cleanup=false$', log, re.MULTILINE)
    algorithms = HIGHER_ALGORITHMS if api_profile in ('higher', 'accelerated') else ALGORITHMS
    if len(rows) != len(algorithms) or {row[0] for row in rows} != algorithms:
        raise ValueError('missing, duplicate, or unexpected diagnostic observations')
    if any(int(cases) != 28 or not 0 <= int(matches) <= 28
           for _, cases, matches in rows):
        raise ValueError('incorrect diagnostic case counts')
    count = 6 if api_profile == 'accelerated' else 5
    if f'test result: ok. {count} passed; 0 failed; 0 ignored;' not in log:
        raise ValueError('observer controls or functional checks did not execute')
    if api_profile == 'accelerated':
        routes = re.findall(r'^CALLER_ACCELERATION: kernel=(\w+); no_fallback=true$', log, re.MULTILINE)
        if kernel not in ('X86Keccak', 'ArmKeccak') or routes != [kernel]:
            raise ValueError('missing/duplicate/wrong accelerated route or revocation control')
    return {name: {'cases': int(cases), 'input_marker_cases': int(matches)}
            for name, cases, matches in rows}


def emitted_command(compiler, common, package, api_profile):
    if api_profile not in PROFILES:
        raise ValueError('unknown API profile')
    features = ['--features', api_profile] if api_profile != 'movable' and package == 'brynja-caller-residue-audit' else []
    if api_profile == 'accelerated' and package in ACCELERATED_PACKAGES:
        # Cargo 1.90 cannot select dependency-package features through the
        # isolated fixture manifest. Emit that library through its own workspace.
        common = list(common)
        if '--manifest-path' in common:
            common[common.index('--manifest-path') + 1] = str(ROOT / 'Cargo.toml')
        features = ['--features', 'hardened-execution']
    return ['cargo', '+' + compiler, 'rustc', *common, '-p', package,
            *features, '--lib', '--', '--emit=mir,llvm-ir,asm']


def require_native_avx2(cpuinfo):
    """Linux flags are OS-filtered; inspect every exposed processor, not the first."""
    processors = [block for block in cpuinfo.split('\n\n') if re.search(r'^processor\s*:', block, re.MULTILINE)]
    if not processors:
        raise ValueError('no native CPU capability evidence')
    for block in processors:
        flags = re.findall(r'^flags\s*:\s*(.+)$', block, re.MULTILINE)
        if len(flags) != 1 or not {'avx', 'avx2', 'xsave'} <= set(flags[0].split()):
            raise ValueError('native AVX2/OS feature bundle unavailable; do not run specialized fixture')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arm', action='store_true', help='also run QEMU AArch64')
    parser.add_argument('--emit', action='store_true', help='retain MIR/LLVM/assembly for inspection')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--scoped', action='store_true', help='observe the borrowed-workspace APIs')
    mode.add_argument('--higher', action='store_true', help='observe scoped KMAC/TupleHash/ParallelHash fixed/XOF APIs')
    mode.add_argument('--accelerated', action='store_true', help='require static AVX2/Arm Keccak for the scoped higher APIs')
    args = parser.parse_args()
    api_profile = 'accelerated' if args.accelerated else 'higher' if args.higher else 'scoped' if args.scoped else 'movable'
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise ValueError('this development driver requires a Linux x86_64 host')
    cpuinfo = Path('/proc/cpuinfo').read_text() if args.accelerated else None
    if args.accelerated:
        require_native_avx2(cpuinfo)
    target_root = ROOT / 'target'
    target_root.mkdir(exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix='caller-residue-', dir=target_root))
    before = sources()
    records = []
    targets = ['x86_64-unknown-linux-gnu']
    if args.arm:
        targets.append('aarch64-unknown-linux-musl')
    for compiler in ('1.90.0', '1.98.1'):
        for target in targets:
            for profile in ('debug', 'release'):
                env = clean_environment()
                build = directory / f'{compiler}-{target}-{profile}'
                env['CARGO_TARGET_DIR'] = str(build)
                if target.startswith('aarch64'):
                    env['RUSTFLAGS'] = '-C linker=rust-lld'
                    env['CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER'] = 'qemu-aarch64 -cpu max'
                kernel = 'ArmKeccak' if target.startswith('aarch64') else 'X86Keccak'
                if args.accelerated:
                    flags = '+neon,+sha2,+sha3' if target.startswith('aarch64') else '+avx2'
                    env['RUSTFLAGS'] = (env.get('RUSTFLAGS', '') + ' -C target-feature=' + flags).strip()
                common = ['--locked', '--offline', '--manifest-path', str(FIXTURE / 'Cargo.toml'),
                          '--target', target]
                if profile == 'release':
                    common.append('--release')
                features = ['--features', api_profile] if api_profile != 'movable' else []
                log = run(['cargo', '+' + compiler, 'test', *common, *features, '--test', 'audit',
                           '--', '--nocapture', '--test-threads=1'], env)
                build.mkdir(exist_ok=True)
                (build / 'observations.log').write_text(log)
                record = {'compiler': run(['rustc', '+' + compiler, '-vV'], env),
                          'target': target, 'profile': profile,
                          'execution': 'QEMU, not native' if target.startswith('aarch64') else 'native',
                          'observations': observations(log, api_profile, kernel), 'artifacts': {},
                          'rustflags': env.get('RUSTFLAGS', ''),
                          'log_sha256': digest(build / 'observations.log')}
                if args.emit:
                    packages = (*PACKAGES, *(HIGHER_PACKAGES if args.higher or args.accelerated else ()),
                                *(('brynja-crypto-cpu',) if args.accelerated else ()), 'brynja-caller-residue-audit')
                    for package in packages:
                        run(emitted_command(compiler, common, package, api_profile), env)
                        stem = package.replace('-', '_')
                        for extension in ('mir', 'll', 's'):
                            files = list((build / target / profile / 'deps').glob(f'{stem}-*.{extension}'))
                            if len(files) != 1:
                                raise ValueError(f'missing/ambiguous emitted artifact: {package}, {extension}')
                            path = files[0]
                            record['artifacts'][str(path.relative_to(directory))] = digest(path)
                records.append(record)
                print(f'CALLER_AUDIT_RECORDED: {compiler} {target} {profile}; '
                      'qualifies_cleanup=false', flush=True)
    if before != sources():
        raise ValueError('source changed during development observations')
    report = {'schema': 1, 'qualifies_register_cleanup': False,
              'api_profile': api_profile,
              'scope': ('static accelerated' if args.accelerated else 'portable') + ' public wrapper normal return; selected volatile registers only',
              'native_cpuinfo': cpuinfo,
              'limitations': ['No stack, upper-vector, interruption or native Windows/Arm qualification',
                              'Only repeated synthetic input markers; zero matches do not prove erasure',
                              'Artifacts retained for inspection, not automatically verified for erasure'],
              'sources': before, 'records': records}
    destination = directory / 'observations.json'
    destination.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(f'Development observations: {destination}; NOT release evidence')


if __name__ == '__main__':
    main()
