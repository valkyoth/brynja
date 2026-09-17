#!/usr/bin/env python3
"""Source-bound vector kernel development evidence; no release-gate changes."""
import argparse
import itertools
import os
from pathlib import Path
import re
import shutil
import tempfile

import check
import check_arm

ROOT = check.ROOT
REPO = ROOT.parents[1]
SOURCES = {
    'x86': REPO / 'crates/brynja-crypto-cpu/src/x86_avx2_keccak/secret.rs',
    'arm': REPO / 'crates/brynja-crypto-cpu/src/aarch64_sha3_keccak/secret.rs',
}
FEATURE = ['--features', 'keccak-probe']
MARKERS = ('KECCAK_CLEANUP: 1024 permutations; 31 unaligned placements; PASS',
           'KECCAK_BOUNDS: 4 guarded placements; readonly constants: PASS')
BATCH = False
BATCH512 = False
KECCAK_BATCH = False
FEATURE_NAME = 'keccak-probe'
CONSTANTS = 'keccak_constants.rs'


def configure_batch256():
    global BATCH, BATCH512, KECCAK_BATCH, SOURCES, FEATURE_NAME, FEATURE, CONSTANTS, MARKERS
    BATCH = True
    BATCH512 = False
    KECCAK_BATCH = False
    SOURCES = {arch: REPO / ('crates/brynja-crypto-cpu/src/sha256_hardened_batch/' +
                            ('x86' if arch == 'x86' else 'arm') + '/secret.rs')
               for arch in ('x86', 'arm')}
    FEATURE_NAME = 'batch256-probe'
    FEATURE = ['--features', FEATURE_NAME]
    CONSTANTS = 'sha256_schedule.rs'
    MARKERS = ('BATCH256_CLEANUP: 1024 independent batches; 31 unaligned placements; PASS',
               'BATCH256_BOUNDS: 4 guarded placements; readonly constants: PASS')


def configure_batch512():
    global BATCH512, SOURCES, FEATURE_NAME, FEATURE, CONSTANTS, MARKERS
    configure_batch256()
    BATCH512 = True
    SOURCES = {arch: Path(str(path).replace('sha256_hardened_batch', 'sha512_hardened_batch'))
               for arch, path in SOURCES.items()}
    FEATURE_NAME = 'batch512-probe'
    FEATURE = ['--features', FEATURE_NAME]
    CONSTANTS = 'sha512_schedule.rs'
    MARKERS = tuple(marker.replace('BATCH256', 'BATCH512') for marker in MARKERS)


def configure_keccak_batch():
    global KECCAK_BATCH, SOURCES, FEATURE_NAME, FEATURE, CONSTANTS, MARKERS
    configure_batch512()
    KECCAK_BATCH = True
    SOURCES = {arch: Path(str(path).replace('sha512_hardened_batch', 'keccak_hardened_batch'))
               for arch, path in SOURCES.items()}
    FEATURE_NAME = 'keccak-batch-probe'
    FEATURE = ['--features', FEATURE_NAME]
    CONSTANTS = 'keccak_constants.rs'
    MARKERS = tuple(marker.replace('BATCH512', 'KECCAK_BATCH') for marker in MARKERS)


def validator(arch, text):
    if arch == 'x86':
        check.REGISTERS = ('eax', 'ecx', 'edx') if BATCH else ('eax', 'ecx', 'edx', 'r8d')
        check.asm_check(text, keccak=not BATCH, batch256=BATCH and not BATCH512,
                        batch512=BATCH512, keccak_batch=KECCAK_BATCH)
    else:
        check_arm.VECTOR = tuple(range(4))
        check_arm.GP = (4, 5, 6) if BATCH else (4, 5, 6, 7, 9)
        check_arm.asm_check(text, keccak=not BATCH, batch256=BATCH and not BATCH512,
                            batch512=BATCH512, keccak_batch=KECCAK_BATCH)


def codegen(arch):
    for compiler in ('1.90.0', '1.98.1'):
        if arch == 'x86':
            targets = ['x86_64-unknown-linux-gnu', 'x86_64-apple-darwin',
                       'x86_64-pc-windows-' + ('gnu' if compiler == '1.90.0' else 'msvc')]
        else:
            targets = ['aarch64-unknown-linux-musl', 'aarch64-apple-darwin',
                       'aarch64-apple-ios', 'aarch64-linux-android']
            if compiler == '1.98.1':
                targets.append('aarch64-pc-windows-msvc')
        for target, optimized in itertools.product(targets, (False, True)):
            with tempfile.TemporaryDirectory(prefix='brynja-keccak-register-codegen-') as directory:
                env = check.clean_env()
                env['CARGO_TARGET_DIR'] = directory
                check.run(['cargo', '+' + compiler, 'rustc', '--locked', '--offline', '--lib',
                           '--manifest-path', str(ROOT / 'Cargo.toml'), *FEATURE, '--target', target,
                           *(['--release'] if optimized else []), '--', '--emit=asm'], env)
                paths = list(Path(directory).glob(f'{target}/*/deps/*.s'))
                if len(paths) != 1:
                    raise ValueError('missing or ambiguous assembly')
                text = paths[0].read_text()
                text = re.sub(r'(?m)^\s*#+\s*BRYNJA_', '# BRYNJA_', text)
                text = re.sub(r'(?m)^\s*(?://|;)\s*BRYNJA_', '// BRYNJA_', text)
                validator(arch, text)
                marker = '# ' if arch == 'x86' else '// '
                load = 'movq (%rdi), %rax\n' if arch == 'x86' else 'ldr x4, [x0]\n'
                spill = 'pushq %rax\n' if arch == 'x86' else 'str x4, [sp]\n'
                for token, replacement in (
                    (marker + 'BRYNJA_SECRET_BEGIN', load + marker + 'BRYNJA_SECRET_BEGIN'),
                    (marker + 'BRYNJA_REGISTER_ERASE', spill + marker + 'BRYNJA_REGISTER_ERASE'),
                    (marker + 'BRYNJA_SECRET_END', load + marker + 'BRYNJA_SECRET_END'),
                    (marker + 'BRYNJA_SECRET_END', marker + 'BRYNJA_SECRET_END\n' + load),
                ):
                    try:
                        validator(arch, text.replace(token, replacement))
                    except ValueError:
                        pass
                    else:
                        raise AssertionError('accepted compiler-boundary mutation')
                label = 'Keccak batch' if KECCAK_BATCH else ('SHA-512 batch' if BATCH512 else 'SHA-256 batch') if BATCH else 'Keccak'
                print(f'{label} boundary: {compiler} {target} release={optimized}: PASS', flush=True)


def mutation_cases(arch, original, mutations):
    if BATCH:
        if KECCAK_BATCH:
            from keccak_batch_mutations import specification
        elif BATCH512:
            from batch512_mutations import specification
        else:
            from batch256_mutations import specification
        marker, erase, poison, algorithm = specification(arch)
    elif arch == 'x86':
        marker = '"# BRYNJA_REGISTER_ERASE",'
        gp = ('eax', 'ecx', 'edx', 'r8d')
        erase = [f'"xor {r}, {r}",' for r in gp]
        erase += [f'"vpxor ymm{i}, ymm{i}, ymm{i}",' for i in range(4)]
        poison = [f'"mov {r}, -1",' for r in gp]
        poison += [f'"vpcmpeqd ymm{i}, ymm{i}, ymm{i}",' for i in range(4)]
        algorithm = (
            ('"mov [{scratch} + rcx], rax",', ''),
            ('"rol rax, 62",', '"rol rax, 61",'),
            ('"vpblendd ymm2, ymm2, ymm3, 0xc0",', '"vpblendd ymm2, ymm2, ymm3, 0x30",'),
            ('"xor [{scratch}], rax",', ''),
            ('"xor rax, [{scratch} + rcx + 160]",', ''),
        )
    else:
        marker = '"// BRYNJA_REGISTER_ERASE",'
        gp = (4, 5, 6, 7, 9)
        erase = [f'"mov x{i}, xzr",' for i in gp]
        erase += [f'"movi v{i}.16b, #0",' for i in range(4)]
        poison = [f'"mov x{i}, #-1",' for i in gp]
        poison += [f'"movi v{i}.16b, #255",' for i in range(4)]
        algorithm = (
            ('"str xzr, [{scratch}, x7]",', ''),
            ('"ror x5, x5, #2",', '"ror x5, x5, #3",'),
            ('"ins v2.d[1], v3.d[0]",', '"ins v2.d[1], v2.d[0]",'),
            ('"str x5, [{scratch}]",', ''),
            ('"ldr x6, [x9, #160]",', '"ldr x6, [x9, #120]",'),
        )
    if original.count(marker) != 1:
        raise ValueError('ambiguous cleanup marker')
    poisoned = original.replace(marker, '\n'.join(poison) + '\n' + marker)
    cases = [('unmodified', original, True), ('poisoned positive control', poisoned, True)]
    if mutations:
        prefix, tail = poisoned.split(marker)
        for token in erase:
            if tail.count(token) != 1:
                raise ValueError('stale erasure mutation: ' + token)
            cases.append((token, prefix + marker + tail.replace(token, ''), False))
        for before, after in algorithm:
            if original.count(before) != 1:
                raise ValueError('stale algorithm mutation: ' + before)
            cases.append((before, original.replace(before, after), False))
    return cases


def execution(arch, mutations):
    if arch == 'x86':
        if os.uname().sysname != 'Linux' or os.uname().machine != 'x86_64':
            raise ValueError('native observer requires Linux x86_64')
        with Path('/proc/cpuinfo').open() as stream:
            identity = stream.read(4 * 1024 * 1024 + 1)
        flags = re.findall(r'^flags\s*:\s*(.+)$', identity, re.M)
        if len(identity) > 4 * 1024 * 1024 or not flags or any(
                not {'avx', 'avx2'} <= set(row.split()) for row in flags):
            raise ValueError('AVX/AVX2 required on every reported CPU')
    with tempfile.TemporaryDirectory(prefix='brynja-keccak-register-mutants-') as directory:
        fixture = Path(directory) / 'fixture'
        shutil.copytree(ROOT, fixture, ignore=shutil.ignore_patterns('target', '__pycache__'))
        lib = fixture / 'src/lib.rs'
        relative = '../../../crates/brynja-crypto-cpu/src/' + CONSTANTS
        lib.write_text(lib.read_text().replace(relative, (ROOT / 'src' / relative).resolve().as_posix())
                       .replace('../../../' + SOURCES[arch].relative_to(REPO).as_posix(), 'keccak.rs'))
        source = fixture / 'src/keccak.rs'
        original = SOURCES[arch].read_text()
        source.write_text(original)
        if arch == 'x86':
            mismatch = check.run(['cargo', '+1.98.1', 'check', '--locked', '--offline', '--tests',
                                  '--manifest-path', str(fixture / 'Cargo.toml'), '--target',
                                  'x86_64-unknown-linux-gnu', '--features', FEATURE_NAME + ',win64-probe'],
                                 check.clean_env(), success=False)
            if mismatch.returncode == 0 or 'expected "win64" fn, found "C" fn' not in mismatch.stderr:
                raise AssertionError('observer ABI mismatch was not rejected')
        cases = mutation_cases(arch, original, mutations)
        for compiler, optimized, abi in itertools.product(
                ('1.90.0', '1.98.1'), (False, True), ('sysv', 'win64') if arch == 'x86' else ('C',)):
            for name, contents, expected in cases:
                source.write_text(contents.replace('extern "C"', 'extern "win64"') if abi == 'win64' else contents)
                env = check.clean_env()
                env['CARGO_TARGET_DIR'] = str(Path(directory) / 'build')
                target = 'x86_64-unknown-linux-gnu' if arch == 'x86' else 'aarch64-unknown-linux-musl'
                env.pop('CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER', None)
                env['RUSTFLAGS'] = '-C target-feature=+avx2' if arch == 'x86' else (
                    '-C linker=rust-lld -C target-feature=+neon' + ('' if BATCH else ',+sha3'))
                if arch == 'arm':
                    env['CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER'] = 'qemu-aarch64 -cpu max'
                features = FEATURE_NAME + (',win64-probe' if abi == 'win64' else '')
                result = check.run(['cargo', '+' + compiler, 'test', '--locked', '--offline',
                                    '--manifest-path', str(fixture / 'Cargo.toml'), '--features', features,
                                    '--target', target, *(['--release'] if optimized else []),
                                    '--', '--nocapture'], env, success=expected)
                if expected and any(m not in result.stdout for m in MARKERS):
                    raise AssertionError('missing actual execution marker')
                if not expected and (result.returncode == 0 or 'test result: FAILED' not in result.stdout):
                    raise AssertionError(f'mutant did not fail in execution: {name}\n{result.stdout}\n{result.stderr}')
            label = 'Keccak batch' if KECCAK_BATCH else ('SHA-512 batch' if BATCH512 else 'SHA-256 batch') if BATCH else 'Keccak'
            print(f'{label} {arch}: {compiler} release={optimized} ABI={abi}: {len(cases)} controls/mutants PASS', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('arch', choices=SOURCES)
    parser.add_argument('--execute', action='store_true', help='native x86 or QEMU Arm')
    parser.add_argument('--mutations', action='store_true')
    parser.add_argument('--sha256-batch', action='store_true')
    parser.add_argument('--sha512-batch', action='store_true')
    parser.add_argument('--keccak-batch', action='store_true')
    args = parser.parse_args()
    if args.mutations and not args.execute:
        parser.error('--mutations requires --execute')
    if sum((args.sha256_batch, args.sha512_batch, args.keccak_batch)) > 1:
        parser.error('select only one batch family')
    if args.sha256_batch:
        configure_batch256()
    if args.sha512_batch:
        configure_batch512()
    if args.keccak_batch:
        configure_keccak_batch()
    codegen(args.arch)
    if args.execute:
        execution(args.arch, args.mutations)
