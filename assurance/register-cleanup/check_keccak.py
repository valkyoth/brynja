#!/usr/bin/env python3
"""Source-bound Keccak development evidence; no release-gate changes."""
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


def validator(arch, text):
    if arch == 'x86':
        check.REGISTERS = ('eax', 'ecx', 'edx', 'r8d')
        check.asm_check(text, keccak=True)
    else:
        check_arm.VECTOR = tuple(range(4))
        check_arm.asm_check(text, keccak=True)


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
                print(f'Keccak boundary: {compiler} {target} release={optimized}: PASS', flush=True)


def mutation_cases(arch, original, mutations):
    if arch == 'x86':
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
        relative = '../../../crates/brynja-crypto-cpu/src/keccak_constants.rs'
        lib.write_text(lib.read_text().replace(relative, (ROOT / 'src' / relative).resolve().as_posix())
                       .replace('../../../' + SOURCES[arch].relative_to(REPO).as_posix(), 'keccak.rs'))
        source = fixture / 'src/keccak.rs'
        original = SOURCES[arch].read_text()
        source.write_text(original)
        if arch == 'x86':
            mismatch = check.run(['cargo', '+1.98.1', 'check', '--locked', '--offline', '--tests',
                                  '--manifest-path', str(fixture / 'Cargo.toml'), '--target',
                                  'x86_64-unknown-linux-gnu', '--features', 'keccak-probe,win64-probe'],
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
                env['RUSTFLAGS'] = '-C target-feature=+avx2' if arch == 'x86' else '-C linker=rust-lld -C target-feature=+neon,+sha3'
                if arch == 'arm':
                    env['CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER'] = 'qemu-aarch64 -cpu max'
                features = 'keccak-probe' + (',win64-probe' if abi == 'win64' else '')
                result = check.run(['cargo', '+' + compiler, 'test', '--locked', '--offline',
                                    '--manifest-path', str(fixture / 'Cargo.toml'), '--features', features,
                                    '--target', target, *(['--release'] if optimized else []),
                                    '--', '--nocapture'], env, success=expected)
                if expected and any(m not in result.stdout for m in MARKERS):
                    raise AssertionError('missing actual execution marker')
                if not expected and (result.returncode == 0 or 'test result: FAILED' not in result.stdout):
                    raise AssertionError(f'mutant did not fail in execution: {name}\n{result.stdout}\n{result.stderr}')
            print(f'Keccak {arch}: {compiler} release={optimized} ABI={abi}: {len(cases)} controls/mutants PASS', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('arch', choices=SOURCES)
    parser.add_argument('--execute', action='store_true', help='native x86 or QEMU Arm')
    parser.add_argument('--mutations', action='store_true')
    args = parser.parse_args()
    if args.mutations and not args.execute:
        parser.error('--mutations requires --execute')
    codegen(args.arch)
    if args.execute:
        execution(args.arch, args.mutations)

