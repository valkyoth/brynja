#!/usr/bin/env python3
"""Legacy SHA-1 source-bound development checks; release workflow unchanged."""
import argparse
import itertools
import os
from pathlib import Path
import re
import shutil
import tempfile

from check import clean_env, run

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
FIXTURE = HERE / 'sha1'
SOURCES = {arch: ROOT / ('crates/brynja-legacy-sha1/src/cpu/' +
                         ('x86_sha1' if arch == 'x86' else 'aarch64_sha1') + '/secret.rs')
           for arch in ('x86', 'arm')}
MARKERS = ('SHA1_REGISTERS: 1024 independent compressions; 15 unaligned placements; PASS',
           'SHA1_BOUNDS: 8 guarded placements; readonly input: PASS')


def require(condition, message):
    if not condition:
        raise ValueError('SHA-1 opaque boundary: ' + message)


def inspect(assembly, arch):
    text = re.sub(r'(?m)^\s*(?:#+|//|;)\s*BRYNJA_', '# BRYNJA_', assembly)
    require(text.count('# BRYNJA_SECRET_BEGIN') == text.count('# BRYNJA_SECRET_END') == 1,
            'absent/ambiguous markers')
    before, rest = text.split('# BRYNJA_SECRET_BEGIN')
    body, after = rest.split('# BRYNJA_SECRET_END')
    require(body.count('# BRYNJA_REGISTER_ERASE') == 1, 'absent/ambiguous erasure')
    active, cleanup = body.split('# BRYNJA_REGISTER_ERASE')
    returns = list(re.finditer(r'(?m)^\s*ret[ql]?\s*(?:[#;].*)?$', text))
    require(len(returns) == 1, 'absent/additional return')
    end = re.search(r'(?m)^\s*ret[ql]?\s*(?:[#;].*)?$', after)
    require(end is not None, 'return precedes cleanup')
    after = after[:end.end()]
    if arch == 'x86':
        require(not re.search(r'%(?:rsp|esp|rbp|ebp)\b|\b(?:call\w*|push\w*|pop\w*|ret\w*)\b', body),
                'stack access or escape')
        required = {'sha1msg1': 16, 'sha1msg2': 16, 'sha1rnds4': 20, 'sha1nexte': 20}
        erase = [r'xorl\s+%eax,\s*%eax'] + [rf'pxor\s+%xmm{i},\s*%xmm{i}' for i in range(4)]
        erase += [r'cmpl\s+%eax,\s*%eax']
        require(not re.search(r'(?m)^\s*(?:v\w+|pshufb|pblend\w*|pinsrd)\s', active),
                'stronger ISA than SHA/SSE2')
        require(not re.search(r'(?m)^\s*(?:pxor|por|paddd|sha1\w*)\s[^\n]*\(', active),
                'aligned-only SSE memory operand')
        outside = r'(?:push[ql]|pop[ql]|mov[ql]|sub[ql]|add[ql]|ret[ql]?)\b'
    else:
        require(not re.search(r'\b(?:sp|wsp|x29|x30|fp|lr|bl|blr|br|ret)\b', body),
                'Arm stack access or escape')
        required = {'sha1su0': 1, 'sha1su1': 1, 'sha1c': 1, 'sha1p': 2, 'sha1m': 1, 'sha1h': 4}
        cleanup = re.sub(r'movi\.16b\s+v([0-9]+),', r'movi v\1.16b,', cleanup)
        erase = [rf'mov\s+x{i},\s*xzr' for i in (4, 5, 6)]
        erase += [rf'movi\s+v{i}\.16b,\s*#0' for i in range(6)]
        erase += [r'cmp\s+xzr,\s*xzr']
        outside = r'(?:mov|sub|add|str|ldr|stp|ldp|ret)\b'
    for op, count in required.items():
        require(len(re.findall(r'(?m)^\s*' + op + r'(?:\.[\w]+)?\s', active)) == count,
                'wrong instruction inventory: ' + op)
    ops = [line.strip() for line in cleanup.splitlines()
           if line.strip() and not line.lstrip().startswith(('#', '//', ';'))]
    require(len(ops) == len(erase) and all(re.fullmatch(pattern, op) for pattern, op in zip(erase, ops)),
            'cleanup altered or computation after cleanup')
    for area in (before, after):
        lines = area.splitlines()
        for index, line in enumerate(lines):
            op = line.strip()
            if not op or op.startswith(('.', '#', '//', ';')) or op.endswith(':'):
                continue
            if re.fullmatch(r'"?@feat\.00"? = [0-9]+', op):
                continue
            branch = re.fullmatch(r'b\s+([.A-Za-z_][.A-Za-z_0-9]*)', op)
            if arch == 'arm' and branch and any(row.strip() == branch[1] + ':' for row in lines[index+1:]):
                continue
            require(re.match(outside, op), 'unreviewed compiler operation: ' + op)
            addresses = re.findall(r'\([^)]*\)' if arch == 'x86' else r'\[[^]]*\]', op)
            pattern = r'\(%(?:rsp|esp|rbp|ebp)\)' if arch == 'x86' else r'\[(?:sp|x29)(?:, #?-?[0-9]+)?\]'
            require(all(re.fullmatch(pattern, address) for address in addresses),
                    'compiler secret memory access: ' + op)


def codegen(arch):
    for compiler in ('1.90.0', '1.98.1'):
        targets = (['x86_64-unknown-linux-gnu', 'i686-unknown-linux-musl', 'x86_64-apple-darwin',
                    'x86_64-pc-windows-' + ('gnu' if compiler == '1.90.0' else 'msvc')] if arch == 'x86' else
                   ['aarch64-unknown-linux-musl', 'aarch64-apple-darwin', 'aarch64-apple-ios',
                    'aarch64-linux-android'] + (['aarch64-pc-windows-msvc'] if compiler == '1.98.1' else []))
        for target, release in itertools.product(targets, (False, True)):
            with tempfile.TemporaryDirectory(prefix='brynja-sha1-register-codegen-') as directory:
                env = dict(clean_env(), CARGO_TARGET_DIR=directory)
                run(['cargo', '+'+compiler, 'rustc', '--locked', '--offline', '--lib',
                     '--manifest-path', str(FIXTURE/'Cargo.toml'), '--target', target,
                     *(['--release'] if release else []), '--', '--emit=asm'], env)
                paths = list(Path(directory).glob(target+'/*/deps/*.s'))
                require(len(paths) == 1, 'ambiguous assembly')
                text = paths[0].read_text()
                inspect(text, arch)
                text = re.sub(r'(?m)^\s*(?:#+|//|;)\s*BRYNJA_', '# BRYNJA_', text)
                load = 'movl (%edi), %eax\n' if arch == 'x86' else 'ldr x4, [x0]\n'
                spill = 'pushl %eax\n' if arch == 'x86' else 'str x4, [sp]\n'
                for before, after in (
                    ('# BRYNJA_SECRET_BEGIN', load+'# BRYNJA_SECRET_BEGIN'),
                    ('# BRYNJA_REGISTER_ERASE', spill+'# BRYNJA_REGISTER_ERASE'),
                    ('# BRYNJA_SECRET_END', load+'# BRYNJA_SECRET_END'),
                    ('# BRYNJA_SECRET_END', '# BRYNJA_SECRET_END\n'+load),
                ):
                    try:
                        inspect(text.replace(before, after), arch)
                    except ValueError:
                        pass
                    else:
                        raise AssertionError('emitted boundary mutation survived')
            print(f'SHA-1 compiler boundary: {compiler}; {target}; release={release}: PASS', flush=True)


def cases(arch, original, mutations):
    if arch == 'x86':
        marker = '"# BRYNJA_REGISTER_ERASE",'
        erase = ['"xor eax, eax",'] + [f'"pxor xmm{i}, xmm{i}",' for i in range(4)]
        poison = ['"mov eax, -1",'] + [f'"pcmpeqd xmm{i}, xmm{i}",' for i in range(4)]
        algorithm = [
            ('"movdqu [{schedule} + 304], xmm0",', ''),
            ('"mov [{schedule} + 12], eax",', '"mov [{schedule} + 8], eax",'),
            ('"sha1rnds4 xmm0, xmm2, 0",', '"sha1rnds4 xmm0, xmm2, 1",'),
            ('"paddd xmm1, xmm2",', ''),
            ('"paddd xmm0, xmm2",', ''),
            ('"pshufd xmm1, xmm1, 0xff",', '"pshufd xmm1, xmm1, 0x00",'),
        ]
    else:
        marker = '"// BRYNJA_REGISTER_ERASE",'
        erase = [f'"mov x{i}, xzr",' for i in (4, 5, 6)] + [f'"movi v{i}.16b, #0",' for i in range(6)]
        poison = [f'"mov x{i}, #-1",' for i in (4, 5, 6)] + [f'"movi v{i}.16b, #255",' for i in range(6)]
        algorithm = [
            ('"str q0, [x5]",', ''),
            ('"sha1su1 v3.4s, v4.4s",', ''),
            ('"rev32 v3.16b, v3.16b",', ''),  # replace both input/state conversions
            ('"mov w6, #31129",', '"mov w6, #31128",'),
            ('"add v1.4s, v1.4s, v4.4s",', ''),
            ('"add v0.4s, v0.4s, v3.4s",', ''),
        ]
    require(original.count(marker) == 1, 'ambiguous erasure marker')
    poisoned = original.replace(marker, '\n'.join(poison)+'\n'+marker)
    result = [('unmodified', original, True), ('poisoned control', poisoned, True)]
    if mutations:
        prefix, tail = poisoned.split(marker)
        for token in erase:
            require(tail.count(token) == 1, 'stale erasure mutation')
            result.append((token, prefix+marker+tail.replace(token, ''), False))
        for before, after in algorithm:
            require(before in original, 'stale algorithm mutation: '+before)
            result.append((before, original.replace(before, after), False))
    return result


def execution(arch, mutations):
    if arch == 'x86':
        require(os.uname().sysname == 'Linux' and os.uname().machine == 'x86_64', 'native Linux x86 host')
        with Path('/proc/cpuinfo').open() as stream:
            identity = stream.read(4*1024*1024+1)
        flags = re.findall(r'^flags\s*:\s*(.+)$', identity, re.M)
        require(len(identity) <= 4*1024*1024 and flags and all(
            {'sha_ni', 'sse2'} <= set(row.split()) for row in flags), 'SHA/SSE2 on every reported CPU')
    with tempfile.TemporaryDirectory(prefix='brynja-sha1-register-mutants-') as directory:
        fixture = Path(directory)/'fixture'
        shutil.copytree(FIXTURE, fixture, ignore=shutil.ignore_patterns('target'))
        lib = fixture/'src/lib.rs'
        lib.write_text(lib.read_text().replace('../../../../'+SOURCES[arch].relative_to(ROOT).as_posix(), 'kernel.rs'))
        source = fixture/'src/kernel.rs'
        original = SOURCES[arch].read_text()
        source.write_text(original)
        if arch == 'x86':
            mismatch = run(['cargo', '+1.98.1', 'check', '--locked', '--offline', '--tests',
                            '--manifest-path', str(fixture/'Cargo.toml'), '--features', 'win64-probe'],
                           clean_env(), success=False)
            require(mismatch.returncode != 0 and 'expected "win64" fn, found "C" fn' in mismatch.stderr,
                    'observer ABI mismatch rejection')
        configurations = [('x86_64-unknown-linux-gnu', 'C'), ('x86_64-unknown-linux-gnu', 'win64'),
                          ('i686-unknown-linux-musl', 'C')] if arch == 'x86' else [('aarch64-unknown-linux-musl', 'C')]
        for compiler, release, (target, abi) in itertools.product(('1.90.0', '1.98.1'), (False, True), configurations):
            for name, text, success in cases(arch, original, mutations):
                source.write_text(text.replace('extern "C"', 'extern "win64"') if abi == 'win64' else text)
                env = dict(clean_env(), CARGO_TARGET_DIR=str(Path(directory)/'build'))
                env['RUSTFLAGS'] = '-C target-feature=' + ('+sha,+sse2' if arch == 'x86' else '+neon,+sha2')
                if target.endswith('musl'):
                    env['RUSTFLAGS'] += ' -C linker=rust-lld'
                if arch == 'arm':
                    env['CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER'] = 'qemu-aarch64 -cpu max'
                result = run(['cargo', '+'+compiler, 'test', '--locked', '--offline',
                              '--manifest-path', str(fixture/'Cargo.toml'), '--target', target,
                              *(['--release'] if release else []),
                              *(['--features', 'win64-probe'] if abi == 'win64' else []), '--', '--nocapture'],
                             env, success=success)
                require(all(m in result.stdout for m in MARKERS) if success else
                        result.returncode != 0 and 'test result: FAILED' in result.stdout,
                        'missing execution or mutant did not fail at runtime: '+name+'\n'+result.stderr)
            print(f'SHA-1 register observers/mutants: {compiler}; {target}; release={release}; ABI={abi}: PASS', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('arch', choices=SOURCES)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--mutations', action='store_true')
    args = parser.parse_args()
    if args.mutations and not args.execute:
        parser.error('--mutations requires --execute')
    codegen(args.arch)
    if args.execute:
        execution(args.arch, args.mutations)
