#!/usr/bin/env python3
"""Legacy MD5 source-bound development checks; release workflow unchanged."""
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
FIXTURE = HERE / 'md5'
SOURCES = {arch: ROOT / ('crates/brynja-legacy-md5/src/cpu/' + arch + '_secret/kernel.rs')
           for arch in ('x86', 'arm')}
MARKERS = ('MD5_CLEANUP: 1024 independent batches; 31 unaligned placements; PASS',
           'MD5_BOUNDS: 4 guarded placements; readonly constants: PASS')


def require(condition, message):
    if not condition:
        raise ValueError('MD5 opaque boundary: ' + message)


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
        required = {'vpaddd': 5, 'vpslld': 1, 'vpsrld': 1}
        erase = [rf'xorl\s+%{r},\s*%{r}' for r in ('eax', 'ecx', 'edx')]
        erase += [rf'vpxor\s+%ymm{i},\s*%ymm{i},\s*%ymm{i}' for i in range(4)]
        erase += [r'cmpl\s+%eax,\s*%eax', 'vzeroupper']
        require(not re.search(r'%zmm|%k[0-7]\b|\b(?:sha\w*|rorx|shrx)\b', active),
                'stronger ISA than AVX2')
        outside = r'(?:push[ql]|pop[ql]|mov[ql]|sub[ql]|add[ql]|ret[ql]?)\b'
    else:
        require(not re.search(r'\b(?:sp|wsp|x29|x30|fp|lr|bl|blr|br|ret)\b', body),
                'Arm stack access or escape')
        required = {'ushl': 2, 'ld1r': 1}
        cleanup = re.sub(r'movi\.16b\s+v([0-9]+),', r'movi v\1.16b,', cleanup)
        erase = [rf'mov\s+x{i},\s*xzr' for i in (4, 5, 6)]
        erase += [rf'movi\s+v{i}\.16b,\s*#0' for i in range(4)]
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
            if arch == 'x86' and op == 'vzeroupper':
                continue
            if arch == 'x86' and re.fullmatch(r'v?mov[au]ps\s+(?:%xmm(?:[6-9]|1[0-5]),\s*[0-9]*\(%rsp\)|[0-9]*\(%rsp\),\s*%xmm(?:[6-9]|1[0-5]))', op):
                continue  # Win64 caller-owned nonvolatile lows, not secret data.
            # LLVM may specialize the public table pointer in this private
            # function. Address formation reads no table or secret bytes.
            if arch == 'x86' and re.fullmatch(r'leaq\s+[.A-Za-z_][\w.]*\(%rip\),\s*%r\w+', op):
                continue
            if arch == 'arm' and re.fullmatch(r'adrp?\s+x\d+,\s*[.A-Za-z_][\w.@]*', op):
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
        targets = (['x86_64-unknown-linux-gnu', 'x86_64-apple-darwin',
                    'x86_64-pc-windows-' + ('gnu' if compiler == '1.90.0' else 'msvc')] if arch == 'x86' else
                   ['aarch64-unknown-linux-musl', 'aarch64-apple-darwin', 'aarch64-apple-ios',
                    'aarch64-linux-android'] + (['aarch64-pc-windows-msvc'] if compiler == '1.98.1' else []))
        for target, release in itertools.product(targets, (False, True)):
            with tempfile.TemporaryDirectory(prefix='brynja-md5-register-codegen-') as directory:
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
                    *([('vzeroupper', 'nop')] if arch == 'x86' else []),
                ):
                    try:
                        inspect(text.replace(before, after), arch)
                    except ValueError:
                        pass
                    else:
                        raise AssertionError('emitted boundary mutation survived')
            print(f'MD5 compiler boundary: {compiler}; {target}; release={release}: PASS', flush=True)


def cases(arch, original, mutations):
    if arch == 'x86':
        marker = '"# BRYNJA_REGISTER_ERASE",'
        erase = [f'"xor {r}, {r}",' for r in ('eax','ecx','edx')]
        erase += [f'"vpxor ymm{i}, ymm{i}, ymm{i}",' for i in range(4)]
        poison = [f'"mov {r}, -1",' for r in ('eax','ecx','edx')]
        poison += [f'"vpcmpeqd ymm{i}, ymm{i}, ymm{i}",' for i in range(4)]
        algorithm = [
            ('"cmp ecx, 64",', '"cmp ecx, 63",'),
            ('"imul edx, ecx, 5",', '"imul edx, ecx, 3",'),
            ('"vpxor ymm0, ymm0, ymm1",', '"vpor ymm0, ymm0, ymm1",'),
            ('"vpaddd ymm0, ymm0, [{scratch} + rcx]",', ''),
            ('"vmovdqu [{scratch} + 832], ymm0",', ''),
            ('"vmovdqu [{scratch} + rcx], ymm0",', ''),
            ('"add eax, 32",', '"add eax, 31",'),
            ('"vmovdqu [{scratch} + 736], ymm0",', '"vmovdqu [{scratch} + 704], ymm0",'),
        ]
    else:
        marker = '"// BRYNJA_REGISTER_ERASE",'
        erase = [f'"mov x{i}, xzr",' for i in (4,5,6)]
        erase += [f'"movi v{i}.16b, #0",' for i in range(4)]
        poison = [f'"mov x{i}, #-1",' for i in (4,5,6)]
        poison += [f'"movi v{i}.16b, #255",' for i in range(4)]
        algorithm = [
            ('"cmp x4, #64",', '"cmp x4, #63",'),
            ('"add x5, x4, x4, lsl #2",', '"add x5, x4, x4, lsl #1",'),
            ('"eor v0.16b, v0.16b, v1.16b",', '"orr v0.16b, v0.16b, v1.16b",'),
            ('"ldr q1, [x6]",', '"movi v1.16b, #0",'),
            ('"str q0, [{scratch}, #848]",', ''),
            ('"str q0, [x6]",', ''),
            ('"str q3, [x6, #656]",', ''),
            ('"sub w6, w6, #32",', '"sub w6, w6, #31",'),
            ('"str q0, [{scratch}, #736]",', '"str q0, [{scratch}, #704]",'),
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
            {'avx2'} <= set(row.split()) for row in flags), 'AVX2 on every reported CPU')
    with tempfile.TemporaryDirectory(prefix='brynja-md5-register-mutants-') as directory:
        fixture = Path(directory)/'fixture'
        shutil.copytree(FIXTURE, fixture, ignore=shutil.ignore_patterns('target'))
        lib = fixture/'src/lib.rs'
        lib.write_text(lib.read_text().replace('../../../../'+SOURCES[arch].relative_to(ROOT).as_posix(), 'kernel.rs'))
        constants = ROOT/'crates/brynja-legacy-md5/src/cpu/constants.rs'
        lib.write_text(lib.read_text().replace('../../../../'+constants.relative_to(ROOT).as_posix(), 'constants.rs'))
        shutil.copyfile(constants, fixture/'src/constants.rs')
        source = fixture/'src/kernel.rs'
        original = SOURCES[arch].read_text()
        source.write_text(original)
        if arch == 'x86':
            mismatch = run(['cargo', '+1.98.1', 'check', '--locked', '--offline', '--tests',
                            '--manifest-path', str(fixture/'Cargo.toml'), '--features', 'win64-probe'],
                           clean_env(), success=False)
            require(mismatch.returncode != 0 and 'expected "win64" fn, found "C" fn' in mismatch.stderr,
                    'observer ABI mismatch rejection')
        configurations = [('x86_64-unknown-linux-gnu', 'C'), ('x86_64-unknown-linux-gnu', 'win64')] if arch == 'x86' else [('aarch64-unknown-linux-musl', 'C')]
        for compiler, release, (target, abi) in itertools.product(('1.90.0', '1.98.1'), (False, True), configurations):
            for name, text, success in cases(arch, original, mutations):
                source.write_text(text.replace('extern "C"', 'extern "win64"') if abi == 'win64' else text)
                env = dict(clean_env(), CARGO_TARGET_DIR=str(Path(directory)/'build'))
                env['RUSTFLAGS'] = '-C target-feature=' + ('+avx2' if arch == 'x86' else '+neon')
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
            print(f'MD5 register observers/mutants: {compiler}; {target}; release={release}; ABI={abi}: PASS', flush=True)


def layout(arch):
    # Compile the actual wrapper and exact owner declaration; only the error
    # enum and module tree are fixture scaffolding. No crypto executes here.
    cpu = ROOT/'crates/brynja-legacy-md5/src/cpu'
    declaration = (cpu/'scratch.rs').read_text().split('#[repr(C)]')[1].split('impl Scratch')[0]
    declaration = '#[repr(C)]' + declaration
    changes = [
        ('initial: [[u8; 32]; 4]', 'initial: [[u8; 32]; 5]'),
        ('words: [[u8; 32]; 16]', 'words: [[u8; 32]; 15]'),
        ('work: [[u8; 32]; 4]', 'work: [[u8; 32]; 3]'),
        ('temporary: [[u8; 32]; 3]', 'temporary: [[u8; 32]; 4]'),
        ('#[repr(C)]', '#[repr(C, align(16))]'),
    ]
    with tempfile.TemporaryDirectory(prefix='brynja-md5-layout-') as directory:
        directory = Path(directory)
        (directory/'kernel.rs').write_bytes(SOURCES[arch].read_bytes())
        (directory/'wrapper.rs').write_bytes((cpu/(arch+'_secret.rs')).read_bytes())
        (directory/'constants.rs').write_bytes((cpu/'constants.rs').read_bytes())
        root = directory/'lib.rs'
        target = 'x86_64-unknown-linux-gnu' if arch == 'x86' else 'aarch64-unknown-linux-musl'
        for optimized in (False, True):
            for change in [None, *changes]:
                owner = declaration if change is None else declaration.replace(*change)
                require(change is None or owner != declaration, 'stale layout mutation')
                root.write_text('#![no_std]\nmod scratch {'+owner+'}\n'
                    'enum Md5BackendError {}\nmod constants;\n#[path="wrapper.rs"] mod wrapper;\n')
                result = run(['rustc', '+1.98.1', '--edition=2024', '--crate-type=lib',
                              '--target', target, '--cfg', 'feature="hardened-execution"',
                              '--emit=metadata', '--out-dir', str(directory),
                              *(['-O'] if optimized else []), str(root)], clean_env(), success=change is None)
                require(change is None or 'E0080' in result.stderr, 'layout mutant did not fail its const assertion')
    print(f'MD5 exact layout: {arch}; ten debug/release regressions rejected', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('arch', choices=SOURCES)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--mutations', action='store_true')
    args = parser.parse_args()
    if args.mutations and not args.execute:
        parser.error('--mutations requires --execute')
    codegen(args.arch)
    layout(args.arch)
    if args.execute:
        execution(args.arch, args.mutations)
