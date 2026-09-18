#!/usr/bin/env python3
"""Scalar KECCAK development evidence; not a release-gate change."""
from pathlib import Path
import re
import shutil
import tempfile

from check import run
from check_callers import clean_environment
from check_transfer import instructions

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SOURCE = ROOT / 'crates/brynja-hash-sha3/src/hardened/permutation/native.rs'
FIXTURE = HERE / 'keccak-scalar'
REGISTERS = ('eax', 'ecx', 'edx', 'r10d', 'r11d')


def inspect(text, arm):
    labels = list(re.finditer(r'(?m)^(_+(?:R|ZN)[^\s:]+):[^\n]*$', text))
    found = [text[m.end():labels[i+1].start() if i+1 < len(labels) else len(text)]
             for i, m in enumerate(labels) if '6scalar' in m[1]
             and ('permutation' in m[1] or 'keccak_scalar_cleanup' in m[1])]
    if len(found) != 1:
        raise ValueError('missing/ambiguous scalar identity')
    body = found[0]
    end = re.search(r'(?m)^\s*retq?\s*(?:[#;].*)?$', body)
    if end is None:
        raise ValueError('missing return')
    body = body[:end.end()]
    for marker in ('BEGIN', 'ERASE', 'END'):
        if body.count('BRYNJA_SCALAR_' + marker) != 1:
            raise ValueError('missing opaque boundary')
    before, rest = re.split(r'[^\n]*BRYNJA_SCALAR_BEGIN[^\n]*', body)
    active, rest = re.split(r'[^\n]*BRYNJA_SCALAR_ERASE[^\n]*', rest)
    cleanup, after = re.split(r'[^\n]*BRYNJA_SCALAR_END[^\n]*', rest)
    if re.search(r'\b(?:call\w*|push\w*|pop\w*|ret\w*|sp|rsp|rbp|bl|blr|br|x18|x29|x30)\b', active):
        raise ValueError('stack/call/escape in scalar computation')
    allowed = (r'(?:ldr|str|mov|cmp|b\.ne|bic|eor|add|ror)\b'
               if arm else r'(?:movq|xorq|xorl|cmpl|jne|andq|notq|addl|rolq)\b')
    if any(not re.match(allowed, op) for op in instructions(active)):
        raise ValueError('unreviewed scalar instruction or stronger ISA')
    expected = ([f'mov x{i}, xzr' for i in range(4, 11)] + ['cmp xzr, xzr'] if arm
                else [f'xorl %{r}, %{r}' for r in REGISTERS])
    normalized = lambda op: re.sub(r'\s+', ' ', op).replace(', ', ',')
    if [normalized(op) for op in instructions(cleanup)] != [normalized(op) for op in expected]:
        raise ValueError('missing wipe or extra post-cleanup computation')
    for area in (before, after):
        for op in instructions(area):
            if re.fullmatch(r'"?@feat\.00"? = [0-9]+', op):
                continue
            if not arm and re.fullmatch(r'leaq\s+[.A-Za-z_][\w.]*\(%rip\),\s*%r\w+', op):
                continue  # LLVM specializes a public constant-table address.
            if arm and re.fullmatch(r'adrp?\s+x\d+,\s*[.A-Za-z_][\w.@]*', op):
                continue
            branch = re.fullmatch(r'b\s+([.A-Za-z_][.A-Za-z_0-9]*)', op)
            if arm and branch:
                target = re.search(r'(?m)^' + re.escape(branch[1]) + ':', area)
                if target and target.start() > area.index(op):
                    continue  # Forward local compiler block; cannot skip the opaque boundary.
            if not re.match(r'(?:mov|movq|movl|pushq|popq|subq|addq|str|stur|stp|ldr|ldur|ldp|sub|add|retq?)\b', op):
                raise ValueError('unreviewed compiler operation: ' + op)
            if re.search(r'%(?:xmm|ymm|zmm)|\b[vdqs][0-9]+\b', op):
                raise ValueError('vector operation outside scalar boundary')
            addresses = re.findall(r'\[[^]]*\]' if arm else r'\([^)]*\)', op)
            bound = r'\[(?:sp|x29)(?:, #?-?[0-9]+)?\]' if arm else r'\(%(?:rsp|rbp)\)'
            if any(not re.fullmatch(bound, address) for address in addresses):
                raise ValueError('secret load/store outside boundary')


def prepare(directory):
    fixture = directory / 'fixture'
    shutil.copytree(FIXTURE, fixture, ignore=shutil.ignore_patterns('target'))
    lib = fixture / 'src/lib.rs'
    lib.write_text(lib.read_text().replace('../../../../crates/brynja-hash-sha3/src/hardened/permutation/native.rs', 'native.rs')
                   .replace('../../../../crates/brynja-hash-sha3/src/keccak.rs', str(ROOT/'crates/brynja-hash-sha3/src/keccak.rs')))
    test = fixture / 'src/tests.rs'
    test.write_text(test.read_text().replace('../../src/guard_memory.rs', str(HERE/'src/guard_memory.rs')))
    source = fixture / 'src/native.rs'
    source.write_text(SOURCE.read_text())
    return fixture, source


def controls(original, arm):
    registers = tuple(f'x{i}' for i in range(4, 11)) if arm else REGISTERS
    wipes = [f'"mov {r}, xzr",' if arm else f'"xor {r}, {r}",' for r in registers]
    poison = ' '.join(f'"mov {r}, #-1",' if arm else f'"mov {r}, -1",' for r in registers)
    marker = '"// BRYNJA_SCALAR_ERASE",' if arm else '"# BRYNJA_SCALAR_ERASE",'
    poisoned = original.replace(marker, poison + marker)
    yield 'original', original, True
    yield 'poison-before-erasure', poisoned, True
    for wipe in wipes:
        prefix, cleanup = poisoned.split(marker)
        assert cleanup.count(wipe) == 1
        yield wipe, prefix + marker + cleanup.replace(wipe, ''), False
    changes = ([
        ('"cmp x8, #192"', '"cmp x8, #184"'),
        ('"ror x5, x5, #63"', '"ror x5, x5, #62"'),
        ('"ror x4, x4, #63"', '"ror x4, x4, #62"'),
        ('"str x4, [{rearranged}, #80]"', '"str x4, [{rearranged}, #88]"'),
        ('"bic x5, x6, x5"', '"and x5, x6, x5"'),
        ('"str x4, [{state}]"', '"nop"'),
        ('"str xzr, [{columns}, x7]"', '"nop"'),
        ('"str xzr, [{theta}, x7]"', '"nop"'),
        ('"str xzr, [{rearranged}, x7]"', '"nop"'),
        ('"cmp x7, #200",\n            "b.ne 7b"', '"cmp x7, #192",\n            "b.ne 7b"'),
    ] if arm else [
        ('"cmp r10d, 192"', '"cmp r10d, 184"'),
        ('"rol rcx, 1"', '"rol rcx, 2"'),
        ('"rol rax, 1"', '"rol rax, 2"'),
        ('"mov [{rearranged} + 80], rax"', '"mov [{rearranged} + 88], rax"'),
        ('"not rcx"', '"nop"'),
        ('"xor [{state}], rax"', '"nop"'),
        ('"mov qword ptr [{columns} + r11], 0"', '"nop"'),
        ('"mov qword ptr [{theta} + r11], 0"', '"nop"'),
        ('"mov qword ptr [{rearranged} + r11], 0"', '"nop"'),
        ('"cmp r11d, 200",\n            "jne 7b"', '"cmp r11d, 192",\n            "jne 7b"'),
    ])
    for old, new in changes:
        assert old in original
        yield old, original.replace(old, new), False


def main():
    with tempfile.TemporaryDirectory(prefix='brynja-keccak-scalar-') as temporary:
        directory = Path(temporary)
        fixture, source = prepare(directory)
        original = source.read_text()
        for compiler in ('1.90.0', '1.98.1'):
            targets = ['x86_64-unknown-linux-gnu', 'x86_64-apple-darwin',
                       'x86_64-pc-windows-' + ('gnu' if compiler == '1.90.0' else 'msvc'),
                       'aarch64-unknown-linux-musl', 'aarch64-apple-darwin',
                       'aarch64-apple-ios', 'aarch64-linux-android']
            if compiler == '1.98.1':
                targets += ['aarch64-pc-windows-msvc']
            for target in targets:
                arm = target.startswith('aarch64')
                for release in (False, True):
                    source.write_text(original)
                    env = clean_environment()
                    env['CARGO_TARGET_DIR'] = str(directory/f'{compiler}-{target}-{release}')
                    if target == 'aarch64-unknown-linux-musl':
                        env['RUSTFLAGS'] = '-C linker=rust-lld'
                        env['CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER'] = 'qemu-aarch64 -cpu max'
                    common = ['--locked', '--offline', '--manifest-path', str(fixture/'Cargo.toml'), '--target', target]
                    if release:
                        common += ['--release']
                    run(['cargo', '+'+compiler, 'rustc', *common, '--lib', '--', '--emit=asm'], env)
                    artifacts = list(Path(env['CARGO_TARGET_DIR']).glob(f'{target}/*/deps/*.s'))
                    assert len(artifacts) == 1
                    text = artifacts[0].read_text()
                    inspect(text, arm)
                    # Real emitted-code spill/reload/early-return mutations.
                    for marker in ('BEGIN', 'ERASE', 'END'):
                        prefix = '// ' if arm else '# '
                        text = re.sub(r'(?m)^\s*(?://|;|#+)\s*BRYNJA_', prefix+'BRYNJA_', text)
                        op = ('str x4, [sp]' if arm else 'pushq %rax') if marker == 'ERASE' else ('ldr x4, [x0]' if arm else 'movq (%rdi), %rax')
                        mutant = text.replace(prefix+'BRYNJA_SCALAR_'+marker, op+'\n'+prefix+'BRYNJA_SCALAR_'+marker)
                        assert mutant != text
                        try:
                            inspect(mutant, arm)
                        except ValueError:
                            pass
                        else:
                            raise ValueError('emitted boundary mutation passed')
                    print(f'Scalar KECCAK assembly: {compiler} {target} release={release}: PASS', flush=True)
                    if target not in ('x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-musl'):
                        continue
                    crate_env = dict(env, CARGO_TARGET_DIR=env['CARGO_TARGET_DIR']+'-crate')
                    run(['cargo', '+'+compiler, 'rustc', '--locked', '--offline', '-p', 'brynja-hash-sha3',
                         '--no-default-features', '--target', target, *(['--release'] if release else []),
                         '--lib', '--', '--emit=asm'], crate_env)
                    actual = list(Path(crate_env['CARGO_TARGET_DIR']).glob(f'{target}/*/deps/brynja_hash_sha3-*.s'))
                    assert len(actual) == 1
                    inspect(actual[0].read_text(), arm)
                    count = 0
                    for label, changed, success in controls(original, arm):
                        source.write_text(changed)
                        result = run(['cargo', '+'+compiler, 'test', *common, '--lib', '--', '--nocapture'], env, success=False)
                        log = result.stdout + result.stderr
                        if success:
                            if result.returncode or 'KECCAK_SCALAR: 1024 independent states;' not in log or 'KECCAK_SCALAR_BOUNDS: 32 placements;' not in log:
                                raise ValueError('positive control failed: '+log[-4000:])
                        elif result.returncode == 0 or 'test result: FAILED' not in log:
                            raise ValueError('mutant did not fail in execution: '+label+log[-4000:])
                        count += 1
                    print(f'Scalar KECCAK real crate + runtime: {compiler} {target} release={release}; {count} controls/mutants: PASS', flush=True)


if __name__ == '__main__':
    main()
