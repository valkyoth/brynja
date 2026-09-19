#!/usr/bin/env python3
"""Borrowed byte-mask development evidence; never changes release gates."""
from pathlib import Path
import re
import shutil
import tempfile

from check import run
from check_callers import clean_environment
from check_transfer import instructions

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SOURCE = ROOT / 'crates/brynja-core/src/secret_memory_mask.rs'
FIXTURE = HERE / 'secret-mask'


def inspect(text, arm):
    labels = list(re.finditer(r'(?m)^(_+(?:R|ZN)[^\s:]+):[^\n]*$', text))
    found = [text[m.end():labels[i+1].start() if i+1 < len(labels) else len(text)]
             for i, m in enumerate(labels) if '9mask_byte' in m[1]
             and ('secret_memory_mask' in m[1] or 'secret_mask_cleanup' in m[1])]
    if len(found) != 1:
        raise ValueError('missing/ambiguous byte-mask identity')
    end = re.search(r'(?m)^\s*retq?\s*(?:[#;].*)?$', found[0])
    if end is None:
        raise ValueError('missing return')
    body = found[0][:end.end()]
    for marker in ('BEGIN', 'ERASE', 'END'):
        if body.count('BRYNJA_MASK_' + marker) != 1:
            raise ValueError('missing opaque boundary')
    before, active = re.split(r'[^\n]*BRYNJA_MASK_BEGIN[^\n]*', body)
    active, cleanup = re.split(r'[^\n]*BRYNJA_MASK_ERASE[^\n]*', active)
    cleanup, after = re.split(r'[^\n]*BRYNJA_MASK_END[^\n]*', cleanup)
    normalized = lambda ops: [re.sub(r'\s+', ' ', op).replace(', ', ',') for op in instructions(ops)]
    work = normalized(active)
    # Exact, branch-free sequence; one byte load/store using the same pointer.
    pattern = (r'ldrb w4,\[(x\d+)\];and w4,w4,w\d+;orr w4,w4,w\d+;strb w4,\[\1\]'
               if arm else r'movzbl \(%(r\w+)\),%eax;andb %\w+,%al;orb %\w+,%al;movb %al,\(%\1\)')
    if not re.fullmatch(pattern, ';'.join(work)):
        raise ValueError('unreviewed byte-mask computation or memory width')
    expected = ['mov x4,xzr', 'cmp xzr,xzr'] if arm else ['xorl %eax,%eax']
    if normalized(cleanup) != expected:
        raise ValueError('missing wipe or post-cleanup work')
    for area in (before, after):
        for op in instructions(area):
            if re.fullmatch(r'"?@feat\.00"? = [0-9]+', op):
                continue
            if arm and area == before and re.fullmatch(r'and\s+w(?!4\b)\d+,\s*w(?!4\b)\d+,\s*#0xff', op):
                continue  # Public mask canonicalization before the sole secret load.
            branch = re.fullmatch(r'b\s+([.A-Za-z_][.A-Za-z_0-9]*)', op)
            if arm and branch:
                target = re.search(r'(?m)^' + re.escape(branch[1]) + ':', area)
                if target and target.start() > area.index(op):
                    continue  # Local forward block cannot skip the opaque boundary.
            if not re.match(r'(?:mov|movq|movl|movb|movzbl|pushq|popq|subq|addq|str|strb|stur|stp|ldr|ldrb|ldur|ldp|sub|add|retq?)\b', op):
                raise ValueError('unreviewed compiler operation: ' + op)
            if re.search(r'%(?:xmm|ymm|zmm)|\b[vdqs][0-9]+\b', op):
                raise ValueError('vector operation outside boundary')
            addresses = re.findall(r'\[[^]]*\]' if arm else r'\([^)]*\)', op)
            bound = r'\[(?:sp|x29)(?:, #?-?[0-9]+)?\]' if arm else r'\(%(?:rsp|rbp)\)'
            if any(not re.fullmatch(bound, address) for address in addresses):
                raise ValueError('secret load/store outside boundary')


def prepare(directory):
    fixture = directory / 'fixture'
    shutil.copytree(FIXTURE, fixture, ignore=shutil.ignore_patterns('target'))
    lib = fixture / 'src/lib.rs'
    lib.write_text(lib.read_text().replace('../../../../crates/brynja-core/src/secret_memory_mask.rs', 'native.rs'))
    manifest = fixture / 'Cargo.toml'
    manifest.write_text(manifest.read_text().replace('../../../crates/brynja-core', str(ROOT/'crates/brynja-core')))
    tests = fixture / 'src/tests.rs'
    tests.write_text(tests.read_text().replace('../../src/guard_memory.rs', str(HERE/'src/guard_memory.rs')))
    source = fixture / 'src/native.rs'
    source.write_text(SOURCE.read_text())
    return fixture, source


def controls(original, arm):
    marker = '"// BRYNJA_MASK_ERASE",' if arm else '"# BRYNJA_MASK_ERASE",'
    wipe = '"mov x4, xzr",' if arm else '"xor eax, eax",'
    poison = '"mov x4, #-1",' if arm else '"mov rax, -1",'
    poisoned = original.replace(marker, poison + marker)
    yield 'original', original, True
    yield 'poison before wipe', poisoned, True
    yield 'omitted wipe', poisoned.replace(wipe, ''), False
    changes = ([('"and w4, w4, {keep:w}"', '"// omitted {keep:w}"'),
                ('"orr w4, w4, {set:w}"', '"// omitted {set:w}"'),
                ('"strb w4, [{byte}]"', '"nop"')]
               if arm else [('"and al, {keep}"', '"# omitted {keep}"'),
                            ('"or al, {set}"', '"# omitted {set}"'),
                            ('"mov byte ptr [{byte}], al"', '"nop"')])
    for old, new in changes:
        if original.count(old) != 1:
            raise ValueError('stale byte-mask mutation')
        yield old, original.replace(old, new), False


def emitted_mutants(text, arm):
    for marker in ('BEGIN', 'ERASE', 'END'):
        spill = ('bl escaped' if arm else 'callq escaped') if marker == 'BEGIN' else ('str x4, [sp]' if arm else 'pushq %rax')
        for op in ((spill, 'ldr x4, [x0]', 'ret') if arm
                   else (spill, 'movq (%rdi), %rax', 'retq')):
            mutant = re.sub(r'(?m)^(.*BRYNJA_MASK_' + marker + r'.*)$', op + r'\n\1', text)
            if mutant == text:
                raise ValueError('missing emitted mutation anchor')
            try:
                inspect(mutant, arm)
            except ValueError:
                continue
            raise ValueError('emitted boundary mutation accepted: ' + marker + ': ' + op)


def main():
    with tempfile.TemporaryDirectory(prefix='brynja-secret-mask-') as temporary:
        directory = Path(temporary)
        fixture, source = prepare(directory)
        original = source.read_text()
        for compiler in ('1.90.0', '1.98.1'):
            targets = ['x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-musl',
                       'x86_64-apple-darwin', 'aarch64-apple-darwin',
                       'x86_64-pc-windows-' + ('gnu' if compiler == '1.90.0' else 'msvc'),
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
                    if len(artifacts) != 1:
                        raise ValueError('ambiguous fixture assembly')
                    text = artifacts[0].read_text()
                    inspect(text, arm)
                    emitted_mutants(text, arm)
                    print(f'Secret mask assembly: {compiler} {target} release={release}: PASS; nine emitted mutants', flush=True)
                    if target not in ('x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-musl'):
                        continue
                    crate_env = dict(env, CARGO_TARGET_DIR=env['CARGO_TARGET_DIR']+'-crate')
                    run(['cargo', '+'+compiler, 'rustc', '--locked', '--offline', '-p', 'brynja-core',
                         '--no-default-features', '--target', target, *(['--release'] if release else []),
                         '--lib', '--', '--emit=asm'], crate_env)
                    actual = list(Path(crate_env['CARGO_TARGET_DIR']).glob(f'{target}/*/deps/brynja_core-*.s'))
                    if len(actual) != 1:
                        raise ValueError('ambiguous actual crate assembly')
                    inspect(actual[0].read_text(), arm)
                    for label, changed, success in controls(original, arm):
                        source.write_text(changed)
                        result = run(['cargo', '+'+compiler, 'test', *common, '--lib', '--', '--nocapture'], env, success=False)
                        log = result.stdout + result.stderr
                        if success:
                            if result.returncode or 'SECRET_MASK: 196608' not in log or 'SECRET_MASK_BOUNDS:' not in log:
                                raise ValueError('positive control failed: '+log[-4000:])
                        elif result.returncode == 0 or 'test result: FAILED' not in log:
                            raise ValueError('mutant must compile and fail at runtime: '+label+log[-4000:])
                    print(f'Secret mask actual crate + runtime: {compiler} {target} release={release}: PASS; six controls/mutants', flush=True)


if __name__ == '__main__':
    main()
