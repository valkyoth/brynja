#!/usr/bin/env python3
"""Borrowed byte-xor development evidence; never changes release gates."""
from pathlib import Path
import re
import shutil
import tempfile

from check import run
from check_callers import clean_environment
from check_transfer import instructions

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SOURCE = ROOT / 'crates/brynja-core/src/secret_memory_xor.rs'
FIXTURE = HERE / 'secret-xor'


def inspect(text, arm):
    labels = list(re.finditer(r'(?m)^(_+(?:R|ZN)[^\s:]+):[^\n]*$', text))
    found = [text[m.end():labels[i+1].start() if i+1 < len(labels) else len(text)]
             for i, m in enumerate(labels) if '8xor_bits' in m[1]
             and ('secret_memory_xor' in m[1] or 'secret_xor_cleanup' in m[1])]
    if len(found) != 1:
        raise ValueError('missing/ambiguous byte-xor identity')
    end = re.search(r'(?m)^\s*retq?\s*(?:[#;].*)?$', found[0])
    if end is None:
        raise ValueError('missing return')
    body = found[0][:end.end()]
    for marker in ('BEGIN', 'ERASE', 'END'):
        if body.count('BRYNJA_XOR_' + marker) != 1:
            raise ValueError('missing opaque boundary')
    before, active = re.split(r'[^\n]*BRYNJA_XOR_BEGIN[^\n]*', body)
    active, cleanup = re.split(r'[^\n]*BRYNJA_XOR_ERASE[^\n]*', active)
    cleanup, after = re.split(r'[^\n]*BRYNJA_XOR_END[^\n]*', cleanup)
    normalized = lambda ops: [re.sub(r'\s+', ' ', op).replace(', ', ',') for op in instructions(ops)]
    work = normalized(active)
    # Exact, branch-free sequence; one byte load/store using the same pointer.
    pattern = (r'ldrb w5,\[x\d+\];lsr w5,w5,w\d+;and w5,w5,w\d+;lsl w5,w5,w\d+;'
               r'ldrb w6,\[(x\d+)\];eor w6,w6,w5;strb w6,\[\1\]'
               if arm else r'movzbl \(%r\w+\),%eax;movl %\w+,%ecx;shrl %cl,%eax;'
               r'andl %\w+,%eax;movl %\w+,%ecx;shll %cl,%eax;xorb %al,\(%r\w+\)')
    if not re.fullmatch(pattern, ';'.join(work)):
        raise ValueError('unreviewed byte-xor computation or memory width')
    expected = ['mov x5,xzr', 'mov x6,xzr', 'cmp xzr,xzr'] if arm else ['xorl %eax,%eax', 'xorl %ecx,%ecx']
    if normalized(cleanup) != expected:
        raise ValueError('missing wipe or post-cleanup work')
    for area in (before, after):
        for op in instructions(area):
            if re.fullmatch(r'"?@feat\.00"? = [0-9]+', op):
                continue
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
    lib.write_text(lib.read_text().replace('../../../../crates/brynja-core/src/secret_memory_xor.rs', 'native.rs'))
    manifest = fixture / 'Cargo.toml'
    manifest.write_text(manifest.read_text().replace('../../../crates/brynja-core', str(ROOT/'crates/brynja-core')))
    tests = fixture / 'src/tests.rs'
    tests.write_text(tests.read_text().replace('../../src/guard_memory.rs', str(HERE/'src/guard_memory.rs')))
    source = fixture / 'src/native.rs'
    source.write_text(SOURCE.read_text())
    return fixture, source


def controls(original, arm):
    marker = '"// BRYNJA_XOR_ERASE",' if arm else '"# BRYNJA_XOR_ERASE",'
    poison = '"mov x5, #-1", "mov x6, #-1",' if arm else '"mov rax, -1", "mov rcx, -1",'
    poisoned = original.replace(marker, poison + marker)
    yield 'original', original, True
    yield 'poison before wipe', poisoned, True
    wipes = ('"mov x5, xzr",', '"mov x6, xzr",') if arm else ('"xor eax, eax",', '"xor ecx, ecx",')
    for wipe in wipes:
        yield 'omitted wipe '+wipe, poisoned.replace(wipe, ''), False
    changes = ([('"lsr w5, w5, {right:w}"', '"// omitted {right:w}"'),
                ('"and w5, w5, {mask:w}"', '"// omitted {mask:w}"'),
                ('"lsl w5, w5, {left:w}"', '"// omitted {left:w}"'),
                ('"strb w6, [{destination}]"', '"nop"')]
               if arm else [('"shr eax, cl"', '"nop"'),
                            ('"and eax, {mask:e}"', '"# omitted {mask:e}"'),
                            ('"shl eax, cl"', '"nop"'),
                            ('"xor byte ptr [{destination}], al"', '"# omitted {destination}"')])
    for old, new in changes:
        if original.count(old) != 1:
            raise ValueError('stale bit-XOR mutation')
        yield old, original.replace(old, new), False


def emitted_mutants(text, arm):
    for marker in ('BEGIN', 'ERASE', 'END'):
        spill = ('bl escaped' if arm else 'callq escaped') if marker == 'BEGIN' else ('str x5, [sp]' if arm else 'pushq %rax')
        for op in ((spill, 'ldr x5, [x0]', 'ret') if arm
                   else (spill, 'movq (%rdi), %rax', 'retq')):
            mutant = re.sub(r'(?m)^(.*BRYNJA_XOR_' + marker + r'.*)$', op + r'\n\1', text)
            if mutant == text:
                raise ValueError('missing emitted mutation anchor')
            try:
                inspect(mutant, arm)
            except ValueError:
                continue
            raise ValueError('emitted boundary mutation accepted: ' + marker + ': ' + op)


def main():
    with tempfile.TemporaryDirectory(prefix='brynja-secret-xor-') as temporary:
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
                    print(f'Secret xor assembly: {compiler} {target} release={release}: PASS; nine emitted mutants', flush=True)
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
                            if result.returncode or 'SECRET_XOR: 104448' not in log or 'SECRET_XOR_BOUNDS:' not in log:
                                raise ValueError('positive control failed: '+log[-4000:])
                        elif result.returncode == 0 or 'test result: FAILED' not in log:
                            raise ValueError('mutant must compile and fail at runtime: '+label+log[-4000:])
                    print(f'Secret xor actual crate + runtime: {compiler} {target} release={release}: PASS; eight controls/mutants', flush=True)


if __name__ == '__main__':
    main()

