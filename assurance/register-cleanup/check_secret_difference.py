#!/usr/bin/env python3
"""Borrowed difference development evidence; no release workflow changes."""
from pathlib import Path
import re
import shutil
import tempfile

from check import run
from check_callers import clean_environment
from check_transfer import instructions

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SOURCE = ROOT / 'crates/brynja-core/src/secret_memory_difference.rs'


def inspect(text, arm):
    labels = list(re.finditer(r'(?m)^(_+(?:R|ZN)[^\s:]+):[^\n]*$', text))
    found = [text[m.end():labels[i+1].start() if i+1 < len(labels) else len(text)]
             for i, m in enumerate(labels) if '15accumulate_byte' in m[1]]
    if len(found) != 1:
        raise ValueError('missing/ambiguous difference identity')
    end = re.search(r'(?m)^\s*retq?\s*(?:[#;].*)?$', found[0])
    if end is None:
        raise ValueError('missing return')
    body = found[0][:end.end()]
    for marker in ('BEGIN', 'ERASE', 'END'):
        if body.count('BRYNJA_DIFFERENCE_' + marker) != 1:
            raise ValueError('missing opaque boundary')
    before, active = re.split(r'[^\n]*BRYNJA_DIFFERENCE_BEGIN[^\n]*', body)
    active, cleanup = re.split(r'[^\n]*BRYNJA_DIFFERENCE_ERASE[^\n]*', active)
    cleanup, after = re.split(r'[^\n]*BRYNJA_DIFFERENCE_END[^\n]*', cleanup)
    normalized = lambda ops: [re.sub(r'\s+', ' ', op).replace(', ', ',') for op in instructions(ops)]
    pattern = (r'ldrb w4,\[x\d+\];ldrb w5,\[x\d+\];eor w4,w4,w5;'
               r'ldrb w5,\[(x\d+)\];orr w4,w4,w5;strb w4,\[\1\]' if arm else
               r'movzbl \(%r\w+\),%eax;xorb \(%r\w+\),%al;orb %al,\(%r\w+\)')
    if not re.fullmatch(pattern, ';'.join(normalized(active))):
        raise ValueError('unreviewed difference computation or byte width')
    expected = ['mov x4,xzr', 'mov x5,xzr', 'cmp xzr,xzr'] if arm else ['xorl %eax,%eax']
    if normalized(cleanup) != expected:
        raise ValueError('missing register/flags cleanup')
    for area in (before, after):
        for op in instructions(area):
            if re.fullmatch(r'"?@feat\.00"? = [0-9]+', op):
                continue
            branch = re.fullmatch(r'b\s+([.A-Za-z_][.A-Za-z_0-9]*)', op)
            if arm and branch:
                target = re.search(r'(?m)^' + re.escape(branch[1]) + ':', area)
                if target and target.start() > area.index(op):
                    continue
            if not re.match(r'(?:mov|movq|movl|pushq|popq|subq|addq|str|stur|stp|ldr|ldur|ldp|sub|add|retq?)\b', op):
                raise ValueError('unreviewed compiler operation: ' + op)
            if re.search(r'%(?:xmm|ymm|zmm)|\b[vdqs][0-9]+\b', op):
                raise ValueError('vector operation outside boundary')
            addresses = re.findall(r'\[[^]]*\]' if arm else r'\([^)]*\)', op)
            bound = r'\[(?:sp|x29)(?:, #?-?[0-9]+)?\]' if arm else r'\(%(?:rsp|rbp)\)'
            if any(not re.fullmatch(bound, address) for address in addresses):
                raise ValueError('secret load/store outside boundary')


def mutants(source, arm):
    marker = '"// BRYNJA_DIFFERENCE_ERASE",' if arm else '"# BRYNJA_DIFFERENCE_ERASE",'
    poison = '"mov x4, #-1", "mov x5, #-1",' if arm else '"mov rax, -1",'
    poisoned = source.replace(marker, poison + marker)
    yield 'control', source, True
    yield 'poison before wipe', poisoned, True
    for wipe in (['"mov x4, xzr",', '"mov x5, xzr",'] if arm else ['"xor eax, eax",']):
        yield 'omitted wipe', poisoned.replace(wipe, ''), False
    changes = ([('"eor w4, w4, w5"', '"eor w4, w4, w4"'),
                ('"orr w4, w4, w5"', '"eor w4, w4, w5"'),
                ('"cmp xzr, xzr"', '"cmp w4, #1"')] if arm else
               [('"xor al, byte ptr [{right}]"', '"xor al, byte ptr [{left}] # {right}"'),
                ('"or byte ptr [{difference}], al"', '"xor byte ptr [{difference}], al"'),
                ('"# BRYNJA_DIFFERENCE_END"', '"cmp eax, 1", "# BRYNJA_DIFFERENCE_END"')])
    for before, after in changes:
        if source.count(before) != 1:
            raise ValueError('missing mutation target')
        yield before, source.replace(before, after), False


def emitted_mutants(text, arm):
    for marker in ('BEGIN', 'ERASE', 'END'):
        for op in (('bl escaped', 'ldr x4, [x0]', 'ret') if arm else
                   ('callq escaped', 'movq (%rdi), %rax', 'retq')):
            mutant = re.sub(r'(?m)^(.*BRYNJA_DIFFERENCE_' + marker + r'.*)$', op + r'\n\1', text)
            try:
                inspect(mutant, arm)
            except ValueError:
                continue
            raise ValueError('emitted mutation escaped: ' + marker + op)


def main():
    with tempfile.TemporaryDirectory(prefix='brynja-difference-') as temporary:
        directory = Path(temporary)
        fixture = directory / 'fixture'
        shutil.copytree(HERE / 'secret-difference', fixture, ignore=shutil.ignore_patterns('target'))
        lib = fixture / 'src/lib.rs'
        lib.write_text(lib.read_text().replace('../../../../crates/brynja-core/src/secret_memory_difference.rs', 'native.rs'))
        tests = fixture / 'src/tests.rs'
        tests.write_text(tests.read_text().replace('../../src/guard_memory.rs', str(HERE / 'src/guard_memory.rs')))
        source = fixture / 'src/native.rs'
        original = SOURCE.read_text()
        for compiler in ('1.90.0', '1.98.1'):
            targets = ['x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-musl',
                       'x86_64-apple-darwin', 'aarch64-apple-darwin',
                       'x86_64-pc-windows-' + ('gnu' if compiler == '1.90.0' else 'msvc'),
                       'aarch64-apple-ios', 'aarch64-linux-android']
            if compiler == '1.98.1':
                targets.append('aarch64-pc-windows-msvc')
            for target in targets:
                arm = target.startswith('aarch64')
                for release in (False, True):
                    source.write_text(original)
                    env = clean_environment()
                    env['CARGO_TARGET_DIR'] = str(directory / f'{compiler}-{target}-{release}')
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
                    print(f'Difference assembly: {compiler} {target} release={release}: PASS; nine emitted mutants', flush=True)
                    if target not in ('x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-musl'):
                        continue
                    crate_env = dict(env, CARGO_TARGET_DIR=env['CARGO_TARGET_DIR']+'-crate')
                    run(['cargo', '+'+compiler, 'rustc', '--locked', '--offline', '-p', 'brynja-core',
                         '--target', target, *(['--release'] if release else []), '--lib', '--', '--emit=asm'], crate_env)
                    actual = list(Path(crate_env['CARGO_TARGET_DIR']).glob(f'{target}/*/deps/brynja_core-*.s'))
                    if len(actual) != 1:
                        raise ValueError('ambiguous actual crate assembly')
                    inspect(actual[0].read_text(), arm)
                    for label, changed, success in mutants(original, arm):
                        source.write_text(changed)
                        result = run(['cargo', '+'+compiler, 'test', *common, '--lib', '--', '--nocapture'], env, success=False)
                        log = result.stdout + result.stderr
                        if success:
                            if result.returncode or 'SECRET_DIFFERENCE: 262144' not in log or 'SECRET_DIFFERENCE_BOUNDS:' not in log:
                                raise ValueError('positive failed: ' + log[-3000:])
                        elif result.returncode == 0 or 'test result: FAILED' not in log:
                            raise ValueError('mutant did not compile and fail: ' + label + log[-3000:])
                    print(f'Difference runtime: {compiler} {target} release={release}: PASS', flush=True)


if __name__ == '__main__':
    main()
