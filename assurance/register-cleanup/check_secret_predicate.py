#!/usr/bin/env python3
"""Borrowed byte-predicate development evidence; never changes release gates."""
from pathlib import Path
import argparse
import re
import shutil
import tempfile

from check import run
from check_callers import clean_environment
from check_transfer import instructions

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SOURCE = ROOT / 'crates/brynja-core/src/secret_memory_predicate.rs'
FIXTURE = HERE / 'secret-predicate'


def inspect(text, arm):
    labels = list(re.finditer(r'(?m)^(_+(?:R|ZN)[^\s:]+):[^\n]*$', text))
    found = [text[m.end():labels[i+1].start() if i+1 < len(labels) else len(text)]
             for i, m in enumerate(labels) if '12mask_is_zero' in m[1]
             and ('secret_memory_predicate' in m[1] or 'secret_predicate_cleanup' in m[1])]
    if len(found) != 1:
        raise ValueError('missing/ambiguous byte-predicate identity')
    end = re.search(r'(?m)^\s*retq?\s*(?:[#;].*)?$', found[0])
    if end is None:
        raise ValueError('missing return')
    body = found[0][:end.end()]
    for marker in ('BEGIN', 'ERASE', 'END'):
        if body.count('BRYNJA_PREDICATE_' + marker) != 1:
            raise ValueError('missing opaque boundary')
    before, active = re.split(r'[^\n]*BRYNJA_PREDICATE_BEGIN[^\n]*', body)
    active, cleanup = re.split(r'[^\n]*BRYNJA_PREDICATE_ERASE[^\n]*', active)
    cleanup, after = re.split(r'[^\n]*BRYNJA_PREDICATE_END[^\n]*', cleanup)
    normalized = lambda ops: [re.sub(r'\s+', ' ', op).replace(', ', ',') for op in instructions(ops)]
    work = normalized(active)
    # One byte load; only the normalized predicate may leave the boundary.
    if arm:
        pattern = r'ldrb w4,\[x\d+\];and w4,w4,w\d+;cmp w4,#0;cset w(?!4\b)\d+,eq'
        valid = re.fullmatch(pattern, ';'.join(work))
    else:
        pattern = r'movzbl \(%r\w+\),%r10d;andl %\w+,%r10d;sete %(\w+);movzbl %(\w+),%(\w+)'
        match = re.fullmatch(pattern, ';'.join(work))
        aliases = {'al': 'eax', 'bl': 'ebx', 'cl': 'ecx', 'dl': 'edx',
                   'sil': 'esi', 'dil': 'edi', 'bpl': 'ebp', 'spl': 'esp'}
        aliases.update({f'r{i}b': f'r{i}d' for i in range(8, 16) if i != 10})
        valid = (match and match[1] == match[2] and aliases.get(match[1]) == match[3])
    if not valid:
        raise ValueError('unreviewed predicate computation, result normalization or byte width')
    expected = ['mov x4,xzr', 'cmp xzr,xzr'] if arm else ['xorl %r10d,%r10d']
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
    lib.write_text(lib.read_text().replace('../../../../crates/brynja-core/src/secret_memory_predicate.rs', 'native.rs'))
    manifest = fixture / 'Cargo.toml'
    manifest.write_text(manifest.read_text().replace('../../../crates/brynja-core', str(ROOT/'crates/brynja-core')))
    tests = fixture / 'src/tests.rs'
    tests.write_text(tests.read_text().replace('../../src/guard_memory.rs', str(HERE/'src/guard_memory.rs')))
    source = fixture / 'src/native.rs'
    source.write_text(SOURCE.read_text())
    return fixture, source


def controls(original, arm):
    marker = '"// BRYNJA_PREDICATE_ERASE",' if arm else '"# BRYNJA_PREDICATE_ERASE",'
    wipe = '"mov x4, xzr",' if arm else '"xor r10d, r10d",'
    poison = '"mov x4, #-1",' if arm else '"mov r10, -1",'
    poisoned = original.replace(marker, poison + marker)
    yield 'original', original, True
    yield 'poison before wipe', poisoned, True
    yield 'omitted wipe', poisoned.replace(wipe, ''), False
    changes = ([('"and w4, w4, {mask:w}"', '"// omitted {mask:w}"'),
                ('"cset {result:w}, eq"', '"cset {result:w}, ne"'),
                ('"cmp xzr, xzr"', '"cmp w4, #1"')]
               if arm else [('"and r10d, {mask:e}"', '"and r10d, 255 # omitted {mask:e}"'),
                            ('"sete {result:l}"', '"setne {result:l}"'),
                            ('"# BRYNJA_PREDICATE_END"', '"cmp r10d, 1", "# BRYNJA_PREDICATE_END"')])
    for old, new in changes:
        if original.count(old) != 1:
            raise ValueError('stale predicate mutation')
        yield old, original.replace(old, new), False


def emitted_mutants(text, arm):
    for marker in ('BEGIN', 'ERASE', 'END'):
        spill = ('bl escaped' if arm else 'callq escaped') if marker == 'BEGIN' else ('str x4, [sp]' if arm else 'pushq %r10')
        for op in ((spill, 'ldr x4, [x0]', 'ret') if arm
                   else (spill, 'movq (%rdi), %r10', 'retq')):
            mutant = re.sub(r'(?m)^(.*BRYNJA_PREDICATE_' + marker + r'.*)$', op + r'\n\1', text)
            if mutant == text:
                raise ValueError('missing emitted mutation anchor')
            try:
                inspect(mutant, arm)
            except ValueError:
                continue
            raise ValueError('emitted boundary mutation accepted: ' + marker + ': ' + op)


def constructor_mutants():
    """Compile the real constructor and tests, not an equivalent model."""
    with tempfile.TemporaryDirectory(prefix='brynja-bit-constructor-') as temporary:
        directory = Path(temporary)
        shutil.copytree(ROOT / 'crates/brynja-hash-core/src', directory / 'src')
        shutil.copy(ROOT / 'crates/brynja-hash-core/README.md', directory / 'README.md')
        (directory / 'Cargo.toml').write_text(
            '[workspace]\n[package]\nname="bit-constructor-probe"\n'
            'version="0.0.0"\nedition="2024"\n')
        source = directory / 'src/bit_string.rs'
        original = source.read_text()
        changes = (
            ('predicate inversion', '!crate::secret_memory_predicate::apply(byte, unused_mask)',
             'crate::secret_memory_predicate::apply(byte, unused_mask)'),
            ('canonicality bypass', '!crate::secret_memory_predicate::apply(byte, unused_mask)',
             'false'),
            ('wrong bit order', 'u8::MAX >> valid_bits_in_last_byte',
             'u8::MAX << valid_bits_in_last_byte'),
            ('wrong source byte', 'bytes.last().ok_or(BitStringError::InvalidValidBitCount)?',
             'bytes.first().ok_or(BitStringError::InvalidValidBitCount)?'),
        )
        for compiler in ('1.90.0', '1.98.1'):
            for release in (False, True):
                command = ['cargo', '+' + compiler, 'test', '--offline', '--manifest-path',
                           str(directory / 'Cargo.toml'), '--lib']
                if release:
                    command += ['--release']
                environment = clean_environment()
                environment['CARGO_TARGET_DIR'] = str(directory / 'target')
                source.write_text(original)
                run(command, environment)
                for label, old, new in changes:
                    if original.count(old) != 1:
                        raise ValueError('stale constructor mutation: ' + label)
                    source.write_text(original.replace(old, new))
                    result = run(command, environment, success=False)
                    if (result.returncode == 0 or 'test result: FAILED' not in result.stdout
                            or 'error[E' in result.stderr):
                        raise ValueError('constructor mutant must compile and fail tests: '
                                         + label + result.stdout + result.stderr)
                print(f'BitString constructor: {compiler} release={release}: PASS; '
                      'four compiled mutants rejected', flush=True)


def main(hash_core=False):
    global SOURCE
    package = 'brynja-hash-core' if hash_core else 'brynja-core'
    if hash_core:
        SOURCE = ROOT / 'crates/brynja-hash-core/src/secret_memory_predicate.rs'
    with tempfile.TemporaryDirectory(prefix='brynja-secret-predicate-') as temporary:
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
                    print(f'Secret predicate assembly: {compiler} {target} release={release}: PASS; nine emitted mutants', flush=True)
                    if target not in ('x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-musl'):
                        continue
                    crate_env = dict(env, CARGO_TARGET_DIR=env['CARGO_TARGET_DIR']+'-crate')
                    run(['cargo', '+'+compiler, 'rustc', '--locked', '--offline', '-p', package,
                         '--no-default-features', '--target', target, *(['--release'] if release else []),
                         '--lib', '--', '--emit=asm'], crate_env)
                    actual = list(Path(crate_env['CARGO_TARGET_DIR']).glob(f'{target}/*/deps/{package.replace("-", "_")}-*.s'))
                    if len(actual) != 1:
                        raise ValueError('ambiguous actual crate assembly')
                    inspect(actual[0].read_text(), arm)
                    for label, changed, success in controls(original, arm):
                        source.write_text(changed)
                        result = run(['cargo', '+'+compiler, 'test', *common, '--lib', '--', '--nocapture'], env, success=False)
                        log = result.stdout + result.stderr
                        if success:
                            if result.returncode or 'SECRET_PREDICATE: 65536' not in log or 'SECRET_PREDICATE_BOUNDS:' not in log:
                                raise ValueError('positive control failed: '+log[-4000:])
                        elif result.returncode == 0 or 'test result: FAILED' not in log:
                            raise ValueError('mutant must compile and fail at runtime: '+label+log[-4000:])
                    print(f'Secret predicate actual crate + runtime: {compiler} {target} release={release}: PASS; six controls/mutants', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hash-core', action='store_true',
                        help='inspect the dependency-free hash-interface predicate and actual crate')
    parser.add_argument('--constructor-only', action='store_true',
                        help='run only the real MSB-first constructor compiled mutations')
    args = parser.parse_args()
    if args.hash_core or args.constructor_only:
        constructor_mutants()
    if not args.constructor_only:
        main(args.hash_core)
