#!/usr/bin/env python3
"""SHA-2/Keccak/MD5 packing development checks; never changes a release gate."""
import argparse
from pathlib import Path
import re
import shutil
import tempfile

import check
from check_callers import clean_environment

ROOT = Path(__file__).resolve().parent
FAMILY = 'sha256'
SOURCE = ROOT.parents[1] / 'crates/brynja-crypto-cpu/src/sha256_hardened_batch/transfer.rs'
FIXTURE = ROOT / 'sha256-transfer'


def instructions(area):
    return [line.strip().split('//')[0].strip() for line in area.splitlines()
            if line.strip() and not line.lstrip().startswith(('.', '#', '//', ';'))
            and not line.strip().endswith(':')]


def assembly(text, arm, count=3, md5=False):
    functions = list(re.finditer(r'(?m)^[_A-Za-z][^\n:]*transpose[^\n:]*:\s*(?:[#;].*)?$', text))
    if len(functions) != count:
        raise ValueError('missing/ambiguous transfer monomorphizations')
    for function in functions:
        body = text[function.end():]
        end = re.search(r'(?m)^\s*retq?\s*(?:[#;].*)?$', body)
        if end is None:
            raise ValueError('transfer return absent')
        body = body[:end.end()]
        for marker in ('BEGIN', 'ERASE', 'END'):
            if body.count('BRYNJA_TRANSFER_' + marker) != 1:
                raise ValueError('missing transfer boundary')
        before, active = re.split(r'[^\n]*BRYNJA_TRANSFER_BEGIN[^\n]*', body)
        active, cleanup = re.split(r'[^\n]*BRYNJA_TRANSFER_ERASE[^\n]*', active)
        cleanup, after = re.split(r'[^\n]*BRYNJA_TRANSFER_END[^\n]*', cleanup)
        if re.search(r'\b(?:call\w*|push\w*|pop\w*|ret\w*|bl|blr|br|sp|rsp|rbp|x18)\b', active):
            raise ValueError('transfer escaped stack-free block')
        registers = ('eax', 'edx', 'r8d', 'r9d') if md5 else ('eax', 'ecx', 'edx', 'r8d', 'r9d')
        expected = ([f'mov x{i}, xzr' for i in range(4, 8)] + ['cmp xzr, xzr'] if arm
                    else [f'xorl %{r}, %{r}' for r in registers])
        actual = [re.sub(r'\s+', ' ', op).replace(', ', ',') for op in instructions(cleanup)]
        if actual != [op.replace(', ', ',') for op in expected]:
            raise ValueError('transfer cleanup is incomplete or gained operations')
        for op in instructions(before + '\n' + after):
            if op.startswith('@feat.00'):
                continue
            if arm:
                if not re.match(r'(?:mov|str|stur|stp|ldr|ldur|ldp|sub|add|ret)\b', op):
                    raise ValueError('unreviewed Arm boundary operation: ' + op)
                if any(not re.match(r'\[(?:sp|x29)(?:,|\])', mem)
                       for mem in re.findall(r'\[[^\]]*\]', op)):
                    raise ValueError('Arm secret access outside boundary')
                if re.search(r'\b[vdqs][0-9]+\b', op):
                    raise ValueError('Arm vector outside boundary')
            else:
                # The real MD5 fixed-copy caller supplies lane=0. LLVM may
                # materialize that public constant here rather than in its caller.
                if md5 and re.fullmatch(r'xorl\s+%ecx,\s*%ecx', op):
                    continue
                if not re.match(r'(?:movq|movl|pushq|popq|subq|addq|retq)\b', op):
                    raise ValueError('unreviewed x86 boundary operation: ' + op)
                if any(not re.fullmatch(r'\(%(?:rsp|rbp)\)', mem)
                       for mem in re.findall(r'\([^)]*\)', op)):
                    raise ValueError('x86 secret access outside boundary')


def prepare(directory):
    fixture = directory / 'fixture'
    shutil.copytree(FIXTURE, fixture, ignore=shutil.ignore_patterns('target'))
    lib = fixture / 'src/lib.rs'
    lib.write_text(lib.read_text().replace('../../../../' + SOURCE.relative_to(ROOT.parents[1]).as_posix(), 'transfer.rs'))
    tests = fixture / 'src/tests.rs'
    tests.write_text(tests.read_text().replace('../../src/guard_memory.rs', (ROOT / 'src/guard_memory.rs').as_posix()))
    source = fixture / 'src/transfer.rs'
    source.write_text(SOURCE.read_text())
    if FAMILY == 'md5':
        shutil.copytree(SOURCE.with_suffix(''), fixture / 'src/transfer')
    return fixture, source


def integrated(directory, compiler, target, release):
    """Inspect the real crate too, not only a forced test monomorphization."""
    env = clean_environment()
    destination = directory / f'crate-{compiler}-{target}-{release}'
    env['CARGO_TARGET_DIR'] = str(destination)
    arm = target.startswith('aarch64')
    env['RUSTFLAGS'] = '-C target-feature=' + ('+neon' if arm else '+avx2')
    package = 'brynja-legacy-md5' if FAMILY == 'md5' else 'brynja-crypto-cpu'
    feature = 'hardened-execution' if FAMILY == 'md5' else FAMILY + '-hardened-batch'
    command = ['cargo', '+' + compiler, 'rustc', '--locked', '--offline',
               '--manifest-path', str(ROOT.parents[1] / 'Cargo.toml'),
               '-p', package, '--features', feature,
               '--target', target, '--lib']
    if release:
        command += ['--release']
    check.run(command + ['--', '--emit=asm'], env)
    files = list(destination.glob(target + '/*/deps/' + package.replace('-', '_') + '-*.s'))
    if len(files) != 1:
        raise ValueError('ambiguous actual CPU crate assembly')
    assembly(files[0].read_text(), arm, {'keccak': 2, 'md5': 4}.get(FAMILY, 3), FAMILY == 'md5')
    print(f'Actual CPU crate transfers: {compiler} {target} release={release}: PASS', flush=True)


def main():
    global FAMILY, SOURCE, FIXTURE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arm', action='store_true')
    parser.add_argument('--family', choices=('sha256', 'sha512', 'keccak', 'md5'), default='sha256')
    args = parser.parse_args()
    FAMILY = args.family
    SOURCE = ROOT.parents[1] / f'crates/brynja-crypto-cpu/src/{FAMILY}_hardened_batch/transfer.rs'
    if FAMILY == 'md5':
        SOURCE = ROOT.parents[1] / 'crates/brynja-legacy-md5/src/cpu/transfer.rs'
    FIXTURE = ROOT / (FAMILY + '-transfer')
    layouts = {'sha256': 2592, 'sha512': 1440, 'keccak': 320, 'md5': 800}[FAMILY]
    guards = {'keccak': 8, 'md5': 28}.get(FAMILY, 12)
    functions = {'keccak': 2, 'md5': 4}.get(FAMILY, 3)
    with tempfile.TemporaryDirectory(prefix=f'brynja-{FAMILY}-transfer-') as temporary:
        directory = Path(temporary)
        fixture, source = prepare(directory)
        original = source.read_text()
        for compiler in ('1.90.0', '1.98.1'):
            targets = ['x86_64-unknown-linux-gnu', 'x86_64-apple-darwin',
                       'x86_64-pc-windows-gnu' if compiler == '1.90.0' else 'x86_64-pc-windows-msvc']
            if args.arm:
                targets += ['aarch64-unknown-linux-musl', 'aarch64-apple-darwin', 'aarch64-apple-ios', 'aarch64-linux-android']
                if compiler == '1.98.1':
                    targets += ['aarch64-pc-windows-msvc']
            for target in targets:
                arm = target.startswith('aarch64')
                for release in (False, True):
                    env = clean_environment()
                    env['CARGO_TARGET_DIR'] = str(directory / f'{compiler}-{target}-{release}')
                    if target == 'aarch64-unknown-linux-musl':
                        env['RUSTFLAGS'] = '-C linker=rust-lld'
                        env['CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER'] = 'qemu-aarch64 -cpu max'
                    common = ['--locked', '--offline', '--manifest-path', str(fixture / 'Cargo.toml'), '--target', target]
                    if release:
                        common += ['--release']
                    source.write_text(original)
                    check.run(['cargo', '+' + compiler, 'rustc', *common, '--lib', '--', '--emit=asm'], env)
                    artifacts = list(Path(env['CARGO_TARGET_DIR']).glob(f'{target}/*/deps/*.s'))
                    if len(artifacts) != 1:
                        raise ValueError('ambiguous assembly artifact')
                    text = artifacts[0].read_text()
                    text = re.sub(r'(?m)^\s*(?://|;)\s*BRYNJA_', '// BRYNJA_', text) if arm else re.sub(r'(?m)^\s*#+\s*BRYNJA_', '# BRYNJA_', text)
                    assembly(text, arm, functions, FAMILY == 'md5')
                    for marker in ('BEGIN', 'ERASE', 'END'):
                        # Add an actual spill or post-cleanup secret reload to the
                        # emitted stream, not merely a mismatching source token.
                        comment = '// ' if arm else '# '
                        probe = 'str x4, [sp]' if arm else 'pushq %rax'
                        if marker in ('BEGIN', 'END'):
                            probe = 'ldr x4, [x0]' if arm else 'movq (%rdi), %rax'
                        mutant = text.replace(comment + 'BRYNJA_TRANSFER_' + marker,
                                              probe + '\n' + comment + 'BRYNJA_TRANSFER_' + marker)
                        if mutant == text:
                            raise ValueError('missing assembly mutation anchor')
                        try:
                            assembly(mutant, arm, functions, FAMILY == 'md5')
                        except ValueError:
                            pass
                        else:
                            raise ValueError('accepted boundary mutation: ' + marker)
                    print(f'Transfer assembly: {compiler} {target} release={release}: PASS', flush=True)
                    if target not in ('x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-musl'):
                        continue
                    integrated(directory, compiler, target, release)
                    narrow = FAMILY in ('sha256', 'md5')
                    register = ('w4' if narrow else 'x4') if arm else ('eax' if narrow else 'rax')
                    mutations = ([('"mov x4, xzr",', '"mov x4, #1",'),
                                  (f'"rev {register}, {register}",', ''),
                                  (f'"str {register}, [{{destination}}, x7]",', '"// omitted {destination}",'),
                                  (f'"ldr {register}, [{{source}}, x7]",', '"// omitted {source}", "mov x4, #0",')]
                                 if arm else [('"xor eax, eax",', '"mov eax, 1",'),
                                              (f'"bswap {register}",', ''),
                                              (f'"mov [{{destination}} + rdx], {register}",', '"# omitted {destination}",'),
                                              (f'"mov {register}, [{{source}} + rdx]",', '"# omitted {source}", "xor eax, eax",')])
                    if FAMILY == 'keccak':
                        # Keccak is little-endian on both supported targets;
                        # there is deliberately no byte reversal to remove.
                        mutations = [item for item in mutations if not item[0].startswith(('"rev ', '"bswap '))]
                        mutations += [(('"cmp x6, #25",' if arm else '"cmp r8, 25",'),
                                       ('"cmp x6, #24",' if arm else '"cmp r8, 24",')),
                                      ('{ 200 }', '{ 192 }')]
                    if FAMILY == 'md5':
                        mutations = [item for item in mutations if not item[0].startswith(('"rev ', '"bswap '))]
                        mutations += [
                            ('words = const WORDS,', 'words = const WORDS - 1,'),
                            (('source_shift = const if PACK { 2 } else { 5 },' if arm else
                              'source_stride = const if PACK { 4 } else { 32 },'),
                             ('source_shift = const if PACK { 2 } else { 4 },' if arm else
                              'source_stride = const if PACK { 4 } else { 16 },')),
                            ('source_lane = const if PACK { 0 } else { 4 },',
                             'source_lane = const if PACK { 0 } else { 0 },'),
                        ]
                    if FAMILY in ('sha512', 'keccak'):
                        # A 32-bit transplant must not truncate the upper half
                        # of a state, input word or output, even if it clears.
                        mutations += ([('"ldr x4, [{source}, x7]",', '"ldr w4, [{source}, x7]",'),
                                       ('"str x4, [{destination}, x7]",', '"str w4, [{destination}, x7]",'),
                                       ('"rev x4, x4",', '"rev w4, w4",')]
                                      if arm else [('"mov rax, [{source} + rdx]",', '"mov eax, [{source} + rdx]",'),
                                                   ('"mov [{destination} + rdx], rax",', '"mov [{destination} + rdx], eax",'),
                                                   ('"bswap rax",', '"bswap eax",')])
                        if FAMILY == 'keccak':
                            mutations = [item for item in mutations if not item[0].startswith(('"rev ', '"bswap '))]
                    cases = [('original', original, True)]
                    # Poison before erasure must still pass; then omit its wipe.
                    wipe = '"mov x4, xzr",' if arm else '"xor eax, eax",'
                    poison = '"mov x4, #-1",' if arm else '"mov rax, -1",'
                    poisoned = original.replace(wipe, poison + wipe)
                    cases += [('poisoned', poisoned, True), ('removed wipe', poisoned.replace(wipe, ''), False)]
                    for before, after in mutations:
                        expected_count = 4 if before == '{ 200 }' else (2 if FAMILY == 'md5' and before.startswith(('words = ', 'source_lane = ')) else 1)
                        if original.count(before) != expected_count:
                            raise ValueError('stale source mutation anchor')
                        cases.append((before, original.replace(before, after), False))
                    for label, changed, succeeds in cases:
                        source.write_text(changed)
                        result = check.run(['cargo', '+' + compiler, 'test', *common, '--lib', '--', '--nocapture'], env, success=False)
                        log = result.stdout + result.stderr
                        if succeeds:
                            if result.returncode or f'{FAMILY.upper()}_TRANSFER: {layouts} layouts;' not in log or f'{FAMILY.upper()}_TRANSFER_BOUNDS: {guards} guarded placements;' not in log:
                                raise ValueError('positive transfer control failed: ' + log[-4000:])
                        elif result.returncode == 0 or 'test result: FAILED' not in log:
                            raise ValueError('mutant did not fail in execution: ' + label + log[-4000:])
                    print(f'Transfer runtime: {compiler} {target} release={release}: {len(cases)} controls/mutants PASS', flush=True)
        source.write_text(original)


if __name__ == '__main__':
    main()
