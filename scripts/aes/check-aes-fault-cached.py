#!/usr/bin/env python3
"""Finite x86-64 AES owner observations on trusted test artifacts, NOT qualification.

Uses public FIPS fixtures and hardware debugger stops; no executable patching.
Default output is status only. Do not run an untrusted executable.
"""
import argparse
import importlib.util
from pathlib import Path
import re
import subprocess
import sys

SPEC = importlib.util.spec_from_file_location(
    'permit_probe', Path(__file__).with_name('check-aes-fault-permit.py'))
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)
CASES = ('baseline', 'destination', 'primary', 'secondary',
         'report-forged', 'result-forged', 'state-after-restore')
PATHS = ('public', 'encrypt', 'decrypt')
OWNERS = ('cached', 'ephemeral')
ANSWERS = {
    16: '69c4e0d86a7b0430d8cdb78070b4c55a',
    24: 'dda97ca4864cdfe06eaf70a0ec0d7191',
    32: '8ea2b7ca516745bfeafc49904b496089',
}
PLAIN = '00112233445566778899aabbccddeeff'


def identity(width, path, case, owner='cached'):
    if width not in ANSWERS or path not in PATHS or case not in CASES or owner not in OWNERS:
        raise ValueError('unknown owner experiment')
    return ('aes::fault_integrity::retained::probe_tests::'
            f'native_{owner}_{width * 8}_{path}')


def answer_at(pointer, answer):
    data = bytes.fromhex(answer)
    if len(data) != 16:
        raise ValueError('invalid fixture answer')
    first, second = (int.from_bytes(data[n:n+8], 'little') for n in (0, 8))
    return (f'(*(unsigned long long*)({pointer}) == {first}ULL && '
            f'*(unsigned long long*)(({pointer})+8) == {second}ULL)')


def commands(width, path, case, permit, guard_symbol, offsets, owner='cached'):
    test = identity(width, path, case, owner)
    expected = PLAIN if path == 'decrypt' else ANSWERS[width]
    result = ['set debuginfod enabled off', 'set pagination off',
              'set disable-randomization off', 'starti', 'set language c',
              f"hbreak *'{permit['symbol']}'"]
    if case in ('report-forged', 'state-after-restore'):
        offset = offsets[-1] if case == 'report-forged' else offsets[24]
        result += [f"hbreak *('{guard_symbol}'+{offset})", 'disable 2']
    elif case == 'result-forged':
        result += [f"hbreak *('{permit['symbol']}'+{permit['ret']})", 'disable 2']
    result += ['continue', 'set $destination=(unsigned char*)$rdi',
               'set $primary=(unsigned char*)$rdx', 'set $secondary=(unsigned char*)$rcx',
               'set $owner=(unsigned char*)$r8']
    bindings = [f'{a} != {b}' for a, b in (
        ('$destination', '$primary'), ('$destination', '$secondary'),
        ('$primary', '$secondary'), ('$owner', '$destination'),
        ('$owner', '$primary'), ('$owner', '$secondary'))]
    checks = [answer_at(p, expected) for p in ('$destination', '$primary', '$secondary')]
    checks += [P.TX.same_bytes('$owner', 0x3c), '$rsi == 16'] + bindings
    result += ['printf "CACHED_SITE %d\\n", ('+' && '.join(checks)+')', 'disable 1']
    if case in P.CASES:
        result += ['enable 2']
    if case == 'state-after-restore':
        result += ['continue',
                   f'printf "CACHED_RESTORED %d\\n", ((unsigned char*)$rdi == $owner && {P.TX.same_bytes("$owner", 0x3c)})',
                   'set *$owner = *$owner ^ 1',
                   'printf "CACHED_MUTATED %d\\n", (*$owner == 0x3d)']
    elif case != 'baseline':
        target = '$'+case if case in ('primary', 'secondary') else '$destination'
        changed = bytes.fromhex(expected)[0] ^ 1
        result += [f'set *{target} = *{target} ^ 1',
                   f'printf "CACHED_MUTATED %d\\n", (*{target} == {changed})']
        if case in ('report-forged', 'result-forged'):
            result += ['continue']
            state = P.TX.same_bytes('$owner', 0xc3)
            if case == 'report-forged':
                result += [f'printf "CACHED_DENIED %d\\n", ({state} && (unsigned char*)$rdi == $owner && *(unsigned char*)$r8 == 0)',
                           'set *(unsigned char*)$r8 = 0xa5',
                           'printf "CACHED_FORGED %d\\n", (*(unsigned char*)$r8 == 0xa5)']
            else:
                result += [f'printf "CACHED_DENIED %d\\n", ({state} && $al == 1)',
                           'set $al = $al ^ 1',
                           'printf "CACHED_FORGED %d\\n", ($al == 0)']
    if case in P.CASES:
        result += ['disable 2']
    return result + ['continue'], test


def validate(text, width, path, case, owner='cached'):
    test = identity(width, path, case, owner)
    expected = ['CACHED_SITE 1']
    if case == 'state-after-restore':
        expected += ['CACHED_RESTORED 1']
    if case != 'baseline':
        expected += ['CACHED_MUTATED 1']
    if case in ('report-forged', 'result-forged'):
        expected += ['CACHED_DENIED 1', 'CACHED_FORGED 1']
    if re.findall(r'^CACHED_[^\r\n]*', text, re.MULTILINE) != expected:
        raise ValueError('cached checkpoints incomplete or inconsistent')
    prefix = 'BRYNJA_'+owner.upper()
    outcome = prefix+('_ACCEPTED' if case == 'baseline' else '_REJECTED_RETIRED')
    if re.findall(r'^BRYNJA_[^\r\n]*', text, re.MULTILINE) != [
        prefix+'_EVIDENCE_CFG=false', f'{prefix}_CASE={width}:{path}',
        prefix+'_STORAGE_CLEARED', outcome,
    ]:
        raise ValueError('cached fixture identity or outcome unconfirmed')
    stops = 2 if case in P.CASES else 1
    if (text.count('Hardware assisted breakpoint ') != stops or
            text.count('hit Breakpoint ') != stops or test not in text or
            text.count('test result: ok. 1 passed; 0 failed; 0 ignored;') != 1 or
            text.count('exited normally') != 1):
        raise ValueError('cached native execution unconfirmed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--path', choices=PATHS, required=True)
    parser.add_argument('--owner', choices=OWNERS, default='cached')
    parser.add_argument('--objdump', default='objdump')
    parser.add_argument('--gdb', default='gdb')
    args = parser.parse_args()
    try:
        binary = args.binary.resolve(strict=True)
        original = binary.read_bytes()
        if original[:6] != b'\x7fELF\x02\x01' or original[18:20] != b'\x3e\x00':
            raise ValueError('requires x86-64 little-endian ELF')
        dump = subprocess.run([args.objdump, '-d', '--demangle', '--no-show-raw-insn', str(binary)],
                              capture_output=True, text=True, check=True, timeout=30).stdout
        guard_symbol, offsets = P.TX.GUARD.inspect(dump)
        permit = P.TX.body(dump, P.PERMIT)
        count = 0
        for width in ANSWERS:
            for case in CASES:
                experiment, test = commands(width, args.path, case, permit, guard_symbol, offsets, args.owner)
                argv = [args.gdb, '-q', '-nx', '-batch']
                for command in experiment:
                    argv += ['-ex', command]
                argv += ['--args', str(binary), '--exact', test, '--nocapture']
                run = subprocess.run(argv, capture_output=True, text=True, check=True, timeout=60)
                validate(run.stdout + run.stderr, width, args.path, case, args.owner)
                count += 1
        if binary.read_bytes() != original or count != len(ANSWERS) * len(CASES):
            raise ValueError('artifact changed or experiment incomplete')
        print(f'{args.owner} {args.path}: {count} declared outcomes reproduced across AES-128/192/256')
        print(f'DEVELOPMENT_{args.owner.upper()}_OBSERVED; NOT complete fault-model or release qualification')
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        detail = str(error) if isinstance(error, ValueError) else type(error).__name__
        print('cached experiment failed: '+detail, file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
