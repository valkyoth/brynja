#!/usr/bin/env python3
"""Finite native retained-key observations; trusted test ELF only, NOT qualification.

Uses hardware stops in existing capture/secondary-computation helpers, with no
source injection hooks or executable patching. Only public FIPS fixtures run.
"""
import argparse
import importlib.util
from pathlib import Path
import re
import subprocess
import sys

SPEC = importlib.util.spec_from_file_location(
    'owner_probe', Path(__file__).with_name('check-aes-fault-cached.py'))
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)
CAPTURE = 'brynja_crypto::aes::fault_integrity::capture::pair'
TRANSFORM = 'brynja_crypto::aes::fault_integrity::schedule::Schedule::transform'
COPY = 'brynja_core::secret_memory_transfer::copy_bytes'
CASES = ('baseline', 'primary-key', 'secondary-key',
         'secondary-schedule-before', 'secondary-schedule-after', 'secondary-rounds-after',
         'input-capture')


def symbol(dump, wanted):
    parent, method = wanted.rsplit('::', 1)
    variants = (wanted, '<'+parent+'>::'+method)
    matches = []
    for line in dump.splitlines():
        match = re.fullmatch(r'\s*[0-9a-fA-F]+ <(.+)>:\s*', line)
        if match and re.sub(r'::h[0-9a-f]{16}$', '', match[1]) in variants:
            matches.append(match[1])
    if len(matches) != 1:
        raise ValueError('missing or ambiguous retained helper')
    return matches[0]


def bytes_at(pointer, data):
    if not data or len(data) % 8:
        raise ValueError('invalid fixture extent')
    return '('+' && '.join(
        f'*(unsigned long long*)(({pointer})+{n}) == {int.from_bytes(data[n:n+8], "little")}ULL'
        for n in range(0, len(data), 8))+')'


def input_capture_commands(width, path, owner, capture, copy):
    test = C.identity(width, path, 'baseline', owner)
    expected = bytes.fromhex(C.ANSWERS[width] if path == 'decrypt' else C.PLAIN)
    changed = bytes([expected[0] ^ 1])+expected[1:]
    result = ['set debuginfod enabled off', 'set pagination off',
              'set disable-randomization off', 'starti', 'set language c',
              f"hbreak *'{capture}'", 'ignore 1 1',
              f"hbreak *('{copy['symbol']}'+{copy['ret']})", 'disable 2', 'continue',
              'set $source=(unsigned char*)$rdi', 'set $first=(unsigned char*)$rdx',
              'set $second=(unsigned char*)$r8']
    checks = ['$rsi == 16', '$rcx == 16', '$r9 == 16',
              '$source != $first', '$source != $second', '$first != $second',
              bytes_at('$source', expected), bytes_at('$first', bytes(16)), bytes_at('$second', bytes(16))]
    result += ['printf "RETAINED_INPUT %d\\n", ('+' && '.join(checks)+')',
               'disable 1', 'enable 2', 'continue',
               f'printf "RETAINED_FIRST_COPY %d\\n", ((unsigned char*)$rdi == $first && (unsigned char*)$rsi == $source && {bytes_at("$first", expected)} && {bytes_at("$source", expected)} && {bytes_at("$second", bytes(16))})',
               'set *$first = *$first ^ 1',
               f'printf "RETAINED_MUTATED %d\\n", ({bytes_at("$first", changed)})',
               'continue',
               f'printf "RETAINED_SECOND_COPY %d\\n", ((unsigned char*)$rdi == $second && (unsigned char*)$rsi == $source && {bytes_at("$first", changed)} && {bytes_at("$second", expected)} && {bytes_at("$source", expected)})',
               'disable 2', 'continue']
    return result, test


def commands(width, path, owner, case, capture, transform, copy=None):
    test = C.identity(width, path, 'baseline', owner)
    if case not in CASES:
        raise ValueError('unknown retained experiment')
    if case == 'input-capture':
        if copy is None:
            raise ValueError('missing native copy boundary')
        return input_capture_commands(width, path, owner, capture, copy)
    key = bytes(range(width))
    expected_input = C.ANSWERS[width] if path == 'decrypt' else C.PLAIN
    expected_output = C.PLAIN if path == 'decrypt' else C.ANSWERS[width]
    inverse = 1 if path == 'decrypt' else 0
    after = case.endswith('-after')
    rounds = width // 4 + 6
    # Public fixture's first 16 key bytes encoded independently into bit planes.
    planes = bytes(sum(((byte >> bit) & 1) << lane for lane, byte in enumerate(key[half:half+8]))
                   for half in (0, 8) for bit in range(8))
    commands = [
        'set debuginfod enabled off', 'set pagination off',
        'set disable-randomization off', 'starti', 'set language c',
        f"hbreak *'{capture}'", f"hbreak *'{transform['symbol']}'", 'disable 2',
    ]
    if after:
        commands += [f"hbreak *('{transform['symbol']}'+{transform['ret']})", 'disable 3']
    commands += ['continue',
        'set $first=(unsigned char*)$rdx', 'set $second=(unsigned char*)$r8',
    ]
    captures = [f'$rsi == {width}', f'$rcx == {width}', f'$r9 == {width}',
                '$first != $second', '$first != (unsigned char*)$rdi', '$second != (unsigned char*)$rdi',
                bytes_at('$rdi', key), bytes_at('$first', bytes([0x91])*width),
                bytes_at('$second', bytes([0x92])*width)]
    commands += ['printf "RETAINED_CAPTURE %d\\n", ('+' && '.join(captures)+')',
                 'disable 1', 'enable 2', 'continue']
    window = [bytes_at('$first', key), bytes_at('$second', bytes(b ^ 255 for b in key)),
              C.answer_at('$rsi', expected_input), f'$cl == {inverse}',
              '$first != (unsigned char*)$rdi', '$second != (unsigned char*)$rdi']
    commands += ['printf "RETAINED_WINDOW %d\\n", ('+' && '.join(window)+')', 'disable 2']
    if case.startswith('secondary-schedule') or case == 'secondary-rounds-after':
        # Explicitly admitted layout hypotheses for this private fixture type:
        # one usize round count and fifteen sixteen-byte planes. Require a
        # unique match; never silently guess offsets for an unfamiliar build.
        commands += [
            'set $schedule=(unsigned char*)$rdi',
            'set $result=(unsigned char*)$rdx',
            f'set $front=(*(unsigned long long*)$schedule == {rounds} && {bytes_at("$schedule+8", planes)})',
            f'set $back=(*(unsigned long long*)($schedule+240) == {rounds} && {bytes_at("$schedule", planes)})',
            'printf "RETAINED_LAYOUT %d\\n", ($front + $back == 1)',
            'set $planes=$schedule+($front ? 8 : 0)',
            'set $rounds=$schedule+($front ? 0 : 240)',
        ]
        if after:
            commands += ['enable 3', 'continue',
                         f'printf "RETAINED_RETURN %d\\n", ($al == 0 && {C.answer_at("$result", expected_output)} && {bytes_at("$planes", planes)} && *(unsigned long long*)$rounds == {rounds})',
                         'disable 3']
        if case == 'secondary-rounds-after':
            commands += ['set *$rounds = *$rounds ^ 1',
                         f'printf "RETAINED_MUTATED %d\\n", (*(unsigned long long*)$rounds == {rounds ^ 1})']
        else:
            commands += ['set *$planes = *$planes ^ 1',
                         f'printf "RETAINED_MUTATED %d\\n", (*$planes == {planes[0] ^ 1})']
    elif case != 'baseline':
        target, expected = ('$first', 1) if case == 'primary-key' else ('$second', 254)
        commands += [f'set *{target} = *{target} ^ 1',
                     f'printf "RETAINED_MUTATED %d\\n", (*{target} == {expected})']
    return commands+['continue'], test


def validate(text, width, path, owner, case):
    test = C.identity(width, path, 'baseline', owner)
    if case not in CASES:
        raise ValueError('unknown retained experiment')
    markers = ['RETAINED_CAPTURE 1', 'RETAINED_WINDOW 1']
    if case.startswith('secondary-schedule') or case == 'secondary-rounds-after':
        markers += ['RETAINED_LAYOUT 1']
    if case.endswith('-after'):
        markers += ['RETAINED_RETURN 1']
    if case != 'baseline':
        markers += ['RETAINED_MUTATED 1']
    if case == 'input-capture':
        markers = ['RETAINED_INPUT 1', 'RETAINED_FIRST_COPY 1',
                   'RETAINED_MUTATED 1', 'RETAINED_SECOND_COPY 1']
    if re.findall(r'^RETAINED_[^\r\n]*', text, re.MULTILINE) != markers:
        raise ValueError('retained event checkpoints unconfirmed')
    prefix = 'BRYNJA_'+owner.upper()
    expected = [prefix+'_EVIDENCE_CFG=false', f'{prefix}_CASE={width}:{path}',
                prefix+'_STORAGE_CLEARED',
                prefix+('_ACCEPTED' if case == 'baseline' else '_REJECTED_RETIRED')]
    if re.findall(r'^BRYNJA_[^\r\n]*', text, re.MULTILINE) != expected:
        raise ValueError('retained-key outcome unconfirmed')
    stops = 3 if case.endswith('-after') else 2
    hits = 3 if case == 'input-capture' else stops
    observed = (
        text.count('Hardware assisted breakpoint '),
        text.count('hit Breakpoint '),
        int(test in text),
        text.count('test result: ok. 1 passed; 0 failed; 0 ignored;'),
        text.count('exited normally'),
    )
    expected = (stops, hits, 1, 1, 1)
    if observed != expected:
        raise ValueError(f'retained native execution unconfirmed: checks={observed}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--owner', choices=C.OWNERS, required=True)
    parser.add_argument('--path', choices=C.PATHS, required=True)
    parser.add_argument('--objdump', default='objdump')
    parser.add_argument('--gdb', default='gdb')
    args = parser.parse_args()
    context = 'artifact setup'
    try:
        binary = args.binary.resolve(strict=True)
        original = binary.read_bytes()
        if original[:6] != b'\x7fELF\x02\x01' or original[18:20] != b'\x3e\x00':
            raise ValueError('requires x86-64 little-endian ELF')
        dump = subprocess.run([args.objdump, '-d', '--demangle', '--no-show-raw-insn', str(binary)],
                              capture_output=True, text=True, check=True, timeout=30).stdout
        capture = symbol(dump, CAPTURE)
        transform = C.P.TX.body(dump, re.sub(r'::h[0-9a-f]{16}$', '', symbol(dump, TRANSFORM)))
        copy = C.P.TX.body(dump, re.sub(r'::h[0-9a-f]{16}$', '', symbol(dump, COPY)))
        count = 0
        for width in C.ANSWERS:
            for case in CASES:
                context = f'{args.owner} {args.path} AES-{width * 8} {case}'
                experiment, test = commands(width, args.path, args.owner, case, capture, transform, copy)
                argv = [args.gdb, '-q', '-nx', '-batch']
                for command in experiment:
                    argv += ['-ex', command]
                argv += ['--args', str(binary), '--exact', test, '--nocapture']
                run = subprocess.run(argv, capture_output=True, text=True, check=True, timeout=60)
                validate(run.stdout+run.stderr, width, args.path, args.owner, case)
                count += 1
        if binary.read_bytes() != original or count != len(C.ANSWERS)*len(CASES):
            raise ValueError('artifact changed or experiment incomplete')
        print(f'{args.owner} {args.path}: {count} retained-key outcomes reproduced across AES-128/192/256')
        print('DEVELOPMENT_RETAINED_OBSERVED; NOT full fault-model or release qualification')
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        detail = str(error) if isinstance(error, ValueError) else type(error).__name__
        print(f'retained experiment failed ({context}): {detail}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
