#!/usr/bin/env python3
"""Finite primary-result mutation plus write-status bypass; NOT DC1 qualification.

Trusted local x86-64 test ELF and public FIPS fixtures only. Debugger output is
captured and never printed. No executable bytes are patched.
"""
import argparse
import importlib.util
from pathlib import Path
import re
import subprocess
import sys

SPEC = importlib.util.spec_from_file_location(
    'round_probe', Path(__file__).with_name('check-aes-fault-round-skip.py'))
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)
R = P.R
CASES = ('baseline', 'data-only', 'combined')


def commands(width, path, owner, case, byte, write):
    if (width not in R.C.ANSWERS or path not in R.C.PATHS or
            owner not in R.C.OWNERS or case not in CASES or not 0 <= byte < 16):
        raise ValueError('unknown primary-output experiment')
    test = R.C.identity(width, path, 'baseline', owner)
    answer = bytes.fromhex(R.C.PLAIN if path == 'decrypt' else R.C.ANSWERS[width])
    changed = bytearray(answer)
    if case != 'baseline':
        changed[byte] ^= 1
    cmds = [
        'set debuginfod enabled off', 'set pagination off', 'set print thread-events off',
        'set disable-randomization off', 'starti', 'set language c',
        f"hbreak *'{write['symbol']}'",
        f"hbreak *('{write['symbol']}'+{write['ret']})", 'disable 2', 'continue',
        'set $destination=(unsigned char*)$rdi',
        'set $primary=(unsigned char*)$rsi', 'set $secondary=(unsigned char*)$rdx',
        f'printf "PRIMARY_ENTRY %d\\n", ({R.bytes_at("$primary", answer)} && {R.bytes_at("$secondary", answer)} && $primary != $secondary && $destination != $primary && $destination != $secondary)',
        'set $before0=*(unsigned long long*)$destination',
        'set $before1=*(unsigned long long*)($destination+8)',
    ]
    if case != 'baseline':
        cmds += [f'set *($primary+{byte}) = *($primary+{byte}) ^ 1',
                 f'printf "PRIMARY_MUTATED %d\\n", ({R.bytes_at("$primary", bytes(changed))} && {R.bytes_at("$secondary", answer)})']
    destination = R.bytes_at('$destination', answer) if case == 'baseline' else (
        '(*(unsigned long long*)$destination == $before0 && '
        '*(unsigned long long*)($destination+8) == $before1)')
    cmds += ['disable 1', 'enable 2', 'continue',
             f'printf "PRIMARY_RETURN %d\\n", ($al == {int(case != "baseline")} && {destination} && {R.bytes_at("$primary", bytes(changed))} && {R.bytes_at("$secondary", answer)})']
    if case == 'combined':
        cmds += ['set $al=0', 'printf "PRIMARY_FORGED %d\\n", ($al == 0)']
    return cmds + ['disable 2', 'continue'], test


def validate(text, width, path, owner, case, byte):
    # Validate identity and parameter bounds even for caller-supplied transcripts.
    _, test = commands(width, path, owner, case, byte, dict(symbol=P.COPY, ret=1))
    markers = ['PRIMARY_ENTRY 1']
    if case != 'baseline':
        markers += ['PRIMARY_MUTATED 1']
    markers += ['PRIMARY_RETURN 1']
    if case == 'combined':
        markers += ['PRIMARY_FORGED 1']
    if re.findall(r'^PRIMARY_[^\r\n]*', text, re.MULTILINE) != markers:
        raise ValueError('primary-output checkpoints unconfirmed')
    prefix = 'BRYNJA_' + owner.upper()
    expected = [prefix+'_EVIDENCE_CFG=false', f'{prefix}_CASE={width}:{path}',
                prefix+'_STORAGE_CLEARED',
                prefix+('_ACCEPTED' if case == 'baseline' else '_REJECTED_RETIRED')]
    if re.findall(r'^BRYNJA_[^\r\n]*', text, re.MULTILINE) != expected:
        raise ValueError('primary-output owner outcome unconfirmed')
    observed = (text.count('Hardware assisted breakpoint '), text.count('hit Breakpoint '),
                int(test in text), text.count('test result: ok. 1 passed; 0 failed; 0 ignored;'),
                text.count('exited normally'))
    if observed != (2, 2, 1, 1, 1):
        raise ValueError(f'native execution unconfirmed (breakpoints/stops/identity/result/exit: {observed})')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--owner', choices=R.C.OWNERS, required=True)
    parser.add_argument('--path', choices=R.C.PATHS, required=True)
    parser.add_argument('--byte', type=int, choices=range(16), default=None)
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
        write = R.C.P.TX.body(dump, re.sub(r'::h[0-9a-f]{16}$', '', R.symbol(dump, P.COPY)))
        positions = range(16) if args.byte is None else (args.byte,)
        cases = [('baseline', 0)] + [(case, byte) for byte in positions for case in CASES[1:]]
        count = 0
        for width in R.C.ANSWERS:
            for case, byte in cases:
                context = f'{args.owner} {args.path} AES-{width*8} {case} byte {byte}'
                experiment, test = commands(width, args.path, args.owner, case, byte, write)
                argv = [args.gdb, '-q', '-nx', '-batch']
                for command in experiment:
                    argv += ['-ex', command]
                argv += ['--args', str(binary), '--exact', test, '--nocapture']
                run = subprocess.run(argv, capture_output=True, text=True, check=True, timeout=60)
                validate(run.stdout+run.stderr, width, args.path, args.owner, case, byte)
                count += 1
        if binary.read_bytes() != original or count != 3*len(cases):
            raise ValueError('artifact changed or population incomplete')
        print(f'{args.owner} {args.path}: {count} primary-output outcomes reproduced')
        print('DEVELOPMENT_PRIMARY_OUTPUT_OBSERVED; NOT complete D1/DC1 or release qualification')
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        detail = str(error) if isinstance(error, ValueError) else type(error).__name__
        print(f'primary-output experiment failed ({context}): {detail}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
