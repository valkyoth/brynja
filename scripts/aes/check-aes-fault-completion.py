#!/usr/bin/env python3
"""Finite native computation-completion probes, NOT release qualification.

Trusted local AES test ELF and public FIPS fixtures only. No code patching.
Raw debugger output is captured, never printed.
"""
import argparse
import importlib.util
from pathlib import Path
import re
import subprocess
import sys

SPEC = importlib.util.spec_from_file_location('retained_probe', Path(__file__).with_name('check-aes-fault-retained.py'))
R = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(R)
COMPUTE = 'brynja_crypto::aes::fault_integrity::retained::Retained::compute'
CASES = ('baseline', 'input-only', 'input-plus-completion-bypass', 'completion-bit')


def commands(width, path, owner, case, compute, capture, copy):
    test = R.C.identity(width, path, 'baseline', owner)
    if case not in CASES:
        raise ValueError('unknown completion experiment')
    source = bytes.fromhex(R.C.ANSWERS[width] if path == 'decrypt' else R.C.PLAIN)
    answer = bytes.fromhex(R.C.PLAIN if path == 'decrypt' else R.C.ANSWERS[width])
    input_fault = case.startswith('input-')
    observed = bytes([source[0] ^ 1])+source[1:] if input_fault else source
    cmds = ['set debuginfod enabled off', 'set pagination off', 'set disable-randomization off',
            'starti', 'set language c', f"hbreak *'{compute['symbol']}'",
            f"hbreak *'{capture}'", 'disable 2',
            f"hbreak *('{copy['symbol']}'+{copy['ret']})", 'disable 3',
            f"hbreak *('{compute['symbol']}'+{compute['ret']})", 'disable 4',
            'continue', 'set $input=(unsigned char*)$rsi',
            'set $primary=(unsigned char*)$rdx', 'set $secondary=(unsigned char*)$rcx',
            'set $completion=(unsigned char*)$r9',
            f'printf "COMPLETION_ENTRY %d\\n", ({R.bytes_at("$input", source)} && {R.bytes_at("$primary", bytes(16))} && {R.bytes_at("$secondary", bytes(16))} && {R.bytes_at("$completion", bytes(16))} && $primary != $secondary && $completion != $primary && $completion != $secondary && ($r8 & 255) == {int(path == "decrypt")})',
            'disable 1', 'enable 2', 'continue',
            'set $first=(unsigned char*)$rdx', 'set $second=(unsigned char*)$r8',
            f'printf "COMPLETION_CAPTURE %d\\n", ((unsigned char*)$rdi == $input && $rsi == 16 && $rcx == 16 && $r9 == 16 && $first != $second && {R.bytes_at("$first", bytes(16))} && {R.bytes_at("$second", bytes(16))})',
            'disable 2', 'enable 3', 'continue',
            f'printf "COMPLETION_FIRST %d\\n", ((unsigned char*)$rdi == $first && (unsigned char*)$rsi == $input && {R.bytes_at("$first", source)} && {R.bytes_at("$second", bytes(16))})']
    if input_fault:
        cmds += ['set *$first = *$first ^ 1', f'printf "COMPLETION_MUTATED %d\\n", ({R.bytes_at("$first", observed)})']
    cmds += ['continue',
             f'printf "COMPLETION_SECOND %d\\n", ((unsigned char*)$rdi == $second && (unsigned char*)$rsi == $input && {R.bytes_at("$first", observed)} && {R.bytes_at("$second", source)} && {R.bytes_at("$input", source)})',
             'disable 3', 'enable 4', 'continue']
    output = bytes(16) if input_fault else answer
    marker = bytes(16) if input_fault else bytes([0x69] * 16)
    cmds += [f'printf "COMPLETION_RETURN %d\\n", ($al == {int(input_fault)} && {R.bytes_at("$primary", output)} && {R.bytes_at("$secondary", output)} && {R.bytes_at("$completion", marker)})']
    if case == 'input-plus-completion-bypass':
        cmds += ['set $al = 0', 'printf "COMPLETION_FORGED %d\\n", ($al == 0)']
    if case == 'completion-bit':
        changed = bytes([0x68] + [0x69] * 15)
        cmds += ['set *$completion = *$completion ^ 1',
                 f'printf "COMPLETION_BIT %d\\n", ({R.bytes_at("$completion", changed)})']
    return cmds+['disable 4', 'continue'], test


def validate(text, width, path, owner, case):
    test = R.C.identity(width, path, 'baseline', owner)
    if case not in CASES:
        raise ValueError('unknown completion experiment')
    markers = ['COMPLETION_ENTRY 1', 'COMPLETION_CAPTURE 1', 'COMPLETION_FIRST 1']
    if case.startswith('input-'): markers += ['COMPLETION_MUTATED 1']
    markers += ['COMPLETION_SECOND 1', 'COMPLETION_RETURN 1']
    if case == 'input-plus-completion-bypass': markers += ['COMPLETION_FORGED 1']
    if case == 'completion-bit': markers += ['COMPLETION_BIT 1']
    if re.findall(r'^COMPLETION_[^\r\n]*', text, re.MULTILINE) != markers:
        raise ValueError('completion event checkpoints unconfirmed')
    prefix = 'BRYNJA_'+owner.upper()
    expected = [prefix+'_EVIDENCE_CFG=false', f'{prefix}_CASE={width}:{path}',
                prefix+'_STORAGE_CLEARED', prefix+('_ACCEPTED' if case == 'baseline' else '_REJECTED_RETIRED')]
    if re.findall(r'^BRYNJA_[^\r\n]*', text, re.MULTILINE) != expected:
        raise ValueError('completion bypass did not meet fixture outcome contract')
    if (text.count('Hardware assisted breakpoint ') != 4 or text.count('hit Breakpoint ') != 5 or
            test not in text or text.count('test result: ok. 1 passed; 0 failed; 0 ignored;') != 1 or
            text.count('exited normally') != 1):
        raise ValueError('completion native execution unconfirmed')


def confirmation_flags(text, test):
    """Bounded diagnostic booleans only; never disclose debugger transcript."""
    return {
        'breakpoints_declared': text.count('Hardware assisted breakpoint ') == 4,
        'breakpoints_hit': text.count('hit Breakpoint ') == 5,
        'fixture_identity': test in text,
        'fixture_passed': text.count('test result: ok. 1 passed; 0 failed; 0 ignored;') == 1,
        'normal_exit': text.count('exited normally') == 1,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--owner', choices=R.C.OWNERS, required=True)
    parser.add_argument('--path', choices=R.C.PATHS, required=True)
    parser.add_argument('--objdump', default='objdump')
    parser.add_argument('--gdb', default='gdb')
    parser.add_argument('--diagnostic-summary', action='store_true',
                        help='on failure, print only bounded confirmation booleans')
    args = parser.parse_args()
    context = 'artifact setup'
    try:
        binary = args.binary.resolve(strict=True)
        original = binary.read_bytes()
        if original[:6] != b'\x7fELF\x02\x01' or original[18:20] != b'\x3e\x00':
            raise ValueError('requires x86-64 little-endian ELF')
        dump = subprocess.run([args.objdump, '-d', '--demangle', '--no-show-raw-insn', str(binary)], capture_output=True, text=True, check=True, timeout=30).stdout
        def body(wanted):
            return R.C.P.TX.body(dump, re.sub(r'::h[0-9a-f]{16}$', '', R.symbol(dump, wanted)))
        compute, copy, capture = body(COMPUTE), body(R.COPY), R.symbol(dump, R.CAPTURE)
        count = 0
        for width in R.C.ANSWERS:
            for case in CASES:
                context = f'{args.owner} {args.path} AES-{width * 8} {case}'
                experiment, test = commands(width, args.path, args.owner, case, compute, capture, copy)
                argv = [args.gdb, '-q', '-nx', '-batch']
                for command in experiment: argv += ['-ex', command]
                argv += ['--args', str(binary), '--exact', test, '--nocapture']
                run = subprocess.run(argv, capture_output=True, text=True, check=True, timeout=60)
                try:
                    validate(run.stdout+run.stderr, width, args.path, args.owner, case)
                except ValueError:
                    if args.diagnostic_summary:
                        flags = confirmation_flags(run.stdout+run.stderr, test)
                        print('completion confirmation flags: ' +
                              ', '.join(f'{name}={int(value)}' for name, value in flags.items()),
                              file=sys.stderr)
                    raise
                count += 1
        if binary.read_bytes() != original or count != len(R.C.ANSWERS)*len(CASES):
            raise ValueError('artifact changed or experiment incomplete')
        print(f'{args.owner} {args.path}: {count} completion outcomes reproduced across AES-128/192/256')
        print('DEVELOPMENT_COMPLETION_OBSERVED; NOT full fault-model or release qualification')
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        detail = str(error) if isinstance(error, ValueError) else type(error).__name__
        print(f'completion experiment failed ({context}): {detail}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
