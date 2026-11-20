#!/usr/bin/env python3
"""Finite native secondary substitution-call skip; NOT S1 qualification.

Trusted optimized local AES test ELF and public FIPS fixtures only. The debugger
transcript is captured and never printed. Skipping a whole call is not proof
about arbitrary instruction skips or physical fault propagation.
"""
import argparse
import importlib.util
from pathlib import Path
import re
import subprocess
import sys

SPEC = importlib.util.spec_from_file_location(
    'retained_probe', Path(__file__).with_name('check-aes-fault-retained.py'))
R = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(R)
TRANSFORM = 'brynja_crypto::aes::fault_integrity::schedule::Schedule::transform'
SUBSTITUTE = 'brynja_crypto::aes::fault_integrity::Planes::substitute'
COPY = 'brynja_crypto::aes::fault_integrity::transaction::guarded_write'


def commands(width, path, owner, step, transform, substitute, copy=None):
    test = R.C.identity(width, path, 'baseline', owner)
    rounds = width // 4 + 6
    if width not in R.C.ANSWERS or path not in R.C.PATHS or owner not in R.C.OWNERS:
        raise ValueError('unknown round-skip fixture')
    if step < 0 or step > rounds:
        raise ValueError('round-skip step outside selected AES width')
    if copy is not None and step == 0:
        raise ValueError('combined bypass requires an actual skipped call')
    source = bytes.fromhex(R.C.ANSWERS[width] if path == 'decrypt' else R.C.PLAIN)
    answer = bytes.fromhex(R.C.PLAIN if path == 'decrypt' else R.C.ANSWERS[width])
    cmds = [
        'set debuginfod enabled off', 'set pagination off',
        'set disable-randomization off', 'starti', 'set language c',
        f"hbreak *'{transform['symbol']}'",
        f"hbreak *'{substitute}'", 'disable 2', 'continue',
        'set $transform_start=$pc',
        'set $input=(unsigned char*)$rsi',
        'set $output=(unsigned char*)$rdx',
        f'printf "ROUND_ENTRY %d\\n", ({R.bytes_at("$input", source)} && {R.bytes_at("$output", bytes(16))} && ($rcx & 255) == {int(path == "decrypt")})',
        'disable 1',
    ]
    if copy is not None:
        position = cmds.index('continue')
        cmds[position:position] = [
            f"hbreak *'{copy['symbol']}'", 'disable 3',
            f"hbreak *('{copy['symbol']}'+{copy['ret']})", 'disable 4']
    if step:
        cmds += ['enable 2']
        if step > 1:
            cmds.append(f'ignore 2 {step-1}')
        cmds += [
            'continue',
            'set $retpc=*(unsigned long long*)$rsp',
            f'printf "ROUND_TARGET %d\\n", ($retpc >= $transform_start && $retpc < $transform_start + {transform["ret"]} && ($rsi & 255) == {int(path == "decrypt")} && {R.bytes_at("$input", source)} && {R.bytes_at("$output", bytes(16))})',
            'set $rip=$retpc', 'set $rsp=$rsp+8', 'set $al=0',
            'printf "ROUND_SKIPPED %d\\n", ($rip == $retpc && $al == 0)',
            'disable 2',
        ]
    if copy is not None:
        cmds += [
            'enable 3', 'continue',
            'set $destination=(unsigned char*)$rdi',
            'set $first=(unsigned char*)$rsi',
            'set $second=(unsigned char*)$rdx',
            f'printf "ROUND_COPY_ENTRY %d\\n", ({R.bytes_at("$first", answer)} && !{R.bytes_at("$second", answer)} && $first != $second && $destination != $first && $destination != $second)',
            'set $before0=*(unsigned long long*)$destination',
            'set $before1=*(unsigned long long*)($destination+8)',
            'disable 3', 'enable 4', 'continue',
            'printf "ROUND_COPY_FAILED %d\\n", ($al == 1 && *(unsigned long long*)$destination == $before0 && *(unsigned long long*)($destination+8) == $before1)',
            'set $al=0', 'printf "ROUND_COPY_FORGED %d\\n", ($al == 0)',
            'disable 4',
        ]
    return cmds + ['continue'], test


def validate(text, width, path, owner, step, bypass_copy=False):
    test = R.C.identity(width, path, 'baseline', owner)
    rounds = width // 4 + 6
    if step < 0 or step > rounds:
        raise ValueError('round-skip step outside selected AES width')
    if bypass_copy and step == 0:
        raise ValueError('combined bypass requires an actual skipped call')
    markers = ['ROUND_ENTRY 1']
    if step:
        markers += ['ROUND_TARGET 1', 'ROUND_SKIPPED 1']
    if bypass_copy:
        markers += ['ROUND_COPY_ENTRY 1', 'ROUND_COPY_FAILED 1', 'ROUND_COPY_FORGED 1']
    if re.findall(r'^ROUND_[^\r\n]*', text, re.MULTILINE) != markers:
        raise ValueError('round-skip checkpoints unconfirmed')
    prefix = 'BRYNJA_' + owner.upper()
    expected = [prefix + '_EVIDENCE_CFG=false', f'{prefix}_CASE={width}:{path}',
                prefix + '_STORAGE_CLEARED',
                prefix + ('_ACCEPTED' if step == 0 else '_REJECTED_RETIRED')]
    if re.findall(r'^BRYNJA_[^\r\n]*', text, re.MULTILINE) != expected:
        raise ValueError('round-skip owner outcome unconfirmed')
    extra = 2 if bypass_copy else 0
    observed = (text.count('Hardware assisted breakpoint '),
                text.count('hit Breakpoint '), int(test in text),
                text.count('test result: ok. 1 passed; 0 failed; 0 ignored;'),
                text.count('exited normally'))
    required = (2 + extra, (1 if step == 0 else 2) + extra, 1, 1, 1)
    if observed != required:
        # Status counts only: never expose the raw debugger transcript.
        raise ValueError(f'round-skip native execution unconfirmed (breakpoints/stops/identity/result/exit: {observed}; required {required})')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--owner', choices=R.C.OWNERS, required=True)
    parser.add_argument('--path', choices=R.C.PATHS, required=True)
    parser.add_argument('--step', type=int, default=None,
                        help='one round to probe; omit to run all rounds')
    parser.add_argument('--bypass-write', dest='bypass_copy', action='store_true',
                        help='also forge guarded-write stage success after a skipped call; partial DC1 only')
    parser.add_argument('--objdump', default='objdump')
    parser.add_argument('--gdb', default='gdb')
    args = parser.parse_args()
    context = 'artifact setup'
    try:
        binary = args.binary.resolve(strict=True)
        original = binary.read_bytes()
        if original[:6] != b'\x7fELF\x02\x01' or original[18:20] != b'\x3e\x00':
            raise ValueError('requires x86-64 little-endian ELF')
        dump = subprocess.run(
            [args.objdump, '-d', '--demangle', '--no-show-raw-insn', str(binary)],
            capture_output=True, text=True, check=True, timeout=30).stdout
        transform_symbol = R.symbol(dump, TRANSFORM)
        transform = R.C.P.TX.body(
            dump, re.sub(r'::h[0-9a-f]{16}$', '', transform_symbol))
        substitute = R.symbol(dump, SUBSTITUTE)
        copy = None
        if args.bypass_copy:
            copy = R.C.P.TX.body(dump, re.sub(r'::h[0-9a-f]{16}$', '', R.symbol(dump, COPY)))
        count = 0
        for width in R.C.ANSWERS:
            rounds = width // 4 + 6
            steps = range(1 if args.bypass_copy else 0, rounds + 1) if args.step is None else (args.step,)
            for step in steps:
                context = f'{args.owner} {args.path} AES-{width * 8} step {step}'
                experiment, test = commands(
                    width, args.path, args.owner, step, transform, substitute, copy)
                argv = [args.gdb, '-q', '-nx', '-batch']
                for command in experiment:
                    argv += ['-ex', command]
                argv += ['--args', str(binary), '--exact', test, '--nocapture']
                run = subprocess.run(
                    argv, capture_output=True, text=True, check=True, timeout=60)
                validate(run.stdout + run.stderr, width, args.path, args.owner, step, args.bypass_copy)
                count += 1
        expected = sum(
            (width // 4 + 7 - int(args.bypass_copy)) if args.step is None else 1 for width in R.C.ANSWERS)
        if binary.read_bytes() != original or count != expected:
            raise ValueError('artifact changed or experiment incomplete')
        print(f'{args.owner} {args.path}: {count} native call-skip outcomes reproduced')
        if args.bypass_copy:
            print('Guarded-write stage success also forged; later rejection required in every case.')
        print('DEVELOPMENT_ROUND_SKIP_OBSERVED; NOT instruction-level S1 qualification')
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        detail = str(error) if isinstance(error, ValueError) else type(error).__name__
        print(f'round-skip experiment failed ({context}): {detail}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
