#!/usr/bin/env python3
"""Finite native permit observations; status-only by default, NOT qualification."""
import argparse
import hashlib
import importlib.util
from pathlib import Path
import re
import subprocess
import sys

SPEC = importlib.util.spec_from_file_location(
    'transaction_probe', Path(__file__).with_name('check-aes-fault-transaction.py')
)
TX = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TX)
PERMIT = 'brynja_crypto::aes::fault_integrity::authorization_model::permit_fresh'
CASES = ('report-forged', 'result-forged', 'state-after-restore')


def commands(case, path, root, permit, guard_symbol, guard_offsets):
    if case not in CASES or path not in ('public', 'secret'):
        raise ValueError('unknown experiment')
    test = TX.TEST if path == 'public' else TX.SECRET_TEST
    result = [
        'set debuginfod enabled off', 'set pagination off',
        'set disable-randomization off', 'starti', 'set language c',
        f"hbreak *'{root['symbol']}'", f"hbreak *'{permit['symbol']}'",
    ]
    if case in ('report-forged', 'state-after-restore'):
        offset = guard_offsets[-1] if case == 'report-forged' else guard_offsets[24]
        result += [f"hbreak *('{guard_symbol}'+{offset})", 'disable 3']
    else:
        result += [f"hbreak *('{permit['symbol']}'+{permit['ret']})", 'disable 3']
    result += ['continue']
    if path == 'public':
        result += ['set $owner=(unsigned char*)$rdi', 'set $destination=(unsigned char*)$rsi']
    else:
        result += ['set $owner=(unsigned char*)$rsi', 'set $destination=(unsigned char*)$rdx']
    result += [
        f'printf "PERMIT_ENTRY %d\\n", ({TX.same_bytes("$owner",0xa5)} && {TX.same_bytes("$destination",0x91)} && $owner != $destination)',
        'disable 1', 'continue', 'set $primary=(unsigned char*)$rdx',
        'set $secondary=(unsigned char*)$rcx',
        f'printf "PERMIT_ACTUAL %d\\n", ({TX.same_bytes("$owner",0x3c)} && {TX.same_bytes("$destination",0x42)} && {TX.same_bytes("$primary",0x42)} && {TX.same_bytes("$secondary",0x42)} && (unsigned char*)$rdi == $destination && $rsi == 16 && (unsigned char*)$r8 == $owner)',
        'disable 2', 'enable 3',
    ]
    if case == 'state-after-restore':
        result += ['continue',
                   f'printf "PERMIT_RESTORED %d\\n", ((unsigned char*)$rdi == $owner && {TX.same_bytes("$owner",0x3c)})',
                   'set *$owner = *$owner ^ 1',
                   'printf "PERMIT_MUTATED %d\\n", (*$owner == 0x3d)']
    else:
        result += ['set *$destination = *$destination ^ 1',
                   'printf "PERMIT_MUTATED %d\\n", (*$destination == 0x43)', 'continue']
        if case == 'report-forged':
            result += [f'printf "PERMIT_DENIED %d\\n", ((unsigned char*)$rdi == $owner && {TX.same_bytes("$owner",0xc3)} && *(unsigned char*)$r8 == 0)',
                       'set *(unsigned char*)$r8 = 0xa5',
                       'printf "PERMIT_FORGED %d\\n", (*(unsigned char*)$r8 == 0xa5)']
        else:
            result += [f'printf "PERMIT_DENIED %d\\n", ({TX.same_bytes("$owner",0xc3)} && $al == 1)',
                       'set $al = $al ^ 1', 'printf "PERMIT_FORGED %d\\n", ($al == 0)']
    return result + ['disable 3', 'continue'], test


def validate(text, case, path):
    if case not in CASES or path not in ('public', 'secret'):
        raise ValueError('unknown experiment')
    expected = {
        'PERMIT_ENTRY': 1, 'PERMIT_ACTUAL': 1, 'PERMIT_MUTATED': 1,
        'PERMIT_DENIED': int(case != 'state-after-restore'),
        'PERMIT_FORGED': int(case != 'state-after-restore'),
        'PERMIT_RESTORED': int(case == 'state-after-restore'),
    }
    for marker, count in expected.items():
        values = re.findall(r'^'+marker+r' ([^\r\n]*)\r?$', text, re.MULTILINE)
        if values != ['1'] * count:
            raise ValueError('missing/incorrect permit checkpoint: '+marker)
    if text.count('Hardware assisted breakpoint ') != 3 or text.count('hit Breakpoint ') != 3:
        raise ValueError('hardware stop count not confirmed')
    test = TX.TEST if path == 'public' else TX.SECRET_TEST
    outcome = ('BRYNJA_TRANSACTION_REJECTED_RESTORED_RETIRED' if path == 'public'
               else 'BRYNJA_SECRET_REJECTED_CLEARED_RETIRED')
    fixture_markers = re.findall(r'^BRYNJA_[^\r\n]*', text, re.MULTILINE)
    if (fixture_markers != ['BRYNJA_TRANSACTION_EVIDENCE_CFG=false', outcome] or
            test not in text or
            text.count('test result: ok. 1 passed; 0 failed; 0 ignored;') != 1 or
            text.count('exited normally') != 1):
        raise ValueError('unconfirmed permit rejection outcome')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--path', choices=('public', 'secret'), required=True)
    parser.add_argument('--objdump', default='objdump')
    parser.add_argument('--gdb', default='gdb')
    args = parser.parse_args()
    try:
        binary = args.binary.resolve(strict=True)
        original = binary.read_bytes()
        if original[:6] != b'\x7fELF\x02\x01' or original[18:20] != b'\x3e\x00':
            raise ValueError('requires x86-64 little-endian ELF')
        dump = subprocess.run(
            [args.objdump, '-d', '--demangle', '--no-show-raw-insn', str(binary)],
            capture_output=True, text=True, check=True, timeout=30,
        ).stdout
        guard_symbol, guard_offsets = TX.GUARD.inspect(dump)
        root = TX.body(dump, TX.ROOT if args.path == 'public' else TX.SECRET_ROOT)
        permit = TX.body(dump, PERMIT)
        observations = []
        for case in CASES:
            argv = [args.gdb, '-q', '-nx', '-batch']
            experiment, test = commands(case, args.path, root, permit, guard_symbol, guard_offsets)
            for command in experiment:
                argv += ['-ex', command]
            argv += ['--args', str(binary), '--exact', test, '--nocapture']
            run = subprocess.run(argv, capture_output=True, text=True, check=True, timeout=60)
            transcript = run.stdout + run.stderr
            validate(transcript, case, args.path)
            observations.append(hashlib.sha256(transcript.encode()).hexdigest())
        if binary.read_bytes() != original or len(observations) != len(CASES):
            raise ValueError('artifact changed or experiment incomplete')
        print(f'{args.path} permit: {len(observations)} declared outcomes reproduced')
        print('DEVELOPMENT_PERMIT_OBSERVED; NOT complete C1/DC1/L1 or release qualification')
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        detail = str(error) if isinstance(error, ValueError) else type(error).__name__
        print('permit experiment failed: '+detail, file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
