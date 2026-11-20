#!/usr/bin/env python3
"""Finite native operation-local completion probes; NOT release qualification.

Trusted local AES test ELF and public FIPS fixtures only. Raw debugger output
is captured, never printed. These cases do not qualify the full fault budget.
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
EPHEMERAL = 'brynja_crypto::aes::fault_integrity::retained::ephemeral::Ephemeral::compute'
RETAINED = 'brynja_crypto::aes::fault_integrity::retained::Retained::compute'
CASES = ('baseline', 'late-key-only', 'late-key-plus-result-bypass')


def commands(width, path, case, capture, ephemeral, retained):
    test = R.C.identity(width, path, 'baseline', 'ephemeral')
    if case not in CASES:
        raise ValueError('unknown outer completion experiment')
    key = bytes(range(width))
    changed = bytes([key[0] ^ 1]) + key[1:]
    source = bytes.fromhex(R.C.ANSWERS[width] if path == 'decrypt' else R.C.PLAIN)
    answer = bytes.fromhex(R.C.PLAIN if path == 'decrypt' else R.C.ANSWERS[width])
    initial = bytes(16)
    marked = bytes([0x69] * 16)
    cmds = [
        'set debuginfod enabled off', 'set pagination off',
        'set disable-randomization off', 'starti', 'set language c',
        f"hbreak *'{capture}'",
        f"hbreak *'{ephemeral['symbol']}'", 'disable 2',
        f"hbreak *('{retained['symbol']}'+{retained['ret']})", 'disable 3',
        f"hbreak *('{ephemeral['symbol']}'+{ephemeral['ret']})", 'disable 4',
        'continue',
        'set $key=(unsigned char*)$rdx',
        f'printf "OUTER_CAPTURE %d\\n", ($rsi == {width} && $rcx == {width} && $r9 == {width} && {R.bytes_at("$rdi", key)} && {R.bytes_at("$key", bytes([0x91])*width)} && {R.bytes_at("$r8", bytes([0x92])*width)})',
        'disable 1', 'enable 2', 'continue',
        'set $input=(unsigned char*)$rsi',
        'set $primary=(unsigned char*)$rdx',
        'set $secondary=(unsigned char*)$rcx',
        'set $outer=(unsigned char*)$r9',
        f'printf "OUTER_ENTRY %d\\n", ({R.bytes_at("$key", key)} && {R.bytes_at("$input", source)} && {R.bytes_at("$primary", initial)} && {R.bytes_at("$secondary", initial)} && {R.bytes_at("$outer", initial)} && $outer != $primary && $outer != $secondary && ($r8 & 255) == {int(path == "decrypt")})',
        'disable 2', 'enable 3', 'continue',
        f'printf "OUTER_INNER_RETURN %d\\n", ($al == 0 && {R.bytes_at("$primary", answer)} && {R.bytes_at("$secondary", answer)} && {R.bytes_at("$key", key)} && {R.bytes_at("$outer", initial)})',
        'disable 3',
    ]
    if case != 'baseline':
        cmds += ['set *$key = *$key ^ 1',
                 f'printf "OUTER_MUTATED %d\\n", ({R.bytes_at("$key", changed)})']
    cmds += [
        'enable 4', 'continue',
        f'printf "OUTER_RETURN %d\\n", ($al == {int(case != "baseline")} && {R.bytes_at("$primary", answer)} && {R.bytes_at("$secondary", answer)} && {R.bytes_at("$key", key if case == "baseline" else changed)} && {R.bytes_at("$outer", marked if case == "baseline" else initial)})',
    ]
    if case == 'late-key-plus-result-bypass':
        cmds += ['set $al = 0', 'printf "OUTER_FORGED %d\\n", ($al == 0)']
    return cmds + ['disable 4', 'continue'], test


def validate(text, width, path, case):
    test = R.C.identity(width, path, 'baseline', 'ephemeral')
    if case not in CASES:
        raise ValueError('unknown outer completion experiment')
    markers = ['OUTER_CAPTURE 1', 'OUTER_ENTRY 1', 'OUTER_INNER_RETURN 1']
    if case != 'baseline':
        markers.append('OUTER_MUTATED 1')
    markers.append('OUTER_RETURN 1')
    if case == 'late-key-plus-result-bypass':
        markers.append('OUTER_FORGED 1')
    if re.findall(r'^OUTER_[^\r\n]*', text, re.MULTILINE) != markers:
        raise ValueError('outer completion checkpoints unconfirmed')
    expected = ['BRYNJA_EPHEMERAL_EVIDENCE_CFG=false',
                f'BRYNJA_EPHEMERAL_CASE={width}:{path}',
                'BRYNJA_EPHEMERAL_STORAGE_CLEARED',
                'BRYNJA_EPHEMERAL_' + ('ACCEPTED' if case == 'baseline' else 'REJECTED_RETIRED')]
    if re.findall(r'^BRYNJA_[^\r\n]*', text, re.MULTILINE) != expected:
        raise ValueError('outer completion outcome unconfirmed')
    if (text.count('Hardware assisted breakpoint ') != 4 or
            text.count('hit Breakpoint ') != 4 or test not in text or
            text.count('test result: ok. 1 passed; 0 failed; 0 ignored;') != 1 or
            text.count('exited normally') != 1):
        raise ValueError('outer native execution unconfirmed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--path', choices=R.C.PATHS, required=True)
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
        def body(wanted):
            symbol = R.symbol(dump, wanted)
            return R.C.P.TX.body(dump, re.sub(r'::h[0-9a-f]{16}$', '', symbol))
        capture = R.symbol(dump, R.CAPTURE)
        ephemeral, retained = body(EPHEMERAL), body(RETAINED)
        count = 0
        for width in R.C.ANSWERS:
            for case in CASES:
                context = f'ephemeral {args.path} AES-{width * 8} {case}'
                experiment, test = commands(width, args.path, case, capture, ephemeral, retained)
                argv = [args.gdb, '-q', '-nx', '-batch']
                for command in experiment:
                    argv += ['-ex', command]
                argv += ['--args', str(binary), '--exact', test, '--nocapture']
                run = subprocess.run(argv, capture_output=True, text=True, check=True, timeout=60)
                validate(run.stdout + run.stderr, width, args.path, case)
                count += 1
        if binary.read_bytes() != original or count != len(R.C.ANSWERS) * len(CASES):
            raise ValueError('artifact changed or experiment incomplete')
        print(f'ephemeral {args.path}: {count} late-completion outcomes reproduced')
        print('DEVELOPMENT_OUTER_COMPLETION_OBSERVED; NOT full fault-model qualification')
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        detail = str(error) if isinstance(error, ValueError) else type(error).__name__
        print(f'outer completion experiment failed ({context}): {detail}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
