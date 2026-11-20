#!/usr/bin/env python3
"""Optional x86-64 debugger experiments on a development leaf, NOT qualification.

Uses hardware breakpoints in a child test executable. Does not patch its bytes.
Never run against an untrusted executable. No network or release gate is used.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

SYMBOL = 'brynja_core::fault_comparison_workbench::guarded_copy::opaque'
TEST = 'fault_comparison_workbench::guarded_copy::tests::both_bad_receipts_leave_output_unchanged'
EXPECTED = '''movb $0x0,(%r8)
xor %eax,%eax
xor %r9d,%r9d
movzwl (%rdx,%r9,1),%r10d
xor $0x3ca5,%r10d
or %r10d,%eax
add $0x2,%r9d
cmp $0x20,%r9d
jb @3
mov $0xffff,%r11d
mov $0x20,%r9d
sub $0x2,%r9d
movzwl (%rcx,%r9,1),%r10d
xor $0xc35a,%r10d
not %r10d
and %r10d,%r11d
test %r9d,%r9d
jne @11
test %eax,%eax
jne @25
cmp $0xffff,%r11d
jne @25
movdqu (%rsi),%xmm0
movdqu %xmm0,(%rdi)
movb $0xa5,(%r8)
pxor %xmm0,%xmm0
xor %eax,%eax
xor %r9d,%r9d
xor %r10d,%r10d
xor %r11d,%r11d
ret'''.splitlines()

# Index, event. Single-bypass cases must leave the output unchanged. In this
# fail-fast order the second branch is unreachable while the first rejects;
# exercising both branch bypasses is explicitly a two-event negative control.
CASES = {
    'baseline': [],
    'skip-first-branch': [(19, 'skip')],
    'flip-first-condition': [(19, 'flags')],
    'erase-first-accumulator': [(18, 'first')],
    'skip-first-test': [(18, 'skip')],
    'repair-second-accumulator': [(18, 'second')],
    'two-branch-bypasses-negative-control': [(19, 'skip'), (21, 'skip')],
}


def inspect(dump):
    selected, found, body, symbol = False, False, [], None
    for line in dump.splitlines():
        header = re.fullmatch(r'\s*([0-9a-fA-F]+) <(.+)>:\s*', line)
        if header:
            selected = re.sub(r'::h[0-9a-f]{16}$', '', header[2]) == SYMBOL
            if selected:
                if found:
                    raise ValueError('duplicate guard leaf')
                found, symbol = True, header[2]
                start = int(header[1], 16)
        elif selected and line.strip():
            instruction = re.fullmatch(r'\s*([0-9a-fA-F]+):\s+(.+?)\s*', line)
            if not instruction:
                raise ValueError('unparsed guard instruction')
            body.append((int(instruction[1], 16), re.sub(r'\s+', ' ', instruction[2]).replace(', ', ',')))
    while body and body[-1][1] == 'int3':
        body.pop()
    addresses = [a for a, _ in body]
    if not found or not body or addresses[0] != start or addresses != sorted(set(addresses)):
        raise ValueError('missing/invalid guard leaf')
    normalized = []
    for _, operation in body:
        branch = re.fullmatch(r'(jb|jne) ([0-9a-fA-F]+)(?: <[^>]+>)?', operation)
        if branch:
            target = int(branch[2], 16)
            if target not in addresses:
                raise ValueError('guard branch escapes leaf')
            operation = branch[1] + ' @' + str(addresses.index(target))
        normalized.append(operation)
    if normalized != EXPECTED:
        raise ValueError('unreviewed guard instructions/operands')
    return symbol, [a - start for a in addresses]


def commands(symbol, offsets, events):
    result = ['set debuginfod enabled off', 'set pagination off',
              'set disable-randomization off', 'starti', 'set language c']
    for index, _ in events:
        result.append(f"hbreak *('{symbol}'+{offsets[index]})")
    for number, (index, event) in enumerate(events, 1):
        result += ['continue',
                   'printf "BRYNJA_GUARD_PRE %x %x\\n", $eax, $r11d']
        if event == 'skip':
            action = f'set $pc = $pc + {offsets[index+1] - offsets[index]}'
            verify = f"($pc == (unsigned long)&'{symbol}' + {offsets[index+1]})"
        elif event == 'flags':
            action, verify = 'set $eflags = $eflags ^ 64', '(($eflags & 64) == 64)'
        elif event == 'first':
            action, verify = 'set $eax = 0', '($eax == 0)'
        elif event == 'second':
            action, verify = 'set $r11d = $r11d ^ 1', '($r11d == 65535)'
        else:
            raise ValueError('unknown debugger event')
        result += [action, f'printf "BRYNJA_GUARD_APPLIED %d\\n", {verify}', f'disable {number}']
    return result + ['continue']


def validate_transcript(text, event_count, negative):
    # GDB may exit zero after a failed command or a crashed inferior: neither is
    # evidence. Demand every hardware stop, known pre-state, applied event, exact
    # test population and normal inferior exit (101 expected for the control).
    if len(re.findall(r'hit Breakpoint \d+,', text)) != event_count:
        raise ValueError('debugger event was not reached exactly once')
    if text.count('Hardware assisted breakpoint ') != event_count:
        raise ValueError('hardware breakpoints unavailable')
    if re.findall(r'BRYNJA_GUARD_PRE ([0-9a-f]+) ([0-9a-f]+)', text) != [('1','fffe')] * event_count:
        raise ValueError('unexpected guard accumulator pre-state')
    if re.findall(r'BRYNJA_GUARD_APPLIED (\d+)', text) != ['1'] * event_count:
        raise ValueError('debugger mutation did not take effect')
    if negative:
        markers = ['test result: FAILED. 0 passed; 1 failed; 0 ignored;',
                   'left: [66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66]',
                   'exited with code 0145']
    else:
        markers = ['test result: ok. 1 passed; 0 failed; 0 ignored;', 'exited normally']
    if TEST not in text or any(marker not in text for marker in markers):
        raise ValueError('fixture outcome or test population not confirmed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--objdump', default='objdump')
    parser.add_argument('--gdb', default='gdb')
    args = parser.parse_args()
    try:
        binary = args.binary.resolve(strict=True)
        original = binary.read_bytes()
        if original[:6] != b'\x7fELF\x02\x01' or original[18:20] != b'\x3e\x00':
            raise ValueError('requires x86-64 little-endian ELF')
        dumped = subprocess.run([args.objdump, '-d', '--demangle', '--no-show-raw-insn', str(binary)],
                                capture_output=True, text=True, check=True, timeout=30).stdout
        symbol, offsets = inspect(dumped)
        observations = []
        for name, events in CASES.items():
            argv = [args.gdb, '-q', '-nx', '-batch']
            for command in commands(symbol, offsets, events):
                argv += ['-ex', command]
            argv += ['--args', str(binary), '--exact', TEST, '--nocapture']
            run = subprocess.run(argv, capture_output=True, text=True, check=True, timeout=60)
            transcript = run.stdout + run.stderr
            validate_transcript(transcript, len(events), name.endswith('negative-control'))
            observations.append(dict(case=name, events=events,
                                     transcript_sha256=hashlib.sha256(transcript.encode()).hexdigest()))
        if binary.read_bytes() != original:
            raise ValueError('artifact changed during debugger experiments')
        print(json.dumps(dict(binary_sha256=hashlib.sha256(original).hexdigest(),
                              guard_symbol=symbol, instruction_offsets=offsets,
                              observations=observations), sort_keys=True))
        print('DEVELOPMENT_GUARD_EXPERIMENT_OBSERVED; NOT AES C1/DC1 or release qualification')
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print('guard experiment failed: '+str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
