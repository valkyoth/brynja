#!/usr/bin/env python3
"""Debug clear entry/write text mutations; no compiler or runtime execution."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_clear_assembly as check
from test_kmac_verify_comparisons import rejects


def mutations(body, role, names, arm):
    lines = body.splitlines()
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith(('.', '_')):
            continue
        yield 'missing instruction', '\n'.join(lines[:index] + lines[index + 1:])
        yield 'duplicated instruction', '\n'.join(lines[:index] + [line, line] + lines[index + 1:])
    if role == 'ENTRY':
        changes = ([('mov\tw1, wzr', 'mov\tw1, #1'),
                    ('ldr\tx0, [sp, #16]', 'ldr\tx0, [sp, #8]'),
                    ('mov\tw0, #4', 'mov\tw0, #0'), ('tbz\tw8', 'tbnz\tw8')]
                   if arm else
                   [('xorl\t%esi, %esi', 'movl\t$1, %esi'),
                    ('movq\t24(%rsp), %rdi', 'movq\t16(%rsp), %rdi'),
                    ('movl\t$4, %edi', 'movl\t$0, %edi'), ('je\t', 'jne\t')])
        callees = ('ITER', 'NEXT', 'WRITE', 'FENCE')
    else:
        changes = ([('strb\tw8, [x9]', 'strb\tw9, [x9]'),
                    ('ldr\tw8, [sp, #20]', 'ldr\tw8, [sp, #24]'),
                    ('ldr\tx9, [sp, #8]', 'ldr\tx9, [sp, #24]'),
                    ('mov\tw8, #1', 'mov\tw8, #2')]
                   if arm else
                   [('movb\t%cl, (%rax)', 'movb\t%dl, (%rax)'),
                    ('movb\t23(%rsp), %cl', 'movb\t24(%rsp), %cl'),
                    ('movq\t8(%rsp), %rax', 'movq\t(%rsp), %rax'),
                    ('movl\t$1, %esi', 'movl\t$2, %esi')])
        callees = ('CHECK',)
    for old, new in changes:
        yield 'wrong byte/destination/alignment/order/branch', body.replace(old, new, 1)
    for callee in callees:
        yield 'unknown callee with reviewed prefix', body.replace(names[callee], names[callee] + '_unreviewed')
    # Entry/helper must not import old payload bytes or add unreviewed work.
    extras = (('ldrb w3, [x0]', 'str x0, [x1]', 'bl unknown', 'movi v0.16b, #0', '.byte 0')
              if arm else
              ('movb (%rdi), %dl', 'movq %rdi, (%rsi)', 'callq unknown', 'vpxor %ymm0, %ymm0, %ymm0', '.byte 0'))
    for extra in extras:
        yield 'payload/escape/call/vector/data injection', body.replace('\n', '\n\t' + extra + '\n', 1)
    for directive in ('.loc 1 1 1', '.file 1 "source" "file.rs"'):
        yield 'instruction hidden after metadata', body.replace('\n', '\n\t' + directive + '; ' + extras[0] + '\n', 1)
    if role == 'ENTRY':
        labels = re.findall(r'(?m)^(\.LBB\d+_\d+):', body)
        yield 'wrong branch destination', body.replace(labels[-1], labels[0], 1)
    yield 'wrong function boundary', body.replace(names[role] + ':', names[role] + '_other:', 1)


def main(record):
    count = controls = builds = boundaries = 0
    for _, bodies, names, location, arm in check.cases(record):
        original_count = check.inspect(bodies, names, location, arm)
        for role, body in bodies.items():
            inspect = lambda text: check.inspect({**bodies, role: text}, names, location, arm)
            count += rejects(inspect, body, mutations(body, role, names, arm))
            renamed = re.sub(r'\.LBB(\d+)_', lambda match: '.LBB' + str(int(match[1]) + 1000) + '_', body)
            spaced = '\n'.join('   ' + line.strip().replace('\t', '  ') if line.startswith('\t') else line
                               for line in body.splitlines())
            metadata = re.sub(r'(?m)^[ \t]*\.loc[ \t]+[^\n]*$', '', body)
            for changed in (spaced, metadata, *([renamed] if renamed != body else [])):
                assert changed != body
                assert inspect(changed) == original_count
                controls += 1
            select = lambda text: check.select(text, names[role])
            boundaries += rejects(select, body, [
                ('duplicate definition', body + '\n' + body),
                ('missing definition', body.replace(names[role] + ':', 'other:', 1)),
                ('missing end', re.sub(r'\.Lfunc_end\d+:$', '', body)),
            ])
        builds += 1
    if (builds, count, boundaries, controls) != (8, 1016, 48, 44):
        raise AssertionError(f'incomplete debug clear assembly campaign: {builds}/{count}/{boundaries}/{controls}')
    print(f'Debug clear assembly rejects {count} instruction/call/identity and {boundaries} extraction mutations; {controls} positive controls across {builds} pairs PASS')
    print('Retained text mutation only; subprocess execution prohibited; no gate changes')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
