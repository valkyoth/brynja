#!/usr/bin/env python3
"""Retained alignment-one assembly mutations; no native/emulated rerun."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_byte_precondition_assembly as check
from test_kmac_verify_comparisons import rejects


def live_lines(body, paths):
    current, block_index, offset = 'entry', 0, 0
    for line in body.splitlines(keepends=True):
        stripped = line.strip()
        if re.fullmatch(r'\.LBB\d+_\d+:', stripped):
            current = 'B' + str(block_index)
            block_index += 1
        if current in paths and stripped and not stripped.startswith(('.', '_')):
            yield offset, line
        offset += len(line)


def mutants(body, role, paths, names, compiler, arm):
    for offset, line in live_lines(body, paths):
        yield 'missing normal instruction', body[:offset] + body[offset + len(line):]
        yield 'duplicated normal instruction', body[:offset] + line + body[offset:]
    if compiler == '1.98.1' and role == 'CHECK':
        yield 'wrong bound alignment callee', body.replace(names['ALIGN'], names['ALIGN'] + '_unreviewed')
        changes = ([('str\tw0, [sp, #20]', 'str\tw1, [sp, #20]'), ('tbnz\tw8', 'tbz\tw8')]
                   if arm else [('movb\t%al, 15(%rsp)', 'movb\t%dl, 15(%rsp)'), ('jne\t', 'je\t')])
    else:
        changes = ([('fmov\td0, x1', 'fmov\td0, x0'), ('cnt\tv0.8b, v0.8b', 'cnt\tv0.8b, v1.8b'),
                    ('subs\tx9, x9, #1', 'subs\tx9, x9, #0'), ('b.ne\t', 'b.eq\t')]
                   if arm else [('movq\t%rsi, %rcx', 'movq\t%rdi, %rcx'),
                                ('$6148914691236517205', '$6148914691236517204'),
                                ('shrq\t$56', 'shrq\t$55'), ('subq\t$1, %rcx', 'subq\t$0, %rcx'),
                                ('jne\t', 'je\t')])
    for old, new in changes:
        yield 'wrong alignment/source/mask/return branch', body.replace(old, new, 1)
    extras = (('ldrb w2, [x0]', 'str x0, [x1]', 'bl unknown', 'movi v2.16b, #1', '.byte 0',
               '.cfi_remember_state; ldrb w2, [x0]') if arm else
              ('movb (%rdi), %dl', 'movq %rdi, (%rsi)', 'callq unknown', 'vpxor %ymm2, %ymm2, %ymm2', '.byte 0',
               '.cfi_remember_state; movb (%rdi), %dl'))
    for extra in extras:
        yield 'payload/escape/call/vector/directive injection', body.replace('\n', '\n\t' + extra + '\n', 1)


def replace_excluded(body, paths, arm):
    # Preserve labels but replace one deliberately unqualified failure body.
    labels = list(re.finditer(r'^\.LBB\d+_\d+:.*$', body, re.M))
    for index, label in enumerate(labels):
        if 'B' + str(index) not in paths:
            end = labels[index + 1].start() if index + 1 < len(labels) else re.search(r'^\.Lfunc_end\d+:', body, re.M).start()
            return body[:label.end()] + ('\n\tbrk #0\n' if arm else '\n\tud2\n') + body[end:]
    raise AssertionError('missing excluded diagnostic block')


def main(record):
    count = extraction = controls = builds = functions = 0
    for _, _, _, bodies, names, compiler, arm in check.cases(record):
        original_count = check.inspect(bodies, names, compiler, arm)
        for role, body in bodies.items():
            _, paths = check.reviewed.contracts(compiler, arm)[role]
            inspect = lambda text: check.inspect({**bodies, role: text}, names, compiler, arm)
            count += rejects(inspect, body, mutants(body, role, paths, names, compiler, arm))
            select = lambda text: check.llvm.entry.select(text, names[role])
            extraction += rejects(select, body, [
                ('duplicate function', body + '\n' + body),
                ('missing function', body.replace(names[role] + ':', 'unknown:', 1)),
                ('missing function end', re.sub(r'\.Lfunc_end\d+:$', '', body)),
            ])
            renamed = re.sub(r'\.LBB(\d+)_', lambda match: '.LBB' + str(int(match[1]) + 1000) + '_', body)
            spaced = '\n'.join('   ' + line.strip().replace('\t', '  ') if line.startswith('\t') else line
                               for line in body.splitlines())
            metadata = re.sub(r'(?m)^[ \t]*\.loc[ \t]+[^\n]*$', '', body)
            for changed in (renamed, spaced, metadata, replace_excluded(body, paths, arm)):
                assert changed != body and inspect(changed) == original_count
                controls += 1
            functions += 1
        builds += 1
    if (builds, functions, count, extraction, controls) != (8, 12, 796, 36, 48):
        raise AssertionError('incomplete byte-precondition assembly campaign')
    print(f'Byte-precondition assembly rejects {count} instruction/branch/identity and {extraction} extraction mutations; {controls} scoped positive controls across {functions} functions PASS')
    print('Invalid-alignment/panic bodies intentionally excluded; subprocess execution prohibited; no gate changes')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
