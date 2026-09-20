#!/usr/bin/env python3
"""Mutate saved iterator/fence machine text without recompilation or execution."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_clear_helpers as check
from test_kmac_verify_comparisons import rejects


def excluded(body, role, arm):
    if role != 'FENCE':
        return -1, -1
    labels = re.findall(r'(?m)^(\.LBB\d+_\d+):', body)
    first = 4 if arm else 0
    return body.index(labels[first] + ':'), body.index(labels[first + 1] + ':')


def mutants(body, role, arm):
    begin, end = excluded(body, role, arm)
    position = 0
    for line in body.splitlines(keepends=True):
        offset = position
        position += len(line)
        stripped = line.strip()
        if begin <= offset < end or not stripped or stripped.startswith(('.', '_')):
            continue
        yield 'missing live instruction/annotation', body[:offset] + body[position:]
        yield 'duplicate live instruction/annotation', body[:offset] + line + body[offset:]
    if role == 'ITER':
        changes = [('add\tx8, x8, x9', 'sub\tx8, x8, x9')] if arm else [('addq\t%rcx, %rax', 'subq\t%rcx, %rax')]
    elif role == 'NEXT':
        changes = ([('add\tx8, x8, #1', 'add\tx8, x8, #2'),
                    ('ldr\tx8, [x0, #8]', 'ldr\tx8, [x0, #16]'), ('b.eq\t', 'b.ne\t'),
                    ('str\tx8, [x9]', 'str\tx9, [x9]')]
                   if arm else
                   [('addq\t$1, %rcx', 'addq\t$2, %rcx'),
                    ('movq\t8(%rdi), %rax', 'movq\t16(%rdi), %rax'), ('je\t', 'jne\t'),
                    ('movq\t%rcx, (%rax)', 'movq\t%rax, (%rax)')])
    else:
        changes = ([('and\tx8, x8, #0xff', 'and\tx8, x8, #0x3'), ('cbz\tx8', 'cbnz\tx8'),
                    ('//MEMBARRIER', '//removed compiler annotation')]
                   if arm else
                   [('movzbl\t%al, %eax', 'xorl\t%eax, %eax'),
                    (',4)', ',8)'), ('#MEMBARRIER', '#removed compiler annotation')])
    for old, new in changes:
        yield 'wrong address/stride/dispatch/store', body.replace(old, new, 1)
    extras = (('ldrb w2, [x0]', 'str x0, [x1]', 'bl unknown', 'movi v0.16b, #0', '.byte 0')
              if arm else ('movb (%rdi), %dl', 'movq %rdi, (%rsi)', 'callq unknown', 'vpxor %ymm0, %ymm0, %ymm0', '.byte 0'))
    for extra in extras:
        yield 'payload/escape/call/vector/data instruction', body.replace('\n', '\n\t' + extra + '\n', 1)
    yield 'hidden instruction', body.replace('\n', '\n\t.loc 1 1 1; ' + extras[0] + '\n', 1)


def main(record):
    count = table_count = bindings = controls = builds = 0
    for _, assembly, bodies, names, table, rows, arm, compiler in check.cases(record):
        original_count = check.inspect(bodies, names, table, rows, arm, compiler)
        for role, body in bodies.items():
            inspect = lambda value: check.inspect({**bodies, role: value}, names, table, rows, arm, compiler)
            count += rejects(inspect, body, mutants(body, role, arm))
            spaced = '\n'.join('   ' + line.strip().replace('\t', '  ') if line.startswith('\t') else line
                               for line in body.splitlines())
            metadata = re.sub(r'(?m)^[ \t]*\.loc[ \t]+[^\n]*$', '', body)
            for changed in (spaced, metadata):
                assert changed != body and inspect(changed) == original_count
                controls += 1
        if not arm:
            inspect_table = lambda text: check.inspect(bodies, names, table, text.splitlines(), arm, compiler)
            original = '\n'.join(rows)
            changes = [('missing entry', '\n'.join(rows[:-1])),
                       ('duplicate entry', original + '\n' + rows[-1]),
                       ('absolute rather than relative', original.replace('-' + table, '')),
                       ('wrong relocation base', original.replace('-' + table, '-unbound'))]
            for index in range(5):
                mutated = list(rows)
                mutated[index] = rows[(index + 1) % 5]
                changes.append(('wrong ordering target', '\n'.join(mutated)))
            table_count += rejects(inspect_table, original, changes)
            inspect_binding = lambda text: check.inspect(
                bodies, names, *check.jump_table(text, bodies['FENCE']), arm, compiler)
            bindings += rejects(inspect_binding, assembly, [
                ('missing definition', assembly.replace(table + ':', 'unbound:', 1)),
                ('duplicate definition', assembly + '\n' + table + ':\n' + original + '\n\n'),
                ('injected table row', assembly.replace(table + ':\n', table + ':\n\t.long 0\n', 1)),
                ('missing SeqCst row', assembly.replace(rows[4], '', 1)),
                ('wrong entry width', assembly.replace(rows[4], rows[4].replace('.long', '.quad'), 1)),
            ])
        # Renaming all block labels must update jump-table targets as well.
        rename = lambda text: re.sub(r'\.LBB(\d+)_', lambda match: '.LBB' + str(int(match[1]) + 1000) + '_', text)
        changed = {role: rename(body) for role, body in bodies.items()}
        assert changed != bodies
        assert check.inspect(changed, names, table, [rename(row) for row in rows], arm, compiler) == original_count
        controls += 1
        # The Relaxed panic path is explicitly outside the checked SeqCst route.
        fence = bodies['FENCE']
        first, last = excluded(fence, 'FENCE', arm)
        label_end = fence.index('\n', first)
        changed = fence[:label_end + 1] + ('\tbrk #0\n' if arm else '\tud2\n') + fence[last:]
        assert changed != fence
        assert check.inspect({**bodies, 'FENCE': changed}, names, table, rows, arm, compiler) == original_count
        controls += 1
        builds += 1
    if (builds, count, table_count, bindings, controls) != (8, 1480, 36, 20, 64):
        raise AssertionError(f'incomplete debug helper campaign: {builds}/{count}/{table_count}/{bindings}/{controls}')
    print(f'Debug clear helpers reject {count} instruction/branch/annotation, {table_count} jump-table and {bindings} table-binding mutations; {controls} scoped positive controls across {builds} builds PASS')
    print('Retained text only; out-of-scope Relaxed panic-body changes intentionally accepted; subprocess execution prohibited')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
