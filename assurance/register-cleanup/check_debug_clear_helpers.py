#!/usr/bin/env python3
"""Retained debug iterator assembly and the clearing caller's SeqCst fence route."""
import argparse
import json
from pathlib import Path
import re

import check_debug_clear_assembly as entry
import debug_clear_helper_contracts as contracts

comparison = entry.comparison
require = entry.require


def fence_contract(arm, compiler):
    require(compiler in ('1.90.0', '1.98.1'), 'reviewed fence compiler')
    old = compiler == '1.90.0'
    if not arm:
        frame, slot = (72, 63) if old else (40, 23)
        prefix = [f'subq ${frame}, %rsp', 'movb %dil, %al', f'movb %al, {slot}(%rsp)']
        if old:
            prefix += ['leaq .Lalloc_08b59b467ebdb5083b29fbbb7ada5445(%rip), %rcx',
                       'movq %rcx, 64(%rsp)']
        prefix += ['movzbl %al, %eax']
        prefix += (['movq %rax, (%rsp)', 'movq (%rsp), %rax',
                    'leaq TABLE(%rip), %rcx', 'movslq (%rcx,%rax,4), %rax',
                    'addq %rcx, %rax', 'jmpq *%rax', 'ud2'] if old else
                   ['movq %rax, 8(%rsp)', 'movq 8(%rsp), %rcx',
                    'leaq TABLE(%rip), %rax', 'movslq (%rax,%rcx,4), %rcx',
                    'addq %rcx, %rax', 'jmpq *%rax', 'ud2'])
        suffix = [line for block in range(1, 4) for line in (f'B{block}:', '#MEMBARRIER', 'jmp B5')]
        suffix += ['B4:', '#MEMBARRIER', 'B5:', f'addq ${frame}, %rsp', 'retq']
        return prefix, suffix, 'B0:', 'B1:'
    frame, saved, slot = (96, 80, '[sp, #8]') if old else (48, 32, '[sp]')
    prefix = [f'sub sp, sp, #{frame}', f'stp x29, x30, [sp, #{saved}]', f'add x29, sp, #{saved}']
    prefix += (['sturb w0, [x29, #-9]',
                'adrp x8, .Lalloc_08b59b467ebdb5083b29fbbb7ada5445',
                'add x8, x8, :lo12:.Lalloc_08b59b467ebdb5083b29fbbb7ada5445',
                'stur x8, [x29, #-8]'] if old else ['strb w0, [sp, #15]'])
    prefix += ['mov w8, w0', 'and x8, x8, #0xff', f'str x8, {slot}', 'cbz x8, B4', 'b B0']
    for block in range(3):
        prefix += [f'B{block}:', f'ldr x8, {slot}', f'subs x8, x8, #{block + 1}',
                   f'b.eq B{block + 5}', f'b B{block + 1}']
    prefix += ['B3:', 'b B8']
    suffix = [line for block in range(5, 9) for line in (f'B{block}:', '//MEMBARRIER', 'b B9')]
    suffix += ['B9:', f'ldp x29, x30, [sp, #{saved}]', f'add sp, sp, #{frame}', 'ret']
    return prefix, suffix, 'B4:', 'B5:'


def jump_table(assembly, body):
    tables = set(re.findall(r'\.LJTI\d+_\d+', body))
    require(len(tables) == 1, 'single debug fence jump table')
    table = tables.pop()
    starts = list(re.finditer(r'^' + re.escape(table) + ':$', assembly, re.M))
    require(len(starts) == 1, 'unique bound debug fence jump table')
    rows = assembly[starts[0].end():].split('\n\n', 1)[0].strip().splitlines()
    return table, rows


def normalized(body, symbol, names):
    # CFI state annotations are not machine instructions; no unwind claim here.
    return [line for line in entry.normalized(body, symbol, names, '.Lalloc_0')
            if line not in ('.cfi_remember_state', '.cfi_restore_state')]


def inspect_fence(body, names, table, rows, arm, compiler):
    lines = normalized(body, names['FENCE'], names)
    if arm:
        require(table is None and not rows, 'no Arm jump-table substitution')
    else:
        require(isinstance(table, str) and re.fullmatch(r'\.LJTI\d+_\d+', table), 'bound x86 fence table')
        labels = re.findall(r'(?m)^(\.LBB\d+_\d+):', body)
        require(len(labels) == 6 and len(rows) == 5, 'five ordering entries and six fence blocks')
        actual = [re.sub(r'\s+', ' ', row.strip()) for row in rows]
        require(actual == [f'.long {label}-{table}' for label in labels[:5]], 'exact relative fence jump targets')
        lines = [line.replace(table, 'TABLE') for line in lines]
    expected_prefix, expected_suffix, panic, normal = fence_contract(arm, compiler)
    require(lines.count(panic) == 1 and lines.count(normal) == 1, 'distinct panic/normal fence blocks')
    first, last = lines.index(panic), lines.index(normal)
    require(first < last, 'isolated relaxed-order panic block')
    require(lines[:first] == expected_prefix and lines[last:] == expected_suffix,
            'exact fence dispatch and return: caller supplies SeqCst discriminant four')
    # The normal caller was checked to pass 4. Its route cannot reach the
    # excluded Relaxed panic block. This does not inspect that block's effects.
    return first + len(lines) - last


def inspect(bodies, names, table, rows, arm, compiler):
    require(set(bodies) == {'ITER', 'NEXT', 'FENCE'}, 'complete debug clear helper inventory')
    count = 0
    for role, contract in contracts.iterator(arm, compiler).items():
        lines = normalized(bodies[role], names[role], names)
        require(lines == contract.splitlines(), 'exact descriptor-only iterator lowering: ' + role)
        count += len(lines)
    return count + inspect_fence(bodies['FENCE'], names, table, rows, arm, compiler)


def cases(record):
    for core, compiler, assembly, arm in entry.llvm.writing.cases(record):
        names = entry.identities(core)
        bodies = {role: entry.select(assembly, names[role]) for role in ('ITER', 'NEXT', 'FENCE')}
        table, rows = (None, []) if arm else jump_table(assembly, bodies['FENCE'])
        yield core, assembly, bodies, names, table, rows, arm, compiler


def main(record):
    before = comparison.capture.sources()
    builds = modeled = operations = 0
    for core, assembly, bodies, names, table, rows, arm, compiler in cases(record):
        # Recheck the actual calling entry/write pair and LLVM geometry too.
        pair = {role: entry.select(assembly, names[role]) for role in ('ENTRY', 'WRITE')}
        locations = set(re.findall(r'\.Lalloc_[0-9a-f]+', pair['ENTRY']))
        require(len(locations) == 1, 'single clearing-entry source location')
        entry.inspect(pair, names, locations.pop(), arm)
        modeled += entry.llvm.inspect(core)
        operations += inspect(bodies, names, table, rows, arm, compiler)
        builds += 1
    require(builds == 8 and before == comparison.capture.sources(), 'complete unchanged debug helper matrix')
    print(f'Debug clear helpers: {builds} iterator/fence triples, {operations} normalized instructions/labels/annotations, {modeled} linked LLVM cases PASS')
    print('Entry/write pairs rechecked; descriptor-only iterators and exact SeqCst route; no hardware-fence claim')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Excludes pointer-precondition/panic machine bodies, whole-call residue, native Arm/Windows and binary execution; no rebuild')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
