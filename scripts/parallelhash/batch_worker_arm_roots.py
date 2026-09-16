"""Independent initialization anchors for Rust 1.98 Arm worker arguments.

This recognizes the reviewed allocation ABI and local minimum-count selection,
not the input plan arithmetic or allocator implementation. Ordinary CFG only.
"""
import re

import batch_worker_handoff as handoff
from batch_worker_handoff import require
from batch_worker_scalar import GROW


def roots(code, labels, edges, symbols, spawn):
    grows = []
    for pc, symbol in enumerate(symbols):
        if not re.fullmatch(GROW, symbol or '') or pc < 6:
            continue
        setup = code[pc - 6:pc]
        if setup[-1] != ('mov', ['w5', '#256']):
            continue
        require(setup[0][0] == 'add' and setup[0][1][:2] == ['x0', 'sp'] and
                re.fullmatch(r'#\d+', setup[0][1][2]) and
                setup[1] in (('mov', ['x1', 'xzr']), ('mov', ['x1', '#0'])) and
                setup[2] == ('mov', ['w2', '#1']) and setup[3][0] == 'mov' and
                setup[3][1][0] == 'x3' and re.fullmatch(r'x\d+', setup[3][1][1]) and
                setup[4] == ('mov', ['w4', '#1']), 'original 256-byte-slot allocation ABI')
        for i in range(pc - 6, pc):
            require(edges[i] == (i + 1,) and not any(
                i + 1 in ts for p, ts in edges.items() if p != i), 'single-entry allocation setup')
        grows.append((pc, int(setup[0][1][2][1:]), setup[3][1][1]))
    require(len(grows) == 1, 'one original machine worker allocation')
    grow, result, count = grows[0]
    selections = [i for i, (op, args) in enumerate(code) if op == 'csel' and
                  len(args) == 4 and args[0] == count and args[3] == 'lo' and i > 0 and
                  code[i - 1] == ('cmp', args[1:3]) and not handoff.reaches(edges, spawn, i)]
    require(len(selections) == 1, 'original full slot-count minimum')
    selection = selections[0]
    require(all(re.fullmatch(r'x\d+', reg) for reg in code[selection][1][:3]) and
            [p for p, ts in edges.items() if selection in ts] == [selection - 1],
            'full-width minimum uses its immediately preceding comparison')
    require(not handoff.reaches(edges, 0, grow, selection), 'slot-count definition dominates allocation')
    branches = [i for i in range(selection + 1, min(selection + 8, len(code)))
                if code[i][0] == 'cbnz' and code[i][1][0] == count]
    require(len(branches) == 1, 'original count selects empty versus allocated storage')
    branch = branches[0]
    require(not handoff.reaches(edges, 0, grow, branch) and not handoff.reaches(edges, 0, spawn, branch) and
            handoff.reaches(edges, labels[code[branch][1][1]], grow, branch + 1) and
            not handoff.reaches(edges, branch + 1, grow, branch),
            'nonzero count reaches original allocation')
    # Empty base is either initialized immediately on the zero branch, or in
    # the still-retained Vec header before the count branch (unwind builds).
    empty = branch + 1
    if code[empty][0] == 'mov' and code[empty][1][1:] == ['#1']:
        reg = code[empty][1][0]
        require(reg.startswith('w') and code[empty + 1][0] == 'stp' and
                code[empty + 1][1][1] == 'x' + reg[1:] and
                handoff.stack_offset(code[empty + 1][1][2], True) is not None,
                'empty storage base initialization')
        require([p for p, ts in edges.items() if empty in ts] == [branch], 'empty base is zero-branch-only')
    else:
        headers = [i for i, (op, args) in enumerate(code[:branch]) if op == 'stp' and
                   len(args) == 3 and args[0] == 'xzr' and re.fullmatch(r'x\d+', args[1]) and
                   (offset := handoff.stack_offset(args[2], True)) is not None and
                   code[i + 1] == ('str', ['xzr', f'[sp, #{offset + 16}]']) and
                   not handoff.reaches(edges, 0, spawn, i)]
        require(len(headers) == 1, 'original retained empty header')
        initial = headers[0]
        reg = 'w' + code[initial][1][1][1:]
        candidates = [i for i in range(max(0, initial - 5), initial) if code[i] == ('mov', [reg, '#1'])]
        require(len(candidates) == 1, 'unique retained empty base definition')
        empty = candidates[0]
    require(code[grow + 1] == ('ldr', ['w8', f'[sp, #{result}]']) and
            code[grow + 2][0] == 'tbz' and code[grow + 2][1][:2] == ['w8', '#0'],
            'reviewed allocation success discriminant')
    loaded = labels[code[grow + 2][1][2]]
    require(code[loaded][0] == 'ldr' and len(code[loaded][1]) == 2 and
            re.fullmatch(r'x\d+', code[loaded][1][0]) and
            code[loaded][1][1] == f'[sp, #{result + 8}]' and
            [p for p, ts in edges.items() if loaded in ts] == [grow + 2],
            'original allocation base through success edge')
    require(not handoff.reaches(edges, labels[code[branch][1][1]], spawn, loaded),
            'nonempty storage reaches spawn only through successful allocation')
    seeds = {selection: ('count', count), empty: ('base', 'x' + reg[1:]),
             loaded: ('base', code[loaded][1][0])}
    require(len(seeds) == 3 and all(not handoff.reaches(edges, spawn, pc) for pc in seeds),
            'no owner initialization after native spawn')
    require(handoff.reaches(edges, 0, spawn), 'reachable machine spawn')
    return seeds, grow, result
