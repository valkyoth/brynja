#!/usr/bin/env python3
"""Optimized KMAC cleanup LLVM-text mutations; no compilation or execution."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_kmac_optimized_cleanup as check
from test_kmac_verify_comparisons import rejects


def replace_block(function, label, lines):
    pattern = r'^' + re.escape(label) + r':[^\n]*\n.*?(?=^' + check.guard.LABEL + r':|^})'
    matches = list(re.finditer(pattern, function, re.M | re.S))
    assert len(matches) == 1
    match = matches[0]
    return function[:match.start()] + label + ':\n' + ''.join('  ' + line + '\n' for line in lines) + '\n' + function[match.end():]


def mutants(function, names, defined):
    graph, edges, events, comparisons, origin, owner, initial = check.inventory(function, names, defined)
    pending, reachable = [initial], set()
    while pending:
        label = pending.pop()
        if label in reachable:
            continue
        reachable.add(label)
        pending.extend(edges[label][0])
    for label in sorted(reachable):
        for index, role, args, invoked in events.get(label, []):
            if role not in ('CLEAR', 'GLUE'):
                continue
            lines = graph[label]
            line = lines[index]
            name = names[role]
            yield 'unbound cleanup callee', function.replace(line, line.replace('@' + name + '(', '@unreviewed('), 1)
            pointer = check.comparison.pointer(args[0])
            changed_arg = args[0].replace(pointer, '%candidate')
            yield 'wrong cleanup owner', function.replace(line, line.replace(args[0], changed_arg, 1), 1)
            if role == 'CLEAR':
                for width in (0, 2, 63, 67):
                    yield 'wrong clearing width', function.replace(line, line.replace(args[1], 'i64 noundef ' + str(width), 1), 1)
                yield 'wrong result ABI', function.replace(line, line.replace('noundef i8 @', 'noundef i32 @', 1), 1)
            else:
                yield 'wrong glue ABI', function.replace(line, line.replace('fastcc void ', 'void ', 1), 1)
            if invoked:
                normal, unwind = edges[label][0]
                bypass = lines[:index] + ['br label %' + normal]
                yield 'skip real cleanup but keep continuation', replace_block(function, label, bypass)
                yield 'swapped clearing normal/unwind edges ' + role + ' ' + label, replace_block(function, label,
                    lines[:-1] + ['to label %' + unwind + ' unwind label %' + normal])
            else:
                yield 'skip real cleanup but keep continuation', replace_block(function, label, lines[:index] + lines[index + 1:])
            repeated = line.replace('invoke ', 'tail call ' if role == 'CLEAR' else 'call ', 1)
            if role == 'CLEAR':
                repeated = re.sub('^' + check.SSA + ' = ', '%injected_duplicate = ', repeated)
            yield 'repeated clearing request', replace_block(function, label, lines[:index] + [repeated] + lines[index:])
    returns = [label for label, (_, terminal) in edges.items() if terminal == 'return']
    resumes = [label for label, (_, terminal) in edges.items() if terminal == 'resume']
    assert len(returns) == len(resumes) == 1
    for label, role, _ in comparisons:
        lines = graph[label]
        for edge_index in (0, 1):
            for target in returns + resumes:
                changed = list(edges[label][0])
                changed[edge_index] = target
                yield 'comparison successor bypasses cleanup', replace_block(function, label,
                    lines[:-1] + ['to label %' + changed[0] + ' unwind label %' + changed[1]])
        line = lines[-2]
        yield 'missing comparison identity', function.replace(line, line.replace('@' + names[role] + '(', '@unreviewed('), 1)
    initial_lines = graph[initial]
    # Keep the metadata extraction intact while changing its continuation.
    switch = next(i for i, line in enumerate(initial_lines) if line.startswith('switch '))
    for end in ('ret { i1, i8 } undef', 'unreachable', 'br label %' + initial):
        yield 'early exit or vacuous loop', replace_block(function, initial, initial_lines[:switch] + [end])
    for line in initial_lines:
        if line.startswith(owner + ' = load ptr, ptr '):
            source = re.search(r'load ptr, ptr (' + check.SSA + ')', line)[1]
            yield 'load metadata from wrong descriptor', function.replace(line, line.replace(source, '%candidate'), 1)
            field = next(item for ls in graph.values() for item in ls if item.startswith(source + ' = '))
            yield 'shifted result metadata field', function.replace(field, re.sub(r'i64 \d+$', 'i64 0', field), 1)
    predicate = next(args for _, role, args in comparisons if role == 'PREDICATE')
    difference = check.comparison.pointer(predicate[0])
    difference_definition = next(line for ls in graph.values() for line in ls if line.startswith(difference + ' = '))
    yield 'wrong metadata difference field', function.replace(difference_definition,
        difference_definition.replace('i64 65', 'i64 64'), 1)
    finish_line = next(line for ls in graph.values() for line in ls if '6finish' in line and 'call ' in line)
    finish_name, finish_args = check.guard.call(finish_line)
    yield 'unbound finish producer', function.replace(finish_line, finish_line.replace('@' + finish_name + '(', '@unreviewed_finish('), 1)
    wrong_slot = finish_args[0].replace(check.comparison.pointer(finish_args[0]), '%self')
    yield 'finish writes wrong result slot', function.replace(finish_line, finish_line.replace(finish_args[0], wrong_slot, 1), 1)


def main(record):
    count = controls = functions = builds = 0
    for _, names, defined, verifiers in check.cases(record):
        for function in verifiers:
            inspect = lambda value: check.inspect(value, names, defined)
            count += rejects(inspect, function, mutants(function, names, defined))
            baseline = inspect(function)
            owner = check.inventory(function, names, defined)[5]
            renamed_owner = re.sub(re.escape(owner) + r'(?![-.$\w])', '%metadata_owner', function)
            renamed_labels = re.sub(r'\bbb(\d+)\b', lambda m: 'bb' + str(int(m[1]) + 1000), function)
            comment = function.replace('start:\n', 'start:\n; harmless qualification comment\n', 1)
            for changed in (renamed_owner, renamed_labels, comment):
                assert changed != function and inspect(changed) == baseline
                controls += 1
            functions += 1
        builds += 1
    assert (builds, functions, count, controls) == (8, 24, 2562, 72), (builds, functions, count, controls)
    print(f'Optimized KMAC cleanup rejects {count} region/sequence/CFG/identity mutations; {controls} owner/label/comment controls across {functions} verifiers PASS')
    print('Retained LLVM-text mutations only; subprocess execution forbidden; release gates unchanged')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
