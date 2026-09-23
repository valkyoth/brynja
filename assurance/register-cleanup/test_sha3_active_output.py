#!/usr/bin/env python3
"""Retained active-reader descriptor and squeeze-routing mutation controls."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_sha3_active_output as check
from test_kmac_optimized_cleanup import replace_block
from test_kmac_verify_comparisons import rejects


def mutations(function, trace, labels, routes, values):
    active, choose, final, bulk = labels
    work, output, owner = values
    graph = trace.graph
    for label in labels:
        for index, line in enumerate(graph[label]):
            if '@llvm.experimental.noalias.scope.decl' not in line:
                yield 'missing active-routing operation', replace_block(function, label, graph[label][:index] + graph[label][index + 1:])
    lines = check.clean(graph[active])
    copy = lines[3]
    _, args = check.adapter.routes.guard.call(copy)
    for index in (0, 1):
        value = check.comparison.pointer(args[index])
        yield 'wrong operation copy endpoint', function.replace(copy, copy.replace(args[index], args[index].replace(value, '%destination.0')), 1)
    for width in (0, 47, 49):
        yield 'partial/oversized operation copy', function.replace(copy, copy.replace('i64 48', 'i64 ' + str(width)), 1)
    yield 'unreviewed volatile copy', function.replace(copy, copy.replace('i1 false', 'i1 true'), 1)
    yield 'reader remains active during work', function.replace(lines[0], lines[0].replace('i8 0', 'i8 1'), 1)
    yield 'foreign owner load', function.replace(lines[1], lines[1].replace('ptr %self', 'ptr %destination.0'), 1)
    for label in (active, choose):
        condition, yes, no = check.adapter.shape.branch(trace, label)
        yield 'inverted ownership/mode selection', replace_block(function, label, graph[label][:-1] + [f'br i1 {condition}, label %{no}, label %{yes}'])
    for index, old, new in ((0, 'i64 8', 'i64 16'), (1, 'i64 32', 'i64 40')):
        line = graph[choose][index]
        yield 'wrong transferred operation field', function.replace(line, line.replace(old, new), 1)
    for line in graph['start']:
        if line.startswith('store '):
            yield 'wrong original public metadata', function.replace(line, re.sub(r'(store i(?:8|64)) %[^,]+', r'\1 0', line), 1)
    for label in (final, bulk):
        line = graph[label][-2]
        name, args = check.adapter.routes.guard.call(line)
        out_index, length_index = (3, 1) if label == final else (1, 2)
        for old, new in ((name, 'unreviewed_squeeze'),
                         (args[0], args[0].replace(owner, '%destination.0')),
                         (args[out_index], args[out_index].replace(output, work)),
                         (args[length_index], 'i64 noundef 0'),
                         ('invoke fastcc noundef i8', 'invoke noundef i8')):
            yield 'wrong squeeze binding/owner/output/length/ABI', function.replace(line, line.replace(old, new), 1)
        yield 'unexpected payload write before squeeze', replace_block(function, label,
            graph[label][:-2] + ['store i8 0, ptr %destination.0, align 1'] + graph[label][-2:])
    line = graph[final][-2]
    _, args = check.adapter.routes.guard.call(line)
    yield 'wrong final bit count', function.replace(line, line.replace(args[2], 'i8 noundef 0'), 1)
    terminal = next(label for label, lines in graph.items()
                    if any('filter [0 x ptr]' in line for line in lines))
    edge = graph[final][-1]
    yield 'split squeeze unwind route', replace_block(function, final,
        graph[final][:-1] + [edge.replace('unwind label %' + routes[0][3], 'unwind label %' + terminal)])


def main(record):
    functions = count = controls = bindings = 0
    for function, begin, wipes, drop, callees in check.cases(record):
        inspect = lambda value: check.inspect(value, begin, wipes, drop, callees)
        trace, labels, routes, values = inspect(function)
        count += rejects(inspect, function, mutations(function, trace, labels, routes, values))
        for _, name, *_ in routes:
            try:
                check.inspect(function, begin, wipes, drop, callees - {name})
            except ValueError:
                bindings += 1
            else:
                raise AssertionError('missing squeeze definition accepted')
        locals_ = {match[1] for lines in trace.graph.values() for line in lines
                   if (match := re.match('(' + check.SSA + ') = ', line))} - {'%valid', '%length'}
        for changed in (
                re.sub(check.SSA, lambda m: '%active_' + m[0][1:] if m[0] in locals_ else m[0], function),
                re.sub(r'\bbb(\d+)\b', lambda m: 'bb' + str(int(m[1]) + 1000), function),
                function.replace('start:\n', 'start:\n; harmless active-reader comment\n', 1)):
            assert changed != function
            inspect(changed)
            controls += 1
        functions += 1
    assert (functions, count, controls, bindings) == (16, 864, 48, 32), (functions, count, controls, bindings)
    print(f'Active reader handoff rejects {count} LLVM mutations and {bindings} missing squeeze bindings; {controls} controls across {functions} bodies PASS')
    print('Retained-text tests only; subprocess execution forbidden; release gates unchanged')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
