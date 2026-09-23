#!/usr/bin/env python3
"""Retained borrowed-reader initialization ordering and rejection mutations."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_sha3_reader_initialization as check
from test_kmac_optimized_cleanup import replace_block
from test_kmac_verify_comparisons import rejects


def mutations(function, trace, labels):
    nonempty, error, success, returning = labels
    graph = trace.graph
    for label in (nonempty, error, returning):
        for index in range(len(graph[label])):
            yield 'missing initialization/rejection operation', replace_block(function, label, graph[label][:index] + graph[label][index + 1:])
    yield 'inverted empty test', function.replace('icmp eq i64 %destination.1, 0', 'icmp ne i64 %destination.1, 0', 1)
    condition, empty, _ = check.adapter.shape.branch(trace, 'start')
    yield 'nonempty bypasses initialization', replace_block(function, 'start', graph['start'][:-1] + [f'br i1 {condition}, label %{nonempty}, label %{empty}'])
    for line in ('%preload = load i8, ptr %destination.0, align 1',
                 '%state = load ptr, ptr %self, align 8',
                 'call void @unreviewed(ptr %destination.0)',
                 'store i8 %1, ptr %destination.0, align 1'):
        yield 'work before destination protection', replace_block(function, 'start', graph['start'][:-2] + [line] + graph['start'][-2:])
    block = graph[nonempty]
    call = block[1]
    name, params = check.adapter.routes.guard.call(call)
    for old, new in ((name, 'unreviewed_begin'), ('%destination.0', '%self'), ('%destination.1', '0'),
                     ('sret([32 x i8])', 'sret([24 x i8])')):
        yield 'wrong initializer destination/identity/ABI', function.replace(call, call.replace(old, new), 1)
    result = re.search('(' + check.SSA + ')$', params[0])[1]
    yield 'decision reads foreign result', function.replace(block[2], block[2].replace(result, '%destination.0'), 1)
    tested, _, _ = check.adapter.shape.branch(trace, nonempty)
    yield 'initializer failure enters success work', replace_block(function, nonempty, block[:-1] + [f'br i1 {tested}, label %{success}, label %{error}'])
    rejected = graph[error]
    substitutions = ((1, 'i64 8', 'i64 0'), (2, 'i8 0', 'i8 1'), (3, 'ptr %self', 'ptr %destination.0'),
                     (5, 'ptr %_0', 'ptr %destination.0'), (6, 'i8 4', 'i8 0'), (7, 'i64 2', 'i64 1'))
    for index, old, new in substitutions:
        changed = list(rejected)
        changed[index] = changed[index].replace(old, new)
        yield 'wrong terminal owner/error result', replace_block(function, error, changed)
    wipe, _ = check.adapter.routes.guard.call(rejected[4])
    yield 'unbound owner cleanup', function.replace(rejected[4], rejected[4].replace(wipe, 'unreviewed_wipe'), 1)
    yield 'rejection continues reader', replace_block(function, error, rejected[:-1] + ['br label %' + empty])
    yield 'return block performs payload work', replace_block(function, returning, ['store i8 0, ptr %destination.0, align 1'] + graph[returning])


def main(record):
    functions = count = controls = bindings = 0
    for function, begin, wipes in check.cases(record):
        inspect = lambda value: check.inspect(value, begin, wipes)
        trace, labels, _, _ = inspect(function)
        count += rejects(inspect, function, mutations(function, trace, labels))
        for wrong_begin, wrong_wipes in (('unreviewed_begin', wipes), (begin, set())):
            try:
                check.inspect(function, wrong_begin, wrong_wipes)
            except ValueError:
                bindings += 1
            else:
                raise AssertionError('missing source binding accepted')
        locals_ = {match[1] for lines in trace.graph.values() for line in lines
                   if (match := re.match('(' + check.SSA + ') = ', line))}
        # The retained %length name identifies the local metadata lifetime;
        # rename other SSA temporaries, not function arguments or that anchor.
        locals_.discard('%length')
        for changed in (
                re.sub(check.SSA, lambda m: '%init_' + m[0][1:] if m[0] in locals_ else m[0], function),
                re.sub(r'\bbb(\d+)\b', lambda m: 'bb' + str(int(m[1]) + 1000), function),
                function.replace('start:\n', 'start:\n; harmless entry comment\n', 1)):
            assert changed != function
            inspect(changed)
            controls += 1
        functions += 1
    assert (functions, count, controls, bindings) == (16, 592, 48, 32)
    print(f'Reader initialization rejects {count} LLVM mutations and {bindings} missing source bindings; {controls} controls across {functions} bodies PASS')
    print('Retained-text tests only; subprocess execution forbidden; release gates unchanged')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
