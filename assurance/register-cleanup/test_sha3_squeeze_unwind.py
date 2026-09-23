#!/usr/bin/env python3
"""Mutations of retained squeeze unwind cleanup and exception preservation."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_sha3_squeeze_unwind as check
from test_kmac_optimized_cleanup import replace_block
from test_kmac_verify_comparisons import rejects


def mutations(function, trace, labels):
    unwind, output, owner, extra, resume, double_output, double_owner = labels
    graph = trace.graph
    for label in labels:
        for index in range(len(graph[label])):
            yield 'missing unwind cleanup operation', replace_block(function, label, graph[label][:index] + graph[label][index + 1:])
    lines = graph[unwind]
    yield 'foreign output ownership', function.replace(lines[2], re.sub(r'ptr %[^,]+', 'ptr %self', lines[2]), 1)
    yield 'inverted presence condition', function.replace(lines[3], lines[3].replace('icmp eq', 'icmp ne'), 1)
    condition, absent, present = check.adapter.shape.branch(trace, unwind)
    yield 'present output bypasses Drop', replace_block(function, unwind, lines[:-1] + [f'br i1 {condition}, label %{present}, label %{absent}'])
    for label, index in ((output, 0), (owner, 1)):
        call = graph[label][index]
        name, args = check.adapter.routes.guard.call(call)
        for old, new in ((name, 'unreviewed_cleanup'), (check.comparison.pointer(args[0]), '%destination.0'), ('invoke void', 'invoke i8')):
            changed = list(graph[label])
            changed[index] = call.replace(old, new)
            yield 'wrong cleanup callee/owner/ABI', replace_block(function, label, changed)
        yield 'payload write during unwind', replace_block(function, label, graph[label][:index] + ['store i8 0, ptr %destination.0, align 1'] + graph[label][index:])
    phi = graph[owner][0]
    exception = re.match('(' + check.SSA + ') = landingpad', lines[0])[1]
    yield 'wrong resumed squeeze exception', function.replace(phi, phi.replace('[ ' + exception + ',', '[ %foreign,'), 1)
    yield 'swallowed squeeze exception', replace_block(function, resume, ['ret void'])
    yield 'foreign resume value', replace_block(function, resume, ['resume { ptr, i32 } %foreign'])
    yield 'cleanup exception skips owner wipe', replace_block(function, extra, graph[extra][:-1] + ['br label %' + resume])
    for label in (double_output, double_owner):
        call = graph[label][2]
        name, _ = check.adapter.routes.guard.call(call)
        yield 'unknown double-panic behavior', replace_block(function, label,
            graph[label][:2] + [call.replace(name, 'unreviewed_panic')] + graph[label][3:])
        yield 'double panic returns normally', replace_block(function, label, graph[label][:-1] + ['ret void'])


def main(record):
    functions = count = controls = bindings = 0
    for function, begin, wipes, drop, callees in check.active.cases(record):
        inspect = lambda value: check.inspect(value, begin, wipes, drop, callees)
        trace, labels = inspect(function)
        count += rejects(inspect, function, mutations(function, trace, labels))
        name, _ = check.adapter.routes.guard.call(trace.graph[labels[2]][1])
        for wrong_wipes, wrong_drop in ((wipes - {name}, drop), (wipes, 'unreviewed_drop')):
            try:
                check.inspect(function, begin, wrong_wipes, wrong_drop, callees)
            except ValueError:
                bindings += 1
            else:
                raise AssertionError('unbound unwind cleanup accepted')
        locals_ = {match[1] for lines in trace.graph.values() for line in lines
                   if (match := re.match('(' + check.SSA + ') = ', line))} - {'%valid', '%length'}
        for changed in (
                re.sub(check.SSA, lambda m: '%unwind_' + m[0][1:] if m[0] in locals_ else m[0], function),
                re.sub(r'\bbb(\d+)\b', lambda m: 'bb' + str(int(m[1]) + 1000), function),
                function.replace('start:\n', 'start:\n; harmless unwind comment\n', 1)):
            assert changed != function
            inspect(changed)
            controls += 1
        functions += 1
    assert (functions, count, controls, bindings) == (16, 656, 48, 32), (functions, count, controls, bindings)
    print(f'Squeeze unwind rejects {count} LLVM mutations and {bindings} missing cleanup bindings; {controls} controls across {functions} readers PASS')
    print('Retained-text tests only; subprocess execution forbidden; release gates unchanged')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
