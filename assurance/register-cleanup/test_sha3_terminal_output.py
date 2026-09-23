#!/usr/bin/env python3
"""Fault controls for retained terminal-reader initialization ownership."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_sha3_terminal_output as check
from test_kmac_optimized_cleanup import replace_block
from test_kmac_verify_comparisons import rejects


def mutations(function, trace, labels):
    accepted, merge, terminal, dropping, done = labels
    graph = trace.graph
    for label in labels:
        for index, line in enumerate(graph[label]):
            if '@llvm.experimental.noalias.scope.decl' not in line:
                yield 'missing transfer/cleanup operation', replace_block(function, label, graph[label][:index] + graph[label][index + 1:])
    for label in (accepted, merge):
        call = next(line for line in graph[label] if '@llvm.memcpy.' in line)
        _, args = check.adapter.routes.guard.call(call)
        for width in (0, 22, 24):
            yield 'truncated/oversized descriptor tail', function.replace(call, call.replace('i64 23', 'i64 ' + str(width)), 1)
        for index in (0, 1):
            pointer = check.comparison.pointer(args[index])
            yield 'foreign descriptor endpoint', function.replace(call, call.replace(args[index], args[index].replace(pointer, '%destination.0')), 1)
        yield 'unreviewed volatile copy', function.replace(call, call.replace('i1 false', 'i1 true'), 1)
    first = graph[accepted]
    for index, old, new in ((0, 'i64 8', 'i64 16'), (2, 'i64 9', 'i64 8')):
        yield 'misaligned initialization descriptor', function.replace(first[index], first[index].replace(old, new), 1)
    merged = graph[merge]
    yield 'lose first descriptor byte', function.replace(merged[0], re.sub(r'\[ %[^,]+,', '[ undef,', merged[0], count=1), 1)
    yield 'lose ownership after successful initialization', function.replace(merged[1], merged[1].replace('[ 1,', '[ 0,'), 1)
    byte_store = next(line for line in merged if line.startswith('store i8 '))
    yield 'clobbered descriptor pointer byte', function.replace(byte_store, re.sub(r'store i8 %[^,]+', 'store i8 0', byte_store), 1)
    rejected = graph[terminal]
    for index, old, new in ((1, 'i8 0', 'i8 4'), (2, 'i64 2', 'i64 1')):
        yield 'wrong terminal error result', function.replace(rejected[index], rejected[index].replace(old, new), 1)
    condition, live, dead = check.adapter.shape.branch(trace, merge)
    yield 'reversed lifecycle branch', replace_block(function, merge, merged[:-1] + [f'br i1 {condition}, label %{dead}, label %{live}'])
    condition, empty, nonempty = check.adapter.shape.branch(trace, terminal)
    yield 'nonempty terminal output skips Drop', replace_block(function, terminal, rejected[:-1] + [f'br i1 {condition}, label %{nonempty}, label %{empty}'])
    cleanup = graph[dropping]
    name, args = check.adapter.routes.guard.call(cleanup[0])
    for old, new in ((name, 'unreviewed_drop'), (check.comparison.pointer(args[0]), '%destination.0'), ('call void', 'call i8')):
        yield 'wrong destructor binding/descriptor/ABI', function.replace(cleanup[0], cleanup[0].replace(old, new), 1)
    yield 'return before destination drop', replace_block(function, dropping, ['ret void'])
    yield 'clobber handle before Drop', replace_block(function, dropping, ['store ptr null, ptr ' + check.comparison.pointer(args[0]) + ', align 8'] + cleanup)
    yield 'end source before descriptor copy', replace_block(function, accepted, [first[4]] + first[:4] + first[5:])


def main(record):
    functions = count = controls = bindings = 0
    for function, begin, wipes, drop in check.cases(record):
        inspect = lambda value: check.inspect(value, begin, wipes, drop)
        trace, labels, _ = inspect(function)
        count += rejects(inspect, function, mutations(function, trace, labels))
        try:
            check.inspect(function, begin, wipes, 'unreviewed_drop')
        except ValueError:
            bindings += 1
        else:
            raise AssertionError('unbound destructor accepted')
        locals_ = {match[1] for lines in trace.graph.values() for line in lines
                   if (match := re.match('(' + check.SSA + ') = ', line))} - {'%valid', '%length'}
        for changed in (
                re.sub(check.SSA, lambda m: '%terminal_' + m[0][1:] if m[0] in locals_ else m[0], function),
                re.sub(r'\bbb(\d+)\b', lambda m: 'bb' + str(int(m[1]) + 1000), function),
                function.replace('start:\n', 'start:\n; harmless terminal comment\n', 1)):
            assert changed != function
            inspect(changed)
            controls += 1
        functions += 1
    assert (functions, count, controls, bindings) == (16, 912, 48, 16), (functions, count, controls, bindings)
    print(f'Terminal reader output rejects {count} LLVM mutations and {bindings} missing destructor bindings; {controls} controls across {functions} bodies PASS')
    print('Retained-text tests only; subprocess execution forbidden; release gates unchanged')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
