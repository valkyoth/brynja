#!/usr/bin/env python3
"""Mutate retained initialization ordering, ownership and clearing boundaries."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_secret_output_begin as check
from test_kmac_optimized_cleanup import replace_block
from test_kmac_verify_comparisons import rejects


def mutations(function, zero):
    graph, (empty, nonempty, returning) = check.inspect(function, zero)
    for label in graph:
        for index in range(len(graph[label])):
            yield 'missing initialization instruction', replace_block(function, label, graph[label][:index] + graph[label][index + 1:])
    success = graph[nonempty]
    call = success[0]
    for old, new in ((zero, 'unreviewed_clear'), ('%region.0', '%_0'), ('%region.1', '0'),
                     ('fastcc void', 'void'), ('ptr ', 'ptr byval(i8) ')):
        yield 'wrong clearing identity/region/ABI', function.replace(call, call.replace(old, new), 1)
    yield 'clear after ownership writes', replace_block(function, nonempty, success[1:-1] + [call, success[-1]])
    yield 'duplicate clearing', replace_block(function, nonempty, [call] + success)
    for index, old, new in ((1, 'i64 8', 'i64 16'), (2, '%region.0', 'null'),
                            (3, 'i64 16', 'i64 24'), (4, '%region.1', '0'),
                            (5, 'i64 24', 'i64 8'), (6, 'i64 0', 'i64 1')):
        changed = list(success)
        changed[index] = changed[index].replace(old, new)
        yield 'wrong ownership field', replace_block(function, nonempty, changed)
    for line in ('%leak = load i8, ptr %region.0, align 1', 'call void @unreviewed(ptr %region.0)'):
        yield 'unexpected payload read/escape', replace_block(function, nonempty, [line] + success)
    yield 'inverted emptiness', function.replace('icmp eq i64 %region.1, 0', 'icmp ne i64 %region.1, 0', 1)
    yield 'wrong empty-region error', replace_block(function, empty, [graph[empty][0], graph[empty][1].replace('i8 0', 'i8 1'), graph[empty][2]])
    final = graph[returning]
    yield 'empty region reported as success', replace_block(function, returning, [final[0].replace('[ 1,', '[ 0,')] + final[1:])
    yield 'cleared region reported as failure', replace_block(function, returning, [final[0].replace('[ 0,', '[ 1,')] + final[1:])


def main(record):
    functions = count = controls = bindings = 0
    for function, zero in check.cases(record):
        inspect = lambda value: check.inspect(value, zero)
        count += rejects(inspect, function, mutations(function, zero))
        try:
            check.inspect(function, 'unreviewed_clear')
        except ValueError:
            bindings += 1
        else:
            raise AssertionError('unbound clear accepted')
        graph, _ = inspect(function)
        locals_ = {match[1] for lines in graph.values() for line in lines
                   if (match := re.match('(' + check.SSA + ') = ', line))}
        for changed in (
                re.sub(check.SSA, lambda m: '%begin_' + m[0][1:] if m[0] in locals_ else m[0], function),
                re.sub(r'\bbb(\d+)\b', lambda m: 'bb' + str(int(m[1]) + 1000), function),
                function.replace('start:\n', 'start:\n; harmless initialization comment\n', 1)):
            assert changed != function
            inspect(changed)
            controls += 1
        functions += 1
    assert (functions, count, controls, bindings) == (8, 280, 24, 8)
    print(f'Secret output begin rejects {count} LLVM mutations and {bindings} unbound-clearing regressions; {controls} controls across {functions} bodies PASS')
    print('Retained-text tests only; subprocess execution forbidden; release gates unchanged')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
