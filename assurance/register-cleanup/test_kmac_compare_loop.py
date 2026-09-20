#!/usr/bin/env python3
"""Retained KMAC comparison-loop mutations; no compiler/runtime execution."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_kmac_compare_loop as check
from test_kmac_optimized_cleanup import replace_block
from test_kmac_verify_comparisons import rejects


def mutations(function, trace):
    for value in sorted(trace.loop_values):
        _, rhs = trace.definitions[value]
        line = value + ' = ' + rhs
        yield 'unrelated loop value', function.replace(line, value + ' = freeze i64 0', 1)
        if rhs.startswith('load '):
            yield 'wrong output length owner', function.replace(line,
                re.sub(r', ptr ' + check.SSA + ',', ', ptr %candidate,', line), 1)
        if rhs.startswith('getelementptr '):
            for offset in (0, 8, 24):
                yield 'wrong output descriptor field', function.replace(line,
                    re.sub(r'i64 16$', 'i64 ' + str(offset), line), 1)
        if rhs.startswith('icmp eq '):
            yield 'inverted guard or loop termination', function.replace(line, line.replace('icmp eq ', 'icmp ne '), 1)
            yield 'unrelated loop comparison operand', function.replace(line,
                re.sub(check.SSA + r',', '%foreign,', line, count=1), 1)
        if '@llvm.umin.i64' in rhs:
            yield 'maximum instead of minimum', function.replace(line, line.replace('llvm.umin', 'llvm.umax'), 1)
            args = check.routes.comparison.arguments(line, line.index('(') + 1)
            for index in (0, 1):
                changed = re.sub(check.SSA + '$', '%foreign', args[index])
                yield 'wrong paired length', function.replace(line, line.replace(args[index], changed, 1), 1)
        if rhs.startswith('select '):
            yield 'null output enters comparison', function.replace(line, line.replace('i1 true,', 'i1 false,'), 1)
    for label in sorted(trace.loop_blocks):
        lines = trace.graph[label]
        if lines[-1].startswith('br i1 '):
            condition, yes, no = check.shape.branch(trace, label)
            for terminal in (
                    f'br i1 {condition}, label %{no}, label %{yes}',
                    f'br i1 %foreign, label %{yes}, label %{no}',
                    f'br label %{yes}', f'br label %{no}'):
                yield 'inverted/bypassed loop edge', replace_block(function, label, lines[:-1] + [terminal])
        elif lines[-1].startswith('br label '):
            yield 'comparison preheader bypass', replace_block(function, label, lines[:-1] + ['ret { i1, i8 } zeroinitializer'])
        elif lines[-1].startswith('to label '):
            normal, unwind = trace.edges[label][0]
            yield 'normal comparison bypasses index advance', replace_block(function, label,
                lines[:-1] + [f'to label %{label} unwind label %{unwind}'])


def main(record):
    count = controls = functions = 0
    for _, function, names, defined, callees in check.routes.cases(record):
        inspect = lambda value: check.inspect(value, names, defined, callees)
        trace = inspect(function)
        count += rejects(inspect, function, mutations(function, trace))
        # Renaming every internal value, not just labels, must preserve the result.
        renamed = re.sub(check.SSA, lambda match: '%renamed_' + match[0][1:]
                         if match[0] in trace.definitions else match[0], function)
        for changed in (
                renamed,
                re.sub(r'\bbb(\d+)\b', lambda match: 'bb' + str(int(match[1]) + 1000), function),
                function.replace('start:\n', 'start:\n; harmless comparison-loop comment\n', 1)):
            assert changed != function
            other = inspect(changed)
            assert len(other.loop_values) == len(trace.loop_values)
            assert len(other.loop_blocks) == len(trace.loop_blocks)
            controls += 1
        functions += 1
    assert (functions, count, controls) == (24, 756, 72)
    print(f'KMAC comparison loop rejects {count} LLVM mutations; {controls} SSA/label/comment controls across {functions} verifiers PASS')
    print('Retained-text mutations only; subprocess execution forbidden; release gates unchanged')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
