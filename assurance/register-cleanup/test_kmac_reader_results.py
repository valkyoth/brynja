#!/usr/bin/env python3
"""Mutate retained KMAC reader-result decisions without rerunning cryptography."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_kmac_reader_results as check
from test_kmac_optimized_cleanup import replace_block
from test_kmac_verify_comparisons import rejects


def mutations(function, trace):
    for value in sorted(trace.result_values):
        label, rhs = trace.definitions[value]
        line = value + ' = ' + rhs
        yield 'unrelated result value', function.replace(line, value + ' = freeze i64 0', 1)
        if rhs.startswith('load '):
            yield 'read discriminator from unrelated owner', function.replace(line,
                re.sub(r', ptr ' + check.SSA + ',', ', ptr %candidate,', line), 1)
        elif rhs.startswith('icmp eq '):
            yield 'inverted error test', function.replace(line, line.replace('icmp eq ', 'icmp ne '), 1)
            yield 'wrong error discriminator', function.replace(line, line.replace(', 2', ', 3'), 1)
        elif rhs.startswith('trunc '):
            yield 'ownership from unrelated discriminator', function.replace(line,
                re.sub(r'i64 ' + check.SSA + ' to', 'i64 %foreign to', line), 1)
    for producer, decision, success, error, absent, comparison, store in trace.result_gates:
        for label in (decision, success):
            lines = trace.graph[label]
            condition, yes, no = check.shape.branch(trace, label)
            for terminal in (f'br i1 {condition}, label %{no}, label %{yes}',
                             f'br i1 %foreign, label %{yes}, label %{no}',
                             f'br label %{yes}', f'br label %{no}'):
                yield 'inverted or bypassed result/ownership branch', replace_block(function, label, lines[:-1] + [terminal])
        lines = trace.graph[success]
        index = lines.index(store)
        yield 'missing transferred discriminator', replace_block(function, success, lines[:index] + lines[index + 1:])
        yield 'duplicate transferred discriminator', replace_block(function, success, lines[:index] + [store] + lines[index:])
        yield 'different transferred discriminator', function.replace(store,
            re.sub(r'store i64 ' + check.SSA + ',', 'store i64 %foreign,', store), 1)
        for destination in (success, comparison):
            yield 'error resumes successful work', replace_block(function, error, ['br label %' + destination])
        yield 'empty output reaches current comparison', replace_block(function, absent, ['br label %' + comparison])
        for injected in ('store i64 1, ptr %candidate, align 8', 'call void @unreviewed(ptr %candidate)'):
            yield 'mutating result-decision block', replace_block(function, decision, [injected] + trace.graph[decision])
        lines = trace.graph[producer]
        _, unwind = trace.edges[producer][0]
        yield 'reader normal return skips decision', replace_block(function, producer,
            lines[:-1] + [f'to label %{success} unwind label %{unwind}'])


def main(record):
    count = controls = functions = 0
    for _, function, names, defined, callees in check.routes.cases(record):
        inspect = lambda value: check.inspect(value, names, defined, callees)
        trace = inspect(function)
        count += rejects(inspect, function, mutations(function, trace))
        for changed in (
                re.sub(check.SSA, lambda match: '%result_' + match[0][1:]
                       if match[0] in trace.definitions else match[0], function),
                re.sub(r'\bbb(\d+)\b', lambda match: 'bb' + str(int(match[1]) + 1000), function),
                function.replace('start:\n', 'start:\n; harmless reader-result comment\n', 1)):
            assert changed != function
            other = inspect(changed)
            assert len(other.result_values) == len(trace.result_values)
            assert len(other.result_gates) == len(trace.result_gates)
            controls += 1
        functions += 1
    assert (functions, count, controls) == (24, 1152, 72)
    print(f'KMAC reader results reject {count} LLVM mutations; {controls} SSA/label/comment controls across {functions} verifiers PASS')
    print('Retained-text mutations only; subprocess execution forbidden; release gates unchanged')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
