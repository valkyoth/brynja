#!/usr/bin/env python3
"""Mutations of squeeze result identity, output Drop and owner cleanup."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_sha3_squeeze_error as check
from test_kmac_optimized_cleanup import replace_block
from test_kmac_verify_comparisons import rejects


def mutations(function, trace, labels, marker):
    final, bulk, error, dropping, cleanup, exiting, returning = labels
    graph = trace.graph
    for label in labels:
        for index in range(len(graph[label])):
            yield 'missing error-path operation', replace_block(function, label, graph[label][:index] + graph[label][index + 1:])
    for label in (final, bulk):
        lines = graph[label]
        for value in range(5):
            yield 'valid error accepted as success', replace_block(function, label,
                [lines[0].rsplit(', ', 1)[0] + ', ' + str(value), lines[1]])
        yield 'inverted squeeze status', replace_block(function, label, [lines[0].replace('icmp eq', 'icmp ne'), lines[1]])
        tested, success, failed = check.adapter.shape.branch(trace, label)
        yield 'swapped success/error edge', replace_block(function, label,
            [lines[0], f'br i1 {tested}, label %{failed}, label %{success}'])
        yield 'foreign squeeze result', replace_block(function, label,
            [re.sub(r'icmp eq i8 %[^,]+', 'icmp eq i8 %foreign', lines[0]), lines[1]])
    lines = graph[error]
    for index in range(2):
        # Each phi edge must use its own actual result, not a fixed substitute.
        for value in range(5):
            match = list(re.finditer(r'\[ (%[^,]+),', lines[0]))[index]
            changed = lines[0][:match.start(1)] + str(value) + lines[0][match.end(1):]
            yield 'error identity substituted', replace_block(function, error, [changed] + lines[1:])
    yield 'foreign ownership discriminator', replace_block(function, error,
        lines[:-3] + [re.sub(r'ptr %[^,]+', 'ptr %self', lines[-3])] + lines[-2:])
    tested, absent, present = check.adapter.shape.branch(trace, error)
    yield 'present output skips Drop', replace_block(function, error,
        lines[:-1] + [f'br i1 {tested}, label %{present}, label %{absent}'])
    for label, index in ((dropping, 0), (cleanup, len(graph[cleanup]) - 2)):
        call = graph[label][index]
        name, args = check.adapter.routes.guard.call(call)
        for old, new in ((name, 'unreviewed_cleanup'), (check.comparison.pointer(args[0]), '%destination.0')):
            block = list(graph[label])
            block[index] = call.replace(old, new)
            yield 'wrong cleanup callee/owner', replace_block(function, label, block)
        yield 'payload write on error path', replace_block(function, label,
            graph[label][:index] + ['store i8 0, ptr %destination.0, align 1'] + graph[label][index:])
    for label in (error, cleanup):
        for index, line in enumerate(graph[label]):
            if line == 'store i64 2, ptr %_0, align 8':
                block = list(graph[label])
                block[index] = 'store i64 1, ptr %_0, align 8'
                yield 'error disguised as success', replace_block(function, label, block)
            if ' = getelementptr ' in line and 'ptr %_0' in line:
                block = list(graph[label])
                block[index] = line.replace('i64 8', 'i64 16')
                yield 'misplaced returned error', replace_block(function, label, block)
    if marker == '5':
        for old, new in (('zext nneg', 'sext'), (' to i64', ' to i32')):
            yield 'lossy error encoding', replace_block(function, error,
                [lines[0], lines[1].replace(old, new)] + lines[2:])
        phi = graph[cleanup][0]
        yield 'error replaced after Drop', replace_block(function, cleanup,
            [re.sub(r'\[ %[^,]+,', '[ null,', phi)] + graph[cleanup][1:])
    else:
        for value in range(5):
            yield 'wrong returned error byte', replace_block(function, error,
                lines[:2] + [re.sub(r'store i8 %[^,]+', 'store i8 ' + str(value), lines[2])] + lines[3:])
    yield 'error cleanup skipped', replace_block(function, error, ['br label %' + returning])
    yield 'error retries successful work', replace_block(function, cleanup,
        graph[cleanup][:-1] + ['br label %' + trace.edges[final][0][0]])
    yield 'reader reactivated after error', replace_block(function, exiting,
        graph[exiting][:-1] + ['store i8 1, ptr %self, align 8', graph[exiting][-1]])


def main(record):
    functions = count = controls = bindings = 0
    for function, begin, wipes, drop, callees, headers in check.cases(record):
        inspect = lambda value: check.inspect(value, begin, wipes, drop, callees, headers)
        trace, labels, marker = inspect(function)
        count += rejects(inspect, function, mutations(function, trace, labels, marker))
        _, _, routes, _ = check.active.inspect(function, begin, wipes, drop, callees)
        for _, name, _, _, _ in routes:
            for replacement in (None, headers[name].replace('range(i8 0, 6)', 'range(i8 -1, 5)')
                                if marker == '5' else headers[name].replace('range(i8 -1, 5)', 'range(i8 0, 6)'),
                                headers[name].replace('range(i8 0, 6)', 'range(i8 0, 7)').replace('range(i8 -1, 5)', 'range(i8 -1, 6)')):
                wrong = dict(headers)
                if replacement is None:
                    del wrong[name]
                else:
                    wrong[name] = replacement
                try:
                    check.inspect(function, begin, wipes, drop, callees, wrong)
                except ValueError:
                    bindings += 1
                else:
                    raise AssertionError('missing or incompatible squeeze result signature accepted')
        locals_ = {match[1] for lines in trace.graph.values() for line in lines
                   if (match := re.match('(' + check.SSA + ') = ', line))} - {'%valid', '%length'}
        for changed in (
                re.sub(check.SSA, lambda m: '%result_' + m[0][1:] if m[0] in locals_ else m[0], function),
                re.sub(r'\bbb(\d+)\b', lambda m: 'bb' + str(int(m[1]) + 1000), function),
                function.replace('start:\n', 'start:\n; harmless error-path comment\n', 1)):
            assert changed != function
            inspect(changed)
            controls += 1
        functions += 1
    assert (functions, count, controls, bindings) == (16, 1032, 48, 96), (functions, count, controls, bindings)
    print(f'Squeeze errors reject {count} LLVM mutations and {bindings} missing/incompatible result bindings; {controls} controls across {functions} readers PASS')
    print('Retained-text tests only; subprocess execution forbidden; release gates unchanged')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
