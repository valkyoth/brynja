#!/usr/bin/env python3
"""Mutation controls for retained secret initialization destructors."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_secret_output_drop as check
from test_kmac_optimized_cleanup import replace_block
from test_kmac_verify_comparisons import rejects


def mutations(function, zero):
    graph, (present, absent) = check.inspect(function, zero)
    for label, lines in graph.items():
        for index in range(len(lines)):
            yield 'missing destructor operation', replace_block(function, label, lines[:index] + lines[index + 1:])
    start, block = graph['start'], graph[present]
    yield 'inverted ownership check', function.replace(start[1], start[1].replace('icmp eq', 'icmp ne'), 1)
    yield 'unconditional skip', replace_block(function, 'start', start[:-1] + ['br label %' + absent])
    yield 'wrong handle pointer', function.replace(start[0], start[0].replace('ptr %self', 'ptr %foreign'), 1)
    yield 'use initialized prefix length', function.replace(block[0], block[0].replace('i64 8', 'i64 16'), 1)
    call = block[2]
    _, args = check.adapter.routes.guard.call(call)
    pointer = check.comparison.pointer(args[0])
    length = re.search('(' + check.SSA + ')$', args[1])[1]
    for old, new in ((zero, 'unreviewed_clear'), (pointer, '%self'), (length, '0'),
                     ('fastcc void', 'void'), ('ptr ', 'ptr byval(i8) ')):
        yield 'wrong cleanup identity/extent/ABI', function.replace(call, call.replace(old, new), 1)
    yield 'duplicate wipe', replace_block(function, present, block[:2] + [call] + block[2:])
    yield 'return before wipe', replace_block(function, present, block[:2] + ['ret void'])
    for line in ('%secret = load i8, ptr ' + pointer + ', align 1',
                 'store ptr null, ptr %self, align 8',
                 'call void @unreviewed(ptr ' + pointer + ')'):
        yield 'unexpected payload or handle work', replace_block(function, present, block[:2] + [line] + block[2:])
    yield 'absent owner performs work', replace_block(function, absent, ['call void @unreviewed(ptr %self)', 'ret void'])


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
            raise AssertionError('unbound destructor callee accepted')
        graph, _ = inspect(function)
        locals_ = {match[1] for lines in graph.values() for line in lines
                   if (match := re.match('(' + check.SSA + ') = ', line))}
        for changed in (
                re.sub(check.SSA, lambda m: '%drop_' + m[0][1:] if m[0] in locals_ else m[0], function),
                re.sub(r'\bbb(\d+)\b', lambda m: 'bb' + str(int(m[1]) + 1000), function),
                function.replace('start:\n', 'start:\n; harmless destructor comment\n', 1)):
            assert changed != function
            inspect(changed)
            controls += 1
        functions += 1
    assert (functions, count, controls, bindings) == (8, 184, 24, 8)
    print(f'Secret initialization drop rejects {count} LLVM mutations and {bindings} wrong-callee bindings; {controls} controls across {functions} bodies PASS')
    print('Retained-text tests only; subprocess execution forbidden; release gates unchanged')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
