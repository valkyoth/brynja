#!/usr/bin/env python3
"""Mutate retained reader-error conversion without rebuilding or running Rust."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_kmac_final_error as check
from test_kmac_optimized_cleanup import replace_block
from test_kmac_verify_comparisons import rejects


def mutations(function, trace, error, mode):
    lines = trace.graph[error]
    for index in range(len(lines)):
        yield 'missing error conversion operation', replace_block(function, error, lines[:index] + lines[index + 1:])
    substitutions = (
        (0, 'i64 8', 'i64 16'),
        (0, trace.adapter_details[5], '%output.0'),
        (1, 'load i8', 'load i64'),
        (2, ', 3', ', 2'),
        (2, 'shl nuw nsw', 'lshr'),
        (3, 'zext nneg', 'sext'),
        (4, 'lshr', 'ashr'),
        (5, 'to i8', 'to i16'),
        (6, 'ptr %_0', 'ptr %output.0'),
        (6, 'i64 8', 'i64 16'),
        (8, 'i64 2', 'i64 1'),
        (9, trace.adapter_details[4], trace.adapter_details[3]),
        (9, trace.adapter_details[4], trace.adapter_details[0]),
    )
    for index, old, new in substitutions:
        changed = list(lines)
        changed[index] = changed[index].replace(old, new)
        yield 'wrong error provenance/encoding/return', replace_block(function, error, changed)
    table = sum(value << (8 * index) for index, value in enumerate(check.MAPPINGS[mode]))
    for index in range(5):
        changed = list(lines)
        changed[4] = changed[4].replace(str(table), str(table ^ (1 << (8 * index))))
        yield 'wrong individual mapped error', replace_block(function, error, changed)
    for line in ('store i8 0, ptr %output.0, align 1', 'call void @unreviewed()'):
        yield 'unexpected payload or callee side effect', replace_block(function, error, lines[:-1] + [line, lines[-1]])
    yield 'return before error construction', replace_block(function, error, ['ret void'])
    changed = list(lines)
    changed[7] = re.sub(r'store i8 [^,]+', 'store i8 0', changed[7])
    yield 'store bypasses converted error', replace_block(function, error, changed)


def main(record):
    functions = count = controls = bindings = 0
    for function, callees, mode in check.cases(record):
        inspect = lambda value: check.inspect(value, callees, mode)
        trace, error = inspect(function)
        count += rejects(inspect, function, mutations(function, trace, error, mode))
        for wrong in ('unknown', 'accelerated' if mode == 'portable' else 'portable'):
            try:
                check.inspect(function, callees, wrong)
            except ValueError:
                bindings += 1
            else:
                raise AssertionError('incorrect feature-layout binding accepted')
        locals_ = {match[1] for lines in trace.graph.values() for line in lines
                   if (match := re.match('(' + check.SSA + ') = ', line))}
        for changed in (
                re.sub(check.SSA, lambda m: '%error_' + m[0][1:] if m[0] in locals_ else m[0], function),
                re.sub(r'\bbb(\d+)\b', lambda m: 'bb' + str(int(m[1]) + 1000), function),
                function.replace('start:\n', 'start:\n; harmless mapping comment\n', 1)):
            assert changed != function
            inspect(changed)
            controls += 1
        functions += 1
    assert (functions, count, controls, bindings) == (16, 512, 48, 32)
    print(f'KMAC final reader error rejects {count} LLVM mutations and {bindings} feature-layout mismatches; {controls} controls across {functions} adapters PASS')
    print('Retained-text tests only; subprocess execution forbidden; release gates unchanged')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
