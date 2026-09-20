#!/usr/bin/env python3
"""Mutation tests for retained volatile-clear LLVM; no compiled fault campaign."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_volatile_clear as check
from test_kmac_verify_comparisons import rejects


def mutants(function):
    for line in function.splitlines():
        if 'store volatile i8' in line:
            for replacement in ('', line.replace('volatile ', ''), line.replace('i8 0', 'i8 1'),
                                re.sub(r'ptr %[-.$\w]+', 'ptr %region.0', line)):
                yield 'omitted/nonvolatile/nonzero/repeated-address store', function.replace(line, replacement)
        if 'getelementptr inbounds nuw i8' in line:
            if '%region.1' in line:
                replacement = line.replace('i64 %region.1', 'i64 0')
            else:
                replacement = re.sub(r'i64 \d+', 'i64 0', line)
            yield 'wrong pointer stride or end', function.replace(line, replacement)
        if line.strip().startswith('br i1'):
            edges = re.search(r'br i1 (\S+), label %(\S+), label %([^,\s]+)', line)
            replacement = line.replace(edges[0], f'br i1 {edges[1]}, label %{edges[3]}, label %{edges[2]}')
            yield 'inverted loop boundary', function.replace(line, replacement)
    fence = '  fence syncscope("singlethread") seq_cst'
    for replacement in ('', fence.replace('seq_cst', 'release'), fence + '\n' + fence):
        yield 'missing/weakened/duplicate fence', function.replace(fence, replacement)
    yield 'premature fence', function.replace(fence + '\n', '').replace('start:', 'start:\n' + fence)
    yield 'payload load', function.replace('start:', 'start:\n  %secret = load i8, ptr %region.0, align 1')
    yield 'unreviewed call', function.replace('start:', 'start:\n  call void @unexpected()')
    yield 'missing return', function.replace('ret void', 'unreachable')
    yield 'by-value region', function.replace('ptr noalias', 'ptr byval([8 x i8]) noalias', 1)
    if '%xtraiter' in function:
        yield 'wrong remainder mask', function.replace('and i64 %region.1, 7', 'and i64 %region.1, 3')
        yield 'wrong bulk threshold', function.replace('i64 %region.1, 8', 'i64 %region.1, 9')
        yield 'no remainder progress', function.replace('add i64 %prol.iter, 1', 'add i64 %prol.iter, 0')


def controls(function):
    # SSA naming and textual phi predecessor order have no semantic effect.
    local = next(re.search(r'(%[-.$\w]+) = phi ptr', line)[1]
                 for line in function.splitlines() if ' = phi ptr' in line)
    yield re.sub(re.escape(local) + r'(?![-.$\w])', '%renamed_cursor', function)
    line = next(line for line in function.splitlines() if ' = phi ptr' in line)
    match = re.search(r'(\[ [^]]+ \]), (\[ [^]]+ \])', line)
    assert match is not None
    yield function.replace(line, line.replace(match[0], match[2] + ', ' + match[1]))


def main(record):
    count = positive = 0
    for function in check.cases(record):
        count += rejects(check.inspect, function, mutants(function))
        for changed in controls(function):
            assert changed != function
            assert check.inspect(changed) == len(check.lengths())
            positive += 1
    if (count, positive) != (312, 16):
        raise AssertionError(f'incomplete volatile-clear campaign: {count}/{positive}')
    print(f'Volatile clearing rejects {count} retained-LLVM regressions; {positive} SSA/phi-order controls PASS')
    print('Artifact-text mutations only; subprocess execution forbidden; production/release gates unchanged')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
