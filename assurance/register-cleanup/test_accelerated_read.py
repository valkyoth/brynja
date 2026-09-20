#!/usr/bin/env python3
"""Mutate retained accelerated read loop/boundary artifacts without rebuilding."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_accelerated_read as check
from test_kmac_verify_comparisons import rejects


def mutants(function, compiler):
    old = compiler == '1.90.0'
    lines = function.splitlines()
    copy = next(line for line in lines if 'invoke ' in line and '18copy_secret_region' in line)
    permute = next(line for line in lines if 'invoke ' in line and '13KeccakSession7permute' in line)
    args = check.shared.invocation(copy)[1]
    destination, source = check.comparison.pointer(args[0]), check.comparison.pointer(args[2])
    count = re.search(check.SSA + '$', args[1])[0]
    minimum = next(line for line in lines if '@llvm.umin.i64(' in line)
    copied = re.search('(' + check.SSA + ') = invoke', copy)[1]
    copy_test = next(line for line in lines if 'icmp eq i8 ' + copied + ',' in line)
    for label, before, after in (
        ('missing copy', copy, ''),
        ('wrong copy destination', copy, copy.replace(destination, source)),
        ('wrong copy source', copy, copy.replace(source, destination)),
        ('empty copy', copy, copy.replace(count, '0')),
        ('mismatched copy slices', copy, copy.replace(args[1], 'i64 noundef 1', 1)),
        ('direct payload read', copy, '  %leak = load i8, ptr ' + source + ', align 1\n' + copy),
        ('premature direct output write', copy, '  store i8 0, ptr ' + destination + ', align 1\n' + copy),
        ('wrong permutation owner', permute, permute.replace('%self', '%wrong_owner')),
        ('missing permutation', permute, ''),
        ('unbounded copy width', minimum, minimum.replace('llvm.umin', 'llvm.umax')),
        ('copy errors count as success', copy_test, copy_test.replace('icmp eq', 'icmp ne')),
        ('wrong cursor field', 'ptr %self, i64 616', 'ptr %self, i64 615'),
        ('wrong rate field', 'ptr %self, i64 608', 'ptr %self, i64 607'),
        ('wrong lanes field', 'ptr %self, i64 656', 'ptr %self, i64 655'),
        ('wrong terminal field', 'ptr %self, i64 859', 'ptr %self, i64 858'),
        ('wrong cleanup memory', 'ptr %self, i64 624', 'ptr %self, i64 623'),
    ):
        yield label, function.replace(before, after)
    for line in lines:
        if '6Memory4wipe' in line and ('call ' in line or 'invoke ' in line):
            yield 'missing engine wipe', function.replace(line, '', 1)
            yield 'unreviewed engine wipe', function.replace(line, line.replace('6Memory4wipe', '6Memory4fake'), 1)
        if line.strip().startswith('store i64') and re.search(r'store i64 %', line):
            yield 'wrong committed cursor', function.replace(line, re.sub(r'store i64 ' + check.SSA, 'store i64 0', line), 1)
            yield 'cursor committed before copy', function.replace(line, '', 1).replace(copy, line + '\n' + copy, 1)
        if line.strip().startswith('resume '):
            yield 'unwind returns success', function.replace(line, '  ret i8 ' + ('12' if old else '-1'), 1)
            yield 'exception substituted', function.replace(line, '  resume { ptr, i32 } %wrong_exception', 1)
    # Branch mutations are confined to the loop/copy/result blocks this checker owns.
    blocks = check.shared.graph(function)
    selected = [body for body in blocks.values() if any(
        token in '\n'.join(body) for token in ('@llvm.umin.i64(', ' = phi ptr ', ' = phi i64 [ %_22',
                                                ' = phi i64 [ %_19', 'store i64 %', 'icmp eq i8 ' + copied))]
    for body in selected:
        branch = body[-1]
        found = re.fullmatch('br i1 (' + check.SSA + '), label %(' + check.LABEL + '), label %(' + check.LABEL + ')', branch)
        if found:
            yield 'inverted loop boundary', function.replace(branch, f'br i1 {found[1]}, label %{found[3]}, label %{found[2]}', 1)
    capacity = next(line for line in lines if re.search(r'icmp (?:ugt|ult) i64 ' + check.SSA + ', ' + ('200' if old else '201') + r'$', line.strip()))
    yield 'off-by-one lane bound', function.replace(capacity, capacity.replace(', 200', ', 201') if old else capacity.replace(', 201', ', 202'), 1)


def main(record):
    counts = []
    for sha3, core, cpu, compiler in check.cases(record):
        definitions = check.comparison.definitions(sha3)
        function = definitions[check.shared.unique(definitions, 'accelerated', '6Engine4read')]
        counts.append(rejects(lambda body: check.inspect(sha3.replace(function, body, 1), core, cpu, compiler), function, mutants(function, compiler)))
    if counts != [30] * 4:
        raise AssertionError(f'incomplete read mutation matrix: {counts}')
    print('Accelerated read rejects 120 retained-LLVM pointer/bound/commit/cleanup/unwind regressions')
    print('Subprocess execution forbidden; no new compiled fault campaign or release-gate change')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
