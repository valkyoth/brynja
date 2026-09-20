#!/usr/bin/env python3
"""Mutate retained portable staging loops without rebuilding production code."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_sha3_staging as check
from test_kmac_verify_comparisons import rejects


def mutants(function):
    lines = function.splitlines()
    write = next(line for line in lines if 'tail call' in line and 'Initialization5write' in line)
    clear = next(line for line in lines if 'tail call' in line and '18clear_owned_region' in line)
    fill = next(line for line in lines if 'tail call' in line and '12fill_staging' in line)
    minimum = next(line for line in lines if '@llvm.umin.i64(' in line)
    count = re.search('(' + check.SSA + ') =', minimum)[1]
    symbol = re.search(check.comparison.SYMBOL, write)
    args = check.comparison.arguments(write, symbol.end())
    stage = check.comparison.pointer(args[1])
    filled = re.search('(' + check.SSA + ') =', fill)[1]
    written = re.search('(' + check.SSA + ') =', write)[1]
    fill_test = next(line for line in lines if 'icmp eq i8 ' + filled + ',' in line)
    write_test = next(line for line in lines if 'icmp eq i8 ' + written + ',' in line)
    progress = next(line for line in lines if ' = sub nuw i64 ' in line)
    loop_test = next(line for line in lines if 'icmp ugt i64' in line)
    for label, old, new in (
        ('wrong staging region', 'ptr %self, i64 584', 'ptr %self, i64 16'),
        ('oversized chunk', minimum, minimum.replace('i64 136)', 'i64 200)').replace('i64 168)', 'i64 200)')),
        ('unbounded chunk', minimum, minimum.replace('llvm.umin', 'llvm.umax')),
        ('missing fill', fill, ''),
        ('wrong fill owner', fill, fill.replace('%self', '%initialization')),
        ('wrong fill count', fill, fill.replace(count, '0')),
        ('inverted fill result', fill_test, fill_test.replace('icmp eq', 'icmp ne')),
        ('missing write', write, ''),
        ('duplicate write', write, write + '\n' + write),
        ('wrong write owner', write, write.replace('%initialization', '%self')),
        ('wrong write source', write, write.replace(stage, '%self')),
        ('wrong write width', write, write.replace(count, '0')),
        ('inverted write result', write_test, write_test.replace('icmp eq', 'icmp ne')),
        ('missing clear', clear, ''),
        ('wrong clear region', clear, clear.replace(stage, '%self')),
        ('partial clear', clear, clear.replace('i64 noundef 168', 'i64 noundef 1')),
        ('only current chunk cleared', clear, clear.replace('i64 noundef 168', 'i64 noundef ' + count)),
        ('wrong clear callee', clear, clear.replace('18clear_owned_region', '18unreviewed_cleanup')),
        ('extra clear before output write', write, clear + '\n' + write),
        ('payload load in transfer block', write, '  %leak = load i8, ptr ' + stage + ', align 1\n' + write),
        ('broken progress', progress, progress.replace('sub nuw', 'add nuw')),
        ('wrong repeat boundary', loop_test, loop_test.replace('icmp ugt', 'icmp uge')),
    ):
        yield label, function.replace(old, new, 1)
    yield 'moved clear before write', function.replace(clear, '', 1).replace(write, clear + '\n' + write, 1)
    for branch in (line for line in lines if line.strip().startswith('br i1')):
        # Only the three inspected loop branches, not the pre-loop counter/empty checks.
        predicate = re.search(r'br i1 (' + check.SSA + ')', branch)[1]
        if not any(predicate + ' = ' in line for line in (fill_test, write_test, loop_test)):
            continue
        edges = re.search(r'label %(\S+), label %([^,\s]+)', branch)
        yield 'reversed loop edge', function.replace(branch, f'  br i1 {predicate}, label %{edges[2]}, label %{edges[1]}', 1)


def main(record):
    count = 0
    for function, sha3, core, compiler in check.cases(record):
        count += rejects(lambda body: check.inspect(body, sha3, core, compiler), function, mutants(function))
    if count != 416:
        raise AssertionError(f'incomplete staging mutations: {count}')
    print('Portable secret squeeze staging rejects 416 pointer, bound, ordering and result/loop regressions')
    print('Actual retained LLVM-text mutations only; subprocess execution forbidden; no release-gate change')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
