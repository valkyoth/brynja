#!/usr/bin/env python3
"""Fault controls for retained output handoff LLVM; no runtime reruns."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_secret_output_finish as check
from test_kmac_verify_comparisons import rejects


def mutants(function):
    equality = re.search('(' + check.SSA + r') = icmp eq i64 (' + check.SSA + r'), (' + check.SSA + ')', function)
    condition, initialized, length = equality.groups()
    branch = re.search(r'br i1 ' + re.escape(condition) + r', label %(' + check.LABEL + r'), label %(' + check.LABEL + ')', function)
    cleanup = next(line for line in function.splitlines() if 'tail call' in line)
    symbol = re.search(check.comparison.SYMBOL, cleanup)
    args = check.comparison.arguments(cleanup, symbol.end())
    pointer = check.comparison.pointer(args[0])
    first_branch = next(line for line in function.splitlines() if line.strip().startswith('br i1'))
    for label, old, new in (
        ('inverted completion', 'icmp eq i64', 'icmp ne i64'),
        ('vacuous completion', equality[0], equality[0].replace(', ' + length, ', ' + initialized)),
        ('reversed completion branches', branch[0], f'br i1 {condition}, label %{branch[2]}, label %{branch[1]}'),
        ('wrong region length field', 'ptr %self, i64 8', 'ptr %self, i64 16'),
        ('wrong initialized field', 'ptr %self, i64 16', 'ptr %self, i64 8'),
        ('returned null pointer', 'store ptr ' + pointer + ',', 'store ptr null,'),
        ('returned zero length', 'store i64 ' + length + ',', 'store i64 0,'),
        ('success marked error', 'store i8 0, ptr %_0', 'store i8 1, ptr %_0'),
        ('wrong error identity', 'store i8 3,', 'store i8 0,'),
        ('missing cleanup', cleanup, ''),
        ('different cleanup function', cleanup, cleanup.replace('zeroize_region_volatile', 'unreviewed_cleanup')),
        ('wrong cleanup pointer', cleanup, cleanup.replace(' ' + pointer + ',', ' %self,')),
        ('partial cleanup length', cleanup, cleanup.replace(' ' + length + ')', ' ' + initialized + ')')),
        ('duplicate cleanup', cleanup, cleanup + '\n' + cleanup),
        ('raw secret load', cleanup, '  %secret = load i64, ptr ' + pointer + ', align 8\n' + cleanup),
        ('payload copy', cleanup, '  call void @llvm.memcpy.p0.p0.i64(ptr %_0, ptr ' + pointer + ', i64 8, i1 false)\n' + cleanup),
        ('early return', first_branch, '  ret void'),
        ('wrong output field', 'ptr %_0, i64 16', 'ptr %_0, i64 8'),
        ('unexpected return ABI', 'ret void', 'ret i64 0'),
        ('dangling branch', 'br label %bb7', 'br label %absent'),
    ):
        yield label, function.replace(old, new)


def main(record):
    count = 0
    for function in check.cases(record):
        count += rejects(check.inspect, function, mutants(function))
    if count != 160:
        raise AssertionError('incomplete ownership-handoff mutations: ' + str(count))
    print('Optimized output handoff rejects 160 completion/ownership/cleanup/control-flow regressions')
    print('Actual retained LLVM-text mutations, not compiled/runtime mutants; subprocess execution forbidden')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('must not rerun compiler or runtime')):
        main(parser.parse_args().record.resolve())
