#!/usr/bin/env python3
"""Mutate portable fill LLVM/model boundaries without compiling production code."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_sha3_fill as check
from test_kmac_verify_comparisons import rejects


def mutants(function):
    lines = function.splitlines()
    copy = next(line for line in lines if 'tail call' in line and '18copy_secret_region' in line)
    permute = next(line for line in lines if 'tail call' in line and '11permutation6native6scalar' in line)
    clears = [line for line in lines if 'tail call' in line and '18clear_owned_region' in line]
    args = check.shared.invocation(copy)[1]
    destination, source = check.comparison.pointer(args[0]), check.comparison.pointer(args[2])
    count = re.search(check.SSA + '$', args[1])[0]
    for label, old, new in (
        ('missing permutation', permute, ''),
        ('repeated permutation', permute, permute + '\n' + permute),
        ('unreviewed permutation', permute, permute.replace('6scalar', '6foobar')),
        ('missing copy', copy, ''),
        ('wrong copy destination', copy, copy.replace(destination, source)),
        ('wrong copy source', copy, copy.replace(source, destination)),
        ('empty copy', copy, copy.replace(count, '0')),
        ('mismatched copy slices', copy, copy.replace(args[3], 'i64 noundef 1', 1)),
        ('direct payload read', copy, '  %payload = load i8, ptr ' + source + ', align 1\n' + copy),
        ('direct payload store', copy, '  store i8 0, ptr ' + destination + ', align 1\n' + copy),
        ('wrong cursor address', 'ptr %self, i64 1039', 'ptr %self, i64 1038'),
        ('wrong staging base', 'ptr %self, i64 584', 'ptr %self, i64 585'),
        ('wrong state base', 'ptr %self, i64 48', 'ptr %self, i64 49'),
        ('unbounded minimum', '@llvm.umin.i64(', '@llvm.umax.i64('),
        ('reject valid full staging', 'icmp ugt i64 %count, 168', 'icmp ugt i64 %count, 167'),
        ('wrong cursor validity check', 'icmp ugt i8', 'icmp ult i8'),
        ('permutation on wrong boundary', 'icmp eq i8', 'icmp ne i8'),
    ):
        yield label, function.replace(old, new, 1)
    for clear in clears:
        width = check.shared.invocation(clear)[1][1]
        yield 'missing scratch clear', function.replace(clear, '', 1)
        yield 'partial scratch clear', function.replace(clear, clear.replace(width, 'i64 noundef 1'), 1)
        yield 'wrong clear callee', function.replace(clear, clear.replace('18clear_owned_region', '18unreviewed_cleanup'), 1)
    for branch in (line for line in lines if line.strip().startswith('br i1')):
        found = re.search('br i1 (' + check.SSA + r'), label %([^,]+), label %([^,\s]+)', branch)
        yield 'inverted fill branch', function.replace(branch, f'  br i1 {found[1]}, label %{found[3]}, label %{found[2]}', 1)


def model_examples():
    # Hand-written geometry checks keep the reference independent of the LLVM parser.
    for old, success in ((True, 5), (False, 255)):
        assert check.expected(136, 0, 255, old, 0) == (success, 255, [])
        assert check.expected(136, 169, 0, old, 0) == (3, 0, [])
        assert check.expected(136, 1, 137, old, 0) == (0, 137, [])
        assert check.expected(136, 1, 135, old, 0) == (success, 136, [('copy', 584, 183, 1), ('cursor', 136)])
        reset = [('permute',), ('clear', 752, 40), ('clear', 792, 40), ('clear', 832, 200), ('cursor', 0)]
        assert check.expected(136, 2, 135, old, 0) == (success, 1,
            [('copy', 584, 183, 1), ('cursor', 136)] + reset + [('copy', 585, 48, 1), ('cursor', 1)])
        assert check.expected(168, 1, 168, old, 1) == (4, 0, reset + [('copy', 584, 48, 1)])


def main(record):
    model_examples()
    counts = []
    for function, sha3, core, compiler in check.cases(record):
        counts.append(rejects(lambda body: check.inspect(body, sha3, core, compiler, thorough=False), function, mutants(function)))
    if counts != [33] * 16:
        raise AssertionError(f'incomplete fill mutation matrix: {counts}')
    print('Portable fill rejects 528 retained-LLVM address/copy/permutation/clear/control regressions')
    print('Twelve hand-written model examples PASS; subprocess execution forbidden; no production or release-gate changes')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
