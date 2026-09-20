#!/usr/bin/env python3
"""Retained byte-precondition LLVM text regressions, not compiled fault tests."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_byte_precondition as check
from test_kmac_verify_comparisons import rejects


def mutants(function, graph):
    actual = check.model.blocks(function)
    for block in graph:
        for instruction in actual[block]:
            yield 'missing normal-path instruction', function.replace(instruction, '', 1)
            yield 'duplicated normal-path instruction', function.replace(instruction, instruction + '\n' + instruction, 1)
    for extra in ('%injected = load i8, ptr %addr, align 1',
                  'store i8 1, ptr %addr, align 1', 'call void @unreviewed()',
                  'ret void'):
        yield 'payload/call/early-return insertion', function.replace('start:\n', 'start:\n  ' + extra + '\n', 1)
    yield 'wrong alignment ABI', function.replace('i64 %align', 'i32 %align', 1)
    yield 'duplicated normal label', function.replace('\n}', '\nstart:\n  unreachable\n}', 1)
    if 'llvm.ctpop.i64' in function:
        yield 'wrong intrinsic operand', function.replace('@llvm.ctpop.i64(i64 %align)', '@llvm.ctpop.i64(i64 0)', 1)
        yield 'wrong address mask', function.replace('sub i64 %align, 1', 'sub i64 %align, 0', 1)
        yield 'wrong mask operation', function.replace('and i64 ', 'or i64 ', 1)
    else:
        yield 'wrong alignment callee', function.replace('13is_aligned_to', '13is_aligned_no', 1)
    branch = next(line for lines in actual.values() for line in lines if line.startswith('br i1 '))
    changed = re.sub(r'label %(\w+), label %(\w+)', lambda match: 'label %' + match[2] + ', label %' + match[1], branch)
    yield 'reversed branch destinations', function.replace(branch, changed, 1)


def main(record):
    count = controls = paths = builds = 0
    for _, _, functions, names, compiler, _ in check.cases(record):
        expected_count = check.inspect(functions, names, compiler)
        for role, function in functions.items():
            graph = check.contracts(compiler)[role]
            inspect = lambda value: check.inspect({**functions, role: value}, names, compiler)
            count += rejects(inspect, function, mutants(function, graph))
            metadata = re.sub(r'(?m)^\s*#dbg_[^\n]*\n', '', function)
            assert metadata != function and inspect(metadata) == expected_count
            controls += 1
            # The valid alignment-one route never enters this diagnostic path.
            block = 'bb4' if compiler == '1.90.0' else 'bb2'
            panic = re.search(r'^' + block + r':[^\n]*\n.*?(?=^\w+:|^})', function, re.M | re.S)
            assert panic is not None and block not in graph
            replaced = function[:panic.start()] + block + ':\n  unreachable\n\n' + function[panic.end():]
            assert replaced != function and inspect(replaced) == expected_count
            controls += 1
            paths += 1
        builds += 1
    if (builds, paths, count, controls) != (8, 12, 544, 24):
        raise AssertionError(f'incomplete normal-path matrix: {builds}/{paths}/{count}/{controls}')
    print(f'Debug byte preconditions reject {count} LLVM normal-path/ABI mutations; {controls} scoped controls across {paths} paths PASS')
    print('Diagnostic panic bodies intentionally excluded; subprocess execution forbidden; no release-gate changes')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
