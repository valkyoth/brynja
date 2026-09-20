#!/usr/bin/env python3
"""Direct-memory negative controls on retained verifier LLVM, without rebuilding."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_kmac_verify_memory as check
from test_kmac_verify_comparisons import rejects


def mutants(function):
    call = check.comparison.comparison_calls(function)[0]
    symbol = re.search(check.comparison.SYMBOL, call)
    args = check.comparison.arguments(call, symbol.end())
    secret = check.comparison.pointer(args[1])
    local = re.search('(' + check.SSA + r') = alloca \[(\d+) x i8\]', function)
    slot, size = local[1], int(local[2])
    def copy(destination, source, length):
        return f'call void @llvm.memcpy.p0.p0.i64(ptr {destination}, ptr {source}, i64 {length}, i1 false)'
    additions = (
        ('secret scalar load', f'%probe = load i8, ptr {secret}, align 1'),
        ('secret alias load', f'%alias = getelementptr i8, ptr {secret}, i64 0\n%probe = load i8, ptr %alias, align 1'),
        ('secret scalar store', f'store i8 0, ptr {secret}, align 1'),
        ('secret copy source', copy(slot, secret, 1)),
        ('secret copy destination', copy(secret, slot, 1)),
        ('oversized local copy', copy(slot, slot, size + 1)),
        ('negative local offset', f'%alias = getelementptr i8, ptr {slot}, i64 -1\n%probe = load i8, ptr %alias, align 1'),
        ('end-of-slot load', f'%alias = getelementptr i8, ptr {slot}, i64 {size}\n%probe = load i8, ptr %alias, align 1'),
        ('external atomic access', f'%probe = atomicrmw xor ptr {secret}, i8 1 monotonic'),
        ('unreviewed vector load', f'%probe = load <2 x i8>, ptr {slot}, align 1'),
        ('volatile secret load', f'%probe = load volatile i8, ptr {secret}, align 1'),
        ('unreviewed memory intrinsic', copy(slot, slot, 1).replace('memcpy', 'memmove')),
        ('integer-derived pointer', '%alias = inttoptr i64 1 to ptr\n%probe = load i8, ptr %alias, align 1'),
        ('cross-boundary load', f'%alias = getelementptr i8, ptr {slot}, i64 {size - 1}\n%probe = load i16, ptr %alias, align 1'),
    )
    for label, extra in additions:
        yield label, function.replace(call, extra + '\n' + call, 1)
    # Constant-offset descriptor aliasing is intentionally accepted, but only
    # when the actual direct access remains inside the known descriptor region.
    positive = f'%alias = getelementptr i8, ptr {slot}, i64 0\n%probe = load i8, ptr %alias, align 1'
    check.inspect(function.replace(call, positive + '\n' + call, 1))


def main(record):
    count, functions = 0, 0
    for row, kmac, _, _ in check.comparison.cases(record):
        for function in check.comparison.verifiers(kmac, row['mode'] == 'accelerated'):
            count += rejects(check.inspect, function, mutants(function))
            functions += 1
    if count != 672 or functions != 48:
        raise AssertionError(f'incomplete direct-memory mutation inventory: {count}/{functions}')
    print('Verifier direct-memory checks accept 48 bounded-alias controls and reject 672 access/copy/bounds regressions')
    print('Retained LLVM-text mutants, not compiled/runtime tests; subprocess execution forbidden')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
