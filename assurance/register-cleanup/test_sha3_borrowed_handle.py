#!/usr/bin/env python3
"""Mutate retained handle uses without rebuilding or executing cryptography."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_sha3_borrowed_handle as check
from test_kmac_optimized_cleanup import replace_block
from test_kmac_verify_comparisons import rejects


def mutations(function, graph, uses, addresses):
    header = function.splitlines()[0]
    symbol = re.search(check.comparison.SYMBOL, header)
    args = check.comparison.arguments(header, symbol.end())
    handle = check.comparison.pointer(args[1])
    for changed in (args[1].replace('noalias ', ''), args[1].replace('dereferenceable(16)', 'dereferenceable(8)')):
        yield 'handle ABI', function.replace(header, header.replace(args[1], changed, 1), 1)
    for _, _, line in uses:
        if 'getelementptr' in line:
            for offset in (0, 7, 9, -1):
                yield 'wrong lifecycle offset', function.replace(line, re.sub(r'i64 8$', 'i64 ' + str(offset), line), 1)
        elif ' = load ptr,' in line:
            yield 'owner pointer read as integer', function.replace(line, line.replace('load ptr,', 'load i64,'), 1)
        elif ' = load i8,' in line:
            yield 'wide lifecycle load', function.replace(line, line.replace('load i8,', 'load i64,'), 1)
        elif line.startswith('store i8 '):
            pointer = re.search(r', ptr (' + check.SSA + ')', line)[1]
            yield 'lifecycle write aliases owner field', function.replace(line, line.replace(pointer, handle), 1)
            yield 'wide lifecycle store', function.replace(line, line.replace('store i8', 'store i64'), 1)
            yield 'nonboolean lifecycle value', function.replace(line, re.sub(r'store i8 [01]', 'store i8 2', line), 1)
    flag = next(name for name, offset in addresses.items() if offset == 8)
    injections = (
        f'store ptr null, ptr {handle}, align 8',
        f'store i8 0, ptr {handle}, align 8',
        f'store ptr {handle}, ptr %_0, align 8',
        f'call void @unreviewed(ptr {handle})',
        f'call void @unreviewed(ptr {flag})',
        f'%escape = ptrtoint ptr {handle} to i64',
        f'%escape = freeze ptr {handle}',
        f'%escape = select i1 true, ptr {handle}, ptr null',
        f'%escape = getelementptr i8, ptr {handle}, i64 %destination.1',
        f'call void @llvm.memset.p0.i64(ptr {handle}, i8 0, i64 8, i1 false)',
        f'call void @llvm.memcpy.p0.p0.i64(ptr %_0, ptr {handle}, i64 16, i1 false)',
        f'call void @llvm.lifetime.end.p0(ptr {handle})',
        f'%escape = atomicrmw xchg ptr {handle}, ptr null seq_cst',
    )
    for injection in injections:
        yield 'handle escape/overwrite', replace_block(function, 'start', [injection] + graph['start'])
    # A derived zero-offset alias cannot smuggle a pointer write past the scan.
    yield 'derived alias owner write', replace_block(function, 'start', [
        f'%alias = getelementptr inbounds nuw i8, ptr {handle}, i64 0',
        'store ptr null, ptr %alias, align 8',
    ] + graph['start'])


def main(record):
    functions = count = controls = 0
    for function in check.cases(record):
        graph, uses, addresses = check.inspect(function)
        count += rejects(check.inspect, function, mutations(function, graph, uses, addresses))
        locals_ = {match[1] for block in graph.values() for line in block
                   if (match := re.match('(' + check.SSA + ') = ', line))}
        header = function.splitlines()[0]
        symbol = re.search(check.comparison.SYMBOL, header)
        handle = check.comparison.pointer(check.comparison.arguments(header, symbol.end())[1])
        for changed in (
                re.sub(check.SSA, lambda m: '%handle_' + m[0][1:] if m[0] in locals_ else m[0], function),
                re.sub(r'\bbb(\d+)\b', lambda m: 'bb' + str(int(m[1]) + 1000), function),
                function.replace('start:\n', 'start:\n; harmless handle comment\n', 1),
                replace_block(function, 'start', [f'%alias = getelementptr inbounds nuw i8, ptr {handle}, i64 0'] + graph['start'])):
            assert changed != function
            check.inspect(changed)
            controls += 1
        functions += 1
    assert (functions, count, controls) == (16, 576, 64)
    print(f'Portable borrowed handle rejects {count} LLVM overwrite/escape/field regressions; {controls} naming/comment/alias controls across {functions} bodies PASS')
    print('Retained-text tests only; subprocess execution forbidden; release gates unchanged')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
