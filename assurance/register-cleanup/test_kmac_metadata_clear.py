#!/usr/bin/env python3
"""Retained KMAC cleanup LLVM mutations, not compiled fault injection."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_kmac_metadata_clear as check
from test_kmac_verify_comparisons import rejects


def mutants(function, role, names):
    symbol = re.search(check.comparison.SYMBOL, function.splitlines()[0])
    yield 'substituted definition identity', function.replace('@' + symbol[1] + '(', '@unreviewed(', 1)
    graph = check.model.blocks(function)
    if role in ('CLEAR', 'EMPTY'):
        for lines in graph.values():
            for instruction in lines:
                yield 'missing wrapper instruction', function.replace(instruction, '', 1)
                yield 'duplicated wrapper instruction', function.replace(instruction, instruction + '\n' + instruction, 1)
        for line in function.splitlines():
            if 'call ' in line and '@' in line:
                symbol = re.search(check.comparison.SYMBOL, line)
                if symbol:
                    yield 'unbound forwarding callee', function.replace('@' + symbol[1] + '(', '@unreviewed(', 1)
        yield 'payload access in forwarding helper', function.replace('start:\n', 'start:\n  %injected = load i8, ptr %region.0, align 1\n', 1)
        if role == 'CLEAR':
            for old, new in (('i64 %region.1)', 'i64 0)'), ('i64 noundef %region.1)', 'i64 noundef 0)')):
                if old in function:
                    yield 'wrong forwarded width', function.replace(old, new, 1)
            branch = next(line for line in graph['start'] if line.startswith('br i1 '))
            reversed_branch = re.sub(r'label %(\w+), label %(\w+)', lambda m: 'label %' + m[2] + ', label %' + m[1], branch)
            yield 'reversed empty/nonempty routes', function.replace(branch, reversed_branch, 1)
        else:
            yield 'inverted empty predicate', function.replace('icmp eq ', 'icmp ne ', 1)
        return
    for line in function.splitlines():
        if 'call ' in line and '@' in line:
            yield 'omitted clearing call', function.replace(line, '', 1)
            yield 'repeated clearing call', function.replace(line, line + '\n' + line, 1)
            symbol = re.search(check.comparison.SYMBOL, line)
            yield 'substituted clearing callee', function.replace('@' + symbol[1] + '(', '@unreviewed(', 1)
            if symbol[1] == names['CLEAR']:
                for width in (0, 2, 63, 67):
                    changed = re.sub(r'i64( noundef)? \d+\)', lambda m: 'i64' + (m[1] or '') + ' ' + str(width) + ')', line)
                    yield 'wrong clearing width', function.replace(line, changed, 1)
        if 'getelementptr' in line:
            for offset in (0, 63, 66):
                changed = re.sub(r'i64 (64|65)', 'i64 ' + str(offset), line)
                yield 'shifted clearing region', function.replace(line, changed, 1)
    for operation in ('%injected = load i8, ptr %self, align 1',
                      'store i8 1, ptr %self, align 1', 'call void @unreviewed()', 'ret void'):
        yield 'unmodeled payload/guard access or early return', function.replace('start:\n', 'start:\n  ' + operation + '\n', 1)
    yield 'wrong cleanup return ABI', function.replace('define void @', 'define i8 @', 1)


def main(record):
    count = controls = builds = 0
    for functions, names, compiler, profile in check.cases(record):
        for role, function in functions.items():
            inspect = lambda value: check.inspect({**functions, role: value}, names, compiler, profile)
            count += rejects(inspect, function, mutants(function, role, names))
            assert inspect(function.replace('start:\n', 'start:\n; harmless inspection comment\n', 1)) == 6
            controls += 1
            without_debug = re.sub(r'(?m)^\s*#dbg_[^\n]*\n', '', function)
            if without_debug != function:
                assert inspect(without_debug) == 6
                controls += 1
        builds += 1
    assert (builds, count, controls) == (16, 1728, 112), (builds, count, controls)
    print(f'KMAC metadata cleanup rejects {count} region/call/forwarding mutations; {controls} comment/debug controls across {builds} builds PASS')
    print('Subprocess execution forbidden; no compiler/runtime rerun or release-gate changes')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
