#!/usr/bin/env python3
"""Retained constructor arithmetic/result mutations; no compiler or runtime."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_fips202_output_constructor as check
from test_kmac_optimized_cleanup import replace_block
from test_kmac_verify_comparisons import rejects


def mutations(function):
    graph, _, _ = check.forwarding.adapter.routes.transfer.finish.graph_info(function)
    header = function.splitlines()[0]
    for old, new in (('sret([32 x i8])', 'sret([24 x i8])'), ('define void @', 'define i64 @'),
                     (' %bytes.1,', ' %foreign,')):
        yield 'constructor ABI', function.replace(header, header.replace(old, new), 1)
    for label, lines in graph.items():
        for index, line in enumerate(lines):
            if ' = icmp ' in line:
                for old, new in ((' eq ', ' ult '), (' ult ', ' ugt '), (' ugt ', ' ult ')):
                    if old in line:
                        yield 'inverted arithmetic predicate', function.replace(line, line.replace(old, new), 1)
                constant = re.search(r', (\d+)$', line)
                if constant:
                    yield 'changed arithmetic threshold', function.replace(line,
                        line[:constant.start(1)] + str(int(constant[1]) + 1), 1)
            elif ' = add ' in line or ' = shl ' in line:
                constant = re.search(r', (-?\d+)$', line)
                if constant:
                    yield 'changed length arithmetic', function.replace(line,
                        line[:constant.start(1)] + str(int(constant[1]) + 1), 1)
                if ' = add i8 ' in line:
                    yield 'poison used for empty shape', function.replace(line, line.replace('add i8', 'add nuw i8'), 1)
            elif ' = select ' in line:
                match = re.fullmatch('(' + check.SSA + ') = select i1 (' + check.OPERAND + '), i1 (' + check.OPERAND + '), i1 (' + check.OPERAND + ')', line)
                yield 'swapped shape selection', function.replace(line,
                    f'{match[1]} = select i1 {match[2]}, i1 {match[4]}, i1 {match[3]}', 1)
            elif ' = extractvalue ' in line:
                yield 'overflow flag replaced by sum', function.replace(line, line[:-1] + '0', 1)
            elif ' = phi ' in line:
                yield 'nonzero empty length', function.replace(line, line.replace('[ 0,', '[ 1,'), 1)
                yield 'wrong phi predecessor', function.replace(line, line.replace('%bb6', '%start'), 1)
            elif ' = getelementptr ' in line:
                offset = int(line.rsplit(' ', 1)[1])
                yield 'wrong result field', function.replace(line, line.rsplit(' ', 1)[0] + ' ' + str(offset + 1), 1)
            elif line.startswith('store '):
                yield 'missing result store', replace_block(function, label, lines[:index] + lines[index + 1:])
                yield 'duplicate result store', replace_block(function, label, lines[:index] + [line] + lines[index:])
                if 'store ptr %bytes.0' in line:
                    yield 'success loses original destination', function.replace(line, line.replace('ptr %bytes.0', 'ptr null'), 1)
                if 'store i8 0,' in line or 'store i8 2,' in line:
                    yield 'wrong error identity', function.replace(line, re.sub(r'store i8 \d+,', 'store i8 1,', line), 1)
            elif line.startswith('br i1 '):
                match = re.fullmatch(r'br i1 (' + check.OPERAND + '), label %(' + check.LABEL + '), label %(' + check.LABEL + ')', line)
                yield 'inverted decision edges', function.replace(line,
                    f'br i1 {match[1]}, label %{match[3]}, label %{match[2]}', 1)
    for injection in ('%payload = load i8, ptr %bytes.0, align 1',
                      'store i8 0, ptr %bytes.0, align 8',
                      'call void @unreviewed(ptr %bytes.0)'):
        yield 'unexpected payload access/call', replace_block(function, 'start', [injection] + graph['start'])


def main(record):
    functions = count = controls = 0
    for function in check.cases(record):
        count += rejects(check.inspect, function, mutations(function))
        graph, _, _ = check.forwarding.adapter.routes.transfer.finish.graph_info(function)
        local_names = {match[1] for lines in graph.values() for line in lines
                       if (match := re.match('(' + check.SSA + ') = ', line))}
        for changed in (
                re.sub(check.SSA, lambda m: '%constructor_' + m[0][1:] if m[0] in local_names else m[0], function),
                re.sub(r'\bbb(\d+)\b', lambda m: 'bb' + str(int(m[1]) + 1000), function),
                function.replace('start:\n', 'start:\n; harmless constructor comment\n', 1)):
            assert changed != function
            assert check.inspect(changed) == 2560
            controls += 1
        functions += 1
    assert (functions, count, controls) == (8, 400, 24)
    print(f'FIPS 202 constructor rejects {count} LLVM arithmetic, result, poison-use and payload-access mutations; {controls} naming/comment controls across {functions} bodies PASS')
    print('Retained metadata-model tests only; subprocess execution forbidden; release gates unchanged')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
