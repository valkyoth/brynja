#!/usr/bin/env python3
"""Mutate candidate split/length routing in retained LLVM; never run crypto."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_kmac_candidate_shape as check
from test_kmac_optimized_cleanup import replace_block
from test_kmac_verify_comparisons import rejects


def mutations(function, trace):
    for value in sorted(trace.shape_values):
        _, rhs = trace.definitions[value]
        line = value + ' = ' + rhs
        yield 'unrelated shape value', function.replace(line, value + ' = freeze i64 0', 1)
        if rhs.startswith(('add ', 'icmp ', 'getelementptr ')):
            changed = re.sub(r'(, (?:i64 )?)(-?\d+)$', lambda m: m[1] + str(int(m[2]) + 1), line)
            if changed != line:
                yield 'changed length/valid field or boundary', function.replace(line, changed, 1)
        if rhs.startswith('load '):
            yield 'shape loaded from unrelated descriptor', function.replace(line,
                re.sub(r', ptr ' + check.SSA + ',', ', ptr %foreign,', line), 1)
        if rhs.startswith('phi '):
            entries = re.findall(r'\[ (' + check.SSA + r'), %(' + check.LABEL + r') \]', rhs)
            for entry in sorted(set(entries)):
                original = f'[ {entry[0]}, %{entry[1]} ]'
                yield 'wrong candidate split value', function.replace(line,
                    line.replace(original, f'[ %foreign, %{entry[1]} ]', 1), 1)
                yield 'wrong split predecessor', function.replace(line,
                    line.replace(original, f'[ {entry[0]}, %start ]', 1), 1)
    for label in sorted(trace.shape_blocks):
        lines = trace.graph[label]
        if lines[-1].startswith('br i1 '):
            condition, yes, no = check.branch(trace, label)
            for replacement in (
                    f'br i1 {condition}, label %{no}, label %{yes}',
                    f'br i1 %foreign, label %{yes}, label %{no}',
                    f'br label %{yes}', f'br label %{no}'):
                yield 'inverted or bypassed shape branch', replace_block(function, label, lines[:-1] + [replacement])
        elif lines[-1] == ']':
            aligned, partial = check.alignment_switch(trace, label, '%valid')
            for position in (-3, -2):
                wrong = list(lines)
                wrong[position] = wrong[position].replace('i8 0,', 'i8 1,').replace('i8 8,', 'i8 7,')
                yield 'wrong byte-alignment case', replace_block(function, label, wrong)
                wrong = list(lines)
                wrong[position] = wrong[position].replace('%' + aligned, '%' + partial)
                yield 'aligned candidate enters partial path', replace_block(function, label, wrong)
            wrong = list(lines)
            wrong[-4] = wrong[-4].replace('%valid,', '%foreign,')
            yield 'unrelated alignment decision', replace_block(function, label, wrong)
            wrong[-4] = lines[-4].replace('%' + partial, '%' + aligned)
            yield 'partial candidate bypasses final byte', replace_block(function, label, wrong)
        else:
            yield 'bulk preheader skips loop', replace_block(function, label, lines[:-1] + ['ret { i1, i8 } zeroinitializer'])
    for label, lines in trace.graph.items():
        for line in lines:
            if line.startswith('invoke void @') and ('12final_secret' in line or '25squeeze_final_bits_secret' in line):
                _, args = check.routes.guard.call(line)
                yield 'final reader uses full-byte mask', function.replace(line, line.replace(args[-1], 'i8 noundef 8'), 1)
                yield 'final reader uses unrelated valid-bit count', function.replace(line, line.replace(args[-1], 'i8 noundef %foreign'), 1)


def main(record):
    count = functions = controls = 0
    for _, function, names, defined, callees in check.routes.cases(record):
        inspect = lambda value: check.inspect(value, names, defined, callees)
        trace = inspect(function)
        count += rejects(inspect, function, mutations(function, trace))
        for changed in (
                re.sub(r'%valid(?![-.$\w])', '%candidate_valid_bits', function),
                function.replace('start:\n', 'start:\n; harmless shape comment\n', 1),
                re.sub(r'\bbb(\d+)\b', lambda m: 'bb' + str(int(m[1]) + 1000), function)):
            assert changed != function
            other = inspect(changed)
            assert len(other.shape_values) == len(trace.shape_values)
            assert len(other.shape_blocks) == len(trace.shape_blocks)
            controls += 1
        functions += 1
    assert (functions, count, controls) == (24, 1056, 72)
    print(f'KMAC candidate shape rejects {count} LLVM mutations; {controls} valid-bit/label/comment controls across {functions} verifiers PASS')
    print('Retained-text tests only; subprocess execution forbidden; release gates unchanged')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
