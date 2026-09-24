#!/usr/bin/env python3
"""Mutate retained counter decoding and its actual iterator/arithmetic helpers."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_counter_decode as check
from test_debug_portable_final_bridge import changed
from test_kmac_optimized_cleanup import replace_block
from test_kmac_verify_comparisons import rejects


def mutants(case):
    _, names, selected, _, _ = check.closure(case)
    _, _, _, visited = check.inspect(case, False)
    for name, body in selected.items():
        yield 'missing decoder dependency ' + name, changed(case, body, '')
        graph = check.model.blocks(body)
        for label, lines in graph.items():
            if (name, label) not in visited:
                continue
            for index, line in enumerate(lines):
                alternatives = []
                symbol = re.search(check.comparison.SYMBOL, line)
                if symbol and 'call ' in line:
                    alternatives.append('')
                    if name == names['counter'] and 'i64 16' in line:
                        alternatives += [line.replace('i64 16', 'i64 ' + str(length)) for length in (15, 17)]
                    if name == names['shift'] and 'i32 8' in line:
                        alternatives.append(line.replace('i32 8', 'i32 7'))
                if found := re.fullmatch(r'br i1 (\S+), label %(\S+), label %(\S+)', line):
                    if graph[found[2]] != ['br label %' + found[3]] and graph[found[3]] != ['br label %' + found[2]]:
                        alternatives.append(f'br i1 {found[1]}, label %{found[3]}, label %{found[2]}')
                if name == names['counter']:
                    if 'shl i128' in line:
                        alternatives.append(line.replace('shl i128', 'or i128'))
                    if 'or i128' in line:
                        alternatives.append(line.replace('or i128', 'and i128'))
                    if line == 'store i128 0, ptr %value, align 16':
                        alternatives.append(line.replace('i128 0', 'i128 1'))
                    if 'load i8, ptr %byte' in line:
                        alternatives.append(line + '\n' + line)
                    if 'and i32 %shift, 127' in line:
                        alternatives.append(line.replace('127', '63'))
                    if 'icmp ult i32 %shift, 128' in line:
                        alternatives.append(line.replace('128', '120'))
                if 'getelementptr' in line and line.endswith(', i64 1'):
                    alternatives.append(line[:-1] + '2')
                if '9enumerate' in name and re.fullmatch(r'store i64 0, ptr %\S+, align 8', line):
                    alternatives.append(line.replace('i64 0', 'i64 1'))
                for alternative in alternatives:
                    assert alternative != line
                    new = lines[:index] + ([alternative] if alternative else []) + lines[index + 1:]
                    yield name + '/' + label + '/' + line + ' -> ' + alternative, changed(case, body, replace_block(body, label, new))


def main(record):
    counts, controls = [], 0
    for case in check.limit.begin.guard.final.cases(record):
        counts.append(rejects(lambda value: check.inspect(value, False), case, mutants(case)))
        _, names, selected, _, _ = check.closure(case)
        body = selected[names['counter']]
        for replacement in (re.sub(r'^\s*#dbg_.*\n', '', body, flags=re.M), re.sub(r'%value\b', '%accumulator', body)):
            assert replacement != body
            assert check.inspect(changed(case, body, replacement), False)[0] == 85
            controls += 1
        print('Debug counter-decoder mutation count: ' + str(counts[-1]), flush=True)
    assert len(counts) == 16 and min(counts) > 40 and controls == 32
    print(f'Debug counter decoding rejects {sum(counts)} byte/iterator/arithmetic/ABI-closure regressions; {controls} metadata/SSA controls PASS')
    print('Per-path counts: ' + repr(counts))
    print('Subprocess execution forbidden; no compiler/native recapture or register/spill erasure claim')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
