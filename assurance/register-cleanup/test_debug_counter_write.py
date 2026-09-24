#!/usr/bin/env python3
"""Mutate actual writer/iterator/narrowing bodies without compiler execution."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_counter_write as check
from test_debug_portable_final_bridge import changed
from test_kmac_optimized_cleanup import replace_block
from test_kmac_verify_comparisons import rejects


def mutants(case):
    names, selected, _ = check.closure(case)
    _, _, decoded, _, _ = check.decode.closure(case)
    _, _, _, visited = check.inspect(case, False)
    for name, body in selected.items():
        if name in decoded:
            continue  # Unchanged conversion/shift helpers retain decoder mutation coverage.
        yield 'missing writer dependency: ' + name, changed(case, body, '')
        if name == names['writer']:
            yield 'by-value destination', changed(case, body, body.replace('ptr ', 'ptr byval([16 x i8]) ', 1))
            yield 'truncated counter value', changed(case, body, body.replace('i128 %value)', 'i64 %value)', 1))
        graph = check.model.blocks(body)
        for label, lines in graph.items():
            if (name, label) not in visited:
                continue
            for index, line in enumerate(lines):
                alternatives = []
                symbol = re.search(check.comparison.SYMBOL, line)
                if symbol and 'call ' in line:
                    alternatives.append('')
                    if name == names['writer'] and 'i64 16' in line:
                        alternatives += [line.replace('i64 16', 'i64 ' + str(length)) for length in (15, 17)]
                if found := re.fullmatch(r'br i1 (\S+), label %(\S+), label %(\S+)', line):
                    if graph[found[2]] != ['br label %' + found[3]] and graph[found[3]] != ['br label %' + found[2]]:
                        alternatives.append(f'br i1 {found[1]}, label %{found[3]}, label %{found[2]}')
                if name == names['writer']:
                    if 'lshr i128' in line:
                        alternatives.append(line.replace('lshr i128', 'shl i128'))
                    if re.fullmatch(r'store i8 %\S+, ptr %byte, align 1', line):
                        alternatives += ['', line + '\n' + line, re.sub(r'i8 %\S+,', 'i8 0,', line)]
                    if 'and i128' in line and line.endswith(', 255'):
                        alternatives.append(line[:-3] + '127')
                    if 'and i32 %shift, 127' in line:
                        alternatives.append(line.replace('127', '63'))
                    if 'icmp ult i32 %shift, 128' in line:
                        alternatives.append(line.replace('128', '120'))
                if 'getelementptr' in line and line.endswith(', i64 1') and 'IterMut' in name and '4next' in name:
                    alternatives.append(line[:-1] + '2')
                if '9enumerate' in name and re.fullmatch(r'store i64 0, ptr %\S+, align 8', line):
                    alternatives.append(line.replace('i64 0', 'i64 1'))
                for alternative in alternatives:
                    assert alternative != line
                    new = lines[:index] + ([alternative] if alternative else []) + lines[index + 1:]
                    yield name + '/' + label + '/' + line + ' -> ' + alternative, changed(case, body, replace_block(body, label, new))


def main(record):
    counts, controls = [], 0
    for case in check.decode.limit.begin.guard.final.cases(record):
        counts.append(rejects(lambda value: check.inspect(value, False), case, mutants(case)))
        names, selected, _ = check.closure(case)
        body = selected[names['writer']]
        for replacement in (re.sub(r'^\s*#dbg_.*\n', '', body, flags=re.M), re.sub(r'%value\b', '%counter_value', body)):
            assert replacement != body
            # Header parameter names are bound by the writer ABI, so rename the
            # declaration back while preserving the original SSA identity.
            if '%counter_value' in replacement:
                replacement = re.sub(r'%counter_value\b', '%value', replacement)
                replacement = re.sub(r'%shift\b', '%byte_offset', replacement)
            assert check.inspect(changed(case, body, replacement), False)[0] == 50
            controls += 1
        print('Debug counter-writer mutation count: ' + str(counts[-1]), flush=True)
    assert len(counts) == 16 and min(counts) > 25 and controls == 32
    print(f'Debug counter writing rejects {sum(counts)} store/order/arithmetic/iterator/ABI regressions; {controls} metadata/SSA controls PASS')
    print('Per-path counts: ' + repr(counts))
    print('Subprocess execution forbidden; squeeze scheduling and scalar/spill erasure remain unqualified')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
