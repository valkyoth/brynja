#!/usr/bin/env python3
"""Mutate retained byte-squeeze scheduling without compiling or running Rust."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_squeeze_operation as check
from test_debug_portable_final_bridge import changed
from test_kmac_optimized_cleanup import replace_block
from test_kmac_verify_comparisons import rejects


def mutants(case):
    names, selected, _ = check.closure(case)
    previous = check.counter.closure(case)[2]
    for name, body in selected.items():
        if name not in previous:
            yield 'missing actual squeeze helper: ' + name, changed(case, body, '')
    root = names['squeeze']
    body = selected[root]
    yield 'by-value owner', changed(case, body, body.replace('(ptr ', '(ptr byval([1040 x i8]) ', 1))
    other_rate = 136 if names['rate'] == 168 else 168
    yield 'wrong rate for reader identity', changed(case, body, body.replace(', i64 ' + str(names['rate']) + ')', ', i64 ' + str(other_rate) + ')', 1))
    graph = check.model.blocks(body)
    for label, lines in graph.items():
        for index, line in enumerate(lines):
            alternatives = []
            if 'call ' in line:
                symbol = re.search(check.comparison.SYMBOL, line)
                if symbol and symbol[1] in (names['writer'], names['fill'], names['output_write'], names['clear']):
                    alternatives.append('')
                if symbol and symbol[1] == names['clear']:
                    alternatives += [line.replace('i64 168', 'i64 167'), line + '\n' + re.sub(r'^%\S+ = ', '', line)]
                if symbol and symbol[1] == names['fill']:
                    alternatives.append(line.replace('i64 %count', 'i64 0'))
                    alternatives.append('%early = getelementptr inbounds i8, ptr %self, i64 16\n'
                                        + 'call void @' + names['writer'] + '(ptr align 1 %early, i128 %new_length)\n' + line)
                if symbol and symbol[1] == 'llvm.usub.sat.i64':
                    alternatives.append(re.sub(r'\(i64 (\S+), i64 (\S+)\)', r'(i64 \2, i64 \1)', line))
            if found := re.fullmatch(r'br i1 (\S+), label %(\S+), label %(\S+)', line):
                alternatives.append(f'br i1 {found[1]}, label %{found[3]}, label %{found[2]}')
            if 'getelementptr' in line and line.endswith(', i64 584'):
                alternatives.append(line[:-3] + '585')
            for alternative in alternatives:
                assert alternative != line
                new = lines[:index] + ([alternative] if alternative else []) + lines[index + 1:]
                yield label + '/' + line + ' -> ' + alternative, changed(case, body, replace_block(body, label, new))
        writes = [index for index, line in enumerate(lines) if '@' + names['output_write'] + '(' in line]
        clears = [index for index, line in enumerate(lines) if '@' + names['clear'] + '(' in line]
        if writes and clears:
            assert len(writes) == len(clears) == 1 and writes[0] < clears[0]
            index = clears[0]
            assert 'getelementptr' in lines[index - 1] and lines[index - 1].endswith(', i64 584')
            early = lines[index - 1:index + 1]
            rest = lines[:index - 1] + lines[index + 1:]
            reordered = rest[:writes[0]] + early + rest[writes[0]:]
            yield 'clear staging before copying output', changed(case, body, replace_block(body, label, reordered))


def main(record):
    counts, controls = [], 0
    for case in check.begin.guard.final.cases(record):
        counts.append(rejects(lambda value: check.inspect(value, False), case, mutants(case)))
        names, selected, _ = check.closure(case)
        body = selected[names['squeeze']]
        for replacement in (re.sub(r'^\s*#dbg_.*\n', '', body, flags=re.M),
                            re.sub(r'%remaining\b', '%remaining_bytes', body)):
            assert replacement != body
            check.inspect(changed(case, body, replacement), False)
            controls += 1
        print('Debug squeeze mutation count: ' + str(counts[-1]), flush=True)
    assert len(counts) == 16 and min(counts) >= 40 and controls == 32
    print(f'Debug squeeze rejects {sum(counts)} dependency/ABI/scheduling/cleanup regressions; {controls} controls PASS')
    print('Per-path counts: ' + repr(counts))
    print('Subprocess execution forbidden; fill/copy/volatile semantics and whole-call residue remain outside this model')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
