#!/usr/bin/env python3
"""Mutation-test actual portable operation handoff, cleanup and finish calls."""
import argparse
from dataclasses import replace
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_producer_operation as check
from test_debug_portable_final_bridge import changed
from test_kmac_optimized_cleanup import replace_block
from test_kmac_verify_comparisons import rejects


def mutants(case):
    _, names, selected, _ = check.closure(case)
    _, _, _, guarded = check.begin.closure(case)
    _, _, completed = check.finish.closure(case)
    _, _, _, visited = check.inspect(case, False)
    for name, body in selected.items():
        if name in guarded or name in completed:
            continue
        if name == names['operation']:
            yield 'wrong result ABI', changed(case, body, body.replace('sret([24 x i8])', 'sret([16 x i8])', 1))
            yield 'direct secret-owner read', changed(case, body, body.replace('start:',
                'start:\n  %disclose = load i8, ptr %owner, align 1', 1))
        for label, lines in check.model.blocks(body).items():
            if (name, label) not in visited:
                continue
            for index, line in enumerate(lines):
                alternatives = []
                symbol = re.search(check.comparison.SYMBOL, line)
                if symbol and re.search(r'\b(?:call|invoke) ', line):
                    if 'invoke ' in line:
                        edge = re.fullmatch(r'to label %(\S+) unwind label %(\S+)', lines[index + 1])
                        assert edge
                        new = lines[:index] + ['br label %' + edge[1]] + lines[index + 2:]
                        yield 'skipped actual helper: ' + name, changed(case, body, replace_block(body, label, new))
                        if symbol[1] in (names['squeeze'], names['final_squeeze'], names['empty_check'], names['finish']):
                            new = lines[:index + 1] + ['to label %' + edge[1] + ' unwind label %' + edge[1]] + lines[index + 2:]
                            yield 'bypassed unwind cleanup', changed(case, body, replace_block(body, label, new))
                    else:
                        alternatives.append('')
                    if symbol[1] in (names['squeeze'], names['final_squeeze'], names['empty_check']):
                        args = check.comparison.arguments(line, symbol.end())
                        for argument in args:
                            if argument.startswith('ptr '):
                                alternatives.append(line.replace(argument, 'ptr null'))
                            elif argument.startswith(('i64 ', 'i8 ')):
                                alternatives.append(line.replace(argument, argument.split()[0] + ' 0'))
                            elif argument == 'i128 0':
                                alternatives.append(line.replace(argument, 'i128 1'))
                    if 'llvm.memcpy' in symbol[1]:
                        alternatives.append(line.replace('i64 32', 'i64 16'))
                if match := re.fullmatch(r'br i1 (\S+), label %(\S+), label %(\S+)', line):
                    alternatives.append(f'br i1 {match[1]}, label %{match[3]}, label %{match[2]}')
                if name == names['operation'] and re.fullmatch(r'store i8 [01], ptr %_30, align 1', line) and not (
                        label == 'start' and line.startswith('store i8 0,')):
                    alternatives.append(line.replace('store i8 0,', 'store i8 1,') if 'i8 0,' in line else line.replace('store i8 1,', 'store i8 0,'))
                if line == 'ret i8 2':
                    alternatives.append('ret i8 0')
                if line.startswith('resume { ptr, i32 }'):
                    alternatives.append('ret void')
                for alternative in alternatives:
                    if alternative == line:
                        continue
                    new = lines[:index] + ([alternative] if alternative else []) + lines[index + 1:]
                    yield name + '/' + label + '/' + line + ' -> ' + alternative, changed(case, body, replace_block(body, label, new))
    definitions = check.comparison.definitions(case.sha3)
    for role in ('squeeze', 'final_squeeze', 'empty_check'):
        body = definitions[names[role]]
        yield 'missing actual ' + role, replace(case, sha3=case.sha3.replace(body, ''))
        yield 'by-value ' + role, changed(case, body, body.replace('ptr ', 'ptr byval([8 x i8]) ', 1))


def main(record):
    counts, controls = [], 0
    for case in check.begin.guard.final.cases(record):
        counts.append(rejects(lambda value: check.inspect(value, False), case, mutants(case)))
        _, names, selected, _ = check.closure(case)
        body = selected[names['operation']]
        for control in (re.sub(r'^\s*#dbg_.*\n', '', body, flags=re.M), re.sub(r'%_25\b', '%completed_owner', body),
                        body.replace('store i8 0, ptr %_30, align 1', 'store i8 1, ptr %_30, align 1', 1)):
            assert control != body
            check.inspect(changed(case, body, control), False)
            controls += 1
        print('Debug operation mutation count: ' + str(counts[-1]), flush=True)
    assert len(counts) == 16 and all(count > 40 for count in counts) and controls == 48
    print(f'Debug operations reject {sum(counts)} dispatch/ownership/cleanup/unwind/ABI mutations; {controls} metadata/SSA/dead-store controls PASS')
    print('Per-path counts: ' + repr(counts))
    print('Retained artifacts only; subprocess execution forbidden; squeeze/check/volatile bodies remain opaque')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
