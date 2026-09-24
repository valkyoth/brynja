#!/usr/bin/env python3
"""Mutate actual output-limit arithmetic, counter selection and result mapping."""
import argparse
from dataclasses import replace
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_output_limit as check
from test_debug_portable_final_bridge import changed
from test_kmac_optimized_cleanup import replace_block
from test_kmac_verify_comparisons import rejects


def mutants(case):
    _, names, selected, _ = check.closure(case)
    for name, body in selected.items():
        if name == names['empty_check']:
            yield 'direct owner bytes', changed(case, body, body.replace('start:',
                'start:\n  %disclose = load i8, ptr %self, align 1', 1))
        for label, lines in check.model.blocks(body).items():
            for index, line in enumerate(lines):
                alternatives = []
                symbol = re.search(check.comparison.SYMBOL, line)
                if symbol and 'call ' in line:
                    alternatives.append('')
                    if symbol[1] in (names['addition'], 'llvm.uadd.with.overflow.i128'):
                        args = check.comparison.arguments(line, symbol.end())
                        alternatives += [line.replace(arg, 'i128 0') for arg in args if arg.startswith('i128 %')]
                    if symbol[1] == names['counter']:
                        alternatives += [line + '\n' + line, line.replace('ptr align 1 %_2', 'ptr align 1 %self')]
                if match := re.fullmatch(r'br i1 (\S+), label %(\S+), label %(\S+)', line):
                    alternatives.append(f'br i1 {match[1]}, label %{match[3]}, label %{match[2]}')
                if '12output_bytes' in name and 'getelementptr' in line and 'ptr %self, i64 16' in line:
                    alternatives.append(line.replace('ptr %self, i64 16', 'ptr %self, i64 0'))
                if re.fullmatch(r'store (i8|i128) [01], ptr %_0, align (1|16)', line):
                    match = re.match(r'store (i8|i128) ([01]),', line)
                    alternatives.append(line.replace('store ' + match[1] + ' ' + match[2] + ',',
                                                     'store ' + match[1] + ' ' + str(1 - int(match[2])) + ','))
                if name == names['addition'] and 'add nuw i128' in line:
                    alternatives.append(line.replace('add nuw i128', 'sub nuw i128'))
                for alternative in alternatives:
                    if alternative == line:
                        continue
                    new = lines[:index] + ([alternative] if alternative else []) + lines[index + 1:]
                    yield name + '/' + label + '/' + line + ' -> ' + alternative, changed(case, body, replace_block(body, label, new))
    definitions = check.comparison.definitions(case.sha3)
    body = definitions[names['counter']]
    yield 'missing decoder', replace(case, sha3=case.sha3.replace(body, ''))
    yield 'by-value decoder', changed(case, body, body.replace('ptr ', 'ptr byval([16 x i8]) ', 1))
    yield 'truncated counter ABI', changed(case, body, body.replace('define i128 @', 'define i64 @', 1))


def main(record):
    counts, controls = [], 0
    for case in check.begin.guard.final.cases(record):
        counts.append(rejects(lambda value: check.inspect(value, False), case, mutants(case)))
        _, names, selected, _ = check.closure(case)
        body = selected[names['empty_check']]
        for control in (re.sub(r'^\s*#dbg_.*\n', '', body, flags=re.M), re.sub(r'%additional\b', '%extra_output', body)):
            assert control != body
            assert check.inspect(changed(case, body, control), False)[0] == 108
            controls += 1
        print('Debug output-limit mutation count: ' + str(counts[-1]), flush=True)
    assert len(counts) == 16 and all(count > 20 for count in counts) and controls == 32
    print(f'Debug output limits reject {sum(counts)} arithmetic/counter/mapping/ABI mutations; {controls} metadata/SSA controls PASS')
    print('Per-path counts: ' + repr(counts))
    print('Retained artifact checks only; subprocess execution forbidden; decoder/volatile bodies remain opaque')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
