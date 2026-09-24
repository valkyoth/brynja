#!/usr/bin/env python3
"""Retained initializer clearing, descriptor and failure-mapping regressions."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_output_begin as check
from test_debug_portable_final_bridge import changed
from test_kmac_optimized_cleanup import replace_block
from test_kmac_verify_comparisons import rejects


def mutants(case):
    _, names, selected, _ = check.closure(case)
    _, visited, _, _ = check.inspect(case, False)
    for name, body in selected.items():
        if name in (names['begin'], names['core_begin']):
            yield 'short initializer ABI', changed(case, body, body.replace('sret([32 x i8])', 'sret([24 x i8])', 1))
            pointer = '%destination.0' if name == names['begin'] else '%region.0'
            yield 'direct payload read', changed(case, body, body.replace('start:',
                'start:\n  %disclose = load i8, ptr ' + pointer + ', align 1', 1))
        for label, lines in check.model.blocks(body).items():
            if (name, label) not in visited:
                continue
            for index, line in enumerate(lines):
                alternatives = []
                symbol = re.search(check.comparison.SYMBOL, line)
                if symbol and re.search(r'\bcall ', line):
                    alternatives.append('')
                    if symbol[1] in (names['core_begin'], names['clear'], names['wipe']):
                        alternatives.append(line + '\n' + line)
                        args = check.comparison.arguments(line, symbol.end())
                        pointer_index = 1 if symbol[1] == names['core_begin'] else 0
                        alternatives.append(line.replace(args[pointer_index], 'ptr null'))
                        alternatives.append(line.replace(args[-1], 'i64 0'))
                    if 'llvm.memcpy' in symbol[1]:
                        alternatives.append(re.sub(r'i64 (24|32)', 'i64 16', line))
                if match := re.fullmatch(r'br i1 (\S+), label %(\S+), label %(\S+)', line):
                    alternatives.append(f'br i1 {match[1]}, label %{match[3]}, label %{match[2]}')
                if match := re.search(r'icmp (eq|ne) ', line):
                    alternatives.append(line.replace(match[0], 'icmp ' + ('ne' if match[1] == 'eq' else 'eq') + ' '))
                # The start block also stores through GEP aliases into unused
                # dbg.spill allocations. Mutate the real success descriptor.
                if name == names['core_begin'] and label == 'bb4' and line.startswith('store ') and '.dbg.spill' not in line:
                    if match := re.fullmatch(r'store (ptr|i64) (%\S+|0), ptr %\S+, align \d+', line):
                        value = 'null' if match[1] == 'ptr' else '1' if match[2] == '0' else '0'
                        alternatives.append(line.replace('store ' + match[1] + ' ' + match[2] + ',',
                                                         'store ' + match[1] + ' ' + value + ',', 1))
                if 'from_residual' in name and line.startswith('store i8 %residual,') and '.dbg.spill' not in line:
                    alternatives.append(line.replace('store i8 %residual,', 'store i8 0,'))
                if '4from' in name and line == 'ret i8 4':
                    alternatives.append('ret i8 0')
                if name in (names['begin'], names['core_begin']) and re.fullmatch(r'store (i8|i64) [012], ptr %_0, align 8', line):
                    match = re.match(r'store (i8|i64) ([012]),', line)
                    value = str((int(match[2]) + 1) % 3)
                    alternatives.append(line.replace('store ' + match[1] + ' ' + match[2] + ',', 'store ' + match[1] + ' ' + value + ','))
                for alternative in alternatives:
                    assert alternative != line
                    new = lines[:index] + ([alternative] if alternative else []) + lines[index + 1:]
                    yield name + '/' + label + '/' + line + ' -> ' + alternative, changed(case, body, replace_block(body, label, new))
    core = check.comparison.definitions(case.core)
    wipe = core[names['wipe']]
    yield 'wrong volatile ABI', changed(case, wipe, wipe.replace('ptr ', 'ptr byval([8 x i8]) ', 1))


def main(record):
    counts, controls = [], 0
    for case in check.guard.final.cases(record):
        counts.append(rejects(lambda value: check.inspect(value, False), case, mutants(case)))
        _, names, selected, _ = check.closure(case)
        body = selected[names['begin']]
        for control in (re.sub(r'^\s*#dbg_.*\n', '', body, flags=re.M), re.sub(r'%_6\b', '%initial_region', body)):
            assert control != body
            assert check.inspect(changed(case, body, control), False)[0] == 68
            controls += 1
        print('Debug initializer mutation count: ' + str(counts[-1]), flush=True)
    assert len(counts) == 16 and controls == 32 and all(count > 40 for count in counts)
    print(f'Debug initializers reject {sum(counts)} clearing/descriptor/failure/ABI mutations; {controls} metadata/SSA controls PASS')
    print('Per-path counts: ' + repr(counts))
    print('Actual initializer and composed guards; retained artifact/model tests only; subprocess execution forbidden')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
