#!/usr/bin/env python3
"""Mutate retained accelerated debug producer guards; no compiler/runtime calls."""
import argparse
from dataclasses import replace
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_accelerated_guard as check
from test_kmac_optimized_cleanup import replace_block


def changed(case, body, replacement):
    assert body != replacement
    fields = {key: getattr(case, key).replace(body, replacement)
              for key in ('kmac', 'sha3', 'core') if body in getattr(case, key)}
    assert fields
    return replace(case, **fields)


def mutants(case):
    root, names, selected = check.closure(case)
    _, visited, _ = check.inspect(case, False)
    for name, body in selected.items():
        if name in (root, names['guard']):
            yield 'short result ABI', changed(case, body, body.replace('sret([24 x i8])', 'sret([16 x i8])', 1))
            yield 'by-value reader', changed(case, body, body.replace('ptr align 8 %self', 'ptr byval([8 x i8]) align 8 %self', 1))
        if name == root:
            yield 'direct output read', changed(case, body, body.replace('start:',
                'start:\n  %disclose = load i8, ptr %output.0, align 1', 1))
        for label, lines in check.model.blocks(body).items():
            if (name, label) not in visited:
                continue
            for index, line in enumerate(lines):
                alternatives = []
                symbol = re.search(check.comparison.SYMBOL, line)
                if symbol and re.search(r'\b(?:call|invoke) ', line):
                    callee = symbol[1]
                    if line.startswith('call void '):
                        alternatives.append('')
                        if any(token in callee for token in ('drop_in_place', 'drop_glue', '4drop', '5clear', '4wipe')) or callee == names['wipe']:
                            alternatives.append(line + '\n' + line)
                    if 'invoke ' in line:
                        edge = re.fullmatch(r'to label %(\S+) unwind label %(\S+)', lines[index + 1])
                        assert edge
                        yield 'omitted invoked helper', changed(case, body,
                            replace_block(body, label, lines[:index] + ['br label %' + edge[1]] + lines[index + 2:]))
                        if callee in (names['operation'], names['predicate']):
                            yield 'unwind bypasses cleanup', changed(case, body, replace_block(body, label,
                                lines[:index + 1] + [lines[index + 1].replace('unwind label %' + edge[2], 'unwind label %' + edge[1])] + lines[index + 2:]))
                    if callee == names['begin']:
                        args = check.comparison.arguments(line, symbol.end())
                        assert len(args) == 3
                        alternatives += [line.replace(args[2], 'i64 0'), line.replace(args[1], 'ptr %self')]
                    if callee == names['operation']:
                        args = check.comparison.arguments(line, symbol.end())
                        alternatives += [line.replace(args[1], 'ptr %self'), line.replace(args[2], 'ptr %self')]
                    if callee == names['wipe']:
                        args = check.comparison.arguments(line, symbol.end())
                        alternatives += [line.replace(args[0], 'ptr null'), line.replace(args[1], 'i64 1')]
                    if 'llvm.memcpy' in callee:
                        alternatives.append(re.sub(r'i64 (24|32|48)', 'i64 16', line))
                if match := re.fullmatch(r'br i1 (\S+), label %(\S+), label %(\S+)', line):
                    alternatives.append(f'br i1 {match[1]}, label %{match[3]}, label %{match[2]}')
                if match := re.search(r'icmp (eq|ne) ', line):
                    alternatives.append(line.replace(match[0], 'icmp ' + ('ne' if match[1] == 'eq' else 'eq') + ' '))
                if name == names['guard'] and re.match(r'store i8 [01], ptr %\d+', line):
                    alternatives.append(line.replace('store i8 0,', 'store i8 1,') if line.startswith('store i8 0,') else line.replace('store i8 1,', 'store i8 0,'))
                if ('5clear' in name or '6cancel' in name or '4wipe' in name) and (match := re.search(r'getelementptr inbounds(?: nuw)? i8, ptr %self, i64 (\d+)', line)):
                    alternatives.append(line[:match.start(1)] + str(int(match[1]) + 1) + line[match.end(1):])
                if line.startswith('resume { ptr, i32 }'):
                    alternatives.append('ret void')
                if re.search(r'insertvalue \{ ptr, i32 } .*?, ptr %\S+, 0', line):
                    alternatives.append(re.sub(r', ptr %\S+, 0', ', ptr null, 0', line))
                if re.search(r'insertvalue \{ ptr, i32 } .*?, i32 %\S+, 1', line):
                    alternatives.append(re.sub(r', i32 %\S+, 1', ', i32 0, 1', line))
                for alternative in alternatives:
                    assert alternative != line
                    yield name + '/' + label + '/' + line, changed(case, body,
                        replace_block(body, label, lines[:index] + ([alternative] if alternative else []) + lines[index + 1:]))
    for field, symbol in (('sha3', names['begin']), ('sha3', names['operation']), ('core', names['wipe'])):
        text = getattr(case, field)
        body = check.comparison.definitions(text)[symbol]
        yield 'missing boundary definition', replace(case, **{field: text.replace(body, '')})
        yield 'by-value boundary', changed(case, body, body.replace('ptr ', 'ptr byval([8 x i8]) ', 1))


def main(record, shard=None):
    before = check.comparison.capture.sources()
    cases = list(check.final.cases(record))
    assert len(cases) == 8 and (shard is None or shard in range(8))
    counts = []
    for case in cases if shard is None else [cases[shard]]:
        check.inspect(case, False)
        count = 0
        for label, mutant in mutants(case):
            try:
                check.inspect(mutant, False)
            except ValueError:
                count += 1
            else:
                raise AssertionError('accepted accelerated guard regression: ' + label)
        root, _, selected = check.closure(case)
        body = selected[root]
        for control in (re.sub(r'^\s*#dbg_.*\n', '', body, flags=re.M), re.sub(r'%_17\b', '%initializer_move_flag', body)):
            assert control != body
            assert check.inspect(changed(case, body, control), False)[0] == 128
        assert count > 75
        counts.append(count)
        print(f'Accelerated debug guard rejects {count} regressions; two metadata/SSA controls PASS', flush=True)
    assert before == check.comparison.capture.sources()
    print('Matrix: ' + ('all 8 paths' if shard is None else f'shard {shard}/8; all eight required'))
    print('Mutation counts: ' + repr(counts))
    print('Compiler/runtime subprocesses forbidden; no whole-call/register/spill/native qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('--shard', type=int, choices=range(8))
    args = parser.parse_args()
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(args.record.resolve(), args.shard)
