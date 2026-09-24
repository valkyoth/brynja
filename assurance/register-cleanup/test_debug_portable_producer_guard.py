#!/usr/bin/env python3
"""Mutate actual retained producer handoff/guard/drop paths without compilation."""
import argparse
from dataclasses import replace
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_portable_producer_guard as check
from test_debug_portable_final_bridge import changed
from test_kmac_optimized_cleanup import replace_block
from test_kmac_verify_comparisons import rejects


def mutants(case):
    root, names, selected = check.closure(case)
    _, visited, _ = check.inspect(case, False)
    for name, body in selected.items():
        if name == root or ('Borrowed' in name and '3run' in name):
            yield 'short result ABI', changed(case, body, body.replace('sret([24 x i8])', 'sret([16 x i8])', 1))
            yield 'by-value reader', changed(case, body, body.replace('ptr align 8 %self', 'ptr byval([16 x i8]) align 8 %self', 1))
        if name == root:
            yield 'direct destination read', changed(case, body, body.replace('start:',
                'start:\n  %disclose = load i8, ptr %destination.0, align 1', 1))
        for label, lines in check.model.blocks(body).items():
            if (name, label) not in visited:
                continue
            for index, line in enumerate(lines):
                alternatives = []
                symbol = re.search(check.comparison.SYMBOL, line)
                if symbol and re.search(r'\b(?:call|invoke) ', line):
                    if line.startswith('call void '):
                        alternatives.append('')
                        if any(token in symbol[1] for token in ('drop_in_place', 'drop_glue', '4drop', '4wipe', 'clear_owned_region')) or symbol[1] == names['wipe']:
                            alternatives.append(line + '\n' + line)
                    if 'invoke ' in line:
                        edge_line = lines[index + 1]
                        edge = re.fullmatch(r'to label %(\S+) unwind label %(\S+)', edge_line)
                        assert edge
                        replacement = lines[:index] + ['br label %' + edge[1]] + lines[index + 2:]
                        yield 'skipped invoked helper: ' + name, changed(case, body, replace_block(body, label, replacement))
                        if symbol[1] in (names['operation'], names['predicate']):
                            replacement = lines[:index + 1] + [edge_line.replace('unwind label %' + edge[2], 'unwind label %' + edge[1])] + lines[index + 2:]
                            yield 'unwind bypasses cleanup', changed(case, body, replace_block(body, label, replacement))
                    if symbol[1] == names['begin']:
                        alternatives += [line.replace('i64 %destination.1', 'i64 0'),
                                         re.sub(r'ptr(?: align 1)? %destination.0', 'ptr %self', line)]
                    if symbol[1] == names['operation']:
                        args = check.comparison.arguments(line, symbol.end())
                        alternatives += [line.replace(args[1], 'ptr %self'), line.replace(args[2], 'ptr %self')]
                    if symbol[1] == names['wipe']:
                        args = check.comparison.arguments(line, symbol.end())
                        alternatives += [line.replace(args[0], 'ptr null'), line.replace(args[1], 'i64 1')]
                    if 'llvm.memcpy' in symbol[1]:
                        alternatives.append(re.sub(r'i64 (24|32|48)', 'i64 16', line))
                if match := re.fullmatch(r'br i1 (\S+), label %(\S+), label %(\S+)', line):
                    alternatives.append(f'br i1 {match[1]}, label %{match[3]}, label %{match[2]}')
                if match := re.search(r'icmp (eq|ne) ', line):
                    alternatives.append(line.replace(match[0], 'icmp ' + ('ne' if match[1] == 'eq' else 'eq') + ' '))
                if ('4wipe' in name or '10into_parts' in name) and (match := re.search(r'getelementptr inbounds(?: nuw)? i8, ptr %self, i64 (\d+)', line)):
                    alternatives.append(line[:match.start(1)] + str(int(match[1]) + 1) + line[match.end(1):])
                if 'Borrowed' in name and '3run' in name and re.match(r'store i8 [01], ptr %\d+', line):
                    alternatives.append(line.replace('store i8 0,', 'store i8 1,') if line.startswith('store i8 0,') else line.replace('store i8 1,', 'store i8 0,'))
                if name == root and label == 'bb4' and re.fullmatch(r'store ptr %\S+, ptr %\S+, align 8', line):
                    alternatives.append(re.sub(r'store ptr %\S+,', 'store ptr null,', line))
                if line.startswith('resume { ptr, i32 }'):
                    alternatives.append('ret void')
                if re.search(r'insertvalue \{ ptr, i32 } .*?, ptr %\S+, 0', line):
                    alternatives.append(re.sub(r', ptr %\S+, 0', ', ptr null, 0', line))
                if re.search(r'insertvalue \{ ptr, i32 } .*?, i32 %\S+, 1', line):
                    alternatives.append(re.sub(r', i32 %\S+, 1', ', i32 0, 1', line))
                for alternative in alternatives:
                    assert alternative != line
                    replacement = lines[:index] + ([alternative] if alternative else []) + lines[index + 1:]
                    yield name + '/' + label + '/' + line + ' -> ' + alternative, changed(case, body, replace_block(body, label, replacement))
    for field, symbol in (('sha3', names['begin']), ('sha3', names['operation']), ('core', names['wipe'])):
        text = getattr(case, field)
        definition = check.comparison.definitions(text)[symbol]
        yield 'missing defined opaque boundary', replace(case, **{field: text.replace(definition, '')})
        yield 'by-value opaque boundary', changed(case, definition, definition.replace('ptr ', 'ptr byval([8 x i8]) ', 1))


def main(record):
    counts, controls = [], 0
    for case in check.final.cases(record):
        counts.append(rejects(lambda value: check.inspect(value, False), case, mutants(case)))
        root, _, selected = check.closure(case)
        body = selected[root]
        for control in (re.sub(r'^\s*#dbg_.*\n', '', body, flags=re.M), re.sub(r'%_16\b', '%initializer_guard', body)):
            assert control != body
            assert check.inspect(changed(case, body, control), False)[0] == 96
            controls += 1
        print('Portable producer guard mutation count: ' + str(counts[-1]), flush=True)
    assert len(counts) == 16 and controls == 32 and all(count > 75 for count in counts)
    print(f'Portable producer guards reject {sum(counts)} handoff/lifecycle/cleanup/unwind mutations; {controls} metadata/SSA controls PASS')
    print('Per-path counts: ' + repr(counts))
    print('Retained artifact/model tests only; subprocess execution forbidden')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
