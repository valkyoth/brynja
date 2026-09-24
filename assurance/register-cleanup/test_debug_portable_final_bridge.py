#!/usr/bin/env python3
"""Mutation tests for retained portable final-reader ownership and cleanup."""
import argparse
from dataclasses import replace
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_portable_final_bridge as check
from test_kmac_optimized_cleanup import replace_block
from test_kmac_verify_comparisons import rejects


def changed(case, body, replacement):
    assert body != replacement
    fields = {key: getattr(case, key).replace(body, replacement)
              for key in ('kmac', 'sha3', 'core', 'hash_core') if body in getattr(case, key)}
    assert fields
    return replace(case, **fields)


def mutants(case):
    producer, wipe, _, selected = check.closure(case)
    _, constructor_functions = check.constructor.closure(check.constructor.Case(case.sha3, case.hash_core))
    _, visited, _ = check.inspect(case, False)
    for name, body in selected.items():
        if name in constructor_functions:
            continue  # Its standalone suite already mutates all constructor paths.
        if name == case.root:
            yield 'short result ABI', changed(case, body, body.replace('sret([24 x i8])', 'sret([16 x i8])', 1))
            yield 'wrong active ABI', changed(case, body, body.replace('i1 zeroext %self.1', 'i8 %self.1', 1))
            for pointer in ('%output.0', '%self.0'):
                yield 'direct payload/owner load', changed(case, body, body.replace('start:',
                    'start:\n  %disclose = load i8, ptr ' + pointer + ', align 1', 1))
        for label, lines in check.model.blocks(body).items():
            if (name, label) not in visited:
                continue
            for index, line in enumerate(lines):
                alternatives = []
                symbol = re.search(check.comparison.SYMBOL, line)
                if symbol and re.search(r'\b(?:call|invoke) ', line):
                    if line.startswith('call void ') and 'panic_in_cleanup' not in line:
                        alternatives.append('')
                        if any(token in symbol[1] for token in ('drop_in_place', '4drop', '4wipe', 'clear_owned_region')) or symbol[1] == wipe:
                            alternatives.append(line + '\n' + line)
                    if line.startswith('invoke void '):
                        edge_line = lines[index + 1]
                        edge = re.fullmatch(r'to label %(\S+) unwind label %(\S+)', edge_line)
                        assert edge
                        new = lines[:index] + ['br label %' + edge[1]] + lines[index + 2:]
                        yield 'skipped invoked handoff/helper: ' + name, changed(case, body, replace_block(body, label, new))
                    if symbol[1] == producer:
                        for old, new in (('i1 zeroext true', 'i1 zeroext false'), ('i8 %valid', 'i8 0'),
                                         ('i64 %destination.1', 'i64 0')):
                            assert old in line
                            alternatives.append(line.replace(old, new))
                        new = lines[:index + 1] + [edge_line.replace('unwind label %' + edge[2], 'unwind label %' + edge[1])] + lines[index + 2:]
                        yield 'producer unwind bypasses destructor', changed(case, body, replace_block(body, label, new))
                    if symbol[1] == wipe:
                        args = check.comparison.arguments(line, symbol.end())
                        alternatives += [line.replace(args[0], 'ptr null'), line.replace(args[1], 'i64 1')]
                    if 'llvm.memcpy' in symbol[1]:
                        alternatives.append(re.sub(r'i64 (24|32)', 'i64 16', line))
                if match := re.fullmatch(r'br i1 (\S+), label %(\S+), label %(\S+)', line):
                    alternatives.append(f'br i1 {match[1]}, label %{match[3]}, label %{match[2]}')
                if '4wipe' in name and (match := re.search(r'getelementptr inbounds(?: nuw)? i8, ptr %self, i64 (\d+)', line)):
                    alternatives.append(line[:match.start(1)] + str(int(match[1]) + 1) + line[match.end(1):])
                if line.startswith('resume { ptr, i32 }'):
                    alternatives.append('ret void')
                if re.search(r'insertvalue \{ ptr, i32 } .*?, ptr %\S+, 0', line):
                    alternatives.append(re.sub(r', ptr %\S+, 0', ', ptr null, 0', line))
                if re.search(r'insertvalue \{ ptr, i32 } .*?, i32 %\S+, 1', line):
                    alternatives.append(re.sub(r', i32 %\S+, 1', ', i32 0, 1', line))
                if '10into_parts' in name and re.match(r'store (ptr|i64|i8) %', line) and '.dbg.spill' not in line:
                    alternatives.append(re.sub(r'^(store (?:ptr|i\d+)) %\S+,', r'\1 0,', line).replace('store ptr 0,', 'store ptr null,'))
                for alternative in alternatives:
                    assert alternative != line
                    new = lines[:index] + ([alternative] if alternative else []) + lines[index + 1:]
                    yield name + '/' + label + '/' + line + ' -> ' + alternative, changed(case, body, replace_block(body, label, new))
    for field, symbol in (('sha3', producer), ('core', wipe)):
        text = getattr(case, field)
        definition = check.comparison.definitions(text)[symbol]
        yield 'missing actual boundary', replace(case, **{field: text.replace(definition, '')})
        yield 'by-value boundary', changed(case, definition, definition.replace('ptr ', 'ptr byval([8 x i8]) ', 1))


def main(record):
    counts, controls = [], 0
    for case in check.cases(record):
        counts.append(rejects(lambda value: check.inspect(value, False), case, mutants(case)))
        root = check.comparison.definitions(case.kmac)[case.root]
        for control in (re.sub(r'^\s*#dbg_.*\n', '', root, flags=re.M), re.sub(r'%_12\b', '%drop_guard', root)):
            assert control != root
            assert check.inspect(changed(case, root, control), False)[0] == 72
            controls += 1
        print('Portable final path mutation count: ' + str(counts[-1]), flush=True)
    assert len(counts) == 16 and controls == 32 and all(count > 50 for count in counts)
    print(f'Portable final bridges reject {sum(counts)} ownership/cleanup/result/unwind mutations; {controls} metadata/SSA controls PASS')
    print('Per-path counts: ' + repr(counts))
    print('Retained artifact modeling only; producer/volatile bodies opaque; subprocess execution forbidden')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
