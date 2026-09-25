#!/usr/bin/env python3
"""Mutate retained accelerated chunk/ownership composition without compiler calls."""
import argparse
from dataclasses import replace
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_accelerated_operation as check
from test_kmac_optimized_cleanup import replace_block


def changed(case, body, replacement):
    assert body != replacement
    fields = {key: getattr(case, key).replace(body, replacement)
              for key in ('kmac', 'sha3', 'core', 'hash_core') if body in getattr(case, key)}
    assert fields
    return replace(case, **fields)


def mutants(case):
    root, names, selected = check.closure(case)
    _, visited, _ = check.inspect(case, False)
    targets = {names[role] for role in ('operation', 'begin', 'finish', 'write')}
    for name in sorted(targets):
        body = selected[name]
        if name == names['operation']:
            yield 'short operation result ABI', changed(case, body, body.replace('sret([24 x i8])', 'sret([16 x i8])', 1))
            yield 'direct storage payload read', changed(case, body, body.replace('start:',
                'start:\n  %disclose = load i8, ptr %storage, align 1', 1))
        graph = check.model.blocks(body)
        instructions = '\n'.join(line for lines in graph.values() for line in lines)
        for label, lines in graph.items():
            if (name, label) not in visited:
                continue
            for index, line in enumerate(lines):
                alternatives = []
                symbol = re.search(check.comparison.SYMBOL, line)
                if symbol and re.search(r'\b(?:call|invoke) ', line):
                    if 'invoke ' in line:
                        edge = re.fullmatch(r'to label %(\S+) unwind label %(\S+)', lines[index + 1])
                        assert edge
                        yield 'omitted helper: ' + line, changed(case, body,
                            replace_block(body, label, lines[:index] + ['br label %' + edge[1]] + lines[index + 2:]))
                        if symbol[1] in {names[key] for key in ('preflight', 'read', 'mask', 'write', 'finish')}:
                            yield 'unwind cleanup bypass: ' + line, changed(case, body,
                                replace_block(body, label, lines[:index + 1]
                                              + [lines[index + 1].replace('unwind label %' + edge[2], 'unwind label %' + edge[1])]
                                              + lines[index + 2:]))
                    else:
                        alternatives.append('')
                    if symbol[1] in {names[key] for key in ('preflight', 'read', 'mask', 'write', 'clear', 'slice', 'finish')}:
                        args = check.comparison.arguments(line, symbol.end())
                        for arg in args:
                            if arg.startswith('ptr ') and 'sret(' not in arg:
                                alternatives.append(line.replace(arg, 'ptr null'))
                            elif arg.startswith(('i64 ', 'i8 ')):
                                alternatives.append(line.replace(arg, arg.split()[0] + (' 1' if arg.endswith(' 0') else ' 0')))
                    if 'llvm.memcpy' in symbol[1]:
                        alternatives.append(re.sub(r'i64 (24|32)', 'i64 16', line))
                if match := re.fullmatch(r'br i1 (\S+), label %(\S+), label %(\S+)', line):
                    alternatives.append(f'br i1 {match[1]}, label %{match[3]}, label %{match[2]}')
                if match := re.search(r'icmp (eq|ne) ', line):
                    alternatives.append(line.replace(match[0], 'icmp ' + ('ne' if match[1] == 'eq' else 'eq') + ' '))
                if name == names['operation'] and 'getelementptr' in line and 'i64 864' in line:
                    # The compiler also computes an unused staging address to
                    # obtain its constant array length. It is not a data path.
                    destination = line.split(' = ', 1)[0]
                    if len(re.findall(re.escape(destination) + r'(?![-.$\w])', instructions)) > 1:
                        alternatives.append(line.replace('i64 864', 'i64 865'))
                if line.startswith('resume { ptr, i32 }'):
                    alternatives.append('ret void')
                if line.startswith('%') and 'phi { ptr, i32 }' in line:
                    match = re.search(r'\[ (%\S+), %\S+ \], \[ (%\S+), %\S+ \]', line)
                    assert match
                    alternatives.append(line.replace(match[1] + ',', match[2] + ',', 1))
                for alternative in alternatives:
                    assert alternative != line, line
                    yield name + '/' + label + '/' + line, changed(case, body,
                        replace_block(body, label, lines[:index] + ([alternative] if alternative else []) + lines[index + 1:]))
    for role in ('preflight', 'read', 'mask', 'copy'):
        for key in ('sha3', 'core'):
            definitions = check.comparison.definitions(getattr(case, key))
            if names[role] not in definitions:
                continue
            body = definitions[names[role]]
            yield 'missing boundary: ' + role, replace(case, **{key: getattr(case, key).replace(body, '')})
            yield 'by-value boundary: ' + role, changed(case, body, body.replace('ptr ', 'ptr byval([8 x i8]) ', 1))


def main(record, shard):
    before = check.comparison.capture.sources()
    cases = list(check.cases(record))
    assert len(cases) == 8
    for case in cases if shard is None else [cases[shard]]:
        count = 0
        for label, mutant in mutants(case):
            try:
                check.inspect(mutant, False)
            except ValueError:
                count += 1
            else:
                raise AssertionError('accepted accelerated operation regression: ' + label)
        _, names, selected = check.closure(case)
        body = selected[names['operation']]
        graph = check.model.blocks(body)
        instructions = '\n'.join(line for lines in graph.values() for line in lines)
        unused = [line for lines in graph.values() for line in lines if 'getelementptr' in line and 'i64 864' in line
                  and len(re.findall(re.escape(line.split(' = ', 1)[0]) + r'(?![-.$\w])', instructions)) == 1]
        assert len(unused) == 1
        for control in (re.sub(r'^\s*#dbg_.*\n', '', body, flags=re.M), re.sub(r'%remaining\b', '%remaining_bytes', body),
                        body.replace(unused[0], unused[0].replace('i64 864', 'i64 865'))):
            assert body != control
            assert check.inspect(changed(case, body, control), False)[0] == 343
        assert count > 80
        print(f'Accelerated debug operation rejects {count} regressions; three metadata/SSA/dead-address controls PASS', flush=True)
    assert before == check.comparison.capture.sources()
    print('Matrix: ' + ('all 8 paths' if shard is None else f'shard {shard}/8; all eight required'))
    print('Compiler/runtime subprocesses forbidden; opaque engine/primitive boundaries; no whole-call erasure claim')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('--shard', type=int, choices=range(8))
    args = parser.parse_args()
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(args.record.resolve(), args.shard)
