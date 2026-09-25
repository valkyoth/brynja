#!/usr/bin/env python3
"""Mutate actual preflight state/authority/counter bodies and composed cleanup."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_accelerated_preflight as check
from test_debug_portable_final_bridge import changed
from test_kmac_optimized_cleanup import replace_block


def mutants(case):
    _, _, names, selected, _ = check.closure(case, False)
    _, _, _, _, visited = check.inspect(case, False, False)
    for name, body in selected.items():
        yield 'missing dependency ' + name, changed(case, body, '')
        graph = check.model.blocks(body)
        for label, lines in graph.items():
            if (name, label) not in visited:
                continue
            for index, line in enumerate(lines):
                alternatives = []
                symbol = re.search(check.comparison.SYMBOL, line)
                if symbol and 'call ' in line:
                    if not (line.startswith('call void ') and '9preflight' in symbol[1]):
                        alternatives.append('')
                    if symbol[1] == names['session']:
                        alternatives.append(line + '\n' + line)
                        alternatives.append(re.sub(r'ptr align 32 %self', 'ptr null', line))
                    if name == names['counter'] and 'i64 16' in line:
                        alternatives += [line.replace('i64 16', 'i64 ' + str(n)) for n in (15, 17)]
                    if 'i1 zeroext true' in line and name == names['preflight']:
                        alternatives.append(line.replace('i1 zeroext true', 'i1 zeroext false'))
                if found := re.fullmatch(r'br i1 (\S+), label %(\S+), label %(\S+)', line):
                    if graph[found[2]] != ['br label %' + found[3]] and graph[found[3]] != ['br label %' + found[2]]:
                        alternatives.append(f'br i1 {found[1]}, label %{found[3]}, label %{found[2]}')
                if name in (names['preflight'], names['counter']) or '6Engine5check' in name:
                    if found := re.search(r'getelementptr inbounds(?: nuw)? i8, ptr %\S+, i64 (624|16|858|859)$', line):
                        alternatives.append(line[:found.start(1)] + str(int(found[1]) + 1))
                    if 'load i8, ptr %byte' in line:
                        alternatives.append(line + '\n' + line)
                    if 'shl i128' in line:
                        alternatives.append(line.replace('shl i128', 'or i128'))
                    if 'or i128' in line:
                        alternatives.append(line.replace('or i128', 'and i128'))
                    if line == 'store i128 0, ptr %value, align 16':
                        alternatives.append(line.replace('i128 0', 'i128 1'))
                    if 'and i64' in line and line.endswith(', 127'):
                        alternatives.append(line[:-3] + '63')
                    if 'zext i64 %bytes to i128' in line:
                        alternatives.append(line.replace('%bytes', '0'))
                if 'getelementptr' in line and line.endswith(', i64 1'):
                    alternatives.append(line[:-1] + '2')
                if '9enumerate' in name and re.fullmatch(r'store i64 0, ptr %\S+, align 8', line):
                    alternatives.append(line.replace('i64 0', 'i64 1'))
                for alternative in alternatives:
                    assert alternative != line
                    new = lines[:index] + ([alternative] if alternative else []) + lines[index + 1:]
                    yield name + '/' + label + '/' + line, changed(case, body, replace_block(body, label, new))
    body = selected[names['preflight']]
    for code in ('  store i8 1, ptr %self, align 1', '  %payload = load i8, ptr %self, align 1'):
        yield 'unowned engine access', changed(case, body, body.replace('start:', 'start:\n' + code, 1))
    yield 'by-value preflight ABI', changed(case, body, body.replace('ptr align 32', 'ptr byval([864 x i8]) align 32', 1))


def main(record, shard):
    before = check.comparison.capture.sources()
    cases = list(check.operation.cases(record))
    assert len(cases) == 8
    for case in cases if shard is None else [cases[shard]]:
        counts = [0, 0]
        for label, mutant in mutants(case):
            for consuming in (False, True):
                try:
                    check.inspect(mutant, False, consuming)
                except ValueError:
                    counts[int(consuming)] += 1
                else:
                    raise AssertionError('accepted actual preflight regression: ' + label)
        _, _, names, selected, _ = check.closure(case, False)
        controls = 0
        for role, variable in (('preflight', 'bytes'), ('counter', 'value')):
            body = selected[names[role]]
            for control in (re.sub(r'^\s*#dbg_.*\n', '', body, flags=re.M),
                            re.sub(r'%' + variable + r'\b', '%renamed_scalar', body)):
                assert control != body
                for consuming in (False, True):
                    assert check.inspect(changed(case, body, control), False, consuming)[0] == 454
                    controls += 1
        # Mapping a successful sum to () is side-effect free; removing that
        # unit-producing closure is a semantic control, not a rejected mutant.
        unit_calls = [(body, label, index, lines) for body in selected.values()
                      for label, lines in check.model.blocks(body).items()
                      for index, line in enumerate(lines)
                      if line.startswith('call void ') and '9preflight' in line]
        assert len(unit_calls) == 1
        body, label, index, lines = unit_calls[0]
        control = replace_block(body, label, lines[:index] + lines[index + 1:])
        for consuming in (False, True):
            assert check.inspect(changed(case, body, control), False, consuming)[0] == 454
            controls += 1
        assert min(counts) > 40 and controls == 10
        print(f'Preflight mutations rejected: bulk={counts[0]}, consuming={counts[1]}; {controls} controls PASS', flush=True)
    assert before == check.comparison.capture.sources()
    print('Matrix: ' + ('all 8 paths' if shard is None else f'shard {shard}/8; all eight required'))
    print('Compiler/runtime subprocesses forbidden; session/read/primitive bodies remain opaque')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('--shard', type=int, choices=range(8))
    args = parser.parse_args()
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(args.record.resolve(), args.shard)
