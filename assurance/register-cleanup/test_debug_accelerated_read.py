#!/usr/bin/env python3
"""Mutate actual engine read, counter writer, permutation adapter and cleanup."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_accelerated_read as check
from test_debug_portable_final_bridge import changed
from test_kmac_optimized_cleanup import replace_block


def completed_drop(name, names, line, lines):
    return (name == names['read'] and line.startswith('call void ') and 'Operation' in line
            and 'drop_' in line and any(item.startswith('store i8 1,') for item in lines))


def mutants(case):
    names, selected, _ = check.closure(case)
    _, _, _, already, _ = check.preflight.closure(case, False)
    _, _, _, visited = check.inspect(case, False)
    for name, body in selected.items():
        if name in already:
            continue  # State/counter admission has its own composed mutations.
        yield 'missing read dependency ' + name, changed(case, body, '')
        graph = check.model.blocks(body)
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
                        skipped = lines[:index] + ['br label %' + edge[1]] + lines[index + 2:]
                        yield 'skipped invocation ' + name + '/' + label, changed(case, body, replace_block(body, label, skipped))
                        if symbol[1] in (names['permutation'], names['lane_copy'], names['preflight'], names['writer']):
                            broken = lines[:index + 1] + ['to label %' + edge[1] + ' unwind label %' + edge[1]] + lines[index + 2:]
                            yield 'wrong unwind target ' + name, changed(case, body, replace_block(body, label, broken))
                    elif not completed_drop(name, names, line, lines):
                        alternatives.append('')
                    if symbol[1] in (names['permutation'], names['lane_copy'], names['wipe']):
                        args = check.comparison.arguments(line, symbol.end())
                        alternatives.append(line.replace(args[0], 'ptr null'))
                    if symbol[1] == names['wipe']:
                        alternatives.append(line + '\n' + line)
                        alternatives.append(re.sub(r'i64 (\d+)', 'i64 1', line))
                    if name == names['writer'] and 'i64 16' in line:
                        alternatives += [line.replace('i64 16', 'i64 ' + str(n)) for n in (15, 17)]
                    if 'llvm.memcpy' in line:
                        alternatives.append(re.sub(r'i64 (24|32)', 'i64 16', line))
                if found := re.fullmatch(r'br i1 (\S+), label %(\S+), label %(\S+)', line):
                    if graph[found[2]] != ['br label %' + found[3]] and graph[found[3]] != ['br label %' + found[2]]:
                        alternatives.append(f'br i1 {found[1]}, label %{found[3]}, label %{found[2]}')
                if name in (names['read'], names['writer']) or '6Engine7permute' in name or '6Engine6cancel' in name or '6Memory4wipe' in name:
                    if found := re.search(r'getelementptr inbounds(?: nuw)? i8, ptr %\S+, i64 (608|616|624|640|656|856|859|16|32)$', line):
                        alternatives.append(line[:found.start(1)] + str(int(found[1]) + 1))
                    if line.startswith('store ') and '.dbg.spill' not in line and (name == names['writer'] or '%operation' in line or '%end' in line):
                        alternatives.append('')
                    if 'lshr i128' in line:
                        alternatives.append(line.replace('lshr i128', 'shl i128'))
                    if 'and i128' in line and line.endswith(', 255'):
                        alternatives.append(line[:-3] + '127')
                    if 'and i64' in line and line.endswith(', 127'):
                        alternatives.append(line[:-3] + '63')
                if '9Operation3new' in name and 'i1 false' in line:
                    alternatives.append(line.replace('i1 false', 'i1 true'))
                if 'getelementptr' in line and line.endswith(', i64 1'):
                    alternatives.append(line[:-1] + '2')
                if line.startswith('resume { ptr, i32 }'):
                    alternatives.append('ret void')
                if re.search(r'insertvalue \{ ptr, i32 } .*?, ptr %\S+, 0', line):
                    alternatives.append(re.sub(r', ptr %\S+, 0', ', ptr null, 0', line))
                for alternative in alternatives:
                    if alternative == line:
                        continue
                    new = lines[:index] + ([alternative] if alternative else []) + lines[index + 1:]
                    yield name + '/' + label + '/' + line, changed(case, body, replace_block(body, label, new))
    body = selected[names['read']]
    for code in ('  %disclose = load i8, ptr %self, align 1',
                 '  store i8 0, ptr %destination.0, align 1'):
        yield 'direct engine/payload access', changed(case, body, body.replace('start:', 'start:\n' + code, 1))
    yield 'by-value read ABI', changed(case, body, body.replace('ptr align 32', 'ptr byval([864 x i8]) align 32', 1))


def main(record, shard):
    before = check.comparison.capture.sources()
    cases = list(check.preflight.operation.cases(record))
    assert len(cases) == 8
    for case in cases if shard is None else [cases[shard]]:
        count = 0
        for label, mutant in mutants(case):
            try:
                check.inspect(mutant, False)
            except ValueError:
                count += 1
            else:
                raise AssertionError('accepted engine-read regression: ' + label)
            if count % 40 == 0:
                print(f'Engine-read mutation progress: {count} rejected', flush=True)
        names, selected, _ = check.closure(case)
        controls = 0
        for role, variable in (('read', 'operation'), ('writer', 'value')):
            body = selected[names[role]]
            for control in (re.sub(r'^\s*#dbg_.*\n', '', body, flags=re.M),
                            re.sub(r'%' + variable + r'\b', '%renamed_local', body)):
                assert control != body
                assert check.inspect(changed(case, body, control), False)[0] == 178
                controls += 1
        # Once completed=true the guard's Drop is a no-op. Removing that
        # success-only call must not be mistaken for lost error cleanup.
        body = selected[names['read']]
        noops = [(label, index, lines) for label, lines in check.model.blocks(body).items()
                 for index, line in enumerate(lines) if completed_drop(names['read'], names, line, lines)]
        assert len(noops) == 1
        label, index, lines = noops[0]
        control = replace_block(body, label, lines[:index] + lines[index + 1:])
        assert check.inspect(changed(case, body, control), False)[0] == 178
        controls += 1
        assert count > 70 and controls == 5
        print(f'Engine read rejects {count} mutations; {controls} metadata/SSA controls PASS', flush=True)
    assert before == check.comparison.capture.sources()
    print('Matrix: ' + ('all 8 paths' if shard is None else f'shard {shard}/8; all eight required'))
    print('Compiler/runtime subprocesses forbidden; explicit primitives/outer integration remain unqualified')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('--shard', type=int, choices=range(8))
    args = parser.parse_args()
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(args.record.resolve(), args.shard)
