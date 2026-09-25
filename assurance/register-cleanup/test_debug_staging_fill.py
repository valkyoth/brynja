#!/usr/bin/env python3
"""Mutate retained debug staging geometry, cursor and cleanup handoffs."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_staging_fill as check
from test_debug_portable_final_bridge import changed


def mutants(case):
    names, selected = check.closure(case)
    fill = selected[names['fill']]
    yield 'read secret payload', changed(case, fill, fill.replace('start:',
        'start:\n  %leak = load i8, ptr %self, align 1', 1))
    for old, new in (('i64 584', 'i64 583'), ('i64 48', 'i64 49'), ('icmp ugt i64 %count, 168', 'icmp ugt i64 %count, 167')):
        assert old in fill
        yield 'wrong fill bound/region', changed(case, fill, fill.replace(old, new))
    for name, body in selected.items():
        if name == names['fill'] or '10next_range' in name:
            for line in body.splitlines():
                if re.search(r'\bcall void @', line) and ('20set_squeeze_position' in line or '11permutation7permute' in line):
                    yield 'missing cursor/permutation handoff', changed(case, body, body.replace(line, '', 1))
        if '10next_range' in name:
            old = next(line for line in body.splitlines() if 'icmp ugt i64' in line)
            yield 'inverted cursor admission', changed(case, body, body.replace(old, old.replace('ugt', 'ult'), 1))
        if '20set_squeeze_position' in name or '16squeeze_position' in name:
            assert 'i64 1037' in body
            yield 'wrong cursor byte', changed(case, body, body.replace('i64 1037', 'i64 1036', 1))
        if '24wipe_permutation_scratch' in name:
            lines = [line for line in body.splitlines() if re.search(r'\bcall i8 @', line) and '18clear_owned_region' in line]
            assert len(lines) == 3
            for line in lines:
                yield 'omitted scratch clearing', changed(case, body, body.replace(line, '', 1))
            yield 'partial scratch clearing', changed(case, body, body.replace('i64 40', 'i64 39', 1))
        if '11permutation6native7permute' in name:
            line = next(
                line for line in body.splitlines() if re.search(r'\bcall void @' + re.escape(names['scalar']) + r'\(', line))
            args = check.comparison.arguments(line, re.search(check.comparison.SYMBOL, line).end())
            yield 'wrong scalar state', changed(case, body, body.replace(line, line.replace(args[0], args[1], 1), 1))
            yield 'wrong scalar constants', changed(case, body, body.replace(line, line.replace(args[-1], args[0], 1), 1))
    table = names['table'].region
    line = next(line for line in case.sha3.splitlines() if line.startswith(table + ' = '))
    assert '\\01' in line
    yield 'changed public round table', changed(case, line, line.replace('\\01', '\\00', 1))
    for source, name in (('sha3', names['scalar']), ('core', names['transfer']), ('core', names['wipe'])):
        body = check.comparison.definitions(getattr(case, source))[name]
        assert body.startswith('define internal void @')
        yield 'primitive returns a value', changed(case, body, body.replace('define internal void @', 'define internal i8 @', 1))


def main(record, shard=None):
    before = check.comparison.capture.sources()
    cases = list(check.guard.begin.guard.final.cases(record))
    assert len(cases) == 16 and (shard is None or shard in range(4))
    chosen = cases if shard is None else cases[4 * shard:4 * shard + 4]
    counts = []
    for case in chosen:
        check.inspect(case, False)
        count = 0
        for label, mutant in mutants(case):
            try:
                check.inspect(mutant, False)
            except ValueError:
                count += 1
            else:
                raise AssertionError('accepted staging regression: ' + label)
        names, selected = check.closure(case)
        body = selected[names['fill']]
        renamed = re.sub(r'%offset\b', '%staging_offset', body)
        assert renamed != body
        check.inspect(changed(case, body, renamed), False)
        assert count == 20
        counts.append(count)
        print(f'Debug staging mutations: {count}; SSA control PASS', flush=True)
    assert before == check.comparison.capture.sources()
    print('Matrix: ' + ('all 16 paths' if shard is None else f'shard {shard}/4; all four required'))
    print(f'Debug staging rejects {sum(counts)} regressions; {len(counts)} SSA controls PASS')
    print('Per-path counts: ' + repr(counts))
    print('Compiler/runtime subprocesses forbidden; no whole-call/register/spill/native qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('--shard', type=int, choices=range(4))
    args = parser.parse_args()
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(args.record.resolve(), args.shard)
