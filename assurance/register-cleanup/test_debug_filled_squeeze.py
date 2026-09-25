#!/usr/bin/env python3
"""Reject staging/squeeze/owner-guard composition regressions in retained IR."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_filled_squeeze as check
from test_debug_portable_final_bridge import changed
from test_kmac_optimized_cleanup import replace_block


def boundaries(case):
    m = check.model
    _, names, _ = check.closure(case)
    machine = check.FilledSqueeze({}, '', names, 0, 1, 1, None, None, 168, None)
    storage = machine.allocate('storage', 1040, payload=True)
    reader = machine.allocate('reader', 16)
    machine.fields(reader, [(0, 8, storage), (8, 1, 0)])
    rejected = 0

    def reject(call):
        try:
            call()
        except ValueError:
            return 1
        raise AssertionError('unarmed/malformed staging boundary accepted')

    rejected += reject(lambda: machine.run(names['fill'], [storage, 1]))
    rejected += reject(lambda: machine.load(m.Pointer('storage', 1039), 1))
    rejected += reject(lambda: machine.store(m.Pointer('storage', 1039), 1, 0))
    machine.initializer = machine.allocate('1:initializer', 24)
    machine.in_squeeze = True
    for args in ([reader, 1], [storage, 0], [storage, names['rate'] + 1]):
        rejected += reject(lambda: machine.run(names['fill'], args))
    machine.store(m.Pointer('reader', 8), 1, 1)
    rejected += reject(lambda: machine.run(names['fill'], [storage, 1]))
    machine.store(m.Pointer('reader', 8), 1, 0)
    machine.in_fill = True
    rejected += reject(lambda: machine.run(names['fill'], [storage, 1]))
    rejected += reject(lambda: machine.load(m.Pointer('storage'), 1))
    rejected += reject(lambda: machine.load(m.Pointer('storage', 1039), 8))
    assert machine.load(m.Pointer('storage', 1039), 1) == 168
    machine.store(m.Pointer('storage', 1039), 1, 0)
    assert machine.cursor == 0
    assert rejected == 10
    print('Staging composition boundary: two controls; ten malformed/unarmed accesses rejected', flush=True)


def mutants(case):
    _, names, merged = check.closure(case)
    guards = [name for name in merged if 'Borrowed' in name and '3run' in name]
    assert len(guards) == 1
    for name in (guards[0], names['operation'], names['squeeze']):
        body = merged[name]
        for label, lines in check.model.blocks(body).items():
            for index, line in enumerate(lines):
                symbol = re.search(check.comparison.SYMBOL, line)
                if symbol and re.search(r'\b(?:call|invoke) ', line):
                    callee = symbol[1]
                    if callee in (names['squeeze'], names['finish'], names['writer']) or any(
                            token in callee for token in ('drop_in_place', 'drop_glue')):
                        if 'invoke ' in line:
                            edge = re.fullmatch(r'to label %(\S+) unwind label %(\S+)', lines[index + 1])
                            assert edge
                            altered = lines[:index] + ['br label %' + edge[1]] + lines[index + 2:]
                        else:
                            altered = lines[:index] + lines[index + 1:]
                        yield 'omitted handoff/destructor', changed(case, body, replace_block(body, label, altered))
                    if callee == names['fill']:
                        args = check.comparison.arguments(line, symbol.end())
                        altered = lines[:index] + [line.replace(args[1], 'i64 0', 1)] + lines[index + 1:]
                        yield 'zero-width fill handoff', changed(case, body, replace_block(body, label, altered))
                        altered = lines[:index] + ['ret i8 ' + str(names['success'])]
                        yield 'skipped fill/output work', changed(case, body, replace_block(body, label, altered))
                if name == guards[0] and re.fullmatch(r'store i8 [01], ptr %\S+, align 8', line):
                    new = line.replace('store i8 0,', 'store i8 1,') if 'i8 0,' in line else line.replace('store i8 1,', 'store i8 0,')
                    yield 'wrong guard state', changed(case, body, replace_block(body, label, lines[:index] + [new] + lines[index + 1:]))
                if line.startswith('resume { ptr, i32 }'):
                    yield 'swallowed unwind', changed(case, body, replace_block(body, label, lines[:index] + ['ret void']))
    owners = [body for name, body in merged.items() if 'HardenedFips202Owner' in name
              and re.search(r'(?<!\d)4wipe(?:17h|B)', name)]
    assert len(owners) == 1
    body = owners[0]
    lines = [line for line in body.splitlines() if '@' + names['clear'] + '(' in line]
    assert len(lines) == 13
    for line in (lines[0], lines[-1]):
        yield 'missing full-owner clear region', changed(case, body, body.replace(line, '', 1))
    for name, body in merged.items():
        if '24wipe_permutation_scratch' in name:
            line = next(line for line in body.splitlines() if re.search(r'\bcall i8 @', line) and '18clear_owned_region' in line)
            yield 'missing inner scratch clear', changed(case, body, body.replace(line, '', 1))


def main(record, shard=None):
    before = check.comparison.capture.sources()
    cases = list(check.guard.begin.guard.final.cases(record))
    assert len(cases) == 16 and (shard is None or shard in range(4))
    chosen = cases if shard is None else cases[4 * shard:4 * shard + 4]
    boundaries(chosen[0])
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
                raise AssertionError('accepted filled-squeeze regression: ' + label)
        _, names, merged = check.closure(case)
        body = merged[names['squeeze']]
        renamed = re.sub(r'%remaining\b', '%bytes_left', body)
        assert renamed != body
        check.inspect(changed(case, body, renamed), False)
        assert count >= 18
        counts.append(count)
        print(f'Filled squeeze mutations: {count}; SSA control PASS', flush=True)
    assert before == check.comparison.capture.sources()
    print('Matrix: ' + ('all 16 paths' if shard is None else f'shard {shard}/4; all four required'))
    print(f'Filled squeeze rejects {sum(counts)} regressions; {len(counts)} SSA controls PASS')
    print('Per-path counts: ' + repr(counts))
    print('Compiler/runtime subprocesses forbidden; no whole-call/register/spill/native qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('--shard', type=int, choices=range(4))
    args = parser.parse_args()
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(args.record.resolve(), args.shard)
