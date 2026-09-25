#!/usr/bin/env python3
"""Reject retained staging/final-bit composition regressions without compiling."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_filled_final as check
import test_debug_filled_squeeze as byte_test
from test_debug_portable_final_bridge import changed
from test_kmac_optimized_cleanup import replace_block


def boundaries(case):
    m = check.model
    _, names, _ = check.closure(case)
    machine = check.FilledFinal({}, '', names, 0, 2, 7, 1, None, None, names['rate'], None)
    storage = machine.allocate('storage', 1040, payload=True)
    reader = machine.allocate('reader', 16)
    output = machine.allocate('output', 2, payload=True)
    initializer = machine.allocate('1:initializer', 24)
    machine.fields(reader, [(0, 8, storage), (8, 1, 1)])
    machine.fields(initializer, [(0, 8, output), (8, 8, 2), (16, 8, 0)])
    rejected = 0

    def reject(call):
        try:
            call()
        except ValueError:
            return 1
        raise AssertionError('malformed/unarmed filled-final boundary accepted')

    rejected += reject(lambda: machine.run(names['final_squeeze'], [storage, 2, 7, initializer]))
    machine.store(m.Pointer('reader', 8), 1, 0)
    for args in ([storage, 2, 8, initializer], [storage, 1, 7, initializer], [reader, 2, 7, initializer]):
        rejected += reject(lambda: machine.run(names['final_squeeze'], args))
    rejected += reject(lambda: machine.run(names['fill'], [storage, 1]))
    rejected += reject(lambda: machine.load(m.Pointer('storage', 1039), 1))
    rejected += reject(lambda: machine.store(m.Pointer('storage', 1039), 1, 0))
    machine.in_squeeze, machine.initializer = True, initializer
    for args in ([reader, 1], [storage, 0], [storage, names['rate'] + 1]):
        rejected += reject(lambda: machine.run(names['fill'], args))
    mask = [m.Pointer('storage', 584), 127, 0]
    rejected += reject(lambda: machine.run(names['apply_mask'], mask))
    machine.prefix_done = True
    assert machine.run(names['apply_mask'], mask) is None
    rejected += reject(lambda: machine.run(names['apply_mask'], [m.Pointer('storage', 584), 255, 0]))
    machine.store(m.Pointer('reader', 8), 1, 1)
    rejected += reject(lambda: machine.run(names['apply_mask'], mask))
    rejected += reject(lambda: machine.run(names['fill'], [storage, 1]))
    machine.store(m.Pointer('reader', 8), 1, 0)
    machine.in_fill = True
    rejected += reject(lambda: machine.run(names['fill'], [storage, 1]))
    rejected += reject(lambda: machine.load(storage, 1))
    rejected += reject(lambda: machine.load(m.Pointer('storage', 1039), 8))
    assert machine.load(m.Pointer('storage', 1039), 1) == names['rate']
    machine.store(m.Pointer('storage', 1039), 1, 0)
    assert machine.cursor == 0 and rejected == 17
    print('Filled-final boundary: three controls; seventeen malformed/unarmed accesses rejected', flush=True)


def mutants(case):
    with patch.object(byte_test, 'check', check):
        yield from byte_test.mutants(case)
    _, names, merged = check.closure(case)
    body = merged[names['final_squeeze']]
    for label, lines in check.model.blocks(body).items():
        for index, line in enumerate(lines):
            symbol = re.search(check.comparison.SYMBOL, line)
            if not symbol or 'call ' not in line:
                continue
            callee, alternatives = symbol[1], []
            if callee in (names['squeeze'], names['fill'], names['apply_mask'], names['output_write'], names['clear']):
                alternatives.append('')
            if callee == names['fill']:
                alternatives.append(line.replace('i64 1)', 'i64 2)'))
            if callee == names['apply_mask']:
                alternatives.append(line.replace(', i8 0)', ', i8 1)'))
            if callee == names['clear']:
                alternatives.append(line.replace('i64 168', 'i64 167'))
            for replacement in alternatives:
                assert replacement != line
                altered = lines[:index] + ([replacement] if replacement else []) + lines[index + 1:]
                yield 'final tail handoff/mask/cleanup', changed(case, body, replace_block(body, label, altered))


def main(record, shard=None):
    before = check.comparison.capture.sources()
    cases = list(check.final.begin.guard.final.cases(record))
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
                raise AssertionError('accepted filled-final regression: ' + label)
        _, names, merged = check.closure(case)
        body = merged[names['final_squeeze']]
        renamed = re.sub(r'%output_bytes\b', '%destination_width', body)
        assert renamed != body
        check.inspect(changed(case, body, renamed), False)
        assert count >= 29
        counts.append(count)
        print(f'Filled final mutations: {count}; SSA control PASS', flush=True)
    assert before == check.comparison.capture.sources()
    print('Matrix: ' + ('all 16 paths' if shard is None else f'shard {shard}/4; all four required'))
    print(f'Filled final rejects {sum(counts)} regressions; {len(counts)} SSA controls PASS')
    print('Per-path counts: ' + repr(counts))
    print('Compiler/runtime subprocesses forbidden; no whole-call/register/spill/native qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('--shard', type=int, choices=range(4))
    args = parser.parse_args()
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(args.record.resolve(), args.shard)
