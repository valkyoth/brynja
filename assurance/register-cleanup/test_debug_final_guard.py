#!/usr/bin/env python3
"""Reject retained final-bit handoff, guard, cleanup and unwind regressions."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_final_guard as check
from test_debug_portable_final_bridge import changed
from test_kmac_optimized_cleanup import replace_block
from test_kmac_verify_comparisons import rejects


def boundaries():
    model = check.model
    names = dict(final_squeeze='final', squeeze='prefix', fill='fill', first='first', apply_mask='mask',
                 output_write='write', copy='copy', staging_get='slice', writer='writer', counter='counter',
                 success=255, rate=168, panics=set())
    body = 'define i8 @final(ptr %self, i64 %length, i8 %valid, ptr %init) {\nstart:\n  ret i8 255\n}'
    functions = {'final': (model.parameters(body), model.blocks(body))}
    machine = check.GuardedFinal(functions, '', names, 0, 2, 7, 1)
    storage = machine.allocate('storage', 1040, payload=True)
    reader = machine.allocate('reader', 16)
    output = machine.allocate('output', 2, payload=True)
    initializer = machine.allocate('1:initializer', 24)
    machine.fields(reader, [(0, 8, storage), (8, 1, 1)])
    machine.fields(initializer, [(0, 8, output), (8, 8, 2), (16, 8, 0)])
    controls = rejected = 0

    def reject(name, args):
        try:
            machine.run(name, args)
        except ValueError:
            return 1
        raise AssertionError('unguarded/malformed final boundary accepted')

    rejected += reject('final', [storage, 2, 7, initializer])
    machine.store(model.Pointer('reader', 8), 1, 0)
    for args in ([storage, 2, 8, initializer], [storage, 1, 7, initializer],
                 [model.Pointer('storage', 1), 2, 7, initializer], [storage, 2, 7, output]):
        rejected += reject('final', args)
    machine.store(model.Pointer(initializer.region, 16), 8, 1)
    rejected += reject('final', [storage, 2, 7, initializer])
    machine.store(model.Pointer(initializer.region, 16), 8, 0)
    assert machine.run('final', [storage, 2, 7, initializer]) == 255 and not machine.in_squeeze
    controls += 1
    mask = [model.Pointer('storage', 584), 127, 0]
    calls = [('fill', [storage, 1]), ('mask', mask),
             ('write', [initializer, model.Pointer('storage', 584), 1]),
             ('copy', [output, model.Pointer('storage', 584), 1])]
    for name, args in calls:
        rejected += reject(name, args)
    machine.in_squeeze = True
    rejected += reject('mask', mask)
    rejected += reject('prefix', [storage, initializer, 2])
    assert machine.run('fill', [storage, 1]) == 255
    controls += 1
    machine.prefix_done = True
    assert machine.run('mask', mask) is None
    controls += 1
    rejected += reject('prefix', [storage, initializer, 1])
    rejected += reject('copy', [model.Pointer('output', 1), model.Pointer('storage', 584), 1])
    assert machine.run('copy', [output, model.Pointer('storage', 584), 1]) is None
    controls += 1
    machine.failure = ('write', 1, 3)
    assert machine.run('write', [initializer, model.Pointer('storage', 584), 1]) == 3
    controls += 1
    machine.store(model.Pointer(initializer.region, 16), 8, 1)
    assert machine.progress == 1 and machine.events[-1] == ('progress', 1)
    controls += 1
    machine.store(model.Pointer('reader', 8), 1, 1)
    for name, args in calls:
        rejected += reject(name, args)
    assert (controls, rejected) == (6, 18)
    print(f'Guarded final model: {controls} controls; {rejected} malformed/unarmed calls rejected', flush=True)


def mutants(case):
    names, _, merged = check.final.closure(case)
    _, _, _, visited = check.inspect(case, False)
    guards = [name for name in merged if 'Borrowed' in name and '3run' in name]
    assert len(guards) == 1
    guard = guards[0]
    for name in (guard, names['operation'], names['final_squeeze'], names['squeeze']):
        body = merged[name]
        for label, lines in check.model.blocks(body).items():
            if (name, label) not in visited:
                continue
            for index, line in enumerate(lines):
                alternatives = []
                symbol = re.search(check.comparison.SYMBOL, line)
                if symbol and re.search(r'\b(?:call|invoke) ', line):
                    callee = symbol[1]
                    important = callee in (names['final_squeeze'], names['squeeze'], names['finish'], names['writer']) or any(
                        token in callee for token in ('drop_in_place', 'drop_glue'))
                    if important and 'invoke ' in line:
                        edge = re.fullmatch(r'to label %(\S+) unwind label %(\S+)', lines[index + 1])
                        assert edge
                        new = lines[:index] + ['br label %' + edge[1]] + lines[index + 2:]
                        yield 'omitted invoked handoff/destructor', changed(case, body, replace_block(body, label, new))
                    elif important:
                        alternatives.append('')
                    if name == names['final_squeeze'] and callee == names['apply_mask']:
                        alternatives.append('')
                    if name == names['final_squeeze'] and callee == names['fill']:
                        alternatives.append('ret i8 ' + str(names['success']))
                if name == guard and re.fullmatch(r'store i8 [01], ptr %\S+, align 8', line):
                    alternatives.append(line.replace('store i8 0,', 'store i8 1,') if 'i8 0,' in line
                                        else line.replace('store i8 1,', 'store i8 0,'))
                if name == guard and (branch := re.fullmatch(r'br i1 (\S+), label %(\S+), label %(\S+)', line)):
                    alternatives.append(f'br i1 {branch[1]}, label %{branch[3]}, label %{branch[2]}')
                if line.startswith('resume { ptr, i32 }'):
                    alternatives.append('ret void')
                for replacement in alternatives:
                    assert replacement != line
                    new = lines[:index] + ([replacement] if replacement else []) + lines[index + 1:]
                    yield name + '/' + label + '/' + line, changed(case, body, replace_block(body, label, new))
    wipes = [body for name, body in merged.items() if 'HardenedFips202Owner' in name and '4wipe' in name]
    assert len(wipes) == 1
    body = wipes[0]
    calls = [line for line in body.splitlines() if '@' + names['clear'] + '(' in line]
    assert len(calls) == 13
    for line in (calls[0], calls[-1]):
        yield 'omitted final owner region', changed(case, body, body.replace(line, '', 1))


def main(record, shard=None):
    boundaries()
    before = check.comparison.capture.sources()
    cases = list(check.begin.guard.final.cases(record))
    assert len(cases) == 16 and (shard is None or shard in range(4))
    chosen = cases if shard is None else cases[4 * shard:4 * shard + 4]
    counts, controls = [], 0
    for case in chosen:
        counts.append(rejects(lambda value: check.inspect(value, False), case, mutants(case)))
        names, _, merged = check.final.closure(case)
        body = merged[names['final_squeeze']]
        replacement = re.sub(r'%output_bytes\b', '%destination_width', body)
        assert replacement != body
        check.inspect(changed(case, body, replacement), False)
        controls += 1
        print('Guarded final mutations: ' + str(counts[-1]), flush=True)
    assert len(counts) == controls == len(chosen) and min(counts) >= 20
    assert before == check.comparison.capture.sources()
    print('Matrix: ' + ('all 16 paths' if shard is None else f'shard {shard}/4; paths {4 * shard}..{4 * shard + 3}'))
    print(f'Guarded final squeeze rejects {sum(counts)} handoff/cleanup/commit/unwind regressions; {controls} SSA controls PASS')
    print('Per-path counts: ' + repr(counts))
    print('Compiler/runtime subprocesses forbidden; secret primitives, consuming wrapper and whole-call residue remain unqualified')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('--shard', type=int, choices=range(4), help='only this quarter; all four required')
    args = parser.parse_args()
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(args.record.resolve(), args.shard)
