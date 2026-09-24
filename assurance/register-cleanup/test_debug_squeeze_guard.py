#!/usr/bin/env python3
"""Reject cross-boundary regressions in retained guarded byte squeezing."""
import argparse
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_squeeze_guard as check
from test_debug_portable_final_bridge import changed
from test_kmac_optimized_cleanup import replace_block
from test_kmac_verify_comparisons import rejects


def boundary_tests():
    model = check.model
    names = dict(squeeze='squeeze', final_squeeze='final', fill='fill', copy='copy',
                 output_write='write', staging_get='slice', success=255, rate=168)
    machine = check.GuardedSqueeze({}, '', names, 0, 169, 1, None, None)
    machine.allocate('storage', 1040, payload=True)
    reader = machine.allocate('reader', 16)
    destination = machine.allocate('output', 169, payload=True)
    initializer = machine.allocate('1:initializer', 24)
    machine.fields(reader, [(0, 8, model.Pointer('storage')), (8, 1, 0)])
    machine.fields(initializer, [(0, 8, destination), (8, 8, 169), (16, 8, 0)])
    rejected = controls = 0

    def reject(name, args):
        try:
            machine.run(name, args)
        except ValueError:
            return 1
        raise AssertionError('invalid guarded boundary accepted')

    for name, args in [('fill', [model.Pointer('storage'), 168]),
                       ('copy', [destination, model.Pointer('storage', 584), 168]),
                       ('write', [initializer, model.Pointer('storage', 584), 168])]:
        rejected += reject(name, args)
    machine.initializer, machine.in_squeeze = initializer, True
    assert machine.run('fill', [model.Pointer('storage'), 168]) == 255
    controls += 1
    for args in ([model.Pointer('output', 1), model.Pointer('storage', 584), 168],
                 [destination, model.Pointer('storage', 585), 168],
                 [destination, model.Pointer('storage', 584), 167]):
        rejected += reject('copy', args)
    assert machine.run('copy', [destination, model.Pointer('storage', 584), 168]) is None
    controls += 1
    machine.store(model.Pointer(initializer.region, 16), 8, 168)
    assert machine.progress == 168 and machine.events[-1] == ('progress', 168)
    controls += 1
    rejected += reject('write', [reader, model.Pointer('storage', 584), 168])
    machine.failure = ('write', 1, 3)
    assert machine.run('write', [initializer, model.Pointer('storage', 584), 168]) == 3
    controls += 1
    machine.store(model.Pointer('reader', 8), 1, 1)
    for name, args in [('fill', [model.Pointer('storage'), 168]),
                       ('copy', [destination, model.Pointer('storage', 584), 168]),
                       ('write', [initializer, model.Pointer('storage', 584), 168]),
                       ('squeeze', [model.Pointer('storage'), initializer, 169])]:
        rejected += reject(name, args)
    rejected += reject('final', [])
    assert (controls, rejected) == (4, 12)
    print(f'Guarded squeeze boundary model: {controls} controls; {rejected} malformed/unarmed calls rejected', flush=True)


def mutants(case):
    names, _, merged = check.squeeze.closure(case)
    _, _, _, visited = check.inspect(case, False)
    guards = [name for name in merged if 'Borrowed' in name and '3run' in name]
    assert len(guards) == 1
    guard = guards[0]
    for name in (guard, names['operation'], names['squeeze']):
        body = merged[name]
        for label, lines in check.model.blocks(body).items():
            if (name, label) not in visited:
                continue
            for index, line in enumerate(lines):
                alternatives = []
                symbol = re.search(check.comparison.SYMBOL, line)
                if symbol and re.search(r'\b(?:call|invoke) ', line):
                    callee = symbol[1]
                    important = callee in (names['squeeze'], names['finish'], names['writer']) or any(
                        token in callee for token in ('drop_in_place', 'drop_glue'))
                    if important and 'invoke ' in line:
                        edge = re.fullmatch(r'to label %(\S+) unwind label %(\S+)', lines[index + 1])
                        assert edge
                        new = lines[:index] + ['br label %' + edge[1]] + lines[index + 2:]
                        yield 'omitted invoked handoff/destructor', changed(case, body, replace_block(body, label, new))
                    elif important:
                        alternatives.append('')
                if name == guard and re.fullmatch(r'store i8 [01], ptr %\S+, align 8', line):
                    alternatives.append(line.replace('store i8 0,', 'store i8 1,') if 'i8 0,' in line
                                        else line.replace('store i8 1,', 'store i8 0,'))
                if name == guard and (branch := re.fullmatch(r'br i1 (\S+), label %(\S+), label %(\S+)', line)):
                    alternatives.append(f'br i1 {branch[1]}, label %{branch[3]}, label %{branch[2]}')
                if line.startswith('resume { ptr, i32 }'):
                    alternatives.append('ret void')
                if name == names['squeeze'] and '@' + names['fill'] + '(' in line:
                    alternatives.append('ret i8 ' + str(names['success']))
                for replacement in alternatives:
                    assert replacement != line
                    new = lines[:index] + ([replacement] if replacement else []) + lines[index + 1:]
                    yield name + '/' + label + '/' + line, changed(case, body, replace_block(body, label, new))
    # Test the observable cleanup footprint through the actual owner helper,
    # including a missing last region rather than only the first clear.
    owner_wipes = 0
    for name, body in merged.items():
        if 'HardenedFips202Owner' not in name or '4wipe' not in name:
            continue
        owner_wipes += 1
        calls = [line for line in body.splitlines() if '@' + names['clear'] + '(' in line]
        assert len(calls) == 13
        for line in (calls[0], calls[-1]):
            yield 'omitted owner region', changed(case, body, body.replace(line, '', 1))
    assert owner_wipes == 1


def main(record):
    boundary_tests()
    counts, controls = [], 0
    for case in check.begin.guard.final.cases(record):
        counts.append(rejects(lambda value: check.inspect(value, False), case, mutants(case)))
        names, _, merged = check.squeeze.closure(case)
        body = merged[names['squeeze']]
        for replacement in (re.sub(r'^\s*#dbg_.*\n', '', body, flags=re.M),
                            re.sub(r'%remaining\b', '%bytes_left', body)):
            assert replacement != body
            check.inspect(changed(case, body, replacement), False)
            controls += 1
        print('Guarded squeeze mutations: ' + str(counts[-1]), flush=True)
    assert len(counts) == 16 and min(counts) >= 20 and controls == 32
    print(f'Guarded byte squeeze rejects {sum(counts)} handoff/cleanup/commit/unwind regressions; {controls} controls PASS')
    print('Per-path counts: ' + repr(counts))
    print('Subprocess execution forbidden; no final-bit, arbitrary-unwind or register/spill qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(parser.parse_args().record.resolve())
