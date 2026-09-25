#!/usr/bin/env python3
"""Regress retained clearing within readers, with bounded model-only execution."""
import argparse
from dataclasses import replace
from pathlib import Path
import re
from unittest.mock import patch

import check_debug_reader_clear as check
from debug_reader_clear import ClearingReader, clear, model
from test_debug_volatile_clear import mutants, memory_controls
from test_debug_accelerated_model import rejects


def one_case(thorough, consuming):
    assert consuming
    yield 1, 7, 3, 136, 136, 0, 1, None, None, None


def boundary_machine():
    # Exercise this mixin's byte/check/fence contract without constructing a
    # synthetic reader call chain. Real reader integration is checked separately.
    machine = object.__new__(ClearingReader)
    model.Model.__init__(machine, {}, '', '')
    machine.names = {'clear_precondition': 'precondition', 'wipe': 'wipe'}
    machine.allocate('storage', 1088, payload=True)
    machine.allocate('output', 8, payload=True)
    machine.counter_bytes = bytearray([255] * 16)
    machine.clearing = [model.Pointer('storage', 640), 2, 0, 0, 0]
    machine.clear_cells = {}
    machine.clear_frame_start, machine.frames = 2, 4
    machine.allocate('1:caller', 8)
    machine.allocate('3:helper', 8)
    return machine


def boundaries():
    p = model.Pointer
    count = 0
    actions = (
        lambda m: m.volatile_store(p('storage', 640), 0),
        lambda m: m.run('precondition', [p('storage', 641), 1, p('@loc')]),
        lambda m: m.run('precondition', [p('output'), 1, p('@loc')]),
        lambda m: m.run('precondition', [p('storage', 640), 2, p('@loc')]),
        lambda m: m.compiler_fence('seq_cst'),
        lambda m: m.store(p('storage', 640), 1, 0),
        lambda m: m.store(p('1:caller'), 8, 0),
        lambda m: m.run('wipe', [p('storage', 640), 2]),
    )
    for action in actions:
        count += rejects(lambda: action(boundary_machine()))
    m = boundary_machine()
    m.store(p('3:helper'), 8, 7)
    assert model.Model.load(m, p('3:helper'), 8) == 7
    m.run('precondition', [p('storage', 640), 1, p('@loc')])
    count += rejects(lambda: m.run('precondition', [p('storage', 640), 1, p('@loc')]))
    count += rejects(lambda: m.volatile_store(p('storage', 640), 1))
    m.volatile_store(p('storage', 640), 0)
    count += rejects(lambda: m.volatile_store(p('storage', 640), 0))
    m.run('precondition', [p('storage', 641), 1, p('@loc')])
    m.volatile_store(p('storage', 641), 0)
    assert m.counter_bytes == bytearray([0, 0] + [255] * 14)
    count += rejects(lambda: m.compiler_fence('release'))
    m.compiler_fence('seq_cst')
    count += rejects(lambda: m.compiler_fence('seq_cst'))
    m.clearing = None
    count += rejects(lambda: m.volatile_store(p('storage', 640), 0))
    count += rejects(lambda: m.compiler_fence('seq_cst'))
    m = boundary_machine()
    m.clearing = [p('output', 8), 0, 0, 0, 0]
    m.compiler_fence('seq_cst')
    assert m.clearing == [p('output', 8), 0, 0, 0, 1]
    assert count == 15
    memory_controls()
    print('Clear composition: fifteen invalid boundary cases rejected; byte-counter/empty-fence and indexed-store controls PASS', flush=True)


def main(record, shard):
    boundaries()
    before = check.comparison.capture.sources()
    cases = list(check.composed.operation.cases(record))
    assert len(cases) == 8
    for case in cases if shard is None else [cases[shard]]:
        with patch.object(check, 'scenarios', one_case):
            assert check.inspect(case, True)[0] == 1
            count = 0
            for label, mutated in mutants(case.core):
                assert mutated != case.core, 'missing mutation: ' + label
                try:
                    check.inspect(replace(case, core=mutated), True)
                except ValueError:
                    count += 1
                else:
                    raise AssertionError('accepted composed clear mutation: ' + label)
            root, _, selected = clear.closure(case.core)
            body = selected[root]
            controls = (re.sub(r'^\s*#dbg_.*\n', '', body, flags=re.M),
                        re.sub(r'%iter\b', '%byte_iterator', body))
            for control in controls:
                assert control != body
                assert check.inspect(replace(case, core=case.core.replace(body, control)), True)[0] == 1
        assert count == 24
        print(f'Composed volatile clear: {count} mutations rejected; two metadata/SSA controls PASS', flush=True)
    assert before == check.comparison.capture.sources()
    print('Matrix: ' + ('all eight paths' if shard is None else f'shard {shard}/8; all eight required'))
    print('Compiler/runtime subprocesses forbidden; F1 and wider qualification remain open')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('--shard', type=int, choices=range(8))
    args = parser.parse_args()
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(args.record.resolve(), args.shard)
