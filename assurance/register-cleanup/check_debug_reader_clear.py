#!/usr/bin/env python3
"""Focused retained-reader/volatile-clear composition; no compiler or native run."""
import argparse
from pathlib import Path
from unittest.mock import patch

from debug_reader_clear import ClearingReader, closure, primitives, require

composed = primitives.composed
comparison = primitives.comparison


def scenarios(thorough, consuming):
    for length in (0, 1, 167, 168, 169, 337, 505):
        yield length, 7 if length else 0, 3, 136, 136, 0, 1, None, None, None
    yield 169, 7, 3, 136, 136, 1, 1, None, None, None
    yield 169, 7, composed.preflight.MAXIMUM, 136, 136, 0, 1, None, None, None
    for session in ((1, 3), (3, 'unwind')):
        yield 169, 7, 3, 136, 136, 0, 1, session, None, None
    for fault in (('copy', 1, 2), ('permute', 1, 3), ('writer', 0, 'unwind')):
        yield 337, 7, 3, 136, 136, 0, 1, None, (2, fault), None
    for failure in (('clear', 0, 2), ('copy', 2, 'unwind'), ('predicate', 0, 'unwind')):
        yield 169, 7, 3, 136, 136, 0, 1, None, None, failure
    if consuming:
        yield 169, 9, 3, 136, 136, 0, 1, None, None, None
        yield 169, 7, 3, 136, 136, 0, 1, None, None, ('mask', 2, 'unwind')


def inspect(case, consuming):
    _, _, names, _ = closure(case, consuming)
    for scenario in scenarios(True, consuming):
        if any(scenario[index] is not None for index in (7, 8, 9)):
            expected = composed.expected(scenario[0], consuming, scenario[1] if consuming else primitives.model.UNKNOWN,
                                         *scenario[2:], names)
            require(not expected[2], 'configured fault is actually reached, never beyond the final call')
    observed = []
    class Observed(ClearingReader):
        def __init__(self, *args):
            super().__init__(*args)
            observed.append(self)
    with patch.object(composed, 'closure', closure), patch.object(composed, 'ComposedRead', Observed), \
            patch.object(composed, 'scenarios', scenarios):
        count, merged, _ = composed.inspect(case, True, consuming)
    total = 0
    for machine in observed:
        expected = []
        for event in machine.events:
            if event[0] == 'wipe':
                expected.append(event[1:])
            elif event[0] == 'engine-read':
                expected.extend(('storage', *inner[1:]) for inner in event[1] if inner[0] == 'wipe')
        require(machine.completed_clears == expected and machine.clearing is None and expected,
                'every independently checked caller clear actually completed, in order')
        total += len(expected)
    return count, len(merged), total


def main(record, shard):
    before = comparison.capture.sources()
    cases = list(composed.operation.cases(record))
    require(len(cases) == 8, 'eight retained reader paths')
    for case in cases if shard is None else [cases[shard]]:
        for consuming in (False, True):
            count, functions, clears = inspect(case, consuming)
            print(f'Reader volatile composition {consuming=}: {count} cases; {functions} functions; {clears} complete clears PASS', flush=True)
    require(before == comparison.capture.sources(), 'captured implementation unchanged')
    print('Matrix: ' + ('all eight paths' if shard is None else f'shard {shard}/8; all eight required'))
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Valid byte-pointer checks assumed; synthetic caller unwind only; no whole-call/F1 qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('--shard', type=int, choices=range(8))
    args = parser.parse_args()
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(args.record.resolve(), args.shard)
