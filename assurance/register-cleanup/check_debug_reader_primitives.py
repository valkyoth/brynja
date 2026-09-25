#!/usr/bin/env python3
"""Retained debug split and copy/mask wrapper bodies, directly and in readers."""
import argparse
from pathlib import Path
from unittest.mock import patch

from debug_reader_primitives import PrimitiveModel, ReaderPrimitives, closure, composed, model, require

comparison = composed.comparison


def setup(case):
    _, _, names, merged = closure(case, False)
    functions = {name: (model.parameters(body), model.blocks(body)) for name, body in merged.items()}
    constants = '\n'.join(dict.fromkeys(line for text in (case.sha3, case.core, case.hash_core, case.kmac)
                                      for line in text.splitlines() if line.startswith(('@anon.', '@alloc_'))))
    return names, functions, constants


def direct(case, quick=False):
    names, functions, constants = setup(case)
    count = 0
    def machine():
        m = PrimitiveModel(functions, constants, names)
        m.allocate('payload', 2048, payload=True)
        m.allocate('result', 32)
        return m
    for length in (0, 1, 7, 8, 63, 64, 72, 104, 136, 144, 168, 200, 337, 505) if not quick else (0, 168):
        for mid in sorted({0, length // 2, max(0, length - 1), length}):
            m = machine()
            m.primitive_body('split', [model.Pointer('result'), model.Pointer('payload', 17), length, mid, model.Pointer('@location')], 0)
            require(not m.raw_calls and not m.events, 'split only constructs descriptors, never accesses payload')
            count += 1
    widths = (0, 1, 7, 8, 168, 200, 505) if not quick else (0, 168)
    for destination in widths:
        for source in widths:
            m = machine()
            m.primitive_body('lane_copy', [model.Pointer('payload', 17), destination, model.Pointer('payload', 1024), source], 0)
            require(not m.events, 'copy wrapper does not load/store secret bytes')
            count += 1
    masks = range(256) if not quick else (0, 1, 127, 255)
    for n in masks:
        for keep, set_value in ((n, 0), (255, n)):
            m = machine()
            m.primitive_body('mask', [model.Pointer('payload', 17), keep, set_value], 0)
            require(not m.events, 'mask wrappers do not load/store secret bytes')
            count += 1
    return count


def inspect(case, thorough=True, consuming=True):
    with patch.object(composed, 'closure', closure), patch.object(composed, 'ComposedRead', ReaderPrimitives):
        return composed.inspect(case, thorough, consuming)


def main(record, shard, quick):
    before = comparison.capture.sources()
    cases = list(composed.operation.cases(record))
    require(len(cases) == 8, 'eight retained debug paths')
    for case in cases if shard is None else [cases[shard]]:
        print(f'Reader primitive direct bodies: {direct(case, quick)} cases PASS', flush=True)
        for consuming in (False, True):
            count, merged, _ = inspect(case, not quick, consuming)
            print(f'Reader primitive composition {consuming=}: {count} cases; {len(merged)} functions PASS', flush=True)
    require(before == comparison.capture.sources(), 'captured implementation unchanged')
    print('Matrix: ' + ('all eight paths' if shard is None else f'shard {shard}/8; all eight required'))
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Valid-pointer preconditions assumed; raw copy/mask, CPU and volatile bodies opaque; no whole-call/F1 qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('--shard', type=int, choices=range(8))
    parser.add_argument('--quick', action='store_true')
    args = parser.parse_args()
    main(args.record.resolve(), args.shard, args.quick)
