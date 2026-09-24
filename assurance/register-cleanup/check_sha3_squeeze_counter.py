#!/usr/bin/env python3
"""Model retained portable bulk squeeze counter admission and serialization."""
import argparse
import json
from pathlib import Path
import re

import check_read_counter as model
import check_sha3_squeeze_progress as progress

comparison = progress.comparison
require = progress.require
MAX = model.MAX
SSA = progress.SSA


def scenarios(thorough=True):
    pairs = {(0, 0), (0, 1), (MAX, 0), (MAX, 1), (MAX - 1, 1), (MAX - 1, 2),
             (0x0102030405060708090a0b0c0d0e0f10, 0x10203)}
    if not thorough:
        return sorted(pairs | {(1 << 127, 0), ((1 << 64) - 1, 1),
                               (MAX - (1 << 63), 1 << 63), (MAX, (1 << 64) - 1)})
    for bit in range(128):
        pairs |= {(1 << bit, 0), (1 << bit, 1), ((1 << bit) - 1, 1)}
    for length in (0, 1, 135, 136, 137, 167, 168, 169, (1 << 64) - 1,
                   *(1 << bit for bit in range(64))):
        pairs |= {(0, length), (MAX - length, length)}
        if length:
            pairs.add((MAX - length + 1, length))
    return sorted(pairs)


def inspect(function, *arguments, thorough=True):
    trace, labels, exits, _ = progress.inspect(function, *arguments)
    _, setup, _, _, _ = labels
    _, commit = exits
    compiler = arguments[3]
    header = function.splitlines()[0]
    params = comparison.arguments(header, re.search(comparison.SYMBOL, header).end())
    length_name = re.search(SSA + '$', params[2])[0]
    require(comparison.pointer(params[0]) == '%self', 'original counter owner parameter')
    # Interpret the original return phi on both rejection and success. Only the
    # data loop is skipped, after the separate progress checker validates it.
    count = 0
    for counter, length in scenarios(thorough):
        state = dict(counter=counter, writes=[])
        stops = dict(error=None, loop=setup)
        outcome = model.evaluate(trace.graph, 'start', None, {length_name: length},
                                 state, None, stops, False, portable_bulk=True)
        if counter + length > MAX:
            require(outcome == ('return', 2) and not state['writes'], 'overflow rejects before work and counter writes')
        else:
            if length:
                require(outcome[0] == 'loop' and not state['writes'], 'accepted nonempty request enters loop without counter commit')
                # The separate progress checker verifies the loop's success-only
                # commit route. This model does not simulate fill or data copying.
                outcome = model.evaluate(trace.graph, commit, None, outcome[1], state,
                                         None, stops, True, portable_bulk=True)
            expected = 5 if compiler == '1.90.0' else 255
            require(outcome == ('return', expected) and state['writes'] == [counter + length],
                    'complete successful counter serialized as exact little-endian u128')
        count += 1
    return count


def main(record):
    before = comparison.capture.sources()
    results = [inspect(*case) for case in progress.cases(record)]
    require(len(results) == 16 and before == comparison.capture.sources(), 'complete unchanged bulk counter matrix')
    print(f'Bulk squeeze counters: 16 retained bodies; {sum(results)} modeled admission/commit cases PASS')
    print('Counter loads, overflow-before-work, zero-length requests and all 128 serialized bits checked at selected boundaries')
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Inspector source SHA-256: ' + json.dumps(comparison.recorded.inspector_sources(), sort_keys=True))
    print('Bounded model, not all-input proof or fill semantics; Arm remains QEMU; no whole-call register/spill or native qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    main(parser.parse_args().record.resolve())
