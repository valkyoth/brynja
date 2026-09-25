#!/usr/bin/env python3
"""Retained readers composed with actual static CPU guards and volatile clearing."""
import argparse
from pathlib import Path
from unittest.mock import patch

import check_debug_keccak_session as session
from debug_reader_session import SessionReader, closure, cpu, clearing, model, require

composed = clearing.primitives.composed
comparison = cpu.comparison


def cases(record):
    cpus = list(cpu.cases(record))
    readers = list(composed.operation.cases(record))
    require(len(cpus) == 4 and len(readers) == 8, 'four CPU rows and eight reader paths')
    for reader in readers:
        matching = [case for case in cpus if case.sha3 == reader.sha3 and case.core == reader.core]
        require(len(matching) == 1, 'unique same-record CPU dependency pair')
        yield reader, matching[0]


def scenarios(thorough, consuming):
    for length in (0, 1, 169, 337):
        yield length, 7 if length else 0, 3, 136, 136, 0, 1, None, None, None
    for call, error in ((1, 3), (3, 4), (3, 5)):
        yield 337, 7, 3, 136, 136, 0, 1, (call, error), None, None
    for chunk, error in ((1, 6), (2, 'unwind')):
        yield 337, 7, 3, 136, 136, 0, 1, None, (chunk, ('permute', 1, error)), None
    yield 169, 7, 3, 136, 136, 0, 1, None, None, ('copy', 2, 'unwind')
    if consuming:
        yield 169, 9, 3, 136, 136, 0, 1, None, None, None


def inspect(case, cpu_case, consuming):
    linked = lambda reader, mode: closure(reader, cpu_case, mode)
    _, _, names, _ = linked(case, consuming)
    inputs = list(scenarios(True, consuming))
    observed = []
    class Observed(SessionReader):
        def __init__(self, *args):
            super().__init__(*args)
            observed.append(self)
    with patch.object(composed, 'closure', linked), patch.object(composed, 'ComposedRead', Observed), \
            patch.object(composed, 'scenarios', scenarios):
        count, merged, _ = composed.inspect(case, True, consuming)
    require(len(observed) == len(inputs) == count, 'every requested composition scenario executed')
    total = calls = 0
    for scenario, machine in zip(inputs, observed):
        events, _, success, *_ = composed.expected(scenario[0], consuming, scenario[1] if consuming else model.UNKNOWN,
                                                  *scenario[2:], names)
        if any(scenario[index] is not None for index in (7, 8, 9)):
            require(not success, 'fault injection reached, not a vacuous later boundary')
        expected, caller_clears = [], []
        checks = chunks = 0
        for event in events:
            if event[0] == 'wipe':
                caller_clears.append(event[1:])
            if event[0] not in ('engine-preflight', 'engine-read'):
                continue
            engine = event[1] if event[0] == 'engine-preflight' else event[2]
            if ('session',) in engine:
                checks += 1
                fault = scenario[7]
                error = fault[1] if fault and fault[0] == checks else names['session_success']
                expected.append(('check', error, (('authority',),)))
            if event[0] != 'engine-read':
                continue
            chunks += 1
            permutations = 0
            for inner in event[1]:
                if inner[0] == 'wipe':
                    caller_clears.append(('storage', *inner[1:]))
                if inner != ('permute',):
                    continue
                permutations += 1
                fault = scenario[8]
                result = (fault[1][2] if fault and fault[0] == chunks and fault[1][:2] == ('permute', permutations)
                          else names['session_success'])
                error, trace, _, _, _ = session.expected(cpu_case, True, 5 if cpu_case.arm else 4,
                                                        1, 2, 2, result, None, names['session_success'])
                expected.append(('permute', error, tuple(trace)))
        require(machine.cpu_records == expected, 'independent exact reader-to-CPU call order, guards, errors and unwind')
        cpu_clears = [('storage', *entry[1:]) for _, _, trace in expected for entry in trace if entry[0] == 'wipe']
        require(machine.completed_clears == machine.clear_requests and not machine.cpu_active and machine.clearing is None,
                'every ordered original clear request executes actual byte loop and fence')
        require([entry for entry in machine.completed_clears if entry[0] != 'storage' or entry[1] >= 576] == caller_clears
                and [entry for entry in machine.completed_clears if entry[0] == 'storage' and entry[1] < 576] == cpu_clears,
                'actual clears match independently checked CPU scratch and reader ownership regions')
        quarantined = any(('quarantine',) in trace for _, _, trace in expected)
        fault = scenario[7]
        expected_health = 2 if quarantined or fault and fault[1] == 4 else 0 if fault and fault[1] == 3 else 1
        require(machine.load(model.Pointer('authority', 8), 1) == expected_health
                and machine.load(machine.owner, 8) == (3 if quarantined else 2), 'exact terminal CPU owner metadata')
        total += len(machine.completed_clears)
        calls += len(expected)
    return count, len(merged), total, calls


def main(record, shard):
    before = comparison.capture.sources()
    pairs = list(cases(record))
    for case, cpu_case in pairs if shard is None else [pairs[shard]]:
        for consuming in (False, True):
            count, functions, clears, calls = inspect(case, cpu_case, consuming)
            print(f'Reader/session composition {consuming=}: {count} cases; {functions} functions; '
                  f'{calls} CPU calls; {clears} actual clears PASS', flush=True)
    require(before == comparison.capture.sources(), 'captured implementation unchanged')
    print('Matrix: ' + ('all eight paths' if shard is None else f'shard {shard}/8; all eight required'))
    print('Record SHA-256: ' + comparison.capture.audit.digest(record))
    print('Static-only; raw kernel payload opaque; synthetic unwind; no whole-call/F1 qualification')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('--shard', type=int, choices=range(8))
    args = parser.parse_args()
    with patch('subprocess.run', side_effect=AssertionError('no compiler/runtime rerun permitted')):
        main(args.record.resolve(), args.shard)
